use silver_beacon_state_data::{
    self as common, BeaconBlockHeader, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR, Eth1Data, ExecutionPayloadHeader, Fork, HISTORICAL_ROOTS_LIMIT,
    LongtailView, MAX_ETH1_VOTES, PENDING_CONSOLIDATIONS_LIMIT, PENDING_DEPOSITS_LIMIT,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT, PendingView, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE,
    StateReadView, SyncCommittee, VALIDATOR_REGISTRY_LIMIT, effective_randao_mixes_into,
    effective_slashings_into,
};
use silver_common::metrics::timed;
pub use silver_common::ssz_hash::*;

#[timed]
pub fn hash_tree_root_block_header(hdr: &BeaconBlockHeader) -> B256 {
    let chunks = [
        uint64_chunk(hdr.slot),
        uint64_chunk(hdr.proposer_index),
        hdr.parent_root,
        hdr.state_root,
        hdr.body_root,
    ];
    merkleize(&chunks)
}

pub fn hash_checkpoint(cp: &Checkpoint) -> B256 {
    hash_concat(&uint64_chunk(cp.epoch), &cp.root)
}

pub fn hash_eth1_data(e: &Eth1Data) -> B256 {
    let chunks = [e.deposit_root, uint64_chunk(e.deposit_count), e.block_hash];
    merkleize(&chunks)
}

/// Reusable buffers for the four merged circular-buffer fields, so repeated
/// `hash_tree_root_state` calls (one per `process_slot`) don't re-allocate the
/// full rings (randao alone is `EPOCHS_PER_HISTORICAL_VECTOR * 32` = 2 MB).
pub struct StateHashScratch {
    pub(crate) block_roots: Vec<B256>,
    pub(crate) state_roots: Vec<B256>,
    randao_mixes: Vec<B256>,
    slashings: Vec<u64>,
}

impl StateHashScratch {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            block_roots: Vec::with_capacity(SLOTS_PER_HISTORICAL_ROOT),
            state_roots: Vec::with_capacity(SLOTS_PER_HISTORICAL_ROOT),
            randao_mixes: Vec::with_capacity(EPOCHS_PER_HISTORICAL_VECTOR),
            slashings: Vec::with_capacity(EPOCHS_PER_SLASHINGS_VECTOR),
        }
    }
}

// TODO(perf): full re-merkleization every block + every process_slot.
// Replace with milhouse-style persistent trees with per-leaf dirty bits.
/// Pure read over a fork's [`StateReadView`] — the caller resolves the bundle
/// (including the boundary tiers, fresh at each call: a boundary
/// `process_epoch` re-rolls them mid-`process_slots`).
#[timed]
pub fn hash_tree_root_state(rv: &StateReadView, scratch: &mut StateHashScratch) -> B256 {
    let imm = rv.imm;
    let slot = rv.slot.state();
    let es = rv.epoch.state();
    let lt = rv.longtail.state();

    rv.slot.effective_block_roots_into(&mut scratch.block_roots);
    rv.slot.effective_state_roots_into(&mut scratch.state_roots);
    effective_randao_mixes_into(&rv.epoch, &rv.slot, &mut scratch.randao_mixes);
    effective_slashings_into(&rv.epoch, &rv.slot, &mut scratch.slashings);
    let block_roots = scratch.block_roots.as_slice();
    let state_roots = scratch.state_roots.as_slice();
    let randao_mixes = scratch.randao_mixes.as_slice();
    let slashings = scratch.slashings.as_slice();
    let n = rv.validators.count();

    let fields: [B256; 38] = [
        uint64_chunk(imm.genesis_time),
        imm.genesis_validators_root,
        uint64_chunk(slot.slot),
        hash_fork(&imm.fork),
        hash_tree_root_block_header(&slot.latest_block_header),
        hash_b256_vector(block_roots),
        hash_b256_vector(state_roots),
        imm.historical_roots_hash,
        hash_eth1_data(&slot.eth1_data),
        hash_eth1_votes(&rv.eth1),
        uint64_chunk(slot.eth1_deposit_index),
        rv.validators.hash_root(),
        rv.balances.hash_root(),
        hash_b256_vector(randao_mixes),
        hash_uint64_vector(slashings),
        hash_uint8_list(rv.previous_participation.iter(), n, VALIDATOR_REGISTRY_LIMIT),
        hash_uint8_list(rv.current_participation.iter(), n, VALIDATOR_REGISTRY_LIMIT),
        uint64_chunk(es.justification_bits as u64),
        hash_checkpoint(&es.previous_justified_checkpoint),
        hash_checkpoint(&es.current_justified_checkpoint),
        hash_checkpoint(&es.finalized_checkpoint),
        hash_uint64_list(rv.inactivity.iter(), n, VALIDATOR_REGISTRY_LIMIT),
        hash_sync_committee(&lt.current_sync_committee),
        hash_sync_committee(&lt.next_sync_committee),
        hash_execution_payload_header(&slot.latest_execution_payload_header),
        uint64_chunk(slot.next_withdrawal_index),
        uint64_chunk(slot.next_withdrawal_validator_index),
        hash_historical_summaries(&rv.longtail),
        uint64_chunk(slot.deposit_requests_start_index),
        uint64_chunk(es.deposit_balance_to_consume),
        uint64_chunk(slot.exit_balance_to_consume),
        uint64_chunk(slot.earliest_exit_epoch),
        uint64_chunk(slot.consolidation_balance_to_consume),
        uint64_chunk(slot.earliest_consolidation_epoch),
        hash_pending_deposits(&rv.pending),
        hash_pending_partial_withdrawals(&rv.pending),
        hash_pending_consolidations(&rv.pending),
        hash_uint64_vector(&es.proposer_lookahead),
    ];

    merkleize(&fields)
}

// ---------------------------------------------------------------------------
// Tier hashers
// ---------------------------------------------------------------------------

#[inline]
fn list_depth(limit: usize) -> u8 {
    limit.next_power_of_two().trailing_zeros() as u8
}

#[timed]
pub fn hash_sync_committee(sc: &SyncCommittee) -> B256 {
    let mut stack = MerkleStack::new();
    for pk in &sc.pubkeys {
        merkle_push(&mut stack, hash_fixed_bytes(pk));
    }
    let pubkeys_root = merkle_finalize(stack, list_depth(SYNC_COMMITTEE_SIZE));
    let agg_root = hash_fixed_bytes(&sc.aggregate_pubkey);
    hash_concat(&pubkeys_root, &agg_root)
}

#[timed]
pub fn hash_eth1_votes(eth1: &common::Eth1View) -> B256 {
    let mut stack = MerkleStack::new();
    for v in eth1.iter() {
        merkle_push(&mut stack, hash_eth1_data(v));
    }
    let root = merkle_finalize(stack, list_depth(MAX_ETH1_VOTES));
    mix_in_length(&root, eth1.len())
}

#[timed]
pub fn hash_fork(f: &Fork) -> B256 {
    let mut pv = ZERO_HASH;
    pv[..4].copy_from_slice(&f.previous_version);
    let mut cv = ZERO_HASH;
    cv[..4].copy_from_slice(&f.current_version);
    merkleize(&[pv, cv, uint64_chunk(f.epoch)])
}

#[timed]
pub fn hash_execution_payload_header(h: &ExecutionPayloadHeader) -> B256 {
    let mut fee_recipient_chunk = ZERO_HASH;
    fee_recipient_chunk[..20].copy_from_slice(&h.fee_recipient);

    let extra_data_root = {
        let mut stack = MerkleStack::new();
        push_bytes_as_chunks(&h.extra_data[..h.extra_data_len as usize], &mut stack);
        let root = merkle_finalize(stack, 0);
        mix_in_length(&root, h.extra_data_len as usize)
    };

    let fields: [B256; 17] = [
        h.parent_hash,
        fee_recipient_chunk,
        h.state_root,
        h.receipts_root,
        hash_fixed_bytes(&h.logs_bloom),
        h.prev_randao,
        uint64_chunk(h.block_number),
        uint64_chunk(h.gas_limit),
        uint64_chunk(h.gas_used),
        uint64_chunk(h.timestamp),
        extra_data_root,
        h.base_fee_per_gas,
        h.block_hash,
        h.transactions_root,
        h.withdrawals_root,
        uint64_chunk(h.blob_gas_used),
        uint64_chunk(h.excess_blob_gas),
    ];
    merkleize(&fields)
}

#[timed]
pub fn hash_pending_deposits(pending: &PendingView) -> B256 {
    let n = pending.pending_deposits_len();
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let d = pending.pending_deposit(i);
        let leaf = merkleize(&[
            hash_fixed_bytes(&d.pubkey),
            d.withdrawal_credentials.0,
            uint64_chunk(d.amount),
            hash_fixed_bytes(&d.signature),
            uint64_chunk(d.slot),
        ]);
        merkle_push(&mut stack, leaf);
    }
    let root = merkle_finalize(stack, list_depth(PENDING_DEPOSITS_LIMIT));
    mix_in_length(&root, n)
}

#[timed]
pub fn hash_pending_partial_withdrawals(pending: &PendingView) -> B256 {
    let n = pending.pending_partial_withdrawals_len();
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let w = pending.pending_partial_withdrawal(i);
        let leaf = merkleize(&[
            uint64_chunk(w.index),
            uint64_chunk(w.amount),
            uint64_chunk(w.withdrawable_epoch),
        ]);
        merkle_push(&mut stack, leaf);
    }
    let root = merkle_finalize(stack, list_depth(PENDING_PARTIAL_WITHDRAWALS_LIMIT));
    mix_in_length(&root, n)
}

#[timed]
pub fn hash_pending_consolidations(pending: &PendingView) -> B256 {
    let n = pending.pending_consolidations_len();
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let c = pending.pending_consolidation(i);
        let leaf = hash_concat(&uint64_chunk(c.source_index), &uint64_chunk(c.target_index));
        merkle_push(&mut stack, leaf);
    }
    let root = merkle_finalize(stack, list_depth(PENDING_CONSOLIDATIONS_LIMIT));
    mix_in_length(&root, n)
}

#[timed]
pub fn hash_historical_summaries(longtail: &LongtailView) -> B256 {
    let n = longtail.historical_summaries_len();
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let s = longtail.historical_summary(i).unwrap();
        let leaf = hash_concat(&s.block_summary_root, &s.state_summary_root);
        merkle_push(&mut stack, leaf);
    }
    let root = merkle_finalize(stack, list_depth(HISTORICAL_ROOTS_LIMIT));
    mix_in_length(&root, n)
}

// Compile-time sanity: spec circular buffer sizes match the slice lengths
// callers actually pass in.
const _: () = {
    assert!(EPOCHS_PER_HISTORICAL_VECTOR.is_power_of_two());
    assert!(EPOCHS_PER_SLASHINGS_VECTOR.is_power_of_two());
    assert!(SLOTS_PER_HISTORICAL_ROOT.is_power_of_two());
};
