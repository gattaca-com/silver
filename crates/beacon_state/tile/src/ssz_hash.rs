use flux_profiler::timed;
use silver_beacon_state_data::{
    self as common, BeaconBlockHeader, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR, Eth1Data, ExecutionPayloadHeader, Fork, HISTORICAL_ROOTS_LIMIT,
    LongtailView, MAX_ETH1_VOTES, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, StateReadView,
    SyncCommittee, effective_randao_mixes_into,
};
use silver_common::merkle::*;
pub use silver_common::ssz_hash::*;

use crate::ssz_hash_gloas::BeaconStateGloas;

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

/// Reusable buffer for the merged `randao_mixes` ring, so repeated
/// `hash_tree_root_state` calls (one per `process_slot`) don't re-allocate
/// `EPOCHS_PER_HISTORICAL_VECTOR * 32` = 2 MB every time.
pub struct StateHashScratch {
    randao_mixes: Vec<B256>,
}

impl StateHashScratch {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { randao_mixes: Vec::with_capacity(EPOCHS_PER_HISTORICAL_VECTOR) }
    }
}

#[inline]
#[timed]
pub fn hash_tree_root_state(rv: &StateReadView, scratch: &mut StateHashScratch) -> B256 {
    if rv.is_gloas() {
        BeaconStateGloas::hash_tree_root(rv, scratch)
    } else {
        hash_tree_root_state_fulu(rv, scratch)
    }
}

// TODO(perf): full re-merkleization every block + every process_slot.
// Replace with milhouse-style persistent trees with per-leaf dirty bits.

/// State fields 0..=37, shared by the Fulu and Gloas layouts. Field 24 is the
/// sole divergence — Fulu hashes `latest_execution_payload_header`, Gloas
/// substitutes `latest_block_hash` — so the caller passes it in.
///
/// Pure read over a fork's [`StateReadView`] — the caller resolves the bundle
/// (including the boundary tiers, fresh at each call: a boundary
/// `process_epoch` re-rolls them mid-`process_slots`).
pub(crate) fn hash_common_fields(
    rv: &StateReadView,
    scratch: &mut StateHashScratch,
    execution_field: B256,
) -> [B256; 38] {
    let imm = rv.imm;
    let slot = rv.slot.state();
    let es = rv.epoch.state();
    let lt = rv.longtail.state();

    effective_randao_mixes_into(&rv.epoch, &rv.slot, &mut scratch.randao_mixes);
    let randao_mixes = scratch.randao_mixes.as_slice();

    [
        uint64_chunk(imm.genesis_time),
        imm.genesis_validators_root,
        uint64_chunk(slot.slot),
        hash_fork(rv.epoch.fork()),
        hash_tree_root_block_header(&slot.latest_block_header),
        rv.block_roots.hash_root(),
        rv.state_roots.hash_root(),
        imm.historical_roots_hash,
        hash_eth1_data(&slot.eth1_data),
        hash_eth1_votes(&rv.eth1),
        uint64_chunk(slot.eth1_deposit_index),
        rv.validators.hash_root(),
        rv.balances.hash_root(),
        hash_b256_vector(randao_mixes),
        rv.slashings.hash_root(),
        rv.previous_participation.hash_root(),
        rv.current_participation.hash_root(),
        uint64_chunk(es.justification_bits as u64),
        hash_checkpoint(&es.previous_justified_checkpoint),
        hash_checkpoint(&es.current_justified_checkpoint),
        hash_checkpoint(&es.finalized_checkpoint),
        rv.inactivity.hash_root(),
        hash_sync_committee(&lt.current_sync_committee),
        hash_sync_committee(&lt.next_sync_committee),
        execution_field,
        uint64_chunk(slot.next_withdrawal_index),
        uint64_chunk(slot.next_withdrawal_validator_index),
        hash_historical_summaries(&rv.longtail),
        uint64_chunk(slot.deposit_requests_start_index),
        uint64_chunk(es.deposit_balance_to_consume),
        uint64_chunk(slot.exit_balance_to_consume),
        uint64_chunk(slot.earliest_exit_epoch),
        uint64_chunk(slot.consolidation_balance_to_consume),
        uint64_chunk(slot.earliest_consolidation_epoch),
        rv.pending.deposits.hash_root(),
        rv.pending.partial_withdrawals.hash_root(),
        rv.pending.consolidations.hash_root(),
        hash_uint64_vector(&es.proposer_lookahead),
    ]
}

fn hash_tree_root_state_fulu(rv: &StateReadView, scratch: &mut StateHashScratch) -> B256 {
    let header = hash_execution_payload_header(&rv.slot.state().latest_execution_payload_header);
    merkleize(&hash_common_fields(rv, scratch, header))
}

// ---------------------------------------------------------------------------
// Tier hashers
// ---------------------------------------------------------------------------

#[timed]
pub fn hash_sync_committee(sc: &SyncCommittee) -> B256 {
    let pubkeys_root = hash_vector(
        MerkleStack::new(SYNC_COMMITTEE_SIZE),
        sc.pubkeys.iter().map(|pk| hash_fixed_bytes(pk)),
    );
    hash_concat(&pubkeys_root, &hash_fixed_bytes(&sc.aggregate_pubkey))
}

#[timed]
pub fn hash_eth1_votes(eth1: &common::Eth1View) -> B256 {
    hash_list(MerkleStack::new(MAX_ETH1_VOTES), eth1.iter().map(hash_eth1_data))
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

    let extra_data_root = mix_in_length(
        &merkleize_bytes(&h.extra_data[..h.extra_data_len as usize], 1),
        h.extra_data_len as usize,
    );

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
pub fn hash_historical_summaries(longtail: &LongtailView) -> B256 {
    let n = longtail.historical_summaries_len();
    hash_list(
        MerkleStack::new(HISTORICAL_ROOTS_LIMIT),
        (0..n).map(|i| {
            let s = longtail.historical_summary(i).unwrap();
            hash_concat(&s.block_summary_root, &s.state_summary_root)
        }),
    )
}

// Compile-time sanity: the spec ring sizes the STF indexes with `%` are powers
// of two, so the bucket arithmetic folds to a mask.
const _: () = {
    assert!(EPOCHS_PER_HISTORICAL_VECTOR.is_power_of_two());
    assert!(EPOCHS_PER_SLASHINGS_VECTOR.is_power_of_two());
    assert!(SLOTS_PER_HISTORICAL_ROOT.is_power_of_two());
};
