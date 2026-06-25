use silver_beacon_state_data::{
    self as common, BeaconBlockHeader, BuilderPendingPayment, BuilderPendingWithdrawal, Checkpoint,
    EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR, Eth1Data, ExecutionPayloadBid,
    ExecutionPayloadHeader, Fork, HISTORICAL_ROOTS_LIMIT, LongtailView, MAX_ETH1_VOTES,
    SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, StateReadView, SyncCommittee, Withdrawal,
    effective_randao_mixes_into, effective_slashings_into,
    gloas::{
        BUILDER_PENDING_PAYMENTS_LEN, BUILDER_PENDING_WITHDRAWALS_LIMIT,
        MAX_BLOB_COMMITMENTS_PER_BLOCK, MAX_WITHDRAWALS_PER_PAYLOAD, PTC_WINDOW_LEN,
    },
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

#[inline]
#[timed]
pub fn hash_tree_root_state(rv: &StateReadView, scratch: &mut StateHashScratch) -> B256 {
    if rv.imm.is_gloas() {
        hash_tree_root_state_gloas(rv, scratch)
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
fn hash_common_fields(
    rv: &StateReadView,
    scratch: &mut StateHashScratch,
    execution_field: B256,
) -> [B256; 38] {
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

    [
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

fn hash_tree_root_state_gloas(rv: &StateReadView, scratch: &mut StateHashScratch) -> B256 {
    // [Modified in Gloas] `latest_block_hash` (Hash32) replaces the header.
    let common = hash_common_fields(rv, scratch, rv.slot.state().latest_block_hash);
    let slot = rv.slot.state();
    let es = rv.epoch.state();

    let mut fields = [[0u8; 32]; 46];
    fields[..38].copy_from_slice(&common);
    // [New in Gloas]
    fields[38..].copy_from_slice(&[
        rv.builders.hash_root(),
        uint64_chunk(slot.next_withdrawal_builder_index),
        hash_bitvector(&slot.execution_payload_availability),
        hash_vector(
            slot.builder_pending_payments.iter(),
            BUILDER_PENDING_PAYMENTS_LEN,
            hash_builder_pending_payment,
        ),
        hash_list(
            slot.builder_pending_withdrawals.iter(),
            slot.builder_pending_withdrawals.len(),
            BUILDER_PENDING_WITHDRAWALS_LIMIT,
            hash_builder_pending_withdrawal,
        ),
        hash_execution_payload_bid(&slot.latest_execution_payload_bid),
        hash_list(
            slot.payload_expected_withdrawals.iter(),
            slot.payload_expected_withdrawals.len(),
            MAX_WITHDRAWALS_PER_PAYLOAD,
            hash_withdrawal,
        ),
        // `ptc_window`: each committee is a `Vector[ValidatorIndex, PTC_SIZE]`.
        hash_vector(es.ptc_window.iter(), PTC_WINDOW_LEN, |c| hash_uint64_vector(c)),
    ]);

    merkleize(&fields)
}

// ---------------------------------------------------------------------------
// Gloas (EIP-7732) leaf hashers
// ---------------------------------------------------------------------------

/// `ExecutionAddress` (20 B) right-padded into a 32-B chunk.
#[inline]
fn address_chunk(addr: &[u8; 20]) -> B256 {
    let mut c = ZERO_HASH;
    c[..20].copy_from_slice(addr);
    c
}

fn hash_builder_pending_withdrawal(w: &BuilderPendingWithdrawal) -> B256 {
    merkleize(&[
        address_chunk(&w.fee_recipient),
        uint64_chunk(w.amount),
        uint64_chunk(w.builder_index),
    ])
}

fn hash_builder_pending_payment(p: &BuilderPendingPayment) -> B256 {
    merkleize(&[
        uint64_chunk(p.weight),
        hash_builder_pending_withdrawal(&p.withdrawal),
        uint64_chunk(p.proposer_index),
    ])
}

fn hash_withdrawal(w: &Withdrawal) -> B256 {
    merkleize(&[
        uint64_chunk(w.index),
        uint64_chunk(w.validator_index),
        address_chunk(&w.address),
        uint64_chunk(w.amount),
    ])
}

fn hash_execution_payload_bid(bid: &ExecutionPayloadBid) -> B256 {
    let kzg_commitments_root = hash_list(
        bid.blob_kzg_commitments.iter(),
        bid.blob_kzg_commitments.len(),
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        |c| hash_fixed_bytes(c),
    );
    merkleize(&[
        bid.parent_block_hash,
        bid.parent_block_root,
        bid.block_hash,
        bid.prev_randao,
        address_chunk(&bid.fee_recipient),
        uint64_chunk(bid.gas_limit),
        uint64_chunk(bid.builder_index),
        uint64_chunk(bid.slot),
        uint64_chunk(bid.value),
        uint64_chunk(bid.execution_payment),
        kzg_commitments_root,
        bid.execution_requests_root,
    ])
}

/// `Bitvector[N]` root: the packed bytes as 32-B chunks, merkleized to the
/// chunk-count depth (no length mix-in).
fn hash_bitvector(bits: &[u8]) -> B256 {
    let mut stack = MerkleStack::new();
    push_bytes_as_chunks(bits, &mut stack);
    merkle_finalize(stack, list_depth(bits.len().div_ceil(32)))
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
    let pubkeys_root =
        hash_vector(sc.pubkeys.iter(), SYNC_COMMITTEE_SIZE, |pk| hash_fixed_bytes(pk));
    hash_concat(&pubkeys_root, &hash_fixed_bytes(&sc.aggregate_pubkey))
}

#[timed]
pub fn hash_eth1_votes(eth1: &common::Eth1View) -> B256 {
    hash_list(eth1.iter(), eth1.len(), MAX_ETH1_VOTES, hash_eth1_data)
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
pub fn hash_historical_summaries(longtail: &LongtailView) -> B256 {
    let n = longtail.historical_summaries_len();
    hash_list(
        (0..n).map(|i| longtail.historical_summary(i).unwrap()),
        n,
        HISTORICAL_ROOTS_LIMIT,
        |s| hash_concat(&s.block_summary_root, &s.state_summary_root),
    )
}

// Compile-time sanity: spec circular buffer sizes match the slice lengths
// callers actually pass in.
const _: () = {
    assert!(EPOCHS_PER_HISTORICAL_VECTOR.is_power_of_two());
    assert!(EPOCHS_PER_SLASHINGS_VECTOR.is_power_of_two());
    assert!(SLOTS_PER_HISTORICAL_ROOT.is_power_of_two());
};
