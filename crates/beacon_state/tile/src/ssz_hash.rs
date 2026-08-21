use flux_profiler::timed;
use silver_beacon_state_data::{
    BeaconBlockHeader, Checkpoint, EPOCHS_PER_HISTORICAL_VECTOR, EPOCHS_PER_SLASHINGS_VECTOR,
    ExecutionPayloadHeader, Fork, SLOTS_PER_HISTORICAL_ROOT, StateReadView,
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

#[inline]
#[timed]
pub fn hash_tree_root_state(rv: &StateReadView) -> B256 {
    if rv.is_gloas() { BeaconStateGloas::hash_tree_root(rv) } else { hash_tree_root_state_fulu(rv) }
}

/// State fields 0..=37, shared by the Fulu and Gloas layouts. Field 24 is the
/// sole divergence — Fulu hashes `latest_execution_payload_header`, Gloas
/// substitutes `latest_block_hash` — so the caller passes it in.
///
/// Pure read over a fork's [`StateReadView`] — the caller resolves the bundle
/// (including the boundary tiers, fresh at each call: a boundary
/// `process_epoch` re-rolls them mid-`process_slots`).
pub(crate) fn hash_common_fields(rv: &StateReadView, execution_field: B256) -> [B256; 38] {
    let imm = rv.imm;
    let slot = rv.slot.state();
    let es = rv.epoch.state();
    let lt = rv.longtail.state();

    [
        uint64_chunk(imm.genesis_time),
        imm.genesis_validators_root,
        uint64_chunk(slot.slot),
        hash_fork(rv.epoch.fork()),
        hash_tree_root_block_header(&slot.latest_block_header),
        rv.block_roots.hash_root(),
        rv.state_roots.hash_root(),
        imm.historical_roots_hash,
        slot.eth1_data.leaf(),
        rv.eth1.hash_root(),
        uint64_chunk(slot.eth1_deposit_index),
        rv.validators.hash_root(),
        rv.balances.hash_root(),
        rv.randao_mixes.hash_root(),
        rv.slashings.hash_root(),
        rv.previous_participation.hash_root(),
        rv.current_participation.hash_root(),
        uint64_chunk(es.justification_bits as u64),
        hash_checkpoint(&es.previous_justified_checkpoint),
        hash_checkpoint(&es.current_justified_checkpoint),
        hash_checkpoint(&es.finalized_checkpoint),
        rv.inactivity.hash_root(),
        lt.sync_committees().current_root(),
        lt.sync_committees().next_root(),
        execution_field,
        uint64_chunk(slot.next_withdrawal_index),
        uint64_chunk(slot.next_withdrawal_validator_index),
        rv.longtail.historical_summaries_root(),
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

fn hash_tree_root_state_fulu(rv: &StateReadView) -> B256 {
    let header = hash_execution_payload_header(&rv.slot.state().latest_execution_payload_header);
    merkleize(&hash_common_fields(rv, header))
}

// ---------------------------------------------------------------------------
// Tier hashers
// ---------------------------------------------------------------------------

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

// Compile-time sanity: the spec ring sizes the STF indexes with `%` are powers
// of two, so the bucket arithmetic folds to a mask.
const _: () = {
    assert!(EPOCHS_PER_HISTORICAL_VECTOR.is_power_of_two());
    assert!(EPOCHS_PER_SLASHINGS_VECTOR.is_power_of_two());
    assert!(SLOTS_PER_HISTORICAL_ROOT.is_power_of_two());
};
