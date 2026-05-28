//! Beacon-state-specific SSZ hash-tree-root functions. Generic primitives,
//! merkleization, and byte-slice container/list hashers live in
//! `silver_common::ssz_hash` and are re-exported here so existing call
//! sites in this crate resolve unchanged.
//!
//! What remains here: hashers that take in-memory beacon-state types
//! (`BeaconBlockHeader`, `Checkpoint`, `Eth1Data`, the
//! `Immutable`/`EpochData`/`SlotData`/... layered state, sync committee,
//! validators, payload header, pending queues, historical summaries,
//! randao mixes, fork).

use silver_common::metrics::timed;
pub use silver_common::ssz_hash::*;
use tracing::instrument;

use crate::{
    types::{
        self, BeaconBlockHeader, Checkpoint, EpochData, Eth1Data, HISTORICAL_ROOTS_LIMIT,
        HistoricalLongtail, Immutable, PendingQueues, SYNC_COMMITTEE_SIZE, SlotData, SlotRoots,
        VALIDATOR_REGISTRY_LIMIT,
    },
    validator_identity::ValidatorsState,
};

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

/// hash_tree_root of the full BeaconState from tiered data.
/// Fulu state: 38 fields → 64 leaves.
// TODO(perf): full re-merkleization every block + every process_slot
// (state_root snapshot + apply_block verification). At 2M validators
// hash_validators alone is ~8M sha256s per call. Lighthouse uses milhouse
// persistent trees that only re-hash dirty subtrees. Add per-leaf dirty bits
// per tier + a layered cache for: validators, balances, inactivity_scores,
// randao_mixes (see hash_randao_mixes), participation lists.
#[timed]
#[allow(clippy::too_many_arguments)]
#[instrument(skip_all)]
pub fn hash_tree_root_state(
    imm: &Immutable,
    vs: &ValidatorsState,
    longtail: &HistoricalLongtail,
    epoch: &EpochData,
    roots: &SlotRoots,
    sd: &SlotData,
    pq: &PendingQueues,
) -> B256 {
    let n = vs.validator_cnt();

    let fields: [B256; 38] = [
        uint64_chunk(imm.genesis_time),
        imm.genesis_validators_root,
        uint64_chunk(sd.slot),
        hash_fork(&imm.fork),
        hash_tree_root_block_header(&sd.latest_block_header),
        hash_b256_vector(&roots.block_roots),
        hash_b256_vector(&roots.state_roots),
        imm.historical_roots_hash,
        hash_eth1_data(&sd.eth1_data),
        hash_eth1_votes(sd),
        uint64_chunk(sd.eth1_deposit_index),
        hash_validators(vs, epoch), // TODO: change to use validator identity layer hashing
        hash_uint64_list(&sd.balances, n, VALIDATOR_REGISTRY_LIMIT),
        hash_randao_mixes(epoch, sd),
        hash_uint64_vector(&epoch.slashings),
        hash_uint8_list(&sd.previous_epoch_participation, n, VALIDATOR_REGISTRY_LIMIT),
        hash_uint8_list(&sd.current_epoch_participation, n, VALIDATOR_REGISTRY_LIMIT),
        uint64_chunk(sd.justification_bits as u64),
        hash_checkpoint(&sd.previous_justified_checkpoint),
        hash_checkpoint(&sd.current_justified_checkpoint),
        hash_checkpoint(&sd.finalized_checkpoint),
        hash_uint64_list(&epoch.inactivity_scores, n, VALIDATOR_REGISTRY_LIMIT),
        hash_sync_committee(&longtail.current_sync_committee),
        hash_sync_committee(&longtail.next_sync_committee),
        hash_execution_payload_header(&sd.latest_execution_payload_header),
        uint64_chunk(sd.next_withdrawal_index),
        uint64_chunk(sd.next_withdrawal_validator_index),
        hash_historical_summaries(longtail),
        uint64_chunk(sd.deposit_requests_start_index),
        uint64_chunk(sd.deposit_balance_to_consume),
        uint64_chunk(sd.exit_balance_to_consume),
        uint64_chunk(sd.earliest_exit_epoch),
        uint64_chunk(sd.consolidation_balance_to_consume),
        uint64_chunk(sd.earliest_consolidation_epoch),
        hash_pending_deposits(pq),
        hash_pending_partial_withdrawals(pq),
        hash_pending_consolidations(pq),
        hash_uint64_vector(&sd.proposer_lookahead),
    ];

    merkleize(&fields)
}

/// Hash randao_mixes with the per-block accumulator override from SlotData.
// TODO(perf): rebuilds the full 65536-leaf tree every block (~65k sha256s).
// Only one leaf changes per slot (current_idx); cache 2N-1 nodes (~4 MB) on
// EpochData and update the log2(N)=16 path on mutation. Replay must rebuild
// the cache from leaves on load.
#[timed]
pub fn hash_randao_mixes(epoch: &EpochData, sd: &SlotData) -> B256 {
    use types::{EPOCHS_PER_HISTORICAL_VECTOR, SLOTS_PER_EPOCH};
    let current_epoch = sd.slot / SLOTS_PER_EPOCH;
    let current_idx = current_epoch as usize % EPOCHS_PER_HISTORICAL_VECTOR;
    let target_depth = EPOCHS_PER_HISTORICAL_VECTOR.trailing_zeros() as u8;

    let mut stack = MerkleStack::new();
    for (i, mix) in epoch.randao_mixes.iter().enumerate() {
        let m = if i == current_idx { sd.randao_mix_current } else { *mix };
        merkle_push(&mut stack, m);
    }
    merkle_finalize(stack, target_depth)
}

#[timed]
pub fn hash_validators(vs: &ValidatorsState, epoch: &EpochData) -> B256 {
    let n = vs.validator_cnt();
    let target_depth = VALIDATOR_REGISTRY_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        merkle_push(&mut stack, hash_single_validator(vs, epoch, i));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, n)
}

fn hash_single_validator(vs: &ValidatorsState, epoch: &EpochData, i: usize) -> B256 {
    let pubkey_hash = hash_fixed_bytes(vs.pubkey(i));
    let chunks = [
        pubkey_hash,
        vs.withdrawal_credentials(i).0,
        uint64_chunk(epoch.val_effective_balance[i]),
        uint64_chunk(epoch.val_slashed(i) as u64),
        uint64_chunk(epoch.val_activation_eligibility_epoch[i]),
        uint64_chunk(epoch.val_activation_epoch[i]),
        uint64_chunk(epoch.val_exit_epoch[i]),
        uint64_chunk(epoch.val_withdrawable_epoch[i]),
    ];
    merkleize(&chunks)
}

pub fn hash_sync_committee(sc: &types::SyncCommittee) -> B256 {
    let target_depth = SYNC_COMMITTEE_SIZE.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for pk in &sc.pubkeys {
        merkle_push(&mut stack, hash_fixed_bytes(pk));
    }
    let pubkeys_root = merkle_finalize(stack, target_depth);
    let agg_root = hash_fixed_bytes(&sc.aggregate_pubkey);
    hash_concat(&pubkeys_root, &agg_root)
}

pub fn hash_eth1_votes(sd: &SlotData) -> B256 {
    let n = sd.eth1_votes.len();
    let target_depth = types::MAX_ETH1_VOTES.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        merkle_push(&mut stack, hash_eth1_data(&sd.eth1_votes[i]));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, n)
}

pub fn hash_fork(f: &types::Fork) -> B256 {
    let mut pv = ZERO_HASH;
    pv[..4].copy_from_slice(&f.previous_version);
    let mut cv = ZERO_HASH;
    cv[..4].copy_from_slice(&f.current_version);
    merkleize(&[pv, cv, uint64_chunk(f.epoch)])
}

pub fn hash_execution_payload_header(h: &types::ExecutionPayloadHeader) -> B256 {
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
pub fn hash_pending_deposits(pq: &PendingQueues) -> B256 {
    let n = pq.pending_deposits.len();
    let target_depth = types::PENDING_DEPOSITS_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let d = &pq.pending_deposits[i];
        let chunks = [
            hash_fixed_bytes(&d.pubkey),
            d.withdrawal_credentials.0,
            uint64_chunk(d.amount),
            hash_fixed_bytes(&d.signature),
            uint64_chunk(d.slot),
        ];
        merkle_push(&mut stack, merkleize(&chunks));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, n)
}

#[timed]
pub fn hash_pending_partial_withdrawals(pq: &PendingQueues) -> B256 {
    let n = pq.pending_partial_withdrawals.len();
    let target_depth =
        types::PENDING_PARTIAL_WITHDRAWALS_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let w = &pq.pending_partial_withdrawals[i];
        let chunks =
            [uint64_chunk(w.index), uint64_chunk(w.amount), uint64_chunk(w.withdrawable_epoch)];
        merkle_push(&mut stack, merkleize(&chunks));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, n)
}

#[timed]
pub fn hash_pending_consolidations(pq: &PendingQueues) -> B256 {
    let n = pq.pending_consolidations.len();
    let target_depth =
        types::PENDING_CONSOLIDATIONS_LIMIT.next_power_of_two().trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let c = &pq.pending_consolidations[i];
        merkle_push(
            &mut stack,
            hash_concat(&uint64_chunk(c.source_index), &uint64_chunk(c.target_index)),
        );
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, n)
}

#[timed]
pub fn hash_historical_summaries(longtail: &HistoricalLongtail) -> B256 {
    let n = longtail.historical_summaries.len();
    let target_depth = HISTORICAL_ROOTS_LIMIT.trailing_zeros() as u8;
    let mut stack = MerkleStack::new();
    for i in 0..n {
        let s = &longtail.historical_summaries[i];
        merkle_push(&mut stack, hash_concat(&s.block_summary_root, &s.state_summary_root));
    }
    let root = merkle_finalize(stack, target_depth);
    mix_in_length(&root, n)
}
