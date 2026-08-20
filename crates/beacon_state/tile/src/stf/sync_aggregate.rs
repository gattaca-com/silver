use flux_profiler::timed;
use silver_beacon_state_data::{
    LongtailView, SLOTS_PER_EPOCH, SYNC_COMMITTEE_SIZE, Slot, StateReadView, StateWriterView,
};
use silver_common::ssz_view::{BLOCK_SYNC_AGGREGATE_SIZE, SyncAggregateView};

use crate::{
    bls::{self, SigBatch},
    error::{Result, SyncAggregateError},
    stf::{
        BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, PROPOSER_WEIGHT, WEIGHT_DENOMINATOR,
        integer_sqrt,
    },
};

/// Pass 1 — resolve sync committee participants from
/// `sync_committee_indices` × bits, push aggregate sig (eth_aggregate
/// semantics — empty + G2-∞ ok).
#[timed]
pub fn collect_sigs_sync_aggregate(
    view: &StateReadView,
    sync_agg: &[u8],
    block_slot: Slot,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) {
    let imm = view.imm;
    let validators = &view.validators;
    let longtail = &view.longtail;
    if sync_agg.len() < BLOCK_SYNC_AGGREGATE_SIZE {
        return;
    }
    let sync_agg_fixed: &[u8; BLOCK_SYNC_AGGREGATE_SIZE] =
        sync_agg[..BLOCK_SYNC_AGGREGATE_SIZE].try_into().unwrap();
    let bits = SyncAggregateView::sync_committee_bits(sync_agg_fixed);
    let sig = SyncAggregateView::sync_committee_signature(sync_agg_fixed);

    let previous_slot = block_slot.saturating_sub(1);
    let previous_block_root = view.block_roots.at_slot(previous_slot);
    let previous_epoch = previous_slot / SLOTS_PER_EPOCH;
    let fork_version = view.epoch.fork_version_at(previous_epoch);

    active_scratch.clear();
    let count = validators.count();
    let sync_indices = *longtail.sync_committees().indices();
    for (i, &vi) in sync_indices.iter().enumerate() {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        if bits[byte_idx] & (1 << bit_idx) != 0 {
            if (vi as usize) >= count {
                sig_batch.poison();
                return;
            }
            active_scratch.push(vi);
        }
    }
    let domain =
        bls::compute_domain(bls::DOMAIN_SYNC_COMMITTEE, fork_version, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&previous_block_root, &domain);
    sig_batch.push_eth_aggregate(
        active_scratch.len(),
        active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
        sig,
        signing_root,
    );
}

/// Pass 2 — apply sync_aggregate balance updates. BLS verified in pass 1.
#[timed]
pub fn process_sync_aggregate(
    view: &mut StateWriterView,
    longtail: LongtailView,
    sync_agg: &[u8],
    proposer_index: u32,
) -> Result<(), SyncAggregateError> {
    let slot = &view.slot;
    let validators = &view.validators;
    let balances = &mut view.balances;
    if sync_agg.len() < BLOCK_SYNC_AGGREGATE_SIZE {
        return Ok(());
    }
    let count = validators.count();
    if (proposer_index as usize) >= count {
        return Err(SyncAggregateError::ProposerOutOfRange { idx: proposer_index as u64, count });
    }
    let sync_agg_fixed: &[u8; BLOCK_SYNC_AGGREGATE_SIZE] =
        sync_agg[..BLOCK_SYNC_AGGREGATE_SIZE].try_into().unwrap();
    let bits = SyncAggregateView::sync_committee_bits(sync_agg_fixed);

    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    let total_active = slot.total_active_balance(current_epoch);
    let sqrt_total = integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;
    let total_active_increments = total_active / EFFECTIVE_BALANCE_INCREMENT;

    const SYNC_REWARD_WEIGHT: u64 = 2;

    let total_base_rewards = base_reward_per_increment * total_active_increments;
    let participant_reward = if total_active_increments > 0 {
        total_base_rewards * SYNC_REWARD_WEIGHT /
            WEIGHT_DENOMINATOR /
            SLOTS_PER_EPOCH /
            SYNC_COMMITTEE_SIZE as u64
    } else {
        0
    };
    let proposer_reward_per =
        participant_reward * PROPOSER_WEIGHT / (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT);

    let sync_indices: [u32; SYNC_COMMITTEE_SIZE] = *longtail.sync_committees().indices();

    let mut proposer_reward_sum = 0u64;
    #[allow(clippy::needless_range_loop)]
    for i in 0..SYNC_COMMITTEE_SIZE {
        let vi = sync_indices[i];
        if (vi as usize) >= count {
            continue;
        }
        if bits[i / 8] & (1 << (i % 8)) != 0 {
            proposer_reward_sum += proposer_reward_per;
            balances.add_at(vi, participant_reward as i64);
        } else {
            balances.add_at(vi, -(participant_reward as i64));
        }
    }
    balances.add_at(proposer_index, proposer_reward_sum as i64);
    balances.rehash_unsorted();
    Ok(())
}
