use silver_beacon_state_data::{
    B256, ColumnSpec, Epoch, EpochView, Immutable, ParticipationWriteView, SLOTS_PER_EPOCH, Slot,
    SlotStateWriteView, StateWriterView, ValidatorsView,
};
use silver_common::{
    metrics::timed,
    ssz_view::{AttestationDataView, AttestationView},
};

use crate::{
    bls::{self, SigBatch},
    error::{AttestationError, Result},
    shuffling, ssz_hash,
    stf::{
        AttestationVote, BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, PROPOSER_WEIGHT,
        ShufflingRef, WEIGHT_DENOMINATOR, for_each_ssz_list_item, integer_sqrt,
        total_active_balance,
    },
    validate,
};

#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_attestations(
    imm: &Immutable,
    validators: &ValidatorsView,
    attestation_data: &[u8],
    block_slot: Slot,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttestationError> {
    let current_epoch = block_slot / SLOTS_PER_EPOCH;
    for_each_ssz_list_item(
        attestation_data,
        |start, end| AttestationError::BadOffsets {
            start,
            end,
            parent_len: attestation_data.len(),
        },
        |att| {
            collect_sigs_single_attestation(
                imm,
                validators,
                att,
                current_epoch,
                shuffling,
                active_scratch,
                sig_batch,
            )
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn collect_sigs_single_attestation(
    imm: &Immutable,
    validators: &ValidatorsView,
    att: &[u8],
    current_epoch: Epoch,
    shuffling: Option<&ShufflingRef<'_>>,
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttestationError> {
    let (fork_epoch, prev_v, curr_v, gvr) = imm.fork_descriptor();
    let data = AttestationView::data(att);
    let att_slot = AttestationDataView::slot(data);
    let target_epoch = AttestationDataView::target_epoch(data);
    let is_current = target_epoch == current_epoch;
    let shuffling = shuffling.ok_or(AttestationError::MissingShuffling)?;
    let (shuffled, committees_per_slot) = shuffling.epoch_slice(is_current);
    if shuffled.is_empty() || committees_per_slot == 0 {
        return Err(AttestationError::EmptyShuffling);
    }
    let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
    let agg_bits = AttestationView::aggregation_bits(att);
    if committee_bits == 0 {
        return Err(AttestationError::EmptyCommitteeBits);
    }

    active_scratch.clear();
    let mut agg_offset = 0usize;
    let count = validators.count();
    for ci in 0..committees_per_slot {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee =
            shuffling::get_beacon_committee(shuffled, att_slot, ci, committees_per_slot);
        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }
            let vi = validator_idx as usize;
            if vi >= count {
                return Err(AttestationError::ValidatorOutOfRange { vi, count });
            }
            active_scratch.push(validator_idx);
        }
        agg_offset += committee.len();
    }

    let fork_version = bls::fork_version_at_epoch(fork_epoch, prev_v, curr_v, target_epoch);
    let sig = AttestationView::signature(att);
    let object_root = ssz_hash::hash_attestation_data(data);
    let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fork_version, &gvr);
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    sig_batch.push_aggregate(
        active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
        sig,
        signing_root,
    );
    Ok(())
}

/// Pass 2 — full data + state-dep validation, apply participation flags +
/// proposer rewards. BLS verified in pass 1.
#[timed]
#[allow(clippy::too_many_arguments)]
pub fn process_attestations(
    view: &mut StateWriterView,
    epoch: EpochView,
    attestation_data: &[u8],
    block_slot: Slot,
    proposer_index: u32,
    shuffling: Option<&ShufflingRef<'_>>,
    votes_sink: &mut Vec<AttestationVote>,
    active_scratch: &mut Vec<u32>,
) -> Result<(), AttestationError> {
    if attestation_data.is_empty() {
        return Ok(());
    }
    let current_epoch = block_slot / SLOTS_PER_EPOCH;
    let previous_epoch = current_epoch.saturating_sub(1);

    let total_active = total_active_balance(&view.validators.reader(), current_epoch);
    for_each_ssz_list_item(
        attestation_data,
        |start, end| AttestationError::BadOffsets {
            start,
            end,
            parent_len: attestation_data.len(),
        },
        |att| {
            let reward = process_single_attestation(
                view,
                epoch,
                att,
                current_epoch,
                previous_epoch,
                total_active,
                shuffling,
                votes_sink,
                active_scratch,
            )?;
            if reward > 0 && (proposer_index as usize) < view.validators.count() {
                let proposer_reward_denominator =
                    (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
                let proposer_reward = reward / proposer_reward_denominator;
                let balance = view.balances.get(proposer_index as usize);
                view.balances.set(proposer_index, balance.saturating_add(proposer_reward));
            }
            Ok(())
        },
    )
}

/// Pass 2 single-attestation worker — full data + state-dep validation +
/// participation flag updates. Returns the proposer reward numerator on
/// success.
#[allow(clippy::too_many_arguments)]
pub fn process_single_attestation(
    view: &mut StateWriterView,
    epoch: EpochView,
    att: &[u8],
    current_epoch: Epoch,
    previous_epoch: Epoch,
    total_active: u64,
    shuffling: Option<&ShufflingRef<'_>>,
    votes_sink: &mut Vec<AttestationVote>,
    active_scratch: &mut Vec<u32>,
) -> Result<u64, AttestationError> {
    let current_slot = view.slot.state().slot;
    validate::validate_attestation_data(att, current_slot, current_epoch, previous_epoch)?;

    let parsed = ParsedAttestationData::parse(att);
    let is_current =
        check_attestation_target_window(parsed.target_epoch, current_epoch, previous_epoch)?;
    check_attestation_source(epoch, is_current, parsed.source_epoch, parsed.source_root)?;

    let flag_weights = compute_attestation_flags(&view.slot, &parsed, current_slot);

    collect_attestation_participants(
        &view.validators.reader(),
        att,
        shuffling,
        &parsed,
        is_current,
        active_scratch,
    )?;

    for &validator_idx in active_scratch.iter() {
        votes_sink.push(AttestationVote {
            validator: validator_idx,
            block_root: parsed.beacon_block_root,
            target_epoch: parsed.target_epoch,
        });
    }

    if !flag_weights.iter().any(|&f| f) {
        return Ok(0);
    }
    // Distinct `Previous`/`Current` types can't share one binding, so branch
    // and let each arm monomorphise the generic helper for its column.
    let validators = view.validators.reader();
    Ok(if is_current {
        apply_attestation_participation_flags(
            &validators,
            &mut view.current_participation,
            active_scratch,
            total_active,
            flag_weights,
        )
    } else {
        apply_attestation_participation_flags(
            &validators,
            &mut view.previous_participation,
            active_scratch,
            total_active,
            flag_weights,
        )
    })
}

struct ParsedAttestationData {
    att_slot: Slot,
    beacon_block_root: B256,
    source_epoch: Epoch,
    source_root: B256,
    target_epoch: Epoch,
    target_root: B256,
}

impl ParsedAttestationData {
    fn parse(att: &[u8]) -> Self {
        let data = AttestationView::data(att);
        Self {
            att_slot: AttestationDataView::slot(data),
            beacon_block_root: *AttestationDataView::beacon_block_root(data),
            source_epoch: AttestationDataView::source_epoch(data),
            source_root: *AttestationDataView::source_root(data),
            target_epoch: AttestationDataView::target_epoch(data),
            target_root: *AttestationDataView::target_root(data),
        }
    }
}

fn check_attestation_target_window(
    target: Epoch,
    curr: Epoch,
    prev: Epoch,
) -> Result<bool, AttestationError> {
    if target == curr {
        Ok(true)
    } else if target == prev {
        Ok(false)
    } else {
        Err(AttestationError::TargetEpochOutOfWindow { target, prev, curr })
    }
}

fn check_attestation_source(
    epoch: EpochView,
    is_current: bool,
    source_epoch: Epoch,
    source_root: B256,
) -> Result<(), AttestationError> {
    let es = epoch.state();
    let justified =
        if is_current { es.current_justified_checkpoint } else { es.previous_justified_checkpoint };
    if source_epoch != justified.epoch || source_root != justified.root {
        return Err(AttestationError::SourceMismatch {
            expected_epoch: justified.epoch,
            expected_root: justified.root,
            got_epoch: source_epoch,
            got_root: source_root,
        });
    }
    Ok(())
}

fn compute_attestation_flags(
    slot: &SlotStateWriteView,
    parsed: &ParsedAttestationData,
    current_slot: Slot,
) -> [bool; 3] {
    let expected_target_root = slot.block_root_at_slot(parsed.target_epoch * SLOTS_PER_EPOCH);
    let is_matching_target = parsed.target_root == expected_target_root;
    let expected_head_root = slot.block_root_at_slot(parsed.att_slot);
    let is_matching_head = is_matching_target && parsed.beacon_block_root == expected_head_root;
    let inclusion_delay = current_slot.saturating_sub(parsed.att_slot);

    [inclusion_delay <= 5, is_matching_target, is_matching_head && inclusion_delay == 1]
}

fn collect_attestation_participants(
    validators: &ValidatorsView,
    att: &[u8],
    shuffling: Option<&ShufflingRef<'_>>,
    parsed: &ParsedAttestationData,
    is_current: bool,
    active_scratch: &mut Vec<u32>,
) -> Result<(), AttestationError> {
    let shuffling = shuffling.ok_or(AttestationError::MissingShuffling)?;
    let (shuffled, committees_per_slot) = shuffling.epoch_slice(is_current);
    if shuffled.is_empty() || committees_per_slot == 0 {
        return Err(AttestationError::EmptyShuffling);
    }

    let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
    let agg_bits = AttestationView::aggregation_bits(att);
    if committee_bits == 0 {
        return Err(AttestationError::EmptyCommitteeBits);
    }
    if committees_per_slot < 64 && (committee_bits >> committees_per_slot) != 0 {
        return Err(AttestationError::CommitteeBitsOverflow {
            committees_per_slot,
            bits: committee_bits,
        });
    }

    active_scratch.clear();
    let count = validators.count();
    let mut agg_offset = 0usize;
    for ci in 0..committees_per_slot {
        if committee_bits & (1u64 << ci) == 0 {
            continue;
        }
        let committee =
            shuffling::get_beacon_committee(shuffled, parsed.att_slot, ci, committees_per_slot);
        let before = active_scratch.len();
        for (j, &validator_idx) in committee.iter().enumerate() {
            let bit_pos = agg_offset + j;
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            if byte_idx >= agg_bits.len() || agg_bits[byte_idx] & (1 << bit_idx) == 0 {
                continue;
            }
            let vi = validator_idx as usize;
            if vi >= count {
                return Err(AttestationError::ValidatorOutOfRange { vi, count });
            }
            active_scratch.push(validator_idx);
        }
        if active_scratch.len() == before {
            return Err(AttestationError::EmptyCommittee);
        }
        agg_offset += committee.len();
    }

    let bitlist_len = ssz_hash::bitlist_len(agg_bits);
    if bitlist_len != agg_offset {
        return Err(AttestationError::BitlistLenMismatch { expected: agg_offset, got: bitlist_len });
    }
    Ok(())
}

fn apply_attestation_participation_flags<M: ColumnSpec<Val = u8>>(
    validators: &ValidatorsView,
    participation: &mut ParticipationWriteView<M>,
    active_scratch: &[u32],
    total_active: u64,
    flag_weights: [bool; 3],
) -> u64 {
    let sqrt_total = integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;

    const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14];
    let mut proposer_reward_numerator = 0u64;
    // Collect changed flags, then apply them in one sorted merge. A committee's
    // participants are distinct validator indices, so the batch is dup-free; a
    // per-validator `set_*_participation` would be O(|edits|) each (quadratic
    // over an epoch's accumulated participation edits).
    let mut updates: Vec<(u32, u8)> = Vec::with_capacity(active_scratch.len());
    for &vi in active_scratch {
        let prev_p = participation.get(vi as usize);
        let mut p = prev_p;
        let effective_balance = validators.effective_balance(vi as usize);
        let base_reward =
            (effective_balance / EFFECTIVE_BALANCE_INCREMENT) * base_reward_per_increment;
        for (fi, &weight) in PARTICIPATION_WEIGHTS.iter().enumerate() {
            let flag_bit = 1u8 << fi;
            if flag_weights[fi] && p & flag_bit == 0 {
                p |= flag_bit;
                proposer_reward_numerator += base_reward * weight;
            }
        }
        if p != prev_p {
            updates.push((vi, p));
        }
    }
    updates.sort_unstable_by_key(|(idx, _)| *idx);
    participation.set_many(&updates);
    proposer_reward_numerator
}
