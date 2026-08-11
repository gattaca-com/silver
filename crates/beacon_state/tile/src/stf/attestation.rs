use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, ColumnSpec, Epoch, EpochView, Immutable, ParticipationWriteView, SLOTS_PER_EPOCH,
    SLOTS_PER_HISTORICAL_ROOT, Slot, SlotStateWriteView, StateWriterView, ValidatorsView,
};
use silver_common::ssz_view::AttestationView;

use crate::{
    bls::{self, SigBatch},
    error::{AttestationError, Result},
    merkle, ssz_hash,
    stf::{
        AttestationVote, BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, EpochShuffling,
        PROPOSER_WEIGHT, ShufflingRef, WEIGHT_DENOMINATOR, for_each_ssz_list_item, integer_sqrt,
        total_active_balance,
    },
    validate,
};

const GLOAS_PAYLOAD_ABSENT: u64 = 0;
const GLOAS_PAYLOAD_PRESENT: u64 = 1;

const TIMELY_HEAD_FLAG_INDEX: usize = 2;

pub fn collect_sigs_attestations(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    attestation_data: &[u8],
    block_slot: Slot,
    shuffling: Option<&ShufflingRef<'_>>,
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
                epoch,
                validators,
                att,
                current_epoch,
                shuffling,
                sig_batch,
            )
        },
    )
}

pub struct AttestedCommittees<'a> {
    shuffling: &'a EpochShuffling<'a>,
    slot: Slot,
    committee_bits: u64,
    agg_bits: &'a [u8],
}

impl<'a> AttestedCommittees<'a> {
    pub fn new(att: &'a [u8], shuffling: &'a EpochShuffling<'a>) -> Result<Self, AttestationError> {
        let committee_bits = u64::from_le_bytes(*AttestationView::committee_bits(att));
        if committee_bits == 0 {
            return Err(AttestationError::EmptyCommitteeBits);
        }
        let committees_per_slot = shuffling.committees_per_slot;
        if committees_per_slot < u64::BITS as usize && (committee_bits >> committees_per_slot) != 0
        {
            return Err(AttestationError::CommitteeBitsOverflow {
                committees_per_slot,
                bits: committee_bits,
            });
        }
        Ok(Self {
            shuffling,
            slot: AttestationView::data(att).slot(),
            committee_bits,
            agg_bits: AttestationView::aggregation_bits(att),
        })
    }

    pub fn resolve(
        att: &'a [u8],
        shuffling: Option<&'a ShufflingRef<'a>>,
        is_current: bool,
        validators_count: usize,
    ) -> Result<Self, AttestationError> {
        let epoch_shuffling =
            shuffling.ok_or(AttestationError::MissingShuffling)?.for_target(is_current);
        if epoch_shuffling.is_empty() {
            return Err(AttestationError::EmptyShuffling);
        }
        let committees = Self::new(att, epoch_shuffling)?;
        committees.check_indices_addressable(validators_count)?;
        Ok(committees)
    }

    fn indices(&self) -> impl Iterator<Item = usize> + use<'_> {
        let bits = self.committee_bits;
        (0..self.shuffling.committees_per_slot).filter(move |ci| bits & (1u64 << ci) != 0)
    }

    fn attested(&self, bit_pos: usize) -> bool {
        self.agg_bits.get(bit_pos / 8).is_some_and(|b| b & (1 << (bit_pos % 8)) != 0)
    }

    /// Named committees paired with their base offset into `aggregation_bits`,
    /// ascending — member `j` of a committee based at `offset` is bit
    /// `offset + j`.
    fn committees(&self) -> impl Iterator<Item = (&'a [u32], usize)> + use<'_, 'a> {
        let mut agg_offset = 0usize;
        self.indices().map(move |ci| {
            let committee = self.shuffling.committee(self.slot, ci);
            let base = agg_offset;
            agg_offset += committee.len();
            (committee, base)
        })
    }

    fn members(&self, attested: bool) -> impl Iterator<Item = u32> + use<'_, 'a> {
        self.committees().flat_map(move |(committee, base)| {
            committee
                .iter()
                .enumerate()
                .filter_map(move |(j, &vi)| (self.attested(base + j) == attested).then_some(vi))
        })
    }

    fn attesters(&self) -> impl Iterator<Item = u32> + use<'_, 'a> {
        self.members(true)
    }

    fn missed(&self) -> impl Iterator<Item = u32> + use<'_, 'a> {
        self.members(false)
    }

    /// Errors if the shuffling outlived the registry it was taken against, so
    /// callers may index the validator columns with what lands in `out`.
    pub fn attesters_into(
        &self,
        validators_count: usize,
        out: &mut Vec<u32>,
    ) -> Result<(), AttestationError> {
        self.check_indices_addressable(validators_count)?;
        out.clear();
        out.extend(self.attesters());
        Ok(())
    }

    fn check_indices_addressable(&self, validators_count: usize) -> Result<(), AttestationError> {
        if self.shuffling.indices_in_range(validators_count) {
            return Ok(());
        }
        Err(AttestationError::ValidatorOutOfRange {
            vi: self.shuffling.built_against - 1,
            count: validators_count,
        })
    }

    fn member_count(&self) -> usize {
        self.committees().map(|(committee, _)| committee.len()).sum()
    }

    /// Popcount over exactly `members` bits, so the bitlist's length sentinel
    /// and any trailing junk are excluded — the same set [`Self::attested`]
    /// reports over, without walking the committees.
    fn attested_count(&self, members: usize) -> usize {
        let whole = members / 8;
        let head: u32 = self.agg_bits.iter().take(whole).map(|b| b.count_ones()).sum();
        let tail = match (members % 8, self.agg_bits.get(whole)) {
            (0, _) | (_, None) => 0,
            (rem, Some(b)) => (b & ((1u8 << rem) - 1)).count_ones(),
        };
        (head + tail) as usize
    }

    fn aggregates<'b>(&self, epoch_aggs: &'b [PublicKey]) -> impl Iterator<Item = &'b PublicKey> {
        let offset = (self.slot % SLOTS_PER_EPOCH) as usize * self.shuffling.committees_per_slot;
        self.indices().map(move |ci| &epoch_aggs[offset + ci])
    }

    pub fn push_aggregate_sig(
        &self,
        validators: &ValidatorsView,
        sig: &[u8; 96],
        signing_root: B256,
        sig_batch: &mut SigBatch,
    ) {
        let members = self.member_count();
        let attested = self.attested_count(members);
        if attested == 0 {
            sig_batch.poison();
            return;
        }

        // Usually there are many more attested than missed, so we can subtract it from
        // sum
        let pubkey = |vi: u32| validators.pubkey_decompressed(vi as usize);
        let attesters_are_majority = attested * 2 > members;
        match self.shuffling.committee_aggs.filter(|_| attesters_are_majority) {
            Some(aggs) => sig_batch.push_aggregate_subtracted(
                self.aggregates(aggs),
                self.missed().map(pubkey),
                sig,
                signing_root,
            ),
            None => sig_batch.push_aggregate(self.attesters().map(pubkey), sig, signing_root),
        }
    }
}

pub fn collect_sigs_single_attestation(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    att: &[u8],
    current_epoch: Epoch,
    shuffling: Option<&ShufflingRef<'_>>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttestationError> {
    let (fork_epoch, prev_v, curr_v) = epoch.fork_descriptor();
    let data = AttestationView::data(att);
    let target_epoch = data.target_epoch();
    let is_current = target_epoch == current_epoch;
    let committees = AttestedCommittees::resolve(att, shuffling, is_current, validators.count())?;

    let fork_version = bls::fork_version_at_epoch(fork_epoch, prev_v, curr_v, target_epoch);
    let sig = AttestationView::signature(att);
    let object_root = ssz_hash::hash_attestation_data(data.as_bytes());
    let domain = bls::compute_domain(
        bls::DOMAIN_BEACON_ATTESTER,
        fork_version,
        &imm.genesis_validators_root,
    );
    let signing_root = bls::compute_signing_root(&object_root, &domain);

    committees.push_aggregate_sig(validators, sig, signing_root, sig_batch);
    Ok(())
}

/// Pass 2 — full data + state-dep validation, apply participation flags +
/// proposer rewards.
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
    let is_gloas = epoch.is_gloas(view.imm.gloas_fork_version);
    validate::validate_attestation_data(
        att,
        current_slot,
        current_epoch,
        previous_epoch,
        is_gloas,
    )?;

    let parsed = ParsedAttestationData::parse(att);
    let is_current =
        check_attestation_target_window(parsed.target_epoch, current_epoch, previous_epoch)?;
    check_attestation_source(epoch, is_current, parsed.source_epoch, parsed.source_root)?;

    let mut flag_weights = compute_attestation_flags(&view.slot, &parsed, current_slot);

    let (same_slot, payload_present) = if is_gloas {
        (
            gloas_payload_vote_is_same_slot(&view.slot, att, &parsed, &mut flag_weights)?,
            gloas_payload_is_present(att),
        )
    } else {
        (false, false)
    };

    collect_attestation_participants(
        &view.validators.reader(),
        att,
        shuffling,
        is_current,
        active_scratch,
    )?;

    for &validator_idx in active_scratch.iter() {
        votes_sink.push(AttestationVote {
            validator: validator_idx,
            block_root: parsed.beacon_block_root,
            target_epoch: parsed.target_epoch,
            attestation_slot: parsed.att_slot,
            payload_present,
        });
    }

    if !flag_weights.iter().any(|&f| f) {
        return Ok(0);
    }
    // Distinct `Previous`/`Current` types can't share one binding, so branch
    // and let each arm monomorphise the generic helper for its column.
    let validators = view.validators.reader();
    let (reward, new_flag_eb) = if is_current {
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
    };

    if same_slot && new_flag_eb > 0 {
        accrue_builder_payment_weight(&mut view.slot, parsed.att_slot, is_current, new_flag_eb);
    }

    Ok(reward)
}

fn accrue_builder_payment_weight(
    slot: &mut SlotStateWriteView,
    att_slot: Slot,
    is_current: bool,
    new_flag_eb: u64,
) {
    let spe = SLOTS_PER_EPOCH as usize;
    let slot_in_epoch = att_slot as usize % spe;
    let ring = if is_current { spe + slot_in_epoch } else { slot_in_epoch };
    if slot.state().builder_pending_payments[ring].withdrawal.amount > 0 {
        slot.state_mut().builder_pending_payments[ring].weight += new_flag_eb;
    }
}

fn gloas_payload_vote_is_same_slot(
    slot: &SlotStateWriteView,
    att: &[u8],
    parsed: &ParsedAttestationData,
    flag_weights: &mut [bool; 3],
) -> Result<bool, AttestationError> {
    let index = AttestationView::data(att).index();
    if index > GLOAS_PAYLOAD_PRESENT {
        return Err(AttestationError::InvalidPayloadIndex { index });
    }
    let same_slot = is_attestation_same_slot(slot, parsed);
    let payload_matches = if same_slot {
        // The payload is revealed after the block, so a same-slot vote must
        // claim "absent".
        if index != GLOAS_PAYLOAD_ABSENT {
            return Err(AttestationError::InvalidPayloadIndex { index });
        }
        true
    } else {
        index == payload_availability_bit(slot, parsed.att_slot)
    };
    flag_weights[TIMELY_HEAD_FLAG_INDEX] &= payload_matches;
    Ok(same_slot)
}

fn gloas_payload_is_present(att: &[u8]) -> bool {
    AttestationView::data(att).index() == GLOAS_PAYLOAD_PRESENT
}

fn is_attestation_same_slot(slot: &SlotStateWriteView, parsed: &ParsedAttestationData) -> bool {
    if parsed.att_slot == 0 {
        return true;
    }
    let root = parsed.beacon_block_root;
    root == slot.block_root_at_slot(parsed.att_slot) &&
        root != slot.block_root_at_slot(parsed.att_slot - 1)
}

fn payload_availability_bit(slot: &SlotStateWriteView, att_slot: Slot) -> u64 {
    let i = (att_slot % SLOTS_PER_HISTORICAL_ROOT as u64) as usize;
    (slot.state().execution_payload_availability[i / 8] >> (i % 8) & 1) as u64
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
            att_slot: data.slot(),
            beacon_block_root: *data.beacon_block_root(),
            source_epoch: data.source_epoch(),
            source_root: *data.source_root(),
            target_epoch: data.target_epoch(),
            target_root: *data.target_root(),
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
    is_current: bool,
    active_scratch: &mut Vec<u32>,
) -> Result<(), AttestationError> {
    let committees = AttestedCommittees::resolve(att, shuffling, is_current, validators.count())?;

    active_scratch.clear();
    let mut agg_offset = 0usize;
    for (committee, base) in committees.committees() {
        let before = active_scratch.len();
        for (j, &validator_idx) in committee.iter().enumerate() {
            if committees.attested(base + j) {
                active_scratch.push(validator_idx);
            }
        }
        if active_scratch.len() == before {
            return Err(AttestationError::EmptyCommittee);
        }
        agg_offset += committee.len();
    }

    let bitlist_len = merkle::bitlist_len(AttestationView::aggregation_bits(att));
    if bitlist_len != agg_offset {
        return Err(AttestationError::BitlistLenMismatch { expected: agg_offset, got: bitlist_len });
    }
    Ok(())
}

/// Returns `(proposer_reward_numerator, effective_balance_sum)` — the latter
/// over attesters that set at least one new flag, for the Gloas builder-payment
/// weight.
fn apply_attestation_participation_flags<M: ColumnSpec<Val = u8>>(
    validators: &ValidatorsView,
    participation: &mut ParticipationWriteView<M>,
    active_scratch: &[u32],
    total_active: u64,
    flag_weights: [bool; 3],
) -> (u64, u64) {
    let sqrt_total = integer_sqrt(total_active);
    let base_reward_per_increment = EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR / sqrt_total;

    const PARTICIPATION_WEIGHTS: [u64; 3] = [14, 26, 14];
    let mut proposer_reward_numerator = 0u64;
    // Collect changed flags, then apply them in one sorted merge. A committee's
    // participants are distinct validator indices, so the batch is dup-free; a
    // per-validator `set_*_participation` would be O(|edits|) each (quadratic
    // over an epoch's accumulated participation edits).
    let mut updates: Vec<(u32, u8)> = Vec::with_capacity(active_scratch.len());
    let mut new_flag_eb = 0u64;
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
            new_flag_eb += effective_balance;
        }
    }
    updates.sort_unstable_by_key(|(idx, _)| *idx);
    participation.set_many(&updates);
    (proposer_reward_numerator, new_flag_eb)
}

#[cfg(test)]
mod tests {
    use super::{AttestedCommittees, EpochShuffling};

    /// `attested_count` short-circuits the committee walk, so it has to agree
    /// with the `members` walk on every bitlist shape — including ones too
    /// short to cover the members.
    #[test]
    fn attested_count_matches_walk() {
        let shuffled: Vec<u32> = (0..640).collect();
        let shuffling = EpochShuffling::with_committees_per_slot(&shuffled, 2);

        for agg_bits in [
            vec![0xFF, 0xFF, 0xFF],
            vec![0b1010_1010, 0b0101_0101, 0b0000_0011],
            vec![0x00, 0x00, 0x00],
            vec![0xFF, 0x0F],
            vec![0xFF],
            vec![],
        ] {
            let committees = AttestedCommittees {
                shuffling: &shuffling,
                slot: 0,
                committee_bits: 0b11,
                agg_bits: &agg_bits,
            };
            let members = committees.member_count();
            assert_eq!(members, 20, "two 10-member committees");

            let walked = committees.attesters().count();
            assert_eq!(committees.attested_count(members), walked, "bits {agg_bits:?}");
        }
    }
}
