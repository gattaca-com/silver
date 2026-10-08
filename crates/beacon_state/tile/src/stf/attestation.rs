use blst::min_pk::PublicKey;
use flux_profiler::timed;
use silver_beacon_state_data::{
    B256, Checkpoint, ColumnSpec, Epoch, EpochView, Immutable, PARTICIPATION_WEIGHTS,
    ParticipationWriteView, SLOTS_PER_EPOCH, Slot, SlotStateWriteView, StateWriterView,
    TIMELY_HEAD_FLAG, TIMELY_SOURCE_FLAG, TIMELY_TARGET_FLAG, ValidatorsView,
};
use silver_common::ssz_view::{AttestationDataView, AttestationView};

use crate::{
    bls::{self, SigBatch},
    error::{AttestationError, Result},
    merkle, ssz_hash,
    stf::{
        BASE_REWARD_FACTOR, EFFECTIVE_BALANCE_INCREMENT, EpochShuffling, PROPOSER_WEIGHT,
        ShufflingRef, StfScratch, VoteBatch, VoteTarget, WEIGHT_DENOMINATOR,
        for_each_ssz_list_item, integer_sqrt,
    },
    validate,
};

const GLOAS_PAYLOAD_ABSENT: u64 = 0;
const GLOAS_PAYLOAD_PRESENT: u64 = 1;

pub fn collect_sigs_attestations(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    attestation_data: &[u8],
    block_slot: Slot,
    shuffling: &ShufflingRef<'_>,
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
        shuffling: &'a ShufflingRef<'a>,
        is_current: bool,
        validators_count: usize,
    ) -> Result<Self, AttestationError> {
        let epoch_shuffling = shuffling.for_target(is_current);
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
            vi: self.shuffling.required_validator_count - 1,
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

#[timed]
pub fn collect_sigs_single_attestation(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    att: &[u8],
    current_epoch: Epoch,
    shuffling: &ShufflingRef<'_>,
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
pub struct BlockAttestations<'a> {
    epoch: EpochView<'a>,
    current_epoch: Epoch,
    previous_epoch: Epoch,
    /// Gloas: the payload availability bit at the parent block's slot, which
    /// every vote's `index` is checked against. It is not at `data.slot`:
    /// the two differ across skipped slots.
    payload_index: Option<u64>,
    base_reward_per_increment: u64,
    shuffling: &'a ShufflingRef<'a>,
}

impl<'a> BlockAttestations<'a> {
    pub fn new(
        slot: &SlotStateWriteView,
        epoch: EpochView<'a>,
        block_slot: Slot,
        parent_slot: Option<Slot>,
        shuffling: &'a ShufflingRef<'a>,
    ) -> Self {
        let current_epoch = block_slot / SLOTS_PER_EPOCH;
        Self {
            epoch,
            current_epoch,
            previous_epoch: current_epoch.saturating_sub(1),
            payload_index: parent_slot.map(|parent| slot.state().payload_available(parent) as u64),
            base_reward_per_increment: EFFECTIVE_BALANCE_INCREMENT * BASE_REWARD_FACTOR /
                integer_sqrt(slot.total_active_balance(current_epoch)),
            shuffling,
        }
    }

    #[timed]
    pub fn process_body(
        &self,
        view: &mut StateWriterView,
        attestation_data: &[u8],
        proposer_index: u32,
        votes_sink: &mut VoteBatch,
        scratch: &mut StfScratch,
    ) -> Result<u64, AttestationError> {
        if attestation_data.is_empty() {
            return Ok(0);
        }
        let proposer_reward_denominator =
            (WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * WEIGHT_DENOMINATOR / PROPOSER_WEIGHT;
        let mut proposer_reward = 0u64;
        for_each_ssz_list_item(
            attestation_data,
            |start, end| AttestationError::BadOffsets {
                start,
                end,
                parent_len: attestation_data.len(),
            },
            |att| {
                let reward_numerator = self.process(view, att, votes_sink, scratch)?;
                proposer_reward += reward_numerator / proposer_reward_denominator;
                Ok(())
            },
        )?;

        let balance = view.balances.get(proposer_index as usize);
        view.balances.set(proposer_index, balance.saturating_add(proposer_reward));
        Ok(proposer_reward)
    }

    /// Returns the proposer reward numerator.
    fn process(
        &self,
        view: &mut StateWriterView,
        att: &[u8],
        votes_sink: &mut VoteBatch,
        scratch: &mut StfScratch,
    ) -> Result<u64, AttestationError> {
        let current_slot = view.slot.state().slot;
        let is_gloas = self.epoch.is_gloas(view.imm.gloas_fork_version);
        validate::validate_attestation_data(
            att,
            current_slot,
            self.current_epoch,
            self.previous_epoch,
            is_gloas,
        )?;

        let parsed = ParsedAttestationData::parse(AttestationView::data(att));
        let is_current = self.target_is_current(parsed.target_epoch)?;
        parsed.check_source(self.justified(is_current))?;

        let payload_index = if is_gloas {
            Some(self.payload_index.ok_or(AttestationError::MissingParentSlot)?)
        } else {
            None
        };
        let flags =
            parsed.flags(|slot| view.block_roots.at_slot(slot), current_slot, payload_index)?;

        let target = VoteTarget {
            block_root: *parsed.beacon_block_root,
            target_epoch: parsed.target_epoch,
            attestation_slot: parsed.att_slot,
            payload_present: parsed.payload_present(),
        };
        self.collect_participants(view.validators.count(), att, is_current, &mut scratch.active)?;
        votes_sink.push(target, &scratch.active);
        let attesters = &scratch.active;

        if flags == 0 {
            return Ok(0);
        }
        // Distinct `Previous`/`Current` types can't share one binding, so branch
        // and let each arm monomorphise the generic helper for its column.
        let validators = view.validators.reader();
        let applied = if is_current {
            self.apply_flags(&mut view.current_participation, &validators, attesters, flags)
        } else {
            self.apply_flags(&mut view.previous_participation, &validators, attesters, flags)
        };

        view.slot.epoch_balances_mut().add_target_attesters(is_current, applied.new_target_eb);

        if is_gloas &&
            applied.first_participation_eb > 0 &&
            parsed.is_same_slot(|slot| view.block_roots.at_slot(slot))
        {
            accrue_builder_payment_weight(
                &mut view.slot,
                parsed.att_slot,
                is_current,
                applied.first_participation_eb,
            );
        }

        Ok(applied.proposer_reward_numerator)
    }

    fn target_is_current(&self, target: Epoch) -> Result<bool, AttestationError> {
        let (curr, prev) = (self.current_epoch, self.previous_epoch);
        if target == curr {
            Ok(true)
        } else if target == prev {
            Ok(false)
        } else {
            Err(AttestationError::TargetEpochOutOfWindow { target, prev, curr })
        }
    }

    fn justified(&self, is_current: bool) -> Checkpoint {
        let es = self.epoch.state();
        if is_current { es.current_justified_checkpoint } else { es.previous_justified_checkpoint }
    }

    /// Append the attesting validator indices to `out`, in ascending order:
    /// committee order is shuffled, and a monotonic sweep makes the
    /// per-attester column reads that follow sequential.
    fn collect_participants(
        &self,
        validator_count: usize,
        att: &[u8],
        is_current: bool,
        out: &mut Vec<u32>,
    ) -> Result<(), AttestationError> {
        let committees =
            AttestedCommittees::resolve(att, self.shuffling, is_current, validator_count)?;

        out.clear();
        let mut agg_offset = 0usize;
        for (committee, base) in committees.committees() {
            let before = out.len();
            for (j, &validator_idx) in committee.iter().enumerate() {
                if committees.attested(base + j) {
                    out.push(validator_idx);
                }
            }
            if out.len() == before {
                return Err(AttestationError::EmptyCommittee);
            }
            agg_offset += committee.len();
        }

        let bitlist_len = merkle::bitlist_len(AttestationView::aggregation_bits(att));
        if bitlist_len != agg_offset {
            return Err(AttestationError::BitlistLenMismatch {
                expected: agg_offset,
                got: bitlist_len,
            });
        }
        out.sort_unstable();
        Ok(())
    }

    fn apply_flags<M: ColumnSpec<Val = u8>>(
        &self,
        participation: &mut ParticipationWriteView<M>,
        validators: &ValidatorsView,
        attesters: &[u32],
        flags: u8,
    ) -> AppliedFlags {
        let mut applied = AppliedFlags::default();
        let epoch_increments = self.epoch.increments();
        for &vi in attesters {
            let prev = participation.get(vi as usize);
            let gained = flags & !prev;
            if gained == 0 {
                continue;
            }
            let increments = epoch_increments.get(vi);
            let effective_balance = increments * EFFECTIVE_BALANCE_INCREMENT;
            debug_assert_eq!(
                effective_balance,
                validators.effective_balance(vi as usize),
                "stale effective-balance increment for validator {vi}",
            );
            let weight: u64 =
                (0..3).map(|fi| u64::from(gained >> fi & 1) * PARTICIPATION_WEIGHTS[fi]).sum();
            applied.proposer_reward_numerator +=
                increments * self.base_reward_per_increment * weight;
            if gained & TIMELY_TARGET_FLAG != 0 && !validators.is_slashed(vi as usize) {
                applied.new_target_eb += effective_balance;
            }
            if prev == 0 {
                applied.first_participation_eb += effective_balance;
            }
            participation.set(vi, prev | gained);
        }
        applied
    }
}

fn accrue_builder_payment_weight(
    slot: &mut SlotStateWriteView,
    att_slot: Slot,
    is_current: bool,
    first_participation_eb: u64,
) {
    let spe = SLOTS_PER_EPOCH as usize;
    let slot_in_epoch = att_slot as usize % spe;
    let ring = if is_current { spe + slot_in_epoch } else { slot_in_epoch };
    if slot.state().builder_pending_payments[ring].withdrawal.amount > 0 {
        slot.state_mut().builder_pending_payments[ring].weight += first_participation_eb;
    }
}

pub(crate) struct ParsedAttestationData<'a> {
    pub(crate) att_slot: Slot,
    index: u64,
    beacon_block_root: &'a B256,
    source_epoch: Epoch,
    source_root: &'a B256,
    pub(crate) target_epoch: Epoch,
    target_root: &'a B256,
}

impl<'a> ParsedAttestationData<'a> {
    pub(crate) fn parse(data: AttestationDataView<'a>) -> Self {
        Self {
            att_slot: data.slot(),
            index: data.index(),
            beacon_block_root: data.beacon_block_root(),
            source_epoch: data.source_epoch(),
            source_root: data.source_root(),
            target_epoch: data.target_epoch(),
            target_root: data.target_root(),
        }
    }

    pub(crate) fn check_source(&self, justified: Checkpoint) -> Result<(), AttestationError> {
        if self.source_epoch != justified.epoch || *self.source_root != justified.root {
            return Err(AttestationError::SourceMismatch {
                expected_epoch: justified.epoch,
                expected_root: justified.root,
                got_epoch: self.source_epoch,
                got_root: *self.source_root,
            });
        }
        Ok(())
    }

    /// Gloas: whether it votes for the block proposed at its slot. `root_at`
    /// is the state's `get_block_root_at_slot`.
    pub(crate) fn is_same_slot(&self, root_at: impl Fn(Slot) -> B256) -> bool {
        self.att_slot == 0 ||
            (*self.beacon_block_root == root_at(self.att_slot) &&
                *self.beacon_block_root != root_at(self.att_slot - 1))
    }

    pub(crate) fn payload_present(&self) -> bool {
        self.index == GLOAS_PAYLOAD_PRESENT
    }

    /// Gloas: whether `index` names the attested block's payload status,
    /// `payload_index` unless the block is from the vote's own slot. The
    /// payload is revealed after the block, so a same-slot vote must claim
    /// "absent".
    fn payload_matches(
        &self,
        root_at: impl Fn(Slot) -> B256,
        payload_index: u64,
    ) -> Result<bool, AttestationError> {
        let same_slot = self.is_same_slot(root_at);
        if self.index > GLOAS_PAYLOAD_PRESENT || same_slot && self.index != GLOAS_PAYLOAD_ABSENT {
            return Err(AttestationError::InvalidPayloadIndex { index: self.index });
        }
        Ok(same_slot || self.index == payload_index)
    }

    /// The spec's `get_attestation_participation_flag_indices`, as flag bits.
    /// `root_at` is the state's `get_block_root_at_slot`; `payload_index` is
    /// `None` before Gloas.
    pub(crate) fn flags(
        &self,
        root_at: impl Fn(Slot) -> B256,
        current_slot: Slot,
        payload_index: Option<u64>,
    ) -> Result<u8, AttestationError> {
        let expected_target_root = root_at(self.target_epoch * SLOTS_PER_EPOCH);
        let is_matching_target = *self.target_root == expected_target_root;
        let expected_head_root = root_at(self.att_slot);
        let mut is_matching_head =
            is_matching_target && *self.beacon_block_root == expected_head_root;
        if let Some(payload_index) = payload_index {
            is_matching_head &= self.payload_matches(&root_at, payload_index)?;
        }
        let inclusion_delay = current_slot.saturating_sub(self.att_slot);

        Ok((u8::from(inclusion_delay <= 5) * TIMELY_SOURCE_FLAG) |
            (u8::from(is_matching_target) * TIMELY_TARGET_FLAG) |
            (u8::from(is_matching_head && inclusion_delay == 1) * TIMELY_HEAD_FLAG))
    }
}

#[derive(Default)]
struct AppliedFlags {
    proposer_reward_numerator: u64,
    /// Gloas builder-payment weight: effective balance of the attesters this
    /// attestation brought from no participation to some.
    first_participation_eb: u64,
    /// Unslashed attesters that newly earned TIMELY_TARGET.
    new_target_eb: u64,
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
