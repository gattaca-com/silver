use std::array;

use silver_beacon_state_data::{
    B256, Checkpoint, Epoch, PARTICIPATION_FLAGS, PARTICIPATION_WEIGHTS, SLOTS_PER_EPOCH, Slot,
    StateReadView, TIMELY_TARGET_FLAG,
};
use silver_common::ssz_view::AttestationDataView;

use crate::{
    stf::{EFFECTIVE_BALANCE_INCREMENT, ParsedAttestationData, ShufflingRef},
    validate::validate_attestation_data_view,
};

/// What a block on the parent state pays for each attester of a vote candidate.
/// A matching target puts the attesters on the parent's chain at the target
/// epoch, so their committees match the parent's shuffling.
pub(super) struct AttestationRewards<'a> {
    /// The parent's state advanced into the block's epoch.
    pre_state: &'a StateReadView<'a>,
    shuffling: ShufflingRef<'a>,
    parent_root: B256,
    block_slot: Slot,
    current_epoch: Epoch,
    /// Indexed by whether the target is the current epoch.
    justified: [Checkpoint; 2],
    /// Indexed by a participation flag mask.
    flags_weight: [u64; 8],
}

impl<'a> AttestationRewards<'a> {
    pub(super) fn new(
        pre_state: &'a StateReadView<'a>,
        shuffling: ShufflingRef<'a>,
        parent_root: B256,
        block_slot: Slot,
    ) -> Self {
        let epoch = pre_state.epoch.state();
        let justified = [epoch.previous_justified_checkpoint, epoch.current_justified_checkpoint];
        let flags_weight = array::from_fn(|mask| {
            let flags = PARTICIPATION_FLAGS.iter().zip(PARTICIPATION_WEIGHTS);
            flags.filter(|&(&flag, _)| mask as u8 & flag != 0).map(|(_, weight)| weight).sum()
        });
        Self {
            pre_state,
            shuffling,
            parent_root,
            block_slot,
            current_epoch: block_slot / SLOTS_PER_EPOCH,
            justified,
            flags_weight,
        }
    }

    fn root_at(&self, slot: Slot) -> B256 {
        if slot < self.pre_state.slot.slot_number() {
            self.pre_state.block_roots.at_slot(slot)
        } else {
            self.parent_root
        }
    }

    /// `None` when the block may not include the vote candidate.
    fn earned_flags(&self, data: AttestationDataView) -> Option<u8> {
        let previous_epoch = self.current_epoch.saturating_sub(1);
        validate_attestation_data_view(
            data,
            self.block_slot,
            self.current_epoch,
            previous_epoch,
            false,
        )
        .ok()?;
        let vote = ParsedAttestationData::parse(data);
        let is_current = vote.target_epoch == self.current_epoch;
        vote.check_source(self.justified[is_current as usize]).ok()?;
        let flags = vote.flags(|slot| self.root_at(slot), self.block_slot);
        (flags & TIMELY_TARGET_FLAG != 0).then_some(flags)
    }

    /// Each committee member's base reward increments times the weight of the
    /// flags it still lacks. The base reward per increment is common to
    /// all, so it is left out. Zero for a committee the block may not
    /// include.
    pub(super) fn weigh(
        &self,
        data: AttestationDataView,
        committee_index: u64,
        weights: &mut [u64],
    ) {
        weights.fill(0);
        let Some(earned) = self.earned_flags(data) else {
            return;
        };
        let is_current = data.target_epoch() == self.current_epoch;
        let shuffling = self.shuffling.for_target(is_current);
        let validators = &self.pre_state.validators;
        if committee_index as usize >= shuffling.committees_per_slot ||
            !shuffling.indices_in_range(validators.count())
        {
            return;
        }
        let committee = shuffling.committee(data.slot(), committee_index as usize);
        if committee.len() != weights.len() {
            return;
        }
        let participation = |validator| {
            if is_current {
                self.pre_state.current_participation.get(validator)
            } else {
                self.pre_state.previous_participation.get(validator)
            }
        };
        for (weight, &validator) in weights.iter_mut().zip(committee) {
            let validator = validator as usize;
            let missing = earned & !participation(validator);
            if missing == 0 {
                continue;
            }
            let increments = validators.effective_balance(validator) / EFFECTIVE_BALANCE_INCREMENT;
            *weight = increments * self.flags_weight[missing as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, EpochState, EpochStateFinalized, StateId, TIMELY_HEAD_FLAG,
        TIMELY_SOURCE_FLAG, ValSeed,
    };
    use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

    use super::*;
    use crate::{stf::EpochShuffling, test_state::TestState};

    const EPOCH: Epoch = 10;
    /// The pre-state sits at the epoch start; slots from here hold the
    /// parent.
    const STATE_SLOT: Slot = EPOCH * SLOTS_PER_EPOCH;
    const BLOCK_SLOT: Slot = STATE_SLOT + 10;
    const PARENT_ROOT: B256 = [0xAA; 32];
    const CURRENT_JUSTIFIED: Checkpoint = Checkpoint { epoch: EPOCH - 1, root: [9; 32] };
    const PREVIOUS_JUSTIFIED: Checkpoint = Checkpoint { epoch: EPOCH - 2, root: [8; 32] };
    /// One committee a slot, two members each, in index order.
    const VALIDATORS: usize = 2 * SLOTS_PER_EPOCH as usize;
    const SOURCE_TARGET_HEAD: u64 = 14 + 26 + 14;

    /// Validator `i` holds `i + 1` increments of effective balance.
    fn state(participation: &[(u32, u8)]) -> (BeaconState, StateId) {
        let seeds: Vec<_> = (0..VALIDATORS as u64)
            .map(|i| ValSeed {
                effective_balance: (i + 1) * EFFECTIVE_BALANCE_INCREMENT,
                activation_epoch: 0,
                ..Default::default()
            })
            .collect();
        let epoch_base = EpochStateFinalized::from_state(EpochState {
            finalized_checkpoint: Checkpoint { epoch: EPOCH, root: [0; 32] },
            current_justified_checkpoint: CURRENT_JUSTIFIED,
            previous_justified_checkpoint: PREVIOUS_JUSTIFIED,
            ..Default::default()
        });
        let mut st = TestState::new(epoch_base, &seeds);
        let StateId { epoch_idx, longtail_idx, .. } = st.state_id;
        let (mut view, _, _) = st.view();
        for &(validator, flags) in participation {
            view.current_participation.set(validator, flags);
            view.previous_participation.set(validator, flags);
        }
        let id = view.commit(epoch_idx, longtail_idx);
        (st.bs, id)
    }

    /// A vote whose source and target match the state.
    fn vote(slot: Slot, head: B256) -> [u8; ATTESTATION_DATA_SIZE] {
        let target_epoch = slot / SLOTS_PER_EPOCH;
        let (justified, target_root) = if target_epoch == EPOCH {
            (CURRENT_JUSTIFIED, PARENT_ROOT)
        } else {
            (PREVIOUS_JUSTIFIED, [0; 32])
        };
        let mut data = [0; ATTESTATION_DATA_SIZE];
        data[0..8].copy_from_slice(&slot.to_le_bytes());
        data[16..48].copy_from_slice(&head);
        data[48..56].copy_from_slice(&justified.epoch.to_le_bytes());
        data[56..88].copy_from_slice(&justified.root);
        data[88..96].copy_from_slice(&target_epoch.to_le_bytes());
        data[96..128].copy_from_slice(&target_root);
        data
    }

    fn weights(state: &(BeaconState, StateId), data: &[u8; ATTESTATION_DATA_SIZE]) -> [u64; 2] {
        weights_of(state, data, 0)
    }

    fn weights_of(
        (bs, id): &(BeaconState, StateId),
        data: &[u8; ATTESTATION_DATA_SIZE],
        committee_index: u64,
    ) -> [u64; 2] {
        let pre_state = bs.read_view(*id);
        let shuffled: Vec<_> = (0..VALIDATORS as u32).collect();
        let shuffling = ShufflingRef {
            curr: EpochShuffling::with_committees_per_slot(&shuffled, 1),
            prev: EpochShuffling::with_committees_per_slot(&shuffled, 1),
        };
        let rewards = AttestationRewards::new(&pre_state, shuffling, PARENT_ROOT, BLOCK_SLOT);
        let mut weights = [u64::MAX; 2];
        rewards.weigh(AttestationDataView::new(data), committee_index, &mut weights);
        weights
    }

    /// The members of `slot`'s committee hold this many increments.
    fn increments(slot: Slot) -> [u64; 2] {
        let first = 2 * (slot % SLOTS_PER_EPOCH);
        [first + 1, first + 2]
    }

    #[test]
    fn timely_head_vote_pays_every_flag_by_stake() {
        let slot = BLOCK_SLOT - 1;

        let weights = weights(&state(&[]), &vote(slot, PARENT_ROOT));

        assert_eq!(weights, increments(slot).map(|i| i * SOURCE_TARGET_HEAD));
    }

    #[test]
    fn only_flags_still_missing_are_paid() {
        let slot = BLOCK_SLOT - 1;
        let [first, second] = increments(slot).map(|i| i as u32 - 1);
        let state = state(&[
            (first, TIMELY_SOURCE_FLAG | TIMELY_TARGET_FLAG),
            (second, TIMELY_SOURCE_FLAG | TIMELY_TARGET_FLAG | TIMELY_HEAD_FLAG),
        ]);

        let weights = weights(&state, &vote(slot, PARENT_ROOT));

        assert_eq!(weights, [increments(slot)[0] * 14, 0]);
    }

    #[test]
    fn wrong_head_pays_source_and_target() {
        let slot = BLOCK_SLOT - 1;

        let weights = weights(&state(&[]), &vote(slot, [0xBB; 32]));

        assert_eq!(weights, increments(slot).map(|i| i * (14 + 26)));
    }

    #[test]
    fn head_needs_an_inclusion_delay_of_one() {
        let slot = BLOCK_SLOT - 2;

        let weights = weights(&state(&[]), &vote(slot, PARENT_ROOT));

        assert_eq!(weights, increments(slot).map(|i| i * (14 + 26)));
    }

    #[test]
    fn late_previous_epoch_vote_pays_target_only() {
        let slot = STATE_SLOT - 20;

        let weights = weights(&state(&[]), &vote(slot, [0; 32]));

        assert_eq!(weights, increments(slot).map(|i| i * 26));
    }

    #[test]
    fn votes_the_block_may_not_include_pay_nothing() {
        let state = state(&[]);
        let slot = BLOCK_SLOT - 1;
        let mutators: [fn(&mut [u8; ATTESTATION_DATA_SIZE]); 5] = [
            |data| data[0..8].copy_from_slice(&BLOCK_SLOT.to_le_bytes()), // slot not past
            |data| data[8] = 1,                                           // index
            |data| data[56] ^= 1,                                         // source root
            |data| data[48] ^= 1,                                         // source epoch
            |data| data[96] ^= 1,                                         // target root
        ];
        for mutate in mutators {
            let mut data = vote(slot, PARENT_ROOT);
            mutate(&mut data);
            assert_eq!(weights(&state, &data), [0, 0]);
        }
        assert_eq!(weights_of(&state, &vote(slot, PARENT_ROOT), 1), [0, 0]);
    }
}
