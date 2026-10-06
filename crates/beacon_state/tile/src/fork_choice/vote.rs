use flux_profiler::timed;
use silver_beacon_state_data::{Epoch, Slot};

use super::{ForkChoice, ForkChoiceNode, PayloadStatus, vote_targets::VoteTargets};
use crate::stf::VoteTarget;

/// Each vote stores two small ids into `targets`, not the targets themselves.
/// A vote is then 8 bytes, so a scan over all validators reads far less memory.
#[derive(Default)]
pub struct VoteTracker {
    pub(super) votes: Box<[Vote]>,
    /// Validator indices whose vote moved since the last `recompute_head`.
    pub(super) dirty: Vec<u32>,
    equivocating: Box<[u64]>,
    targets: VoteTargets,
}

impl VoteTracker {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            votes: vec![Vote::default(); capacity].into_boxed_slice(),
            dirty: Vec::with_capacity(capacity),
            equivocating: vec![0u64; capacity.div_ceil(64)].into_boxed_slice(),
            targets: VoteTargets::default(),
        }
    }

    pub fn record_votes(
        &mut self,
        target: &VoteTarget,
        validators: &[u32],
        validator_count: usize,
    ) {
        if self.targets.needs_compaction() {
            self.compact_targets();
        }
        let id = self.targets.get_or_insert(target);
        for &validator in validators {
            self.record_vote(id, target.target_epoch, validator, validator_count);
        }
    }

    fn record_vote(&mut self, id: u32, epoch: Epoch, validator: u32, validator_count: usize) {
        let validator_idx = validator as usize;
        if validator_idx >= validator_count || self.is_equivocating(validator_idx) {
            return;
        }
        let v = &mut self.votes[validator_idx];
        if v.latest != 0 && epoch <= self.targets.get(v.latest).target_epoch {
            return;
        }
        v.latest = id;
        self.dirty.push(validator);
    }

    fn is_equivocating(&self, idx: usize) -> bool {
        let (w, b) = (idx / 64, idx % 64);
        self.equivocating.get(w).is_some_and(|word| word & (1u64 << b) != 0)
    }

    pub fn mark_equivocating(&mut self, idx: usize) {
        let (w, b) = (idx / 64, idx % 64);
        let Some(word) = self.equivocating.get_mut(w) else {
            return;
        };
        if *word & (1u64 << b) != 0 {
            return;
        }
        *word |= 1u64 << b;
        if let Some(v) = self.votes.get_mut(idx) &&
            (v.applied != 0 || v.latest != 0)
        {
            v.latest = 0;
            self.dirty.push(idx as u32);
        }
    }

    /// Walks every validator's vote. So it runs only at finalization, or when
    /// the target table has doubled, never per block.
    pub(super) fn compact_targets(&mut self) {
        self.targets.compact(self.votes.iter_mut().flat_map(|v| [&mut v.latest, &mut v.applied]));
    }
}

#[derive(Clone, Copy, Default)]
pub struct Vote {
    latest: u32,
    applied: u32,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct WeightDelta {
    pub pending: i64,
    pub empty: i64,
    pub full: i64,
}

impl WeightDelta {
    #[inline]
    pub(super) fn total(&self) -> i64 {
        self.pending + self.empty + self.full
    }
}

#[inline]
pub(super) fn branch_voted_for(
    node: &ForkChoiceNode,
    vote_slot: Slot,
    present: bool,
) -> PayloadStatus {
    if node.payload.is_gloas && node.slot < vote_slot {
        if present { PayloadStatus::Full } else { PayloadStatus::Empty }
    } else {
        PayloadStatus::Pending
    }
}

#[inline]
fn add_vote_weight_changes(d: &mut WeightDelta, branch: PayloadStatus, v: i64) {
    match branch {
        PayloadStatus::Full => d.full += v,
        PayloadStatus::Empty => d.empty += v,
        PayloadStatus::Pending => d.pending += v,
    }
}

impl ForkChoice {
    /// Fold vote/balance movement into `self.weight_deltas` (staged for
    /// `apply_score_changes`). Unapplied balance moves fold first, so a dirty
    /// vote visited afterwards finds its weight already carried and returns.
    #[timed]
    pub(super) fn compute_weight_deltas(&mut self) {
        let Self { vote_tracker, lookup, nodes, justified, weight_deltas: deltas, .. } = self;
        let (applied_balances, balances, unapplied) = justified.pending_weight_update();
        let validator_count = balances.len();
        let VoteTracker { votes, dirty, targets, .. } = vote_tracker;

        deltas.clear();
        deltas.resize(nodes.len(), WeightDelta::default());

        let resolved = targets.resolve(lookup, nodes);
        let mut apply = |vote: &mut Vote, old_balance: u64, new_balance: u64| {
            if vote.applied == vote.latest && old_balance == new_balance {
                return;
            }
            if let Some((node, branch)) = resolved[vote.applied as usize] {
                add_vote_weight_changes(&mut deltas[node], branch, -(old_balance as i64));
            }
            if let Some((node, branch)) = resolved[vote.latest as usize] {
                add_vote_weight_changes(&mut deltas[node], branch, new_balance as i64);
            }
            // Mark the vote applied even if its block is not in the tree. It then
            // carries no weight until the validator attests again. Lighthouse's
            // proto_array does the same.
            vote.applied = vote.latest;
        };

        // `applied_balances` may be shorter than the current validator set;
        // validators added since then carry no prior weight.
        for &vi in unapplied {
            let vi = vi as usize;
            if vi < validator_count {
                let applied_balance = applied_balances.get(vi).copied().unwrap_or(0);
                apply(&mut votes[vi], applied_balance, balances[vi]);
            }
        }
        for &vi in dirty.iter() {
            let vi = vi as usize;
            if vi < validator_count {
                apply(&mut votes[vi], balances[vi], balances[vi]);
            }
        }
    }
}

impl ForkChoice {
    pub fn record_votes(
        &mut self,
        target: &VoteTarget,
        validators: &[u32],
        validator_count: usize,
    ) {
        self.vote_tracker.record_votes(target, validators, validator_count);
    }

    pub fn mark_equivocating(&mut self, idx: usize) {
        self.vote_tracker.mark_equivocating(idx);
    }

    /// Spec `on_attestation` folds a vote only once `current_slot >= slot + 1`;
    /// a vote for `current_slot` or later (clock disparity) stays deferred.
    pub fn record_or_defer_votes(
        &mut self,
        target: VoteTarget,
        validators: &[u32],
        validator_count: usize,
        current_slot: Slot,
    ) {
        if target.attestation_slot >= current_slot {
            self.pending_votes.push(target, validators);
        } else {
            self.vote_tracker.record_votes(&target, validators, validator_count);
        }
    }

    pub fn drain_pending_votes(&mut self, validator_count: usize, current_slot: Slot) {
        let Self { vote_tracker, pending_votes, .. } = self;
        pending_votes.retain(|target, validators| {
            if target.attestation_slot >= current_slot {
                return true;
            }
            vote_tracker.record_votes(target, validators, validator_count);
            false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::VoteTracker;
    use crate::{fork_choice::vote_targets::MIN_COMPACT_AT, stf::VoteTarget};

    /// Without finality, `prune` never runs, yet every epoch adds new targets.
    /// The table must still shrink on its own and keep each validator's newest
    /// vote.
    #[test]
    fn targets_stay_bounded_without_finality() {
        const VALIDATORS: u32 = 64;
        let mut tracker = VoteTracker::with_capacity(VALIDATORS as usize);
        let target = |epoch: u64, slot: u64| VoteTarget {
            block_root: [(slot % 251) as u8; 32],
            target_epoch: epoch,
            attestation_slot: slot,
            payload_present: false,
        };
        for epoch in 1..=1000u64 {
            for slot in epoch * 32..epoch * 32 + 32 {
                let validator = (slot % 32) as u32;
                tracker.record_votes(
                    &target(epoch, slot),
                    &[validator, validator + 32],
                    VALIDATORS as usize,
                );
            }
        }
        assert!(tracker.targets.len() <= 2 * MIN_COMPACT_AT, "{} targets", tracker.targets.len());
        for (validator, vote) in tracker.votes.iter().enumerate() {
            let epoch = tracker.targets.get(vote.latest).target_epoch;
            assert_eq!(epoch, 1000, "validator {validator} lost its newest vote");
        }
    }
}
