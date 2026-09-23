use flux_profiler::timed;
use silver_beacon_state_data::{B256, Epoch, Slot};

use super::{ForkChoice, ForkChoiceNode, PayloadStatus};
use crate::stf::VoteTarget;

#[derive(Default)]
pub struct VoteTracker {
    pub(super) votes: Box<[Vote]>,
    /// Validator indices whose vote moved since the last `recompute_head`.
    pub(super) dirty: Vec<u32>,
    equivocating: Box<[u64]>,
}

impl VoteTracker {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            votes: vec![Vote::default(); capacity].into_boxed_slice(),
            dirty: Vec::with_capacity(capacity),
            equivocating: vec![0u64; capacity.div_ceil(64)].into_boxed_slice(),
        }
    }

    pub fn record_votes(
        &mut self,
        target: &VoteTarget,
        validators: &[u32],
        validator_count: usize,
    ) {
        for &validator in validators {
            self.record_vote(target, validator, validator_count);
        }
    }

    pub fn record_vote(&mut self, target: &VoteTarget, validator: u32, validator_count: usize) {
        let validator_idx = validator as usize;
        if validator_idx >= validator_count || self.is_equivocating(validator_idx) {
            return;
        }
        // Zero `latest_root` is the uninitialised sentinel — first vote always
        // takes; a real attestation never has a zero `beacon_block_root`.
        let v = &mut self.votes[validator_idx];
        if v.latest_root != [0u8; 32] && target.target_epoch <= v.latest_epoch {
            return;
        }
        v.latest_root = target.block_root;
        v.latest_epoch = target.target_epoch;
        v.latest_slot = target.attestation_slot;
        v.latest_payload_present = target.payload_present;
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
            (v.applied_root != [0u8; 32] || v.latest_root != [0u8; 32])
        {
            v.latest_root = [0u8; 32];
            self.dirty.push(idx as u32);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Vote {
    pub applied_root: B256,
    pub latest_root: B256,
    pub latest_epoch: Epoch,

    pub applied_slot: Slot,
    pub applied_payload_present: bool,
    pub latest_slot: Slot,
    pub latest_payload_present: bool,
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
        let votes = &mut vote_tracker.votes;

        deltas.clear();
        deltas.resize(nodes.len(), WeightDelta::default());

        let mut apply = |vote: &mut Vote, old_balance: u64, new_balance: u64| {
            // Unchanged only when target, balance, AND payload branch all match — a
            // re-vote that flips the payload branch must still move weight.
            if vote.applied_root == vote.latest_root &&
                vote.applied_slot == vote.latest_slot &&
                vote.applied_payload_present == vote.latest_payload_present &&
                old_balance == new_balance
            {
                return;
            }

            if vote.applied_root != [0u8; 32] &&
                let Some(old_idx) = lookup.get(&vote.applied_root)
            {
                let branch = branch_voted_for(
                    &nodes[old_idx],
                    vote.applied_slot,
                    vote.applied_payload_present,
                );
                add_vote_weight_changes(&mut deltas[old_idx], branch, -(old_balance as i64));
            }

            // Add new balance to new target.
            if vote.latest_root != [0u8; 32] &&
                let Some(new_idx) = lookup.get(&vote.latest_root)
            {
                let branch = branch_voted_for(
                    &nodes[new_idx],
                    vote.latest_slot,
                    vote.latest_payload_present,
                );
                add_vote_weight_changes(&mut deltas[new_idx], branch, new_balance as i64);
            }

            // Note: if latest_root is non-zero but unknown (pruned/never-imported),
            // we still bump applied_root, "consuming" the vote with no delta
            // contribution. Self-heals on the validator's next attestation.
            // Matches Lighthouse proto_array.
            vote.applied_root = vote.latest_root;
            vote.applied_slot = vote.latest_slot;
            vote.applied_payload_present = vote.latest_payload_present;
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
        for &vi in vote_tracker.dirty.iter() {
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
