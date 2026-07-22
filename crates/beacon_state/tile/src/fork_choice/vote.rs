use flux_profiler::timed;
use silver_beacon_state_data::{B256, Checkpoint, Epoch, Slot, ValidatorsView};

use super::{ForkChoice, ForkChoiceNode, PayloadStatus};
use crate::stf::{AttestationVote, EFFECTIVE_BALANCE_INCREMENT};

#[repr(C)]
#[derive(Default)]
pub struct VoteTracker {
    pub votes: Box<[Vote]>,
}

impl VoteTracker {
    pub fn with_capacity(capacity: usize) -> Self {
        Self { votes: vec![Vote::default(); capacity].into_boxed_slice() }
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
    /// `apply_score_changes`): a fresh balance snapshot means a full pass
    /// against the previous snapshot; otherwise only the dirtied votes are
    /// folded against the unchanged snapshot.
    #[timed]
    pub(super) fn compute_weight_deltas(&mut self) {
        let Self {
            vote_tracker,
            lookup,
            nodes,
            votes_dirty,
            justified_balances,
            prev_justified_balances,
            justified_balances_full_pass,
            weight_deltas: deltas,
            ..
        } = self;
        let full_pass = *justified_balances_full_pass;
        let validator_count = justified_balances.len();
        let (old_balances, new_balances) = if full_pass {
            (prev_justified_balances.as_slice(), justified_balances.as_slice())
        } else {
            (justified_balances.as_slice(), justified_balances.as_slice())
        };
        let changed = (!full_pass).then_some(votes_dirty.as_slice());
        let votes = &mut vote_tracker.votes;

        deltas.clear();
        deltas.resize(nodes.len(), WeightDelta::default());

        let mut apply = |vi: usize, vote: &mut Vote| {
            // `old_balances` (previous snapshot) may be shorter than the current
            // validator set; validators added since then carry no prior weight.
            let old_balance = old_balances.get(vi).copied().unwrap_or(0);
            let new_balance = new_balances.get(vi).copied().unwrap_or(0);

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

        match changed {
            Some(dirty) => {
                for &vi in dirty {
                    let vi = vi as usize;
                    if vi < validator_count {
                        apply(vi, &mut votes[vi]);
                    }
                }
            }
            None => {
                for (vi, vote) in votes.iter_mut().enumerate().take(validator_count) {
                    apply(vi, vote);
                }
            }
        }
    }
}

impl ForkChoice {
    pub fn record_vote(&mut self, vote: &AttestationVote, validator_count: usize) {
        let validator_idx = vote.validator as usize;
        if validator_idx >= validator_count || self.is_equivocating(validator_idx) {
            return;
        }
        // Zero `latest_root` is the uninitialised sentinel — first vote always
        // takes; a real attestation never has a zero `beacon_block_root`.
        let v = &mut self.vote_tracker.votes[validator_idx];
        if v.latest_root != [0u8; 32] && vote.target_epoch <= v.latest_epoch {
            return;
        }
        v.latest_root = vote.block_root;
        v.latest_epoch = vote.target_epoch;
        v.latest_slot = vote.attestation_slot;
        v.latest_payload_present = vote.payload_present;
        self.votes_dirty.push(vote.validator);
    }

    pub fn defer_vote(&mut self, vote: AttestationVote) {
        self.pending_votes.push(vote);
    }

    pub fn drain_pending_votes(&mut self, validator_count: usize) {
        for i in 0..self.pending_votes.len() {
            let v = self.pending_votes[i];
            self.record_vote(&v, validator_count);
        }
        self.pending_votes.clear();
    }

    pub fn is_equivocating(&self, idx: usize) -> bool {
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
        if let Some(v) = self.vote_tracker.votes.get_mut(idx) &&
            (v.applied_root != [0u8; 32] || v.latest_root != [0u8; 32])
        {
            v.latest_root = [0u8; 32];
            self.votes_dirty.push(idx as u32);
        }
    }

    /// True when the justified-balance snapshot must be rebuilt — the justified
    /// checkpoint moved, or we have no snapshot yet.
    pub fn justified_balances_stale(&self) -> bool {
        self.justified_checkpoint != self.justified_balances_cp ||
            self.justified_balances.is_empty()
    }

    pub fn set_justified_balances(&mut self, cp: Checkpoint, validators: ValidatorsView<'_>) {
        std::mem::swap(&mut self.justified_balances, &mut self.prev_justified_balances);
        let buf = &mut self.justified_balances;
        buf.clear();

        let mut act = validators.iter_activation_epochs();
        let mut exit = validators.iter_exit_epochs();
        let mut eff = validators.iter_effective_balances();
        let mut slashed = validators.iter_slashed();
        let mut total_active = 0u64;
        for _ in 0..validators.count() {
            let a = act.next().unwrap();
            let x = exit.next().unwrap();
            let b = eff.next().unwrap();
            let s = slashed.next().unwrap();
            let active = a <= cp.epoch && cp.epoch < x;
            if active {
                total_active += b;
            }
            buf.push(if active && !s { b } else { 0 });
        }

        self.justified_total_active_balance = total_active.max(EFFECTIVE_BALANCE_INCREMENT);
        self.justified_balances_cp = cp;
        self.justified_balances_full_pass = true;
    }

    #[cfg(test)]
    pub fn justified_total_active_balance(&self) -> u64 {
        self.justified_total_active_balance
    }
}
