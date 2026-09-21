use flux_profiler::timed;
use silver_beacon_state_data::{Checkpoint, ValidatorsView};

use crate::stf::EFFECTIVE_BALANCE_INCREMENT;

/// Per-validator effective balance of the justified state, zero for validators
/// inactive or slashed at the checkpoint epoch: the weight each LMD vote
/// carries.
///
/// The next checkpoint's snapshot is built ahead of time (`precompute`) from
/// the checkpoint block's post-state, which exists an epoch before the
/// checkpoint is justified. `install` then swaps it in and hands the weight
/// fold the index list of balances that moved, so a checkpoint move costs a
/// sparse pass instead of a sweep over every vote.
#[derive(Default)]
pub struct JustifiedBalances {
    current: Snapshot,
    /// Balances the node weights currently carry.
    applied: Vec<u64>,
    /// Diffed against `current`; every `install` unsets its `checkpoint`, so a
    /// live candidate's `unapplied` always refers to the live `current`.
    candidate: Snapshot,
}

/// Balances of one checkpoint state; `checkpoint` is `None` until built.
#[derive(Default)]
struct Snapshot {
    checkpoint: Option<Checkpoint>,
    balances: Vec<u64>,
    total_active: u64,
    /// Indices whose balance differs from the applied one; empty once the
    /// weights carry this snapshot.
    unapplied: Vec<u32>,
}

impl JustifiedBalances {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            current: Snapshot::with_capacity(capacity),
            applied: Vec::with_capacity(capacity),
            candidate: Snapshot::with_capacity(capacity),
        }
    }

    pub fn stale(&self, justified: Checkpoint) -> bool {
        self.current.checkpoint != Some(justified)
    }

    pub fn total_active(&self) -> u64 {
        self.current.total_active
    }

    /// `(applied, current, unapplied)`: move each unapplied index's weight
    /// from its applied balance to its current one.
    pub fn pending_weight_update(&self) -> (&[u64], &[u64], &[u32]) {
        (&self.applied, &self.current.balances, &self.current.unapplied)
    }

    pub fn mark_applied(&mut self) {
        self.current.unapplied.clear();
    }

    pub fn wants_candidate(&self, cp: Checkpoint) -> bool {
        let current_epoch = self.current.checkpoint.map_or(0, |c| c.epoch);
        cp.epoch > current_epoch && self.candidate.checkpoint != Some(cp)
    }

    #[timed]
    pub fn precompute(&mut self, cp: Checkpoint, validators: ValidatorsView<'_>) {
        self.candidate.rebuild(cp, validators, &self.current.balances);
    }

    /// A second install before the weights catch up diffs against the same
    /// `applied`. The candidate was diffed against `current`, so it only
    /// serves once `current` is applied.
    #[timed]
    pub fn install(&mut self, cp: Checkpoint, validators: ValidatorsView<'_>) {
        let current_applied = self.current.unapplied.is_empty();
        let from_candidate = self.candidate.checkpoint.take() == Some(cp) && current_applied;
        tracing::debug!(
            epoch = cp.epoch,
            from_candidate,
            current_applied,
            "justified balances installed"
        );

        if current_applied {
            std::mem::swap(&mut self.applied, &mut self.current.balances);
        }
        if from_candidate {
            std::mem::swap(&mut self.current, &mut self.candidate);
            self.current.checkpoint = Some(cp);
            self.candidate.checkpoint = None;
        } else {
            self.current.rebuild(cp, validators, &self.applied);
        }
    }
}

impl Snapshot {
    fn with_capacity(capacity: usize) -> Self {
        Self { balances: Vec::with_capacity(capacity), ..Default::default() }
    }

    fn rebuild(&mut self, cp: Checkpoint, validators: ValidatorsView<'_>, applied: &[u64]) {
        self.balances.clear();
        self.balances.resize(validators.count(), 0);
        let mut act = validators.iter_activation_epochs();
        let mut exit = validators.iter_exit_epochs();
        let mut eff = validators.iter_effective_balances();
        let mut slashed = validators.iter_slashed();
        let mut total_active = 0u64;
        for weight in &mut self.balances {
            let a = act.next().unwrap();
            let x = exit.next().unwrap();
            let b = eff.next().unwrap();
            let s = slashed.next().unwrap();
            let active = (a <= cp.epoch) & (cp.epoch < x);
            total_active += b * active as u64;
            *weight = b * (active & !s) as u64;
        }

        self.diff_against(applied);
        self.total_active = total_active.max(EFFECTIVE_BALANCE_INCREMENT);
        self.checkpoint = Some(cp);
    }

    /// A validator missing from one side counts as zero there. Before the
    /// first snapshot no vote carries weight, so `unapplied` stays empty.
    fn diff_against(&mut self, applied: &[u64]) {
        self.unapplied.clear();
        if applied.is_empty() {
            return;
        }
        let new = &self.balances;
        let shared = applied.len().min(new.len());
        for (i, (a, n)) in applied[..shared].iter().zip(&new[..shared]).enumerate() {
            if a != n {
                self.unapplied.push(i as u32);
            }
        }
        let longer = if applied.len() > new.len() { applied } else { new.as_slice() };
        for (i, b) in longer.iter().enumerate().skip(shared) {
            if *b != 0 {
                self.unapplied.push(i as u32);
            }
        }
    }
}
