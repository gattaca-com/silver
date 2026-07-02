use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, StateId};
use silver_common::{PayloadValidationStatus, metrics::timed};

use super::BeaconStateTile;
use crate::stf;

impl BeaconStateTile {
    /// Rebuild fork choice's justified-balance snapshot when its justified
    /// checkpoint has moved.
    #[timed]
    pub(super) fn refresh_justified_balances(&mut self) {
        if !self.fork_choice.justified_balances_stale() {
            return;
        }

        let jc = self.fork_choice.justified_checkpoint;
        // Justified is lifted only to resident roots; fall back to the head if
        // somehow absent (boot before the anchor node is wired).
        let sid = match self.fork_choice.find_node_idx(&jc.root) {
            Some(idx) => self.fork_choice.node(idx).state_id,
            None => self.last_applied,
        };

        let mut buf = self.fork_choice.take_justified_scratch();
        let mut total_active = 0u64;
        {
            let v = self.state.read_view(sid).validators;
            let mut act = v.iter_activation_epochs();
            let mut exit = v.iter_exit_epochs();
            let mut eff = v.iter_effective_balances();
            let mut slashed = v.iter_slashed();
            for _ in 0..v.count() {
                let a = act.next().unwrap();
                let x = exit.next().unwrap();
                let b = eff.next().unwrap();
                let s = slashed.next().unwrap();
                let active = a <= jc.epoch && jc.epoch < x;
                if active {
                    total_active += b;
                }
                buf.push(if active && !s { b } else { 0 });
            }
        }
        // Clamp matches `total_active_balance` (avoids a zero proposer score on
        // a degenerate empty active set).
        let total_active = total_active.max(stf::EFFECTIVE_BALANCE_INCREMENT);
        self.fork_choice.commit_justified_balances(buf, total_active, jc);
    }

    #[timed]
    pub(super) fn recompute_head(&mut self) {
        // Spec `get_current_store_epoch`: viability reads the wall-clock epoch.
        self.fork_choice.set_current_epoch(self.ticker.current_slot() / SLOTS_PER_EPOCH);
        // Lift first: an epoch-boundary block's post-state may advance the
        // justified checkpoint, and `lift_checkpoints` reads the head post-state
        // (`last_applied`). Lifting before the refresh lets
        // `refresh_justified_balances` rebuild the snapshot for the *new*
        // checkpoint and fold weight against the new balances in this same pass.
        self.lift_checkpoints();
        self.refresh_justified_balances();
        self.fork_choice.recompute_head();
    }

    /// Monotonically lift fork-choice justified/finalized from the head post-
    /// state, but only to roots present in our node list — during sync the
    /// post-state often names checkpoints from blocks we never imported.
    pub(super) fn lift_checkpoints(&mut self) {
        let (j, f) = self.head_checkpoints();
        if j.epoch > self.fork_choice.justified_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&j.root).is_some()
        {
            self.fork_choice.justified_checkpoint = j;
        }
        if f.epoch > self.fork_choice.finalized_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&f.root).is_some()
        {
            self.fork_choice.finalized_checkpoint = f;
        }
    }

    /// Spec `on_tick_per_slot` epoch-boundary pull-up: lift store
    /// justified/finalized from the head node's *unrealized* checkpoints
    /// (monotone, resident-only). For the canonical head this largely
    /// duplicates the realized `lift_checkpoints` after the eager
    /// `on_slot_start` advance; the value is consistency when the head node
    /// itself hasn't crossed the boundary yet.
    fn lift_unrealized_checkpoints(&mut self) {
        let head = self.fork_choice.find_head();
        let Some(idx) = self.fork_choice.find_node_idx(&head) else {
            return;
        };
        let n = self.fork_choice.node(idx);
        let (uj, uf) = (n.unrealized_justified_checkpoint, n.unrealized_finalized_checkpoint);
        if uj.epoch > self.fork_choice.justified_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&uj.root).is_some()
        {
            self.fork_choice.justified_checkpoint = uj;
        }
        if uf.epoch > self.fork_choice.finalized_checkpoint.epoch &&
            self.fork_choice.find_node_idx(&uf.root).is_some()
        {
            self.fork_choice.finalized_checkpoint = uf;
        }
    }

    /// Spec `on_tick`, fork-choice only: expire proposer boost, make the
    /// previous slot's deferred votes eligible, refold the head, and at an
    /// epoch boundary pull up unrealized checkpoints.
    pub(super) fn fork_choice_tick(&mut self) {
        let prev_epoch = self.fork_choice.current_epoch();
        let new_epoch = self.ticker.current_slot() / SLOTS_PER_EPOCH;
        self.fork_choice.expire_proposer_boost();
        let n = self.head_validator_count();
        self.fork_choice.drain_pending_votes(n);
        self.recompute_head();
        if new_epoch > prev_epoch {
            self.lift_unrealized_checkpoints();
        }
    }

    /// Index bundle of fork-choice's canonical tip. For gossip-object
    /// validation per spec ("the head state").
    pub(super) fn canonical_state_id(&self) -> StateId {
        let head_root = self.fork_choice.find_head();
        let idx = self
            .fork_choice
            .find_node_idx(&head_root)
            .expect("find_head returns a node-resident root");
        self.fork_choice.node(idx).state_id
    }

    /// EL payload verdict, from either newPayload or an FCU response.
    pub(super) fn on_payload_verdict(
        &mut self,
        block_root: &B256,
        latest_valid_hash: &B256,
        status: PayloadValidationStatus,
    ) {
        match status {
            PayloadValidationStatus::Valid => {
                self.fork_choice.on_payload_valid(block_root);
            }
            PayloadValidationStatus::Invalid => {
                self.fork_choice.on_payload_invalid(block_root, latest_valid_hash);
                self.recompute_head();
            }
            // Optimistic: EL still syncing; verdict arrives on a later FCU.
            PayloadValidationStatus::Syncing | PayloadValidationStatus::Accepted => {}
        }
    }
}
