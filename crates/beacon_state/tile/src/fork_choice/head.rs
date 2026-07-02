use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};

use super::{
    ExecutionStatus, ForkChoice, GENESIS_EPOCH, MAX_FORK_CHOICE_NODES, NULL, NodeLookup,
    PayloadStatus, WeightDelta, node::PTC_SIZE,
};

impl ForkChoice {
    pub fn apply_score_changes(&mut self, deltas: &mut [WeightDelta; MAX_FORK_CHOICE_NODES]) {
        Self::add_proposer_boost(
            deltas,
            &self.lookup,
            &self.applied_boost_root,
            -(self.applied_boost_score as i64),
        );
        Self::add_proposer_boost(
            deltas,
            &self.lookup,
            &self.proposer_boost_root,
            self.proposer_boost_score as i64,
        );

        self.applied_boost_root = self.proposer_boost_root;
        self.applied_boost_score = self.proposer_boost_score;

        let len = self.nodes.len();
        for i in (0..len).rev() {
            let d = deltas[i];
            let total = d.total();
            let parent;
            let edge;
            {
                let n = &mut self.nodes[i];
                n.empty.weight = (n.empty.weight as i64 + d.empty).max(0) as u64;
                n.full.weight = (n.full.weight as i64 + d.full).max(0) as u64;
                n.weight = (n.weight as i64 + total).max(0) as u64;
                parent = n.parent_ix;
                edge = n.payload.parent_status;
            }

            if parent != NULL {
                if edge == PayloadStatus::Full {
                    deltas[parent].full += total;
                } else {
                    deltas[parent].empty += total;
                }
            }
        }

        for i in (0..len).rev() {
            let parent = self.nodes[i].parent_ix;
            if parent != NULL {
                self.maybe_update_best_branch(parent, i);
            }
        }
    }

    fn add_proposer_boost(
        deltas: &mut [WeightDelta; MAX_FORK_CHOICE_NODES],
        lookup: &NodeLookup,
        root: &B256,
        score: i64,
    ) {
        if *root != [0u8; 32] &&
            let Some(i) = lookup.get(root)
        {
            deltas[i].pending = deltas[i].pending.saturating_add(score);
        }
    }

    pub fn find_head(&self) -> B256 {
        let justified_idx = match self.find_node_idx(&self.justified_checkpoint.root) {
            Some(idx) => idx,
            None => return self.justified_checkpoint.root,
        };

        let best_desc = self.resolved_branch_best_desc(justified_idx);
        if self.node_is_viable_for_head(best_desc) {
            return self.nodes[best_desc].block_root;
        }

        // Fallback: best_descendant not viable (shouldn't happen with correct scoring).
        self.nodes[justified_idx].block_root
    }

    /// Returns `(head_root, head_exec, safe_exec, finalized_exec)`
    pub fn fcu_execution_hashes(&self) -> (B256, B256, B256, B256) {
        let zero = [0u8; 32];
        let Some(ji) = self.find_node_idx(&self.justified_checkpoint.root) else {
            return (zero, zero, zero, zero);
        };

        let best_desc = self.resolved_branch_best_desc(ji);
        let head_idx = if self.node_is_viable_for_head(best_desc) { best_desc } else { ji };
        let node = &self.nodes[ji];
        let fin_exec = self
            .find_node_idx(&self.finalized_checkpoint.root)
            .map(|i| self.nodes[i].execution_block_hash)
            .unwrap_or(zero);

        let head_exec = self.head_execution_hash(head_idx);
        (self.nodes[head_idx].block_root, head_exec, node.execution_block_hash, fin_exec)
    }

    /// The execution-payload hash at the canonical tip ending at `head_idx`:
    /// the latest node on its chain whose payload resolves FULL.
    fn head_execution_hash(&self, head_idx: usize) -> B256 {
        let mut idx = head_idx;
        loop {
            if self.resolves_to_full(idx) {
                return self.nodes[idx].payload.bid_block_hash;
            }
            if self.nodes[idx].parent_ix == NULL {
                return self.nodes[idx].execution_block_hash;
            }
            idx = self.nodes[idx].parent_ix;
        }
    }

    #[cfg(any(test, feature = "ef_tests"))]
    pub fn head_payload_present(&self) -> bool {
        let Some(ji) = self.find_node_idx(&self.justified_checkpoint.root) else {
            return true;
        };
        let head_idx = self.resolved_branch_best_desc(ji);
        self.resolves_to_full(head_idx)
    }

    /// Spec `get_checkpoint_block(store, root, epoch)`: nearest ancestor of
    /// `root` with `slot <= epoch_start_slot`.
    pub fn get_checkpoint_block(&self, root: &B256, epoch_start_slot: Slot) -> Option<B256> {
        let mut idx = self.find_node_idx(root)?;
        loop {
            let n = &self.nodes[idx];
            if n.slot <= epoch_start_slot {
                return Some(n.block_root);
            }
            if n.parent_ix == NULL {
                return None;
            }
            idx = n.parent_ix;
        }
    }

    fn node_is_viable_for_head(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        // For Gloas EMPTY branch is still viable
        if !n.payload.is_gloas && n.execution_status == ExecutionStatus::Invalid {
            return false;
        }

        // Spec `get_voting_source`
        let block_epoch = n.slot / SLOTS_PER_EPOCH;
        let voting_source = if self.current_epoch() > block_epoch {
            n.checkpoints.unrealized_justified
        } else {
            n.checkpoints.justified
        };

        // Justified: the voting source is at the store's justified epoch, or no
        // more than two epochs behind the current epoch (the spec relaxation
        // that keeps a just-missed-justification branch viable).
        let correct_justified = self.justified_checkpoint.epoch == GENESIS_EPOCH ||
            voting_source.epoch == self.justified_checkpoint.epoch ||
            voting_source.epoch + 2 >= self.current_epoch();

        // Finalized: the node must descend from the store's finalized block (its
        // ancestor at the finalized epoch's start slot is the finalized root).
        let correct_finalized = self.finalized_checkpoint.epoch == GENESIS_EPOCH ||
            self.get_checkpoint_block(
                &n.block_root,
                self.finalized_checkpoint.epoch * SLOTS_PER_EPOCH,
            ) == Some(self.finalized_checkpoint.root);

        correct_justified && correct_finalized
    }

    #[inline]
    fn leads_to_viable_head(&self, idx: usize) -> bool {
        let best = self.resolved_branch_best_desc(idx);
        self.node_is_viable_for_head(best) || self.node_is_viable_for_head(idx)
    }

    #[inline]
    fn resolves_to_full(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        if !n.payload.verified || n.execution_status == ExecutionStatus::Invalid {
            return false;
        }
        // [Gloas] spec `get_weight` forces 0 for the *previous-slot* payload
        // decision, so the empty/full choice for the just-passed slot is made
        // purely by `should_extend_payload`, independent of subtree weight.
        if n.slot + 1 == self.current_slot {
            return self.should_extend_payload(idx);
        }

        n.full.weight >= n.empty.weight
    }

    #[inline]
    fn resolved_branch_best_desc(&self, idx: usize) -> usize {
        let bd = self.nodes[idx].branch(self.resolves_to_full(idx)).best_desc;
        if bd != NULL { bd } else { idx }
    }

    /// Prefer the FULL resolution on a tie when the PTC saw the payload timely
    /// and available, or when proposer boost does not point at a conflicting
    /// (empty-extending) child of this node.
    fn should_extend_payload(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        if !n.payload.verified {
            return false;
        }
        if n.ptc.present_count() > PTC_SIZE / 2 && n.ptc.da_count() > PTC_SIZE / 2 {
            return true;
        }
        let boost = self.proposer_boost_root;
        if boost == [0u8; 32] {
            return true;
        }
        let Some(bidx) = self.find_node_idx(&boost) else {
            return true;
        };

        let b = &self.nodes[bidx];
        // Boost does not extend this node, or extends its FULL payload → extend.
        b.parent_ix != idx || b.payload.parent_status == PayloadStatus::Full
    }

    /// Update `parent_idx`'s best child / best-descendant on the payload branch
    /// that `child_idx` attaches to (its `parent_status` edge).
    pub(super) fn maybe_update_best_branch(&mut self, parent_idx: usize, child_idx: usize) {
        let is_full = self.nodes[child_idx].payload.parent_status == PayloadStatus::Full;
        let old_best = self.nodes[parent_idx].branch(is_full).best_child;
        let child_viable = self.leads_to_viable_head(child_idx);

        let (new_child, new_desc) = if old_best == NULL || old_best == child_idx {
            if child_viable {
                (child_idx, self.resolved_branch_best_desc(child_idx))
            } else {
                (NULL, NULL)
            }
        } else {
            let old_viable = self.leads_to_viable_head(old_best);
            match (child_viable, old_viable) {
                (true, true) => {
                    if self.is_heavier_or_eq(child_idx, old_best) {
                        (child_idx, self.resolved_branch_best_desc(child_idx))
                    } else {
                        (old_best, self.resolved_branch_best_desc(old_best))
                    }
                }
                (true, false) => (child_idx, self.resolved_branch_best_desc(child_idx)),
                (false, true) => (old_best, self.resolved_branch_best_desc(old_best)),
                (false, false) => (NULL, NULL),
            }
        };

        let branch = self.nodes[parent_idx].branch_mut(is_full);
        branch.best_child = new_child;
        branch.best_desc = new_desc;
    }

    #[inline]
    fn is_heavier_or_eq(&self, a: usize, b: usize) -> bool {
        let na = &self.nodes[a];
        let nb = &self.nodes[b];
        (na.weight, na.block_root) >= (nb.weight, nb.block_root)
    }
}
