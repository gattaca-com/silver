use flux::utils::ArrayVec;

use crate::types::*;

const NULL: usize = usize::MAX;

pub struct BlockImport {
    pub slot: Slot,
    pub block_root: B256,
    pub parent_root: B256,
    pub state_root: B256,
    pub execution_block_hash: B256,
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
    pub state_ref: BeaconStateRef,
}

impl ForkChoice {
    pub fn init(
        finalized_checkpoint: Checkpoint,
        justified_checkpoint: Checkpoint,
        finalized_slot: Slot,
        finalized_block_root: B256,
        finalized_state_root: B256,
        state_ref: BeaconStateRef,
    ) -> Self {
        let mut nodes = ArrayVec::new();
        let mut indices = ArrayVec::new();

        nodes.push(ForkChoiceNode {
            slot: finalized_slot,
            block_root: finalized_block_root,
            state_root: finalized_state_root,
            parent_root: [0u8; 32],
            execution_block_hash: [0u8; 32],
            parent: NULL,
            best_child: NULL,
            best_descendant: 0, // self
            weight: 0,
            justified_checkpoint,
            finalized_checkpoint,
            execution_status: 2, // valid
            state: state_ref,
        });
        indices.push(ForkChoiceIndex { block_root: finalized_block_root, node_idx: 0 });

        Self {
            nodes,
            indices,
            finalized_checkpoint,
            justified_checkpoint,
            proposer_boost_root: [0u8; 32],
            proposer_boost_score: 0,
        }
    }

    /// Insert a block node into the proto-array.
    pub fn on_block(&mut self, b: &BlockImport) {
        if self.find_node_idx(&b.block_root).is_some() {
            return;
        }

        let node_idx = self.nodes.len();
        let parent = self.find_node_idx(&b.parent_root).unwrap_or(NULL);

        self.nodes.push(ForkChoiceNode {
            slot: b.slot,
            block_root: b.block_root,
            state_root: b.state_root,
            parent_root: b.parent_root,
            execution_block_hash: b.execution_block_hash,
            parent,
            best_child: NULL,
            best_descendant: node_idx, // leaf: self
            weight: 0,
            justified_checkpoint: b.justified,
            finalized_checkpoint: b.finalized,
            // TODO(EL): newly imported blocks are optimistic until
            // engine_newPayloadV4 returns VALID/INVALID. Wire EL responses
            // back to flip this to 2 (valid) or 3 (invalid) and drop invalid
            // descendants from the head choice.
            execution_status: 1, // optimistic
            state: b.state_ref,
        });
        self.indices.push(ForkChoiceIndex { block_root: b.block_root, node_idx });

        // Propagate best_child/best_descendant up to the root so
        // find_head is correct even before apply_score_changes.
        let mut child = node_idx;
        let mut ancestor = parent;
        while ancestor != NULL {
            self.maybe_update_best(ancestor, child);
            child = ancestor;
            ancestor = self.nodes[ancestor].parent;
        }
    }

    /// Apply weight deltas and update best_child/best_descendant.
    ///
    /// Two passes: first propagate deltas leaf-to-root
    /// so all weights are final, then update best_child/best_descendant with
    /// coherent weights.
    pub fn apply_score_changes(&mut self, deltas: &mut [i64; MAX_FORK_CHOICE_NODES]) {
        let len = self.nodes.len();
        for i in (0..len).rev() {
            let delta = deltas[i];
            let w = (self.nodes[i].weight as i64).saturating_add(delta);
            self.nodes[i].weight = w.max(0) as u64;

            let parent = self.nodes[i].parent;
            if parent != NULL {
                deltas[parent] += delta;
            }
        }

        for i in (0..len).rev() {
            let parent = self.nodes[i].parent;
            if parent != NULL {
                self.maybe_update_best(parent, i);
            }
        }
    }

    /// Return the head block root. O(1): justified → best_descendant.
    pub fn find_head(&self) -> B256 {
        let justified_idx = match self.find_node_idx(&self.justified_checkpoint.root) {
            Some(idx) => idx,
            None => return self.justified_checkpoint.root,
        };

        let node = &self.nodes[justified_idx];
        let best_desc =
            if node.best_descendant != NULL { node.best_descendant } else { justified_idx };

        if self.node_is_viable_for_head(best_desc) {
            return self.nodes[best_desc].block_root;
        }

        // Fallback: best_descendant not viable (shouldn't happen with correct scoring).
        self.nodes[justified_idx].block_root
    }

    /// Remove all nodes below the current finalized root.
    /// Returns state refs of pruned nodes so the caller can release pool
    /// entries.
    pub fn prune(&mut self) -> ArrayVec<BeaconStateRef, MAX_FORK_CHOICE_NODES> {
        let mut pruned = ArrayVec::new();

        let fin_idx = match self.find_node_idx(&self.finalized_checkpoint.root) {
            Some(idx) => idx,
            None => return pruned,
        };
        if fin_idx == 0 {
            return pruned;
        }

        for i in 0..fin_idx {
            pruned.push(self.nodes[i].state);
        }

        let surviving = self.nodes.len() - fin_idx;
        for i in 0..surviving {
            self.nodes[i] = self.nodes[fin_idx + i];
            let n = &mut self.nodes[i];
            n.parent = offset_idx(n.parent, fin_idx);
            n.best_child = offset_idx(n.best_child, fin_idx);
            n.best_descendant = offset_idx(n.best_descendant, fin_idx);
        }
        self.nodes.truncate(surviving);

        self.indices.clear();
        for i in 0..self.nodes.len() {
            self.indices
                .push(ForkChoiceIndex { block_root: self.nodes[i].block_root, node_idx: i });
        }

        pruned
    }

    // TODO(perf): O(n_nodes) scan. Hit per on_block (parent lookup), per
    // find_head (justified root), and per moved validator vote in
    // compute_deltas (worst case 2M × MAX_FORK_CHOICE_NODES on
    // apply_score_changes). Replace `indices` with HashMap<B256, u32> or sort
    // by root for binary search; both keep prune cost low.
    pub fn find_node_idx(&self, root: &B256) -> Option<usize> {
        self.indices.as_slice().iter().find(|e| &e.block_root == root).map(|e| e.node_idx)
    }

    pub fn node(&self, idx: usize) -> &ForkChoiceNode {
        &self.nodes[idx]
    }

    fn node_is_viable_for_head(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        // Spec viability has three pieces silver does not implement:
        //   (a) genesis-epoch exception (always viable in epoch 0),
        //   (b) unrealized-justification (use the block's *unrealized* j/f
        //       checkpoints when its post-state hasn't crossed the epoch
        //       boundary yet),
        //   (c) finalized-descendant ancestry (the head must descend from
        //       the finalized block).
        // Acceptable for a passive follower that trusts its checkpoint anchor
        // — silver isn't a proposer. Implication: blocks whose post-state
        // names checkpoints more advanced than ours get filtered, and we
        // accept only blocks <= our anchor's j/f. Revisit if/when proposing.
        n.justified_checkpoint.epoch <= self.justified_checkpoint.epoch &&
            n.finalized_checkpoint.epoch <= self.finalized_checkpoint.epoch
    }

    fn leads_to_viable_head(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        let best = if n.best_descendant != NULL { n.best_descendant } else { idx };
        self.node_is_viable_for_head(best) || self.node_is_viable_for_head(idx)
    }

    /// Re-evaluate parent's best_child/best_descendant.
    fn maybe_update_best(&mut self, parent_idx: usize, child_idx: usize) {
        let old_best = self.nodes[parent_idx].best_child;
        let child_viable = self.leads_to_viable_head(child_idx);

        let change_to_child = || (child_idx, self.best_desc_or_self(child_idx));
        let no_change = || {
            // Refresh best_descendant from current best_child (it may have changed).
            (old_best, self.best_desc_or_self(old_best))
        };

        let (new_child, new_desc) = if old_best == NULL {
            if child_viable { change_to_child() } else { (NULL, NULL) }
        } else if old_best == child_idx {
            // Child is already best: refresh descendant or demote if no longer viable.
            if child_viable { change_to_child() } else { (NULL, NULL) }
        } else {
            let old_viable = self.leads_to_viable_head(old_best);
            match (child_viable, old_viable) {
                (true, true) => {
                    if self.is_heavier_or_eq(child_idx, old_best) {
                        change_to_child()
                    } else {
                        no_change()
                    }
                }
                (true, false) => change_to_child(),
                (false, true) => no_change(),
                (false, false) => (NULL, NULL),
            }
        };

        self.nodes[parent_idx].best_child = new_child;
        self.nodes[parent_idx].best_descendant = new_desc;
    }

    fn is_heavier_or_eq(&self, a: usize, b: usize) -> bool {
        let na = &self.nodes[a];
        let nb = &self.nodes[b];
        (na.weight, na.block_root) >= (nb.weight, nb.block_root)
    }

    fn best_desc_or_self(&self, idx: usize) -> usize {
        let bd = self.nodes[idx].best_descendant;
        if bd != NULL { bd } else { idx }
    }
}

/// Compute weight deltas from vote changes and balance changes.
/// For each validator whose vote or balance changed, subtract old balance
/// from old target and add new balance to new target.
pub fn compute_deltas(
    votes: &mut [Vote; MAX_VALIDATORS],
    validator_count: usize,
    indices: &[ForkChoiceIndex],
    old_balances: &[u64; MAX_VALIDATORS],
    new_balances: &[u64; MAX_VALIDATORS],
) -> [i64; MAX_FORK_CHOICE_NODES] {
    let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];

    for vi in 0..validator_count {
        let vote = &mut votes[vi];

        let old_bal = old_balances[vi];
        let new_bal = new_balances[vi];

        if vote.current_root == vote.next_root && old_bal == new_bal {
            continue;
        }

        if vote.current_root != [0u8; 32] &&
            let Some(old_idx) = find_idx(indices, &vote.current_root)
        {
            deltas[old_idx] -= old_bal as i64;
        }

        // Add new balance to new target.
        if vote.next_root != [0u8; 32] &&
            let Some(new_idx) = find_idx(indices, &vote.next_root)
        {
            deltas[new_idx] += new_bal as i64;
        }

        // Note: if next_root is non-zero but unknown (pruned/never-imported),
        // we still bump current_root, "consuming" the vote with no delta
        // contribution. Self-heals on the validator's next attestation.
        // Matches Lighthouse proto_array.
        vote.current_root = vote.next_root;
    }

    deltas
}

fn find_idx(indices: &[ForkChoiceIndex], root: &B256) -> Option<usize> {
    indices.iter().find(|e| &e.block_root == root).map(|e| e.node_idx)
}

fn offset_idx(idx: usize, offset: usize) -> usize {
    if idx == NULL || idx < offset { NULL } else { idx - offset }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::box_zeroed;

    fn root(b: u8) -> B256 {
        let mut r = [0u8; 32];
        r[0] = b;
        r
    }

    fn cp(epoch: Epoch, b: u8) -> Checkpoint {
        Checkpoint { epoch, root: root(b) }
    }

    fn blk(
        slot: Slot,
        block_root: B256,
        parent_root: B256,
        jus: Checkpoint,
        fin: Checkpoint,
    ) -> BlockImport {
        BlockImport {
            slot,
            block_root,
            parent_root,
            state_root: block_root,
            execution_block_hash: [0u8; 32],
            justified: jus,
            finalized: fin,
            state_ref: BeaconStateRef::default(),
        }
    }

    fn default_sref() -> BeaconStateRef {
        BeaconStateRef::default()
    }

    #[test]
    fn single_chain_head() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        fc.on_block(&blk(2, root(3), root(2), jus, fin));

        assert_eq!(fc.find_head(), root(3));
    }

    #[test]
    fn fork_heavier_wins() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        fc.on_block(&blk(1, root(3), root(1), jus, fin));

        let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];
        deltas[2] = 100; // root(3) is node index 2
        fc.apply_score_changes(&mut deltas);

        assert_eq!(fc.find_head(), root(3));
    }

    #[test]
    fn two_pass_weight_correctness() {
        // Regression: single-pass apply_score_changes could pick the wrong
        // child when a higher-index child gains weight and a lower-index
        // sibling loses weight.
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        // root(1) → root(2) [idx 1] and root(3) [idx 2]
        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        fc.on_block(&blk(1, root(3), root(1), jus, fin));

        // Give root(2) initial weight.
        let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];
        deltas[1] = 200;
        fc.apply_score_changes(&mut deltas);
        assert_eq!(fc.find_head(), root(2));

        // Now root(2) loses weight, root(3) gains → root(3) should win.
        let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];
        deltas[1] = -150; // root(2): 200 - 150 = 50
        deltas[2] = 100; // root(3): 0 + 100 = 100
        fc.apply_score_changes(&mut deltas);
        assert_eq!(fc.find_head(), root(3));
    }

    #[test]
    fn prune_below_finalized() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        fc.on_block(&blk(2, root(3), root(2), jus, fin));
        assert_eq!(fc.nodes.len(), 3);

        fc.finalized_checkpoint = cp(1, 2);
        let pruned = fc.prune();

        assert_eq!(pruned.len(), 1);
        assert_eq!(fc.nodes.len(), 2);
        assert_eq!(fc.nodes[0].block_root, root(2));
        assert_eq!(fc.nodes[0].parent, NULL);
        assert_eq!(fc.find_node_idx(&root(3)), Some(1));
    }

    #[test]
    fn deltas_moving_votes() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());
        fc.on_block(&blk(1, root(2), root(1), jus, fin));

        let mut votes: Box<[Vote; MAX_VALIDATORS]> = box_zeroed();
        let mut balances: Box<[u64; MAX_VALIDATORS]> = box_zeroed();

        // 16 validators all move from root(1) to root(2).
        for i in 0..16 {
            votes[i] = Vote { current_root: root(1), next_root: root(2), next_epoch: 0 };
            balances[i] = 42;
        }

        let deltas = compute_deltas(&mut votes, 16, fc.indices.as_slice(), &balances, &balances);

        let total = 42i64 * 16;
        assert_eq!(deltas[0], -total);
        assert_eq!(deltas[1], total);

        for i in 0..16 {
            assert_eq!(votes[i].current_root, root(2));
        }
    }

    #[test]
    fn deltas_different_votes() {
        // Each validator votes for a different block.
        let fin = cp(0, 100);
        let jus = cp(0, 100);
        let mut fc = ForkChoice::init(fin, jus, 0, root(100), root(100), default_sref());

        for i in 1..=16u8 {
            fc.on_block(&blk(i as u64, root(i), root(100), jus, fin));
        }

        let mut votes: Box<[Vote; MAX_VALIDATORS]> = box_zeroed();
        let mut balances: Box<[u64; MAX_VALIDATORS]> = box_zeroed();

        for i in 0..16 {
            votes[i] =
                Vote { current_root: [0u8; 32], next_root: root((i + 1) as u8), next_epoch: 0 };
            balances[i] = 42;
        }

        let deltas = compute_deltas(&mut votes, 16, fc.indices.as_slice(), &balances, &balances);

        // Each block should get exactly one validator's balance.
        for i in 1..=16 {
            assert_eq!(deltas[i], 42);
        }
    }

    #[test]
    fn deltas_move_out_of_tree() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        let mut votes: Box<[Vote; MAX_VALIDATORS]> = box_zeroed();
        let mut balances: Box<[u64; MAX_VALIDATORS]> = box_zeroed();

        // Validator 0 moves from root(1) to zero hash (genesis alias).
        votes[0] = Vote { current_root: root(1), next_root: [0u8; 32], next_epoch: 0 };
        balances[0] = 42;

        // Validator 1 moves from root(1) to unknown root.
        votes[1] = Vote { current_root: root(1), next_root: root(99), next_epoch: 0 };
        balances[1] = 42;

        let deltas = compute_deltas(&mut votes, 2, fc.indices.as_slice(), &balances, &balances);

        // root(1) should lose both balances.
        assert_eq!(deltas[0], -(42 * 2));
    }

    #[test]
    fn deltas_changing_balances() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());
        fc.on_block(&blk(1, root(2), root(1), jus, fin));

        let mut votes: Box<[Vote; MAX_VALIDATORS]> = box_zeroed();
        let mut old_bal: Box<[u64; MAX_VALIDATORS]> = box_zeroed();
        let mut new_bal: Box<[u64; MAX_VALIDATORS]> = box_zeroed();

        // 16 validators move from root(1) to root(2), balance doubles.
        for i in 0..16 {
            votes[i] = Vote { current_root: root(1), next_root: root(2), next_epoch: 0 };
            old_bal[i] = 42;
            new_bal[i] = 84;
        }

        let deltas = compute_deltas(&mut votes, 16, fc.indices.as_slice(), &old_bal, &new_bal);

        // Old balance subtracted from old target, new balance added to new.
        assert_eq!(deltas[0], -(42i64 * 16));
        assert_eq!(deltas[1], 84i64 * 16);
    }

    #[test]
    fn deltas_balance_change_no_vote_change() {
        // Balances change but votes don't — still need deltas.
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        let mut votes: Box<[Vote; MAX_VALIDATORS]> = box_zeroed();
        let mut old_bal: Box<[u64; MAX_VALIDATORS]> = box_zeroed();
        let mut new_bal: Box<[u64; MAX_VALIDATORS]> = box_zeroed();

        // Validator already voted for root(1), balance changes.
        votes[0] = Vote { current_root: root(1), next_root: root(1), next_epoch: 0 };
        old_bal[0] = 42;
        new_bal[0] = 84;

        let deltas = compute_deltas(&mut votes, 1, fc.indices.as_slice(), &old_bal, &new_bal);

        // Net delta = new - old = +42.
        assert_eq!(deltas[0], 42);
    }

    /// Tiebreaker: equal-weight siblings → higher block root wins (spec: >=).
    #[test]
    fn split_tie_breaker_no_attestations() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        // Two blocks at slot 1 forking from genesis. root(2) < root(3).
        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        fc.on_block(&blk(1, root(3), root(1), jus, fin));

        // No weight applied → both have weight 0. Higher root wins.
        assert_eq!(fc.find_head(), root(3));
    }

    /// Shorter chain with more attestation weight beats a longer chain.
    #[test]
    fn shorter_chain_but_heavier_weight() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        // Long chain: root(1) → root(2) → root(3) → root(4).
        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        fc.on_block(&blk(2, root(3), root(2), jus, fin));
        fc.on_block(&blk(3, root(4), root(3), jus, fin));

        // Short chain: root(1) → root(5).
        fc.on_block(&blk(1, root(5), root(1), jus, fin));

        // Without weight, long chain wins (deeper best_descendant, higher root
        // tiebreak). Give root(5) more weight to flip.
        let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];
        deltas[4] = 1000; // root(5) is node 4
        fc.apply_score_changes(&mut deltas);

        assert_eq!(fc.find_head(), root(5));
    }

    /// Duplicate block insertion is a no-op.
    #[test]
    fn on_block_duplicate() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        assert_eq!(fc.nodes.len(), 2);

        fc.on_block(&blk(1, root(2), root(1), jus, fin));
        assert_eq!(fc.nodes.len(), 2); // no change
    }

    /// Unknown parent → node still inserted (parent = NULL).
    #[test]
    fn on_block_unknown_parent() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), default_sref());

        // root(99) is not known.
        fc.on_block(&blk(1, root(2), root(99), jus, fin));
        assert_eq!(fc.nodes.len(), 2);
        assert_eq!(fc.nodes[1].parent, NULL);
    }
}
