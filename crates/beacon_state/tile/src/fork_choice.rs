use silver_beacon_state_data::{
    B256, Checkpoint, Epoch, SLOTS_PER_EPOCH, SLOTS_RING_N, Slot, StateId,
};
use silver_common::metrics::timed;
use tracing::info;

// Pinned to the slot-state ring: every node carries a `state_id` into that
// ring, so the node table cannot outgrow the resident states it indexes.
//
// TODO(stalls): ~8 epochs of unpruned mainnet activity fills the ring. The May
// 2023 incident lasted ~25 epochs. Surviving that needs the ring and node table
// to grow or shed together — grow + paginate, or drop lowest-weight subtrees
// (freeing their ring slots) under pressure. A larger cap here alone would only
// move the panic, not raise the ceiling.
pub const MAX_FORK_CHOICE_NODES: usize = SLOTS_RING_N;

const NULL: usize = usize::MAX;

/// Spec PROPOSER_SCORE_BOOST (percent). A timely current-slot block earns a
/// transient weight of this fraction of one slot's attesting balance.
pub const PROPOSER_SCORE_BOOST: u64 = 40;

pub fn proposer_boost_score(total_active_balance: u64) -> u64 {
    (total_active_balance / SLOTS_PER_EPOCH) * PROPOSER_SCORE_BOOST / 100
}

/// LMD-GHOST store: the proto-array plus the per-validator vote tracking and
/// balance snapshot that drive its weights.
#[derive(Default)]
pub struct ForkChoice {
    pub nodes: Vec<ForkChoiceNode>,
    pub lookup: NodeLookup,
    pub finalized_checkpoint: Checkpoint,
    pub justified_checkpoint: Checkpoint,
    // Spec proposer boost. `*_root`/`*_score` is the *current* target, set on a
    // timely current-slot block import and zeroed at the next slot boundary.
    // `applied_*` is what the last `apply_score_changes` folded into weights, so
    // the next call can net the previous boost out before applying the current.
    pub proposer_boost_root: B256,
    pub proposer_boost_score: u64,
    applied_boost_root: B256,
    applied_boost_score: u64,

    /// Spec `latest_messages`: per-validator latest LMD vote.
    pub vote_tracker: Box<VoteTracker>,
    /// Validator indices whose vote moved since the last `recompute_head`; lets
    /// the fold visit only the changed votes when the balance snapshot is
    /// fixed.
    vote_dirty: Vec<u32>,
    /// Spec `equivocating_indices` bitset: validators caught double-voting are
    /// permanently excluded from votes and weighting.
    equivocating: Box<[u64]>,
    /// Spec `validate_on_attestation` deferral: current-slot votes held until
    /// the next slot, drained by the tick before a recompute.
    pending_votes: Vec<(u32, B256, Epoch)>,

    /// Spec `get_attestation_score` balances: validator i → effective balance
    /// if active at `justified_balances_cp.epoch` and unslashed, else 0.
    /// Double-buffered (`prev_*` holds the pre-rebuild snapshot for the one
    /// full-pass recompute a checkpoint change triggers).
    pub justified_balances: Vec<u64>,
    prev_justified_balances: Vec<u64>,
    /// The checkpoint `justified_balances` was built for.
    justified_balances_cp: Checkpoint,
    /// Set when a fresh snapshot was installed; arms the next `recompute_head`
    /// as a full pass (every weight may shift), then cleared.
    justified_balances_full_pass: bool,
    /// Spec `get_proposer_score` input: total active balance of the justified
    /// state at `justified_balances_cp.epoch` (active set incl. slashed,
    /// clamped to one increment).
    justified_total_active_balance: u64,
}

const LOOKUP_SLOTS: usize = 2 * MAX_FORK_CHOICE_NODES;
const LOOKUP_MASK: usize = LOOKUP_SLOTS - 1;

/// Open-addressed root → node-idx table. `2 * MAX_FORK_CHOICE_NODES` slots
/// (power of two); probe position = first 8 bytes of the root & mask, confirmed
/// against the stored full root. An all-zero root marks an empty slot (no real
/// block root is zero). Linear probe, no tombstones — inserted in `on_block`,
/// rebuilt wholesale in `prune`.
pub struct NodeLookup {
    slots: Box<[(B256, u32)]>,
}

impl Default for NodeLookup {
    fn default() -> Self {
        Self { slots: vec![([0u8; 32], 0u32); LOOKUP_SLOTS].into_boxed_slice() }
    }
}

impl NodeLookup {
    #[inline]
    fn probe(root: &B256) -> usize {
        usize::from_le_bytes(root[..8].try_into().unwrap()) & LOOKUP_MASK
    }

    fn clear(&mut self) {
        self.slots.fill(([0u8; 32], 0));
    }

    fn insert(&mut self, root: B256, node_idx: usize) {
        let mut i = Self::probe(&root);
        loop {
            if self.slots[i].0 == [0u8; 32] {
                self.slots[i] = (root, node_idx as u32);
                return;
            }
            i = (i + 1) & LOOKUP_MASK;
        }
    }

    #[inline]
    pub fn get(&self, root: &B256) -> Option<usize> {
        if *root == [0u8; 32] {
            return None;
        }
        let mut i = Self::probe(root);
        loop {
            let (r, idx) = &self.slots[i];
            if *r == [0u8; 32] {
                return None;
            }
            if r == root {
                return Some(*idx as usize);
            }
            i = (i + 1) & LOOKUP_MASK;
        }
    }
}

/// EL payload-verification state of a node. Optimistic on import until the EL
/// returns a verdict; invalid nodes are excluded from head viability.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    /// Imported, EL has not yet verified the payload.
    Optimistic,
    /// EL fully validated the payload (and transitively its ancestors).
    Valid,
    /// EL declared the payload invalid.
    Invalid,
}

#[derive(Clone)]
pub struct ForkChoiceNode {
    pub slot: Slot,
    pub block_root: B256,
    // Stored for the eventual EL/engine API (`engine_forkchoiceUpdatedV3`)
    // and slashing-status checks; not consumed by current fork-choice logic.
    #[allow(dead_code)]
    pub state_root: B256,
    #[allow(dead_code)]
    pub parent_root: B256,

    pub execution_block_hash: B256,

    /// Index into nodes array. usize::MAX = null.
    pub parent: usize,
    pub best_child: usize,
    pub best_descendant: usize,

    pub weight: u64,

    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    pub execution_status: ExecutionStatus,

    pub state_id: StateId,
}

#[repr(C)]
#[derive(Default)]
pub struct VoteTracker {
    pub votes: Box<[Vote]>,
}

impl VoteTracker {
    pub fn with_capacity(capacity: usize) -> Box<Self> {
        Box::new(Self { votes: vec![Vote::default(); capacity].into_boxed_slice() })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Vote {
    pub current_root: B256,
    pub next_root: B256,
    pub next_epoch: Epoch,
}

pub struct BlockImport {
    pub slot: Slot,
    pub block_root: B256,
    pub parent_root: B256,
    pub state_root: B256,
    pub execution_block_hash: B256,
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
    /// Per-tier index bundle of this block's post-state.
    pub state_id: StateId,
}

impl ForkChoice {
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        finalized_checkpoint: Checkpoint,
        justified_checkpoint: Checkpoint,
        finalized_slot: Slot,
        finalized_block_root: B256,
        finalized_state_root: B256,
        finalized_execution_block_hash: B256,
        state_id: StateId,
        capacity: usize,
    ) -> Self {
        let mut nodes = Vec::with_capacity(MAX_FORK_CHOICE_NODES);
        let mut lookup = NodeLookup::default();

        nodes.push(ForkChoiceNode {
            slot: finalized_slot,
            block_root: finalized_block_root,
            state_root: finalized_state_root,
            parent_root: [0u8; 32],
            execution_block_hash: finalized_execution_block_hash,
            parent: NULL,
            best_child: NULL,
            best_descendant: 0, // self
            weight: 0,
            justified_checkpoint,
            finalized_checkpoint,
            execution_status: ExecutionStatus::Valid,
            state_id,
        });
        lookup.insert(finalized_block_root, 0);

        Self {
            nodes,
            lookup,
            finalized_checkpoint,
            justified_checkpoint,
            proposer_boost_root: [0u8; 32],
            proposer_boost_score: 0,
            applied_boost_root: [0u8; 32],
            applied_boost_score: 0,
            vote_tracker: VoteTracker::with_capacity(capacity),
            vote_dirty: Vec::with_capacity(capacity),
            equivocating: vec![0u64; capacity.div_ceil(64)].into_boxed_slice(),
            pending_votes: Vec::with_capacity(capacity / SLOTS_PER_EPOCH as usize),
            justified_balances: Vec::with_capacity(capacity),
            prev_justified_balances: Vec::with_capacity(capacity),
            justified_balances_cp: Checkpoint::default(),
            justified_balances_full_pass: false,
            justified_total_active_balance: 0,
        }
    }

    /// Insert a block node into the proto-array.
    pub fn on_block(&mut self, b: BlockImport) {
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
            execution_status: ExecutionStatus::Optimistic,
            state_id: b.state_id,
        });
        self.lookup.insert(b.block_root, node_idx);

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

    /// Add a signed proposer-boost contribution to a resident root's delta.
    fn fold_boost(
        deltas: &mut [i64; MAX_FORK_CHOICE_NODES],
        lookup: &NodeLookup,
        root: &B256,
        score: i64,
    ) {
        if *root != [0u8; 32] &&
            let Some(i) = lookup.get(root)
        {
            deltas[i] = deltas[i].saturating_add(score);
        }
    }

    /// Apply weight deltas and update best_child/best_descendant.
    ///
    /// Two passes: first propagate deltas leaf-to-root
    /// so all weights are final, then update best_child/best_descendant with
    /// coherent weights.
    pub fn apply_score_changes(&mut self, deltas: &mut [i64; MAX_FORK_CHOICE_NODES]) {
        // Net proposer boost into the deltas before propagation: remove what the
        // previous call applied, add the current target's. Folding it here lets
        // the leaf-to-root loop carry it up the ancestor chain like any vote
        // delta. The per-slot tick zeroes `proposer_boost_root`, so on a new slot
        // this subtracts the expired boost and adds nothing.
        Self::fold_boost(
            deltas,
            &self.lookup,
            &self.applied_boost_root,
            -(self.applied_boost_score as i64),
        );
        Self::fold_boost(
            deltas,
            &self.lookup,
            &self.proposer_boost_root,
            self.proposer_boost_score as i64,
        );
        self.applied_boost_root = self.proposer_boost_root;
        self.applied_boost_score = self.proposer_boost_score;

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

    /// Remove all nodes below the current finalized root. Callers re-anchor
    /// the survivors via `live_state_ids` after pruning.
    pub fn prune(&mut self) {
        let Some(fin_idx) = self.find_node_idx(&self.finalized_checkpoint.root) else {
            return;
        };
        if fin_idx == 0 {
            return;
        }

        self.nodes.drain(..fin_idx);

        for n in self.nodes.iter_mut() {
            n.parent = offset_idx(n.parent, fin_idx);
            n.best_child = offset_idx(n.best_child, fin_idx);
            n.best_descendant = offset_idx(n.best_descendant, fin_idx);
        }

        self.lookup.clear();
        for i in 0..self.nodes.len() {
            self.lookup.insert(self.nodes[i].block_root, i);
        }
    }

    /// Returns `(head_root, head_exec, safe_exec, finalized_exec)` for
    /// `engine_forkchoiceUpdatedV3`. `head_root` is the head's beacon root,
    /// echoed by the engine tile so the FCU verdict can be applied here.
    /// safe = justified block; zeros when the checkpoint block is absent from
    /// the tree.
    pub fn fcu_execution_hashes(&self) -> (B256, B256, B256, B256) {
        let zero = [0u8; 32];
        let Some(ji) = self.find_node_idx(&self.justified_checkpoint.root) else {
            return (zero, zero, zero, zero);
        };
        let node = &self.nodes[ji];
        let head_idx =
            if node.best_descendant != NULL && self.node_is_viable_for_head(node.best_descendant) {
                node.best_descendant
            } else {
                ji
            };
        let fin_exec = self
            .find_node_idx(&self.finalized_checkpoint.root)
            .map(|i| self.nodes[i].execution_block_hash)
            .unwrap_or(zero);
        let head = &self.nodes[head_idx];
        (head.block_root, head.execution_block_hash, node.execution_block_hash, fin_exec)
    }

    /// EL VALID verdict (newPayload or FCU response): the EL fully validated
    /// `block_root`'s payload, which transitively validates every ancestor.
    /// Walk up until the first already-valid node.
    pub fn on_payload_valid(&mut self, block_root: &B256) {
        let Some(mut idx) = self.find_node_idx(block_root) else {
            return;
        };
        loop {
            let n = &mut self.nodes[idx];
            if n.execution_status == ExecutionStatus::Valid {
                break;
            }
            n.execution_status = ExecutionStatus::Valid;
            if n.parent == NULL {
                break;
            }
            idx = n.parent;
        }
    }

    /// EL INVALID verdict (newPayload or FCU response): `block_root` and
    /// everything above the last valid ancestor (`latest_valid_hash`) is
    /// invalid. When the EL gave no usable hash, condemn only `block_root` —
    /// optimistic ancestors keep their status. Caller must recompute head
    /// afterwards: invalid nodes are filtered by `node_is_viable_for_head`
    /// and the next score pass reroutes best_child/best_descendant around
    /// them.
    pub fn on_payload_invalid(&mut self, block_root: &B256, latest_valid_hash: &B256) {
        let Some(head_idx) = self.find_node_idx(block_root) else {
            return;
        };
        let lvh_idx = if *latest_valid_hash == [0u8; 32] {
            None
        } else {
            self.nodes.iter().position(|n| n.execution_block_hash == *latest_valid_hash)
        };

        info!(?block_root, ?latest_valid_hash, "payload invalid, marking branch");

        // Ancestor segment: block down to (exclusive) the last valid ancestor.
        let mut idx = head_idx;
        loop {
            if Some(idx) == lvh_idx {
                self.nodes[idx].execution_status = ExecutionStatus::Valid;
                break;
            }
            let n = &mut self.nodes[idx];
            if n.execution_status == ExecutionStatus::Valid {
                break;
            }
            n.execution_status = ExecutionStatus::Invalid;
            n.best_child = NULL;
            n.best_descendant = NULL;
            // Unknown ancestor: only `block_root` is provably bad.
            if n.parent == NULL || lvh_idx.is_none() {
                break;
            }
            idx = n.parent;
        }

        // Descendants of an invalid node are invalid. Parents always precede
        // children in `nodes`, so one forward pass suffices.
        for i in 0..self.nodes.len() {
            let p = self.nodes[i].parent;
            if p != NULL && self.nodes[p].execution_status == ExecutionStatus::Invalid {
                let n = &mut self.nodes[i];
                n.execution_status = ExecutionStatus::Invalid;
                n.best_child = NULL;
                n.best_descendant = NULL;
            }
        }
    }

    #[inline]
    pub fn find_node_idx(&self, root: &B256) -> Option<usize> {
        self.lookup.get(root)
    }

    #[inline]
    pub fn node(&self, idx: usize) -> &ForkChoiceNode {
        &self.nodes[idx]
    }

    /// Spec `update_latest_messages`: record a validator's latest LMD vote.
    /// Newer-epoch votes only; out-of-range and equivocating validators are
    /// skipped. Dirties the index so the next `recompute_head` folds the move.
    pub fn record_vote(
        &mut self,
        validator_idx: usize,
        block_root: B256,
        epoch: Epoch,
        validator_count: usize,
    ) {
        if validator_idx >= validator_count || self.is_equivocating(validator_idx) {
            return;
        }
        // Zero `next_root` is the uninitialised sentinel — first vote always
        // takes; a real attestation never has a zero `beacon_block_root`.
        let v = &mut self.vote_tracker.votes[validator_idx];
        if v.next_root != [0u8; 32] && epoch <= v.next_epoch {
            return;
        }
        v.next_root = block_root;
        v.next_epoch = epoch;
        self.vote_dirty.push(validator_idx as u32);
    }

    /// Spec `validate_on_attestation`: hold a current-slot vote until the next
    /// slot, when the tick drains it via `drain_pending_votes`.
    pub fn defer_vote(&mut self, validator_idx: u32, block_root: B256, epoch: Epoch) {
        self.pending_votes.push((validator_idx, block_root, epoch));
    }

    /// Fold the deferred votes into the tracker (called by the tick, one slot
    /// after they arrived). Duplicates are absorbed by the epoch-monotonic
    /// guard.
    pub fn drain_pending_votes(&mut self, validator_count: usize) {
        for i in 0..self.pending_votes.len() {
            let (vi, root, epoch) = self.pending_votes[i];
            self.record_vote(vi as usize, root, epoch, validator_count);
        }
        self.pending_votes.clear();
    }

    pub fn is_equivocating(&self, idx: usize) -> bool {
        let (w, b) = (idx / 64, idx % 64);
        self.equivocating.get(w).is_some_and(|word| word & (1u64 << b) != 0)
    }

    /// Spec `on_attester_slashing`: mark a validator equivocating. Idempotent.
    /// If it had a live vote, zero the target and dirty it so the next
    /// recompute subtracts its weight (moved-vote path). The bit — not the
    /// zero sentinel — is the permanent exclusion.
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
            (v.current_root != [0u8; 32] || v.next_root != [0u8; 32])
        {
            v.next_root = [0u8; 32];
            self.vote_dirty.push(idx as u32);
        }
    }

    /// Set the proposer-boost target (a timely current-slot block).
    pub fn set_proposer_boost(&mut self, root: B256, score: u64) {
        self.proposer_boost_root = root;
        self.proposer_boost_score = score;
    }

    /// Expire proposer boost at a slot boundary; the next `apply_score_changes`
    /// nets the previously-applied boost back out.
    pub fn expire_proposer_boost(&mut self) {
        self.proposer_boost_root = [0u8; 32];
    }

    /// True when the justified-balance snapshot must be rebuilt — the justified
    /// checkpoint moved, or we have no snapshot yet.
    pub fn justified_balances_stale(&self) -> bool {
        self.justified_checkpoint != self.justified_balances_cp ||
            self.justified_balances.is_empty()
    }

    /// Lend out the spare snapshot buffer (cleared) for the caller to fill from
    /// the justified state, returned via `commit_justified_balances`.
    pub fn take_justified_scratch(&mut self) -> Vec<u64> {
        let mut buf = std::mem::take(&mut self.prev_justified_balances);
        buf.clear();
        buf
    }

    /// Install a freshly-built snapshot: rotate current→previous (the full-pass
    /// `old`), adopt `filled` plus its total active balance, and arm the next
    /// `recompute_head` as a full pass.
    pub fn commit_justified_balances(
        &mut self,
        filled: Vec<u64>,
        total_active: u64,
        cp: Checkpoint,
    ) {
        self.prev_justified_balances = std::mem::replace(&mut self.justified_balances, filled);
        self.justified_total_active_balance = total_active;
        self.justified_balances_cp = cp;
        self.justified_balances_full_pass = true;
    }

    /// Cached total active balance of the justified state (spec
    /// `get_proposer_score`). Valid once `refresh_justified_balances` has run
    /// for the current justified checkpoint.
    pub fn justified_total_active_balance(&self) -> u64 {
        self.justified_total_active_balance
    }

    /// Fold accumulated vote/balance changes into weights and refresh
    /// best_descendant. A fresh balance snapshot (`commit_justified_balances`)
    /// arms a full pass; otherwise only the dirtied votes are folded against
    /// the unchanged snapshot. Caller lifts checkpoints afterwards.
    pub fn recompute_head(&mut self) {
        let full_pass = self.justified_balances_full_pass;
        let n = self.justified_balances.len();
        let (old, new) = if full_pass {
            (&self.prev_justified_balances, &self.justified_balances)
        } else {
            (&self.justified_balances, &self.justified_balances)
        };
        let changed = (!full_pass).then_some(self.vote_dirty.as_slice());
        let mut deltas =
            compute_deltas(&mut self.vote_tracker.votes, n, &self.lookup, old, new, changed);
        self.apply_score_changes(&mut deltas);
        self.vote_dirty.clear();
        self.justified_balances_full_pass = false;
    }

    /// Index bundles of all currently-live nodes — the caller re-anchors them
    /// against the freshly promoted base at finalization.
    pub fn live_state_ids(&self) -> impl Iterator<Item = StateId> + '_ {
        self.nodes.iter().map(|n| n.state_id)
    }

    /// Spec `get_checkpoint_block(store, root, epoch)`: deepest ancestor of
    /// `root` with `slot <= epoch_start_slot`. `None` if `root` isn't in fork
    /// choice or no ancestor satisfies the bound (walked above tree root).
    pub fn get_checkpoint_block(&self, root: &B256, epoch_start_slot: Slot) -> Option<B256> {
        let mut idx = self.find_node_idx(root)?;
        loop {
            let n = &self.nodes[idx];
            if n.slot <= epoch_start_slot {
                return Some(n.block_root);
            }
            if n.parent == NULL {
                return None;
            }
            idx = n.parent;
        }
    }

    #[inline]
    fn node_is_viable_for_head(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        // An EL-invalid node (and its subtree) is never viable. The rest is the
        // realized j/f filter.
        //
        // TODO: Spec viability has three pieces silver does not implement:
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
        n.execution_status != ExecutionStatus::Invalid &&
            n.justified_checkpoint.epoch <= self.justified_checkpoint.epoch &&
            n.finalized_checkpoint.epoch <= self.finalized_checkpoint.epoch
    }

    #[inline]
    fn leads_to_viable_head(&self, idx: usize) -> bool {
        let n = &self.nodes[idx];
        let best = if n.best_descendant != NULL { n.best_descendant } else { idx };
        self.node_is_viable_for_head(best) || self.node_is_viable_for_head(idx)
    }

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

    #[inline]
    fn is_heavier_or_eq(&self, a: usize, b: usize) -> bool {
        let na = &self.nodes[a];
        let nb = &self.nodes[b];
        (na.weight, na.block_root) >= (nb.weight, nb.block_root)
    }

    #[inline]
    fn best_desc_or_self(&self, idx: usize) -> usize {
        let bd = self.nodes[idx].best_descendant;
        if bd != NULL { bd } else { idx }
    }
}

/// Compute weight deltas from vote changes and balance changes.
/// For each visited validator whose vote or balance changed, subtract old
/// balance from old target and add new balance to new target.
///
/// `changed`: `Some(dirty)` visits only those validator indices — sound only
/// when the balance snapshot is unchanged (`old == new` everywhere, so a
/// non-dirty validator contributes nothing). `None` is the full pass, used on
/// the (≤ once-per-epoch) justified-balance snapshot swap.
#[timed]
pub fn compute_deltas(
    votes: &mut [Vote],
    validator_count: usize,
    lookup: &NodeLookup,
    old_balances: &[u64],
    new_balances: &[u64],
    changed: Option<&[u32]>,
) -> [i64; MAX_FORK_CHOICE_NODES] {
    let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];

    let mut apply = |vi: usize, vote: &mut Vote| {
        // `old_balances` (previous snapshot) may be shorter than the current
        // validator set; validators added since then carry no prior weight.
        let old_balance = old_balances.get(vi).copied().unwrap_or(0);
        let new_balance = new_balances.get(vi).copied().unwrap_or(0);

        if vote.current_root == vote.next_root && old_balance == new_balance {
            return;
        }

        if vote.current_root != [0u8; 32] &&
            let Some(old_idx) = lookup.get(&vote.current_root)
        {
            deltas[old_idx] -= old_balance as i64;
        }

        // Add new balance to new target.
        if vote.next_root != [0u8; 32] &&
            let Some(new_idx) = lookup.get(&vote.next_root)
        {
            deltas[new_idx] += new_balance as i64;
        }

        // Note: if next_root is non-zero but unknown (pruned/never-imported),
        // we still bump current_root, "consuming" the vote with no delta
        // contribution. Self-heals on the validator's next attestation.
        // Matches Lighthouse proto_array.
        vote.current_root = vote.next_root;
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

    deltas
}

#[inline]
fn offset_idx(idx: usize, offset: usize) -> usize {
    if idx == NULL || idx < offset { NULL } else { idx - offset }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Opaque per-tier bundle for topology/weight tests that never resolve
    /// state. Built field-by-field — `StateId` deliberately has no `Default`.
    fn test_state_id() -> StateId {
        StateId {
            epoch_idx: None,
            longtail_idx: None,
            balances_idx: Default::default(),
            eth1_idx: Default::default(),
            validators_idx: Default::default(),
            pending_idx: Default::default(),
            previous_participation_idx: Default::default(),
            current_participation_idx: Default::default(),
            inactivity_idx: Default::default(),
            slot_idx: Default::default(),
        }
    }

    fn root(b: u8) -> B256 {
        let mut r = [0u8; 32];
        r[0] = b;
        r
    }

    fn cp(epoch: Epoch, b: u8) -> Checkpoint {
        Checkpoint { epoch, root: root(b) }
    }

    // Fork choice nodes carry their post-state index bundle; the topology /
    // weight tests don't read state, so a constant seq is fine.
    fn block(
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
            state_id: test_state_id(),
        }
    }

    #[test]
    fn single_chain_head() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        fc.on_block(block(1, root(2), root(1), jus, fin));
        fc.on_block(block(2, root(3), root(2), jus, fin));

        assert_eq!(fc.find_head(), root(3));
    }

    #[test]
    fn fork_heavier_wins() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        fc.on_block(block(1, root(2), root(1), jus, fin));
        fc.on_block(block(1, root(3), root(1), jus, fin));

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
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        // root(1) → root(2) [idx 1] and root(3) [idx 2]
        fc.on_block(block(1, root(2), root(1), jus, fin));
        fc.on_block(block(1, root(3), root(1), jus, fin));

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
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        fc.on_block(block(1, root(2), root(1), jus, fin));
        fc.on_block(block(2, root(3), root(2), jus, fin));
        assert_eq!(fc.nodes.len(), 3);

        fc.finalized_checkpoint = cp(1, 2);
        fc.prune();

        assert_eq!(fc.nodes.len(), 2);
        assert_eq!(fc.nodes[0].block_root, root(2));
        assert_eq!(fc.nodes[0].parent, NULL);
        assert_eq!(fc.find_node_idx(&root(3)), Some(1));
    }

    #[test]
    fn deltas_moving_votes() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);
        fc.on_block(block(1, root(2), root(1), jus, fin));

        let mut votes = vec![Vote::default(); 16];
        let mut balances = vec![0u64; 16];

        // 16 validators all move from root(1) to root(2).
        for i in 0..16 {
            votes[i] = Vote { current_root: root(1), next_root: root(2), next_epoch: 0 };
            balances[i] = 42;
        }

        let deltas = compute_deltas(&mut votes, 16, &fc.lookup, &balances[..], &balances[..], None);

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
        let mut fc =
            ForkChoice::init(fin, jus, 0, root(100), root(100), [0u8; 32], test_state_id(), 0);

        for i in 1..=16u8 {
            fc.on_block(block(i as u64, root(i), root(100), jus, fin));
        }

        let mut votes = vec![Vote::default(); 16];
        let mut balances = vec![0u64; 16];

        for i in 0..16 {
            votes[i] =
                Vote { current_root: [0u8; 32], next_root: root((i + 1) as u8), next_epoch: 0 };
            balances[i] = 42;
        }

        let deltas = compute_deltas(&mut votes, 16, &fc.lookup, &balances[..], &balances[..], None);

        // Each block should get exactly one validator's balance.
        for i in 1..=16 {
            assert_eq!(deltas[i], 42);
        }
    }

    #[test]
    fn deltas_move_out_of_tree() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        let mut votes = vec![Vote::default(); 16];
        let mut balances = vec![0u64; 16];

        // Validator 0 moves from root(1) to zero hash (genesis alias).
        votes[0] = Vote { current_root: root(1), next_root: [0u8; 32], next_epoch: 0 };
        balances[0] = 42;

        // Validator 1 moves from root(1) to unknown root.
        votes[1] = Vote { current_root: root(1), next_root: root(99), next_epoch: 0 };
        balances[1] = 42;

        let deltas = compute_deltas(&mut votes, 2, &fc.lookup, &balances[..], &balances[..], None);

        // root(1) should lose both balances.
        assert_eq!(deltas[0], -(42 * 2));
    }

    #[test]
    fn deltas_changing_balances() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);
        fc.on_block(block(1, root(2), root(1), jus, fin));

        let mut votes = vec![Vote::default(); 16];
        let mut old_bal = vec![0u64; 16];
        let mut new_bal = vec![0u64; 16];

        // 16 validators move from root(1) to root(2), balance doubles.
        for i in 0..16 {
            votes[i] = Vote { current_root: root(1), next_root: root(2), next_epoch: 0 };
            old_bal[i] = 42;
            new_bal[i] = 84;
        }

        let deltas = compute_deltas(&mut votes, 16, &fc.lookup, &old_bal[..], &new_bal[..], None);

        // Old balance subtracted from old target, new balance added to new.
        assert_eq!(deltas[0], -(42i64 * 16));
        assert_eq!(deltas[1], 84i64 * 16);
    }

    #[test]
    fn deltas_balance_change_no_vote_change() {
        // Balances change but votes don't — still need deltas.
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        let mut votes = vec![Vote::default(); 16];
        let mut old_bal = vec![0u64; 16];
        let mut new_bal = vec![0u64; 16];

        // Validator already voted for root(1), balance changes.
        votes[0] = Vote { current_root: root(1), next_root: root(1), next_epoch: 0 };
        old_bal[0] = 42;
        new_bal[0] = 84;

        let deltas = compute_deltas(&mut votes, 1, &fc.lookup, &old_bal[..], &new_bal[..], None);

        // Net delta = new - old = +42.
        assert_eq!(deltas[0], 42);
    }

    /// Tiebreaker: equal-weight siblings → higher block root wins (spec: >=).
    #[test]
    fn split_tie_breaker_no_attestations() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        // Two blocks at slot 1 forking from genesis. root(2) < root(3).
        fc.on_block(block(1, root(2), root(1), jus, fin));
        fc.on_block(block(1, root(3), root(1), jus, fin));

        // No weight applied → both have weight 0. Higher root wins.
        assert_eq!(fc.find_head(), root(3));
    }

    /// Shorter chain with more attestation weight beats a longer chain.
    #[test]
    fn shorter_chain_but_heavier_weight() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        // Long chain: root(1) → root(2) → root(3) → root(4).
        fc.on_block(block(1, root(2), root(1), jus, fin));
        fc.on_block(block(2, root(3), root(2), jus, fin));
        fc.on_block(block(3, root(4), root(3), jus, fin));

        // Short chain: root(1) → root(5).
        fc.on_block(block(1, root(5), root(1), jus, fin));

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
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        fc.on_block(block(1, root(2), root(1), jus, fin));
        assert_eq!(fc.nodes.len(), 2);

        fc.on_block(block(1, root(2), root(1), jus, fin));
        assert_eq!(fc.nodes.len(), 2); // no change
    }

    /// Unknown parent → node still inserted (parent = NULL).
    #[test]
    fn on_block_unknown_parent() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);

        // root(99) is not known.
        fc.on_block(block(1, root(2), root(99), jus, fin));
        assert_eq!(fc.nodes.len(), 2);
        assert_eq!(fc.nodes[1].parent, NULL);
    }

    /// `NodeLookup` resolves every node, misses unknown/zero roots, and stays
    /// correct after a prune rebuild.
    #[test]
    fn node_lookup_equivalence_and_prune() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);
        for i in 2..=20u8 {
            fc.on_block(block(i as u64, root(i), root(i - 1), jus, fin));
        }
        for (i, n) in fc.nodes.iter().enumerate() {
            assert_eq!(fc.find_node_idx(&n.block_root), Some(i));
        }
        assert_eq!(fc.find_node_idx(&root(99)), None);
        assert_eq!(fc.find_node_idx(&[0u8; 32]), None);

        fc.finalized_checkpoint = cp(1, 10);
        fc.prune();
        assert_eq!(fc.nodes[0].block_root, root(10));
        for (i, n) in fc.nodes.iter().enumerate() {
            assert_eq!(fc.find_node_idx(&n.block_root), Some(i));
        }
    }

    /// Proposer boost flips the head onto a lighter sibling, then expires on
    /// the next pass once `proposer_boost_root` is zeroed (boost netted
    /// out).
    #[test]
    fn proposer_boost_flips_then_expires() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);
        fc.on_block(block(1, root(2), root(1), jus, fin)); // idx 1
        fc.on_block(block(1, root(3), root(1), jus, fin)); // idx 2

        // root(3) is the heavier (vote-weighted) sibling.
        let mut deltas = [0i64; MAX_FORK_CHOICE_NODES];
        deltas[2] = 100;
        fc.apply_score_changes(&mut deltas);
        assert_eq!(fc.find_head(), root(3));

        // Boost root(2) above root(3): head flips.
        fc.proposer_boost_root = root(2);
        fc.proposer_boost_score = 150;
        fc.apply_score_changes(&mut [0i64; MAX_FORK_CHOICE_NODES]);
        assert_eq!(fc.find_head(), root(2));

        // Next slot zeroes the boost root: the applied boost is subtracted and
        // the head reverts to the vote-heavier sibling.
        fc.proposer_boost_root = [0u8; 32];
        fc.apply_score_changes(&mut [0i64; MAX_FORK_CHOICE_NODES]);
        assert_eq!(fc.find_head(), root(3));
    }

    /// Dirty-only `compute_deltas` reproduces the full-pass result when the
    /// balance snapshot is unchanged (stable votes contribute nothing either
    /// way; only moved votes count).
    #[test]
    fn compute_deltas_dirty_matches_full() {
        let fin = cp(0, 1);
        let jus = cp(0, 1);
        let mut fc = ForkChoice::init(fin, jus, 0, root(1), root(1), [0u8; 32], test_state_id(), 0);
        for i in 2..=5u8 {
            fc.on_block(block(1, root(i), root(1), jus, fin));
        }

        let bal = vec![10u64; 32];
        let mut votes_full = vec![Vote::default(); 32];
        let mut dirty = Vec::new();
        for (i, v) in votes_full.iter_mut().enumerate() {
            let r = root(2 + (i % 4) as u8);
            if i % 2 == 0 {
                // Moved vote (dirty).
                *v = Vote { current_root: [0u8; 32], next_root: r, next_epoch: 0 };
                dirty.push(i as u32);
            } else {
                // Stable vote — full pass skips it (current == next, equal bal).
                *v = Vote { current_root: r, next_root: r, next_epoch: 0 };
            }
        }
        let mut votes_dirty = votes_full.clone();

        let d_full = compute_deltas(&mut votes_full, 32, &fc.lookup, &bal, &bal, None);
        let d_dirty = compute_deltas(&mut votes_dirty, 32, &fc.lookup, &bal, &bal, Some(&dirty));
        assert_eq!(d_full, d_dirty);
        for i in 0..32 {
            assert_eq!(votes_full[i].current_root, votes_dirty[i].current_root);
        }
    }
}
