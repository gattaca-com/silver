use flux_profiler::timed;
use silver_beacon_state_data::{B256, Checkpoint, Epoch, SLOTS_PER_EPOCH, Slot, StateId};

use crate::stf::AttestationVote;

mod head;
mod lookup;
mod node;
mod payload;
#[cfg(test)]
mod tests;
mod vote;

pub use lookup::NodeLookup;
use node::{Branch, NodeCheckpoints, PayloadAxis, PtcVotes};
pub use node::{ExecutionStatus, ForkChoiceNode, PayloadStatus};
pub use vote::{VoteTracker, WeightDelta};

/// Pre-allocation hint only — the node table and the state rings both grow
/// under sustained non-finality.
pub const FORK_CHOICE_NODES_HINT: usize = 256;

pub(super) const NULL: usize = usize::MAX;
pub(super) const GENESIS_EPOCH: Epoch = 0;

pub const PROPOSER_SCORE_BOOST_PERCENT: u64 = 40;

fn proposer_boost_score(total_active_balance: u64) -> u64 {
    (total_active_balance / SLOTS_PER_EPOCH) * PROPOSER_SCORE_BOOST_PERCENT / 100
}

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
    pub(super) applied_boost_root: B256,
    pub(super) applied_boost_score: u64,

    pub vote_tracker: VoteTracker,
    /// Validator indices whose vote moved since the last `recompute_head`.
    pub(super) votes_dirty: Vec<u32>,
    pub(super) equivocating: Box<[u64]>,
    pub(super) pending_votes: Vec<AttestationVote>,

    pub justified_balances: Vec<u64>,
    pub(super) prev_justified_balances: Vec<u64>,
    pub(super) justified_balances_cp: Checkpoint,
    /// Set when a fresh snapshot was installed; arms the next `recompute_head`
    /// as a full pass (every weight may shift), then cleared.
    pub(super) justified_balances_full_pass: bool,
    /// Spec `get_proposer_score` input: total active balance of the justified
    /// state at `justified_balances_cp.epoch`.
    pub(super) justified_total_active_balance: u64,

    pub(super) current_slot: Slot,

    /// `recompute_head` scratch, reused so the per-attestation path stays
    /// allocation-free once warm.
    weight_deltas: Vec<WeightDelta>,
}

pub struct BlockImport {
    pub slot: Slot,
    pub block_root: B256,
    pub parent_root: B256,
    pub execution_block_hash: B256,
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
    pub unrealized_justified: Checkpoint,
    pub unrealized_finalized: Checkpoint,
    pub state_id: StateId,
    pub bid_block_hash: B256,
    pub parent_payload_status: PayloadStatus,
    pub payload_verified: bool,
    pub is_gloas: bool,
}

impl ForkChoice {
    #[allow(clippy::too_many_arguments)]
    pub fn init(
        finalized_checkpoint: Checkpoint,
        justified_checkpoint: Checkpoint,
        finalized_slot: Slot,
        finalized_block_root: B256,
        finalized_execution_block_hash: B256,
        anchor_is_gloas: bool,
        state_id: StateId,
        capacity: usize,
    ) -> Self {
        let mut nodes = Vec::with_capacity(FORK_CHOICE_NODES_HINT);
        let mut lookup = NodeLookup::default();

        nodes.push(ForkChoiceNode {
            slot: finalized_slot,
            block_root: finalized_block_root,
            execution_block_hash: finalized_execution_block_hash,
            parent_ix: NULL,
            execution_status: ExecutionStatus::Valid,
            state_id,
            weight: 0,
            full: Branch::new_leaf(0),
            empty: Branch::new_leaf(0),
            checkpoints: NodeCheckpoints {
                justified: justified_checkpoint,
                finalized: finalized_checkpoint,
                unrealized_justified: justified_checkpoint,
                unrealized_finalized: finalized_checkpoint,
            },
            // A pre-Gloas anchor is fully-resolved (full, verified); a Gloas
            // anchor presents EMPTY (its envelope is not in the store at boot).
            payload: PayloadAxis {
                bid_block_hash: finalized_execution_block_hash,
                parent_status: PayloadStatus::Full,
                verified: !anchor_is_gloas,
                is_gloas: anchor_is_gloas,
            },
            ptc: PtcVotes::default(),
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
            votes_dirty: Vec::with_capacity(capacity),
            equivocating: vec![0u64; capacity.div_ceil(64)].into_boxed_slice(),
            pending_votes: Vec::with_capacity(capacity / SLOTS_PER_EPOCH as usize),
            justified_balances: Vec::with_capacity(capacity),
            prev_justified_balances: Vec::with_capacity(capacity),
            justified_balances_cp: Checkpoint::default(),
            justified_balances_full_pass: false,
            justified_total_active_balance: 0,
            current_slot: 0,
            weight_deltas: Vec::with_capacity(FORK_CHOICE_NODES_HINT),
        }
    }

    #[timed]
    pub fn on_block(&mut self, b: BlockImport) {
        if self.find_node_idx(&b.block_root).is_some() {
            return;
        }

        let node_idx = self.nodes.len();
        let parent = self.find_node_idx(&b.parent_root).unwrap_or(NULL);

        self.nodes.push(ForkChoiceNode {
            slot: b.slot,
            block_root: b.block_root,
            execution_block_hash: b.execution_block_hash,
            parent_ix: parent,
            execution_status: ExecutionStatus::Optimistic,
            state_id: b.state_id,
            weight: 0,
            full: Branch::new_leaf(node_idx),
            empty: Branch::new_leaf(node_idx),
            checkpoints: NodeCheckpoints {
                justified: b.justified,
                finalized: b.finalized,
                unrealized_justified: b.unrealized_justified,
                unrealized_finalized: b.unrealized_finalized,
            },
            payload: PayloadAxis {
                bid_block_hash: b.bid_block_hash,
                parent_status: b.parent_payload_status,
                verified: b.payload_verified,
                is_gloas: b.is_gloas,
            },
            ptc: PtcVotes::default(),
        });
        self.lookup.insert(b.block_root, node_idx);

        // Propagate best-child/best-descendant up to the root so find_head is
        // correct even before apply_score_changes (the new node carries no
        // weight yet; this routes it onto the matching-edge branch of each
        // ancestor).
        let mut child = node_idx;
        let mut ancestor = parent;
        while ancestor != NULL {
            self.maybe_update_best_branch(ancestor, child);
            child = ancestor;
            ancestor = self.nodes[ancestor].parent_ix;
        }
    }

    /// Remove all nodes below the current finalized root. Callers re-anchor
    /// the survivors via `live_state_ids` after pruning.
    #[timed]
    pub fn prune(&mut self) {
        let Some(fin_idx) = self.find_node_idx(&self.finalized_checkpoint.root) else {
            return;
        };
        if fin_idx == 0 {
            return;
        }

        self.nodes.drain(..fin_idx);

        for n in self.nodes.iter_mut() {
            n.parent_ix = offset_idx(n.parent_ix, fin_idx);
            n.full.best_child = offset_idx(n.full.best_child, fin_idx);
            n.full.best_desc = offset_idx(n.full.best_desc, fin_idx);
            n.empty.best_child = offset_idx(n.empty.best_child, fin_idx);
            n.empty.best_desc = offset_idx(n.empty.best_desc, fin_idx);
        }

        self.lookup.clear();
        for i in 0..self.nodes.len() {
            self.lookup.insert(self.nodes[i].block_root, i);
        }
    }

    /// Fold accumulated vote/balance changes into weights and refresh
    /// best_descendant. A fresh balance snapshot (`set_justified_balances`)
    /// arms a full pass; otherwise only the dirtied votes are folded against
    /// the unchanged snapshot.
    #[timed]
    pub fn recompute_head(&mut self) {
        self.compute_weight_deltas();
        self.apply_score_changes();
        self.votes_dirty.clear();
        self.justified_balances_full_pass = false;
    }

    #[inline]
    pub fn find_node_idx(&self, root: &B256) -> Option<usize> {
        self.lookup.get(root)
    }

    #[inline]
    pub fn node(&self, idx: usize) -> &ForkChoiceNode {
        &self.nodes[idx]
    }

    pub fn set_proposer_boost(&mut self, root: B256) {
        self.proposer_boost_root = root;
        self.proposer_boost_score = proposer_boost_score(self.justified_total_active_balance);
    }

    pub fn expire_proposer_boost(&mut self) {
        self.proposer_boost_root = [0u8; 32];
    }

    pub fn lift_justified(&mut self, cp: Checkpoint) {
        if cp.epoch > self.justified_checkpoint.epoch && self.find_node_idx(&cp.root).is_some() {
            self.justified_checkpoint = cp;
        }
    }

    pub fn lift_finalized(&mut self, cp: Checkpoint) {
        if cp.epoch > self.finalized_checkpoint.epoch && self.find_node_idx(&cp.root).is_some() {
            self.finalized_checkpoint = cp;
        }
    }

    pub fn set_current_slot(&mut self, slot: Slot) {
        self.current_slot = slot;
    }

    #[inline]
    pub fn current_epoch(&self) -> Epoch {
        self.current_slot / SLOTS_PER_EPOCH
    }

    pub fn live_state_ids(&self) -> impl Iterator<Item = StateId> + '_ {
        self.nodes.iter().map(|n| n.state_id)
    }
}

#[inline]
fn offset_idx(idx: usize, offset: usize) -> usize {
    if idx == NULL || idx < offset { NULL } else { idx - offset }
}
