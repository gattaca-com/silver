use flux_profiler::timed;
use silver_beacon_state_data::B256;
use silver_common::ssz_view::BUILDER_EXIT_REQUEST_SIZE;
use silver_log::info;

use super::{ExecutionStatus, ForkChoice, NULL, node::PTC_SIZE};

impl ForkChoice {
    #[timed]
    pub fn on_payload_valid(&mut self, block_root: &B256) {
        let Some(mut idx) = self.find_node_idx(block_root) else {
            return;
        };
        self.head_moved = true;
        loop {
            let n = &mut self.nodes[idx];
            if n.execution_status == ExecutionStatus::Valid {
                break;
            }
            n.execution_status = ExecutionStatus::Valid;
            if n.parent_ix == NULL {
                break;
            }
            idx = n.parent_ix;
        }
    }

    #[timed]
    pub fn on_payload_invalid(&mut self, block_root: &B256, latest_valid_hash: Option<B256>) {
        let Some(head_idx) = self.find_node_idx(block_root) else {
            return;
        };
        self.head_moved = true;

        if self.nodes[head_idx].payload.is_gloas {
            self.nodes[head_idx].execution_status = ExecutionStatus::Invalid;
            self.nodes[head_idx].full.best_child = NULL;
            self.nodes[head_idx].full.best_desc = NULL;
            return;
        }

        let lvh_idx = latest_valid_hash
            .and_then(|hash| self.nodes.iter().position(|n| n.execution_block_hash == hash));

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
            n.full.best_child = NULL;
            n.full.best_desc = NULL;
            n.empty.best_child = NULL;
            n.empty.best_desc = NULL;
            // Unknown ancestor: only `block_root` is provably bad.
            if n.parent_ix == NULL || lvh_idx.is_none() {
                break;
            }
            idx = n.parent_ix;
        }

        // Descendants of an invalid node are invalid. Parents always precede
        // children in `nodes`, so one forward pass suffices.
        for i in 0..self.nodes.len() {
            let p = self.nodes[i].parent_ix;
            if p != NULL && self.nodes[p].execution_status == ExecutionStatus::Invalid {
                let n = &mut self.nodes[i];
                n.execution_status = ExecutionStatus::Invalid;
                n.full.best_child = NULL;
                n.full.best_desc = NULL;
                n.empty.best_child = NULL;
                n.empty.best_desc = NULL;
            }
        }
    }

    pub fn mark_payload_verified(
        &mut self,
        block_root: &B256,
        builder_exits: Box<[[u8; BUILDER_EXIT_REQUEST_SIZE]]>,
    ) {
        if let Some(idx) = self.find_node_idx(block_root) {
            let node = &mut self.nodes[idx];
            node.payload.verified = true;
            node.builder_exits = builder_exits;
            self.head_moved = true;
        }
    }

    /// The node at or above `idx` whose block committed to `block_hash`.
    pub fn payload_owner(&self, mut idx: usize, block_hash: &B256) -> Option<usize> {
        loop {
            let n = &self.nodes[idx];
            if n.payload.bid_block_hash == *block_hash {
                return Some(idx);
            }
            if n.parent_ix == NULL {
                return None;
            }
            idx = n.parent_ix;
        }
    }

    pub fn is_payload_verified(&self, block_root: &B256) -> bool {
        self.find_node_idx(block_root).is_some_and(|idx| self.nodes[idx].payload.verified)
    }

    pub fn record_ptc_vote(&mut self, block_root: &B256, ptc_idx: usize, present: bool, da: bool) {
        let Some(idx) = self.find_node_idx(block_root) else {
            return;
        };
        if ptc_idx >= PTC_SIZE {
            return;
        }
        self.nodes[idx].ptc.record(ptc_idx, present, da);
        self.head_moved = true;
    }

    pub fn record_ptc_votes(
        &mut self,
        block_root: &B256,
        positions: &[u64; PTC_SIZE / 64],
        present: bool,
        da: bool,
    ) {
        let Some(idx) = self.find_node_idx(block_root) else {
            return;
        };
        self.nodes[idx].ptc.record_mask(positions, present, da);
        self.head_moved = true;
    }

    #[cfg(any(test, feature = "ef_tests"))]
    pub fn ptc_timeliness_votes(&self, block_root: &B256) -> [Option<bool>; PTC_SIZE] {
        match self.find_node_idx(block_root) {
            Some(idx) => self.nodes[idx].ptc.timeliness(),
            None => [None; PTC_SIZE],
        }
    }

    #[cfg(any(test, feature = "ef_tests"))]
    pub fn ptc_data_availability_votes(&self, block_root: &B256) -> [Option<bool>; PTC_SIZE] {
        match self.find_node_idx(block_root) {
            Some(idx) => self.nodes[idx].ptc.availability(),
            None => [None; PTC_SIZE],
        }
    }
}
