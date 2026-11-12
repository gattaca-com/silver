use flux_profiler::timed;
use silver_beacon_state_data::B256;
use silver_log::info;

use super::{ExecutionStatus, ForkChoice, NULL, PayloadStatus, node::PTC_SIZE};

impl ForkChoice {
    #[timed]
    pub fn on_payload_valid(&mut self, block_root: &B256) {
        let Some(idx) = self.find_node_idx(block_root) else {
            return;
        };
        self.head_moved = true;
        self.validate_payload_chain(idx);
    }

    fn validate_payload_chain(&mut self, idx: usize) {
        let mut next = Some(idx);
        while let Some(idx) = next {
            let status = &mut self.nodes[idx].execution_status;
            if *status == ExecutionStatus::Valid {
                break;
            }
            *status = ExecutionStatus::Valid;
            next = self.payload_parent(idx);
        }
    }

    /// The nearest ancestor whose payload this node builds on. An EMPTY edge
    /// skips its parent's payload, so the search continues from the parent.
    fn payload_parent(&self, idx: usize) -> Option<usize> {
        let mut child = &self.nodes[idx];
        while child.parent_ix != NULL {
            if child.payload.parent_status == PayloadStatus::Full {
                return Some(child.parent_ix);
            }
            child = &self.nodes[child.parent_ix];
        }
        None
    }

    pub fn chain_execution_status(&self, idx: usize) -> ExecutionStatus {
        let node = &self.nodes[idx];
        if !node.payload.is_gloas {
            return node.execution_status;
        }
        self.payload_parent(idx).map_or(node.execution_status, |p| self.nodes[p].execution_status)
    }

    #[timed]
    pub fn on_payload_invalid(&mut self, block_root: &B256, latest_valid_hash: Option<B256>) {
        let Some(invalid_idx) = self.find_node_idx(block_root) else {
            return;
        };
        self.head_moved = true;

        // Two branches can carry the same payload, so only an ancestor counts.
        let lvh_idx = latest_valid_hash.and_then(|hash| self.payload_ancestor(invalid_idx, &hash));

        info!(?block_root, ?latest_valid_hash, "payload invalid, marking branch");

        let mut next = Some(invalid_idx);
        while let Some(idx) = next {
            if Some(idx) == lvh_idx {
                self.validate_payload_chain(idx);
                break;
            }
            if self.nodes[idx].execution_status == ExecutionStatus::Valid {
                break;
            }
            self.invalidate_payload(idx);
            // Unknown ancestor: only `block_root` is provably bad.
            if lvh_idx.is_none() {
                break;
            }
            next = self.payload_parent(idx);
        }

        // A payload built on an invalid one is invalid. Parents always precede
        // children in `nodes`, so one forward pass suffices.
        for i in 0..self.nodes.len() {
            if self
                .payload_parent(i)
                .is_some_and(|p| self.nodes[p].execution_status == ExecutionStatus::Invalid)
            {
                self.invalidate_payload(i);
            }
        }
    }

    /// A Gloas block outlives its payload as EMPTY; a pre-Gloas block does not.
    fn invalidate_payload(&mut self, idx: usize) {
        let n = &mut self.nodes[idx];
        n.execution_status = ExecutionStatus::Invalid;
        n.full.best_child = NULL;
        n.full.best_desc = NULL;
        if !n.payload.is_gloas {
            n.empty.best_child = NULL;
            n.empty.best_desc = NULL;
        }
    }

    fn payload_ancestor(&self, idx: usize, block_hash: &B256) -> Option<usize> {
        let mut next = Some(idx);
        while let Some(idx) = next {
            if self.nodes[idx].payload.bid_block_hash == *block_hash {
                return Some(idx);
            }
            next = self.payload_parent(idx);
        }
        None
    }

    pub fn mark_payload_verified(&mut self, block_root: &B256) {
        if let Some(idx) = self.find_node_idx(block_root) {
            self.nodes[idx].payload.verified = true;
            self.head_moved = true;
        }
    }

    /// False for a pre-Gloas block, whose payload has no separate envelope.
    pub fn unmark_payload_verified(&mut self, block_root: &B256) -> bool {
        let Some(idx) = self.find_node_idx(block_root) else { return false };
        if !self.nodes[idx].payload.is_gloas {
            return false;
        }
        self.nodes[idx].payload.verified = false;
        self.head_moved = true;
        true
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

    pub fn is_payload_invalid(&self, block_root: &B256) -> bool {
        self.find_node_idx(block_root)
            .is_some_and(|idx| self.nodes[idx].execution_status == ExecutionStatus::Invalid)
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
