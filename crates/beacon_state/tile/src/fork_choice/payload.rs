use flux_profiler::timed;
use silver_beacon_state_data::B256;
use tracing::info;

use super::{ExecutionStatus, ForkChoice, NULL, node::PTC_SIZE};

impl ForkChoice {
    #[timed]
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
            if n.parent_ix == NULL {
                break;
            }
            idx = n.parent_ix;
        }
    }

    #[timed]
    pub fn on_payload_invalid(&mut self, block_root: &B256, latest_valid_hash: &B256) {
        let Some(head_idx) = self.find_node_idx(block_root) else {
            return;
        };

        if self.nodes[head_idx].payload.is_gloas {
            self.nodes[head_idx].execution_status = ExecutionStatus::Invalid;
            self.nodes[head_idx].full.best_child = NULL;
            self.nodes[head_idx].full.best_desc = NULL;
            return;
        }

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

    pub fn mark_payload_verified(&mut self, block_root: &B256) {
        if let Some(idx) = self.find_node_idx(block_root) {
            self.nodes[idx].payload.verified = true;
        }
    }

    pub fn record_ptc_vote(&mut self, block_root: &B256, ptc_idx: usize, present: bool, da: bool) {
        let Some(idx) = self.find_node_idx(block_root) else {
            return;
        };
        if ptc_idx >= PTC_SIZE {
            return;
        }
        self.nodes[idx].ptc.record(ptc_idx, present, da);
    }

    #[cfg(feature = "ef_tests")]
    pub fn ptc_timeliness_votes(&self, block_root: &B256) -> [Option<bool>; PTC_SIZE] {
        match self.find_node_idx(block_root) {
            Some(idx) => self.nodes[idx].ptc.timeliness(),
            None => [None; PTC_SIZE],
        }
    }

    #[cfg(feature = "ef_tests")]
    pub fn ptc_data_availability_votes(&self, block_root: &B256) -> [Option<bool>; PTC_SIZE] {
        match self.find_node_idx(block_root) {
            Some(idx) => self.nodes[idx].ptc.availability(),
            None => [None; PTC_SIZE],
        }
    }
}
