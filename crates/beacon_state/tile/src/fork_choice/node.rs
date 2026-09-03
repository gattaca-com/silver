use silver_beacon_state_data::{B256, Checkpoint, Slot, StateId};

use super::NULL;

pub(super) const PTC_SIZE: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Optimistic,
    Valid,
    Invalid,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PayloadStatus {
    Pending,
    Empty,
    Full,
}

#[derive(Clone)]
pub struct ForkChoiceNode {
    pub slot: Slot,
    pub block_root: B256,
    pub execution_block_hash: B256,

    pub parent_ix: usize,

    pub execution_status: ExecutionStatus,

    pub state_id: StateId,

    // Total subtree weight = pending + empty.weight + full.weight.
    pub weight: u64,

    pub(super) full: Branch,
    pub(super) empty: Branch,

    pub checkpoints: NodeCheckpoints,
    pub payload: PayloadAxis,
    pub(super) ptc: PtcVotes,
}

impl ForkChoiceNode {
    #[inline]
    pub(super) fn branch(&self, full: bool) -> &Branch {
        if full { &self.full } else { &self.empty }
    }

    #[inline]
    pub(super) fn branch_mut(&mut self, full: bool) -> &mut Branch {
        if full { &mut self.full } else { &mut self.empty }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Branch {
    pub best_child: usize,
    pub best_desc: usize,
    pub weight: u64,
}

impl Branch {
    #[inline]
    pub(super) fn new_leaf(node_idx: usize) -> Self {
        Self { best_child: NULL, best_desc: node_idx, weight: 0 }
    }
}

#[derive(Clone, Copy)]
pub struct NodeCheckpoints {
    pub justified: Checkpoint,
    pub finalized: Checkpoint,
    pub unrealized_justified: Checkpoint,
    pub unrealized_finalized: Checkpoint,
}

/// Pre-Gloas the block itself carries the payload:
/// `parent_status = Full`, `verified = true`, `is_gloas = false`,
/// `bid_block_hash == execution_block_hash`.
#[derive(Clone, Copy)]
pub struct PayloadAxis {
    pub bid_block_hash: B256,
    pub parent_status: PayloadStatus,
    pub verified: bool,
    pub is_gloas: bool,
}

#[derive(Clone, Copy, Default)]
pub(super) struct PtcVotes {
    voted: [u64; 8],
    present: [u64; 8],
    da: [u64; 8],
}

impl PtcVotes {
    #[inline]
    pub(super) fn record(&mut self, idx: usize, present: bool, da: bool) {
        let (w, b) = (idx / 64, idx % 64);
        self.voted[w] |= 1u64 << b;
        if present {
            self.present[w] |= 1u64 << b;
        }
        if da {
            self.da[w] |= 1u64 << b;
        }
    }

    #[inline]
    pub(super) fn record_mask(&mut self, positions: &[u64; 8], present: bool, da: bool) {
        for (word, &positions) in self.voted.iter_mut().zip(positions) {
            *word |= positions;
        }
        if present {
            for (word, &positions) in self.present.iter_mut().zip(positions) {
                *word |= positions;
            }
        }
        if da {
            for (word, &positions) in self.da.iter_mut().zip(positions) {
                *word |= positions;
            }
        }
    }

    #[inline]
    pub(super) fn present_count(&self) -> usize {
        popcount(&self.present)
    }

    #[inline]
    pub(super) fn da_count(&self) -> usize {
        popcount(&self.da)
    }

    #[cfg(any(test, feature = "ef_tests"))]
    pub(super) fn timeliness(&self) -> [Option<bool>; PTC_SIZE] {
        self.optional(&self.present)
    }

    /// Data-availability votes (see `timeliness`).
    #[cfg(any(test, feature = "ef_tests"))]
    pub(super) fn availability(&self) -> [Option<bool>; PTC_SIZE] {
        self.optional(&self.da)
    }

    #[cfg(any(test, feature = "ef_tests"))]
    fn optional(&self, value: &[u64; 8]) -> [Option<bool>; PTC_SIZE] {
        let mut out = [None; PTC_SIZE];
        for (i, slot) in out.iter_mut().enumerate() {
            let (w, b) = (i / 64, i % 64);
            if self.voted[w] & (1u64 << b) != 0 {
                *slot = Some(value[w] & (1u64 << b) != 0);
            }
        }
        out
    }
}

#[inline]
fn popcount(bits: &[u64; 8]) -> usize {
    bits.iter().map(|w| w.count_ones() as usize).sum()
}
