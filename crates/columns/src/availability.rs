use std::time::{Duration, Instant};

use silver_common::{Wheel, ssz_view::NUMBER_OF_COLUMNS};

use crate::BlockRoot;

#[derive(Clone, Copy)]
struct Custody(u128);

impl Custody {
    fn contains_any(self, columns: u128) -> bool {
        self.0 & columns != 0
    }

    fn is_covered_by(self, validated: u128) -> bool {
        validated & self.0 == self.0
    }

    fn missed_from_custody(self, validated: u128) -> u128 {
        self.0 & !validated
    }

    /// Any half of the column set recovers the other half, so a node holding
    /// that many can declare the data available before its own set is complete.
    fn data_available(self, validated: u128) -> bool {
        validated.count_ones() as usize >= NUMBER_OF_COLUMNS / 2 || self.is_covered_by(validated)
    }
}

#[derive(Default)]
struct BlockColumns {
    /// Columns of this block that passed KZG validation here.
    validated: u128,
    /// Proposer signature already BLS-verified for this block root. The root
    /// does not pin the signature, so the memo hits only on bytes-equality.
    signature: Option<[u8; 96]>,
}

/// Which columns this node has for each block it still tracks, plus the custody
/// set it is required to keep. Every question needs both — which columns to ask
/// for next, and whether the custody set is complete — so they live together.
pub(crate) struct ColumnTracker {
    custody: Custody,
    blocks: Wheel<BlockRoot, BlockColumns, 4>,
}

impl ColumnTracker {
    pub(crate) fn new(custody_columns: u128, retention: Duration) -> Self {
        Self { custody: Custody(custody_columns), blocks: Wheel::new(retention) }
    }

    /// Returns `(data_available, custody_complete)` edges — each true only on
    /// the call that crosses its threshold, so both fire once per block.
    pub(crate) fn record(&mut self, root: BlockRoot, columns: u128) -> (bool, bool) {
        let custody = self.custody;
        let block = self.blocks.entry(root).or_default();
        let before = block.validated;
        block.validated |= columns;
        (
            !custody.data_available(before) && custody.data_available(block.validated),
            !custody.is_covered_by(before) && custody.is_covered_by(block.validated),
        )
    }

    /// Custody columns not yet validated for `root` — what a chase should ask
    /// for.
    pub(crate) fn to_request(&self, root: &BlockRoot) -> u128 {
        self.custody.missed_from_custody(self.validated(root))
    }

    pub(crate) fn custody_complete(&self, root: &BlockRoot) -> bool {
        self.custody.is_covered_by(self.validated(root))
    }

    /// Whether any of `columns` is ours to keep.
    pub(crate) fn wants(&self, columns: u128) -> bool {
        self.custody.contains_any(columns)
    }

    pub(crate) fn has_any(&self, root: &BlockRoot, columns: u128) -> bool {
        self.blocks.get(root).is_some_and(|b| b.validated & columns != 0)
    }

    pub(crate) fn signature_verified(&self, root: &BlockRoot, signature: &[u8; 96]) -> bool {
        self.blocks.get(root).is_some_and(|b| b.signature.as_ref() == Some(signature))
    }

    pub(crate) fn set_signature(&mut self, root: BlockRoot, signature: [u8; 96]) {
        self.blocks.entry(root).or_default().signature = Some(signature);
    }

    pub(crate) fn maybe_rotate(&mut self, now: Instant) {
        self.blocks.maybe_rotate(now);
    }

    fn validated(&self, root: &BlockRoot) -> u128 {
        self.blocks.get(root).map_or(0, |b| b.validated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HALF: usize = NUMBER_OF_COLUMNS / 2;
    const ROOT: BlockRoot = [1; 32];

    fn column(i: usize) -> u128 {
        1u128 << i
    }

    fn tracker(custody: u128) -> ColumnTracker {
        ColumnTracker::new(custody, Duration::from_secs(60))
    }

    #[test]
    fn supernode_declares_data_at_half_and_custody_at_all() {
        let mut tracker = tracker(u128::MAX);
        let edges: Vec<_> = (0..NUMBER_OF_COLUMNS)
            .map(|i| (i, tracker.record(ROOT, column(i))))
            .filter(|(_, edges)| *edges != (false, false))
            .collect();
        assert_eq!(edges, vec![(HALF - 1, (true, false)), (NUMBER_OF_COLUMNS - 1, (false, true))]);
    }

    #[test]
    fn small_node_declares_both_on_its_last_custody_column() {
        let mut tracker = tracker(column(3) | column(7));
        assert_eq!(tracker.record(ROOT, column(3)), (false, false));
        assert_eq!(tracker.record(ROOT, column(7)), (true, true));
        assert_eq!(tracker.record(ROOT, column(7)), (false, false), "edges fire once");
    }
}
