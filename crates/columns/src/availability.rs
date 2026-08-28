use std::time::{Duration, Instant};

use silver_common::Wheel;

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

    pub(crate) fn record(&mut self, root: BlockRoot, columns: u128) {
        self.blocks.entry(root).or_default().validated |= columns;
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
