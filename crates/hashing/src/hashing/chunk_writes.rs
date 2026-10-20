use std::ops::Range;

use crate::hashing::{chunk_bits::ChunkBits, subtree::NodeRange};

/// Chunks written since the last load or commit: a page is dirty iff one of
/// them lies under it. Those not yet rehashed are kept apart, so a rehash
/// visits each write once.
#[derive(Default)]
pub(super) struct ChunkWrites {
    unhashed: ChunkBits,
    hashed: ChunkBits,
    unhashed_ranges: Vec<NodeRange>,
}

impl ChunkWrites {
    #[inline]
    pub(super) fn mark(&mut self, chunk: usize) {
        self.unhashed.mark(chunk);
    }

    /// Marks every chunk as written and already hashed, after a whole-tree
    /// rewrite.
    #[inline]
    pub(super) fn mark_all_hashed(&mut self) {
        self.hashed.mark_all();
    }

    #[inline]
    pub(super) fn has_unhashed(&self) -> bool {
        !self.unhashed.is_empty()
    }

    #[inline]
    pub(super) fn touches(&self, chunks: Range<usize>) -> bool {
        self.unhashed.any_in(chunks.clone()) || self.hashed.any_in(chunks)
    }

    /// The unhashed chunks as sorted, disjoint, maximal ranges; they count as
    /// hashed from here on.
    #[inline]
    pub(super) fn take_unhashed(&mut self) -> &mut [NodeRange] {
        self.unhashed.drain_into(&mut self.hashed, &mut self.unhashed_ranges);
        &mut self.unhashed_ranges
    }

    pub(super) fn resize(&mut self, chunks: usize) {
        self.unhashed.resize(chunks);
        self.hashed.resize(chunks);
    }

    pub(super) fn clear(&mut self) {
        self.unhashed.clear();
        self.hashed.clear();
    }
}
