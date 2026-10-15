use std::ops::Range;

use super::{ColumnSpec, format::TreeFormat};
use crate::progressive::PROGRESSIVE_SEGMENT_START;

/// One Merkle tree of a column, cut into pages that forks can share.
///
/// A column's flat tree is one array: internal nodes in heap order, then the
/// leaves. A fixed list is one subtree; a progressive list has one per segment.
/// Each subtree is cut into pages, small mini-trees a commit copies or shares
/// whole. Eight leaves, page size 4:
///
/// ```text
/// flat tree:  _ 1 2 3 4 5 6 7 | 8 9 10 11 12 13 14 15
///             internal nodes  | leaves
///
///       ┌─────────────────────────┐
///       │            1            │      page level 1: the root page
///       │  2                   3  │
///       └──┬───────────────────┬──┘
///     ┌────┴────┐         ┌────┴────┐
/// ┌───┴───┐ ┌───┴───┐ ┌───┴───┐ ┌───┴───┐
/// │   4   │ │   5   │ │   6   │ │   7   │
/// │ 8   9 │ │ 10 11 │ │ 12 13 │ │ 14 15 │ page level 0: the leaf pages
/// └───────┘ └───────┘ └───────┘ └───────┘
///
/// page slots, rows bracketed:
///   root page:  [_ [1] [2 3]]
///   leaf pages: [_ [4] [8 9]]  [_ [5] [10 11]]  [_ [6] [12 13]]  [_ [7] [14 15]]
/// ```
///
/// - Each box is a page: the mini-tree under one node. Slot 1 holds that node,
///   and slot 0 is unused.
/// - A row is a page's nodes on one merkle level, like `[2 3]` or `[8 9]`. It
///   is contiguous in the flat tree too, so a page copies row by row.
/// - Pages are cut from the leaves up, in page levels of equal height. Only the
///   root page can be shorter, when the height does not divide evenly.
/// - A page level spans `log2(page size)` merkle levels. The page size is fixed
///   per column by `ColumnSpec::Page`, so a bigger tree gets more page levels,
///   not taller ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Subtree {
    nodes_start: usize,
    data_start: usize,
    pub(super) height: u32,
    leaves_offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PagePos {
    pub(super) page_level: u32,
    pub(super) index: usize,
}

impl Subtree {
    pub(super) fn of<C: ColumnSpec>(format: TreeFormat, s: usize) -> Self {
        match format {
            TreeFormat::Fixed { max_elements } => Self {
                nodes_start: 0,
                data_start: max_elements,
                height: max_elements.trailing_zeros(),
                leaves_offset: 0,
            },
            TreeFormat::Progressive { .. } => Self {
                nodes_start: C::SEG_OFF[s],
                data_start: format.data_start::<C>(),
                height: 2 * s as u32,
                leaves_offset: PROGRESSIVE_SEGMENT_START[s],
            },
        }
    }

    #[inline]
    fn node(&self, level: u32, pos: usize) -> usize {
        if level == self.height {
            self.data_start + self.leaves_offset + pos
        } else {
            self.nodes_start + (1 << level) + pos
        }
    }

    #[inline]
    pub(super) fn page_levels<C: ColumnSpec>(&self) -> u32 {
        (self.height + 1).div_ceil(levels_per_page::<C>())
    }

    #[inline]
    fn top_level<C: ColumnSpec>(&self, page_level: u32) -> u32 {
        (self.height + 1).saturating_sub((page_level + 1) * levels_per_page::<C>())
    }

    #[inline]
    pub(super) fn rows<C: ColumnSpec>(&self, page_level: u32) -> u32 {
        self.height + 1 - page_level * levels_per_page::<C>() - self.top_level::<C>(page_level)
    }

    #[inline]
    pub(super) fn root<C: ColumnSpec>(&self) -> PagePos {
        PagePos { page_level: self.page_levels::<C>() - 1, index: 0 }
    }

    #[inline]
    pub(super) fn child<C: ColumnSpec>(&self, at: PagePos, j: usize) -> PagePos {
        PagePos {
            page_level: at.page_level - 1,
            index: (at.index << self.rows::<C>(at.page_level)) + j,
        }
    }

    #[inline]
    pub(super) fn child_count<C: ColumnSpec>(&self, at: PagePos) -> usize {
        if at.page_level == 0 { 0 } else { 1 << self.rows::<C>(at.page_level) }
    }

    /// `(flat-tree node, len)` per row of `at`; a row of `len` nodes starts at
    /// page slot `len`.
    pub(super) fn rows_of<C: ColumnSpec>(
        self,
        at: PagePos,
    ) -> impl Iterator<Item = (usize, usize)> {
        let top = self.top_level::<C>(at.page_level);
        (0..self.rows::<C>(at.page_level)).map(move |i| (self.node(top + i, at.index << i), 1 << i))
    }

    #[inline]
    pub(super) fn top_node<C: ColumnSpec>(self, at: PagePos) -> usize {
        self.node(self.top_level::<C>(at.page_level), at.index)
    }

    #[inline]
    pub(super) fn chunks_under<C: ColumnSpec>(self, at: PagePos) -> Range<usize> {
        let width = 1 << (self.height - self.top_level::<C>(at.page_level));
        let start = self.leaves_offset + at.index * width;
        start..start + width
    }

    /// Page slot of node (`level`, `pos`) and the child index to follow at each
    /// page level above it, root first.
    pub(super) fn path_to<C: ColumnSpec>(
        self,
        level: u32,
        pos: usize,
    ) -> (impl Iterator<Item = usize>, usize) {
        let page_level = (self.height - level) / levels_per_page::<C>();
        let page_index = move |b: u32| pos >> (level - self.top_level::<C>(b));
        let children = (page_level + 1..self.page_levels::<C>())
            .rev()
            .map(move |b| page_index(b - 1) - (page_index(b) << self.rows::<C>(b)));
        let i = level - self.top_level::<C>(page_level);
        (children, (1 << i) | (pos & ((1 << i) - 1)))
    }
}

#[inline]
const fn levels_per_page<C: ColumnSpec>() -> u32 {
    C::PAGE_NODES.trailing_zeros()
}

#[cfg(test)]
mod tests;
