use std::ops::Range;

use crate::{TreeSpec, flat_hashing::format::TreeFormat, progressive::PROGRESSIVE_SEGMENT_START};

/// One binary subtree of a flat tree, and how it is cut into pages.
///
/// The flat tree is one array: internal nodes in heap order, then the leaves.
/// A fixed list is a single subtree; a progressive list has one per segment.
/// A commit copies or shares each page, a small mini-tree, whole. Eight
/// leaves in pages of four nodes:
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
/// - A box is a page: the mini-tree under one node. That node sits in slot 1;
///   slot 0 is unused.
/// - A row is a page's nodes on one merkle level, like `[2 3]` or `[8 9]`. Rows
///   are contiguous in the flat tree too, so a page copies row by row.
/// - Pages are cut from the leaves up, in page levels of equal height. Only the
///   root page can be shorter, when the height does not divide evenly.
/// - A page level spans `log2(page size)` merkle levels. The page size is fixed
///   per list by `TreeSpec::Page`, so a taller tree gets more page levels, not
///   taller pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Subtree {
    nodes_start: usize,
    data_start: usize,
    pub(super) height: u32,
    leaves_offset: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PagePos {
    pub(super) page_level: u32,
    pub(super) index: usize,
}

impl Subtree {
    pub(crate) fn of<C: TreeSpec>(format: TreeFormat, s: usize) -> Self {
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
    pub(super) fn page_levels<C: TreeSpec>(&self) -> u32 {
        (self.height + 1).div_ceil(levels_per_page::<C>())
    }

    #[inline]
    fn top_level<C: TreeSpec>(&self, page_level: u32) -> u32 {
        (self.height + 1).saturating_sub((page_level + 1) * levels_per_page::<C>())
    }

    #[inline]
    pub(super) fn rows<C: TreeSpec>(&self, page_level: u32) -> u32 {
        self.height + 1 - page_level * levels_per_page::<C>() - self.top_level::<C>(page_level)
    }

    #[inline]
    pub(crate) fn root<C: TreeSpec>(&self) -> PagePos {
        PagePos { page_level: self.page_levels::<C>() - 1, index: 0 }
    }

    #[inline]
    pub(crate) fn child<C: TreeSpec>(&self, at: PagePos, j: usize) -> PagePos {
        PagePos {
            page_level: at.page_level - 1,
            index: (at.index << self.rows::<C>(at.page_level)) + j,
        }
    }

    #[inline]
    pub(crate) fn child_count<C: TreeSpec>(&self, at: PagePos) -> usize {
        if at.page_level == 0 { 0 } else { 1 << self.rows::<C>(at.page_level) }
    }

    /// `(flat-tree node, len)` per row of `at`; a row of `len` nodes starts at
    /// page slot `len`.
    pub(super) fn rows_of<C: TreeSpec>(self, at: PagePos) -> impl Iterator<Item = (usize, usize)> {
        let top = self.top_level::<C>(at.page_level);
        (0..self.rows::<C>(at.page_level)).map(move |i| (self.node(top + i, at.index << i), 1 << i))
    }

    #[inline]
    pub(super) fn top_node<C: TreeSpec>(self, at: PagePos) -> usize {
        self.node(self.top_level::<C>(at.page_level), at.index)
    }

    #[inline]
    pub(super) fn chunks_under<C: TreeSpec>(self, at: PagePos) -> Range<usize> {
        let width = 1 << (self.height - self.top_level::<C>(at.page_level));
        let start = self.leaves_offset + at.index * width;
        start..start + width
    }

    /// Merkle depth of `at`'s top node. Pages are cut from the leaves up, so
    /// the depth also fixes the row count: an all-zero page is the same for
    /// every tree at the same depth.
    #[inline]
    pub(crate) fn depth<C: TreeSpec>(self, at: PagePos) -> u32 {
        self.height - self.top_level::<C>(at.page_level)
    }

    /// Page slot of node (`level`, `pos`) and the child index to follow at each
    /// page level above it, root first.
    pub(crate) fn path_to<C: TreeSpec>(
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
const fn levels_per_page<C: TreeSpec>() -> u32 {
    C::PAGE_NODES.trailing_zeros()
}

#[cfg(test)]
mod tests;
