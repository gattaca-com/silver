use super::ColumnSpec;
use crate::{
    merkle::{ZERO_HASHES, hash_concat, mix_in_length},
    progressive::{
        PROGRESSIVE_SEGMENT_START, fold_progressive_spine, progressive_segment_of_chunk,
        progressive_segments_for,
    },
    types::B256,
};

pub(super) const MAX_SEGS: usize = 16;

/// Page-aligned offsets of progressive container subtree roots, for a given
/// page size. Only the *values* depend on the column; the length is fixed,
/// which is what keeps this legal as a per-column associated const
/// ([`ColumnSpec::SEG_OFF`]).
pub(super) const fn seg_off(page_nodes: usize) -> [usize; MAX_SEGS + 1] {
    let mut t = [0usize; MAX_SEGS + 1];
    let mut k = 1;
    while k <= MAX_SEGS {
        let region = 1usize << (2 * (k - 1));
        t[k] = t[k - 1] + if region < page_nodes { page_nodes } else { region };
        k += 1;
    }
    t
}

/// Node ids are `u32` (`dirty_chunks`), so the node array must fit `u32`. The
/// deepest segment dominates the sum, so this bounds every page size up to the
/// one asserted here; a column wanting more than 4096 nodes per page has to
/// widen `dirty_chunks` first.
const _: () = assert!(seg_off(4096)[MAX_SEGS] <= u32::MAX as usize);

pub(super) fn progressive_last_seg_for_chunks(cap_chunks: usize) -> u32 {
    progressive_segment_of_chunk(cap_chunks.saturating_sub(1))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeFormat {
    Fixed { max_elements: usize },
    Progressive { last_seg: u32 },
}

impl Default for TreeFormat {
    fn default() -> Self {
        TreeFormat::Fixed { max_elements: 0 }
    }
}

impl TreeFormat {
    #[inline]
    pub(super) fn num_nodes<C: ColumnSpec>(self) -> usize {
        match self {
            TreeFormat::Fixed { max_elements } => 2 * max_elements,
            TreeFormat::Progressive { .. } => self.data_start::<C>() + self.data_capacity(),
        }
    }

    #[inline]
    pub(super) fn data_capacity(self) -> usize {
        match self {
            TreeFormat::Fixed { max_elements } => max_elements,
            TreeFormat::Progressive { last_seg } => {
                PROGRESSIVE_SEGMENT_START[last_seg as usize + 1]
            }
        }
    }

    #[inline]
    pub(super) fn data_start<C: ColumnSpec>(self) -> usize {
        match self {
            TreeFormat::Fixed { max_elements } => max_elements,
            TreeFormat::Progressive { last_seg } => C::SEG_OFF[last_seg as usize + 1],
        }
    }

    #[inline]
    pub(super) fn leaf_pos<C: ColumnSpec>(self, chunk: usize) -> usize {
        self.data_start::<C>() + chunk
    }

    pub(super) fn hash_root<C: ColumnSpec>(
        self,
        count: usize,
        node: impl Fn(usize) -> B256,
    ) -> B256 {
        let vals_per_chunk = C::VALS_PER_CHUNK;
        let root = match self {
            TreeFormat::Fixed { max_elements } => {
                let padded_chunks = C::SSZ_LIMIT.div_ceil(vals_per_chunk).next_power_of_two();
                let mut root = node(1);
                for h in max_elements.trailing_zeros()..padded_chunks.trailing_zeros() {
                    root = hash_concat(&root, &ZERO_HASHES[h as usize]);
                }
                root
            }
            TreeFormat::Progressive { .. } => {
                let num_chunks = count.div_ceil(vals_per_chunk);
                let data_start = self.data_start::<C>();
                fold_progressive_spine(progressive_segments_for(num_chunks), |k| {
                    node(if k == 0 { data_start } else { C::SEG_OFF[k] + 1 })
                })
            }
        };
        if C::IS_LIST { mix_in_length(&root, count) } else { root }
    }
}

#[inline]
pub(super) fn progressive_internal_parent<C: ColumnSpec>(chunk: usize) -> Option<(usize, usize)> {
    let k = progressive_segment_of_chunk(chunk) as usize;
    if k == 0 {
        return None;
    }
    let leaf_local = (1usize << (2 * k)) + (chunk - PROGRESSIVE_SEGMENT_START[k]);
    let seg_off = C::SEG_OFF;
    Some((seg_off[k] + (leaf_local >> 1), seg_off[k]))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct P32;
    impl ColumnSpec for P32 {
        type Val = u64;
        type Page = [B256; 32];
        const SSZ_LIMIT: usize = 8192;
        const IS_LIST: bool = false;
    }
    struct P512;
    impl ColumnSpec for P512 {
        type Val = u64;
        type Page = [B256; 512];
        const SSZ_LIMIT: usize = 8192;
        const IS_LIST: bool = false;
    }

    #[test]
    fn seg_off_page_aligned_and_contiguous() {
        // Block k is `max(4^k, page_nodes)`: segments narrower than a page each
        // round up to one, and from the first segment wider than a page the
        // block is the region itself. Checked across every page size a column
        // may name, so tuning one column cannot break the geometry.
        for page_nodes in [8, 16, 32, 64, 128, 256, 512, 1024] {
            let table = seg_off(page_nodes);
            for k in 0..MAX_SEGS {
                let region = 1usize << (2 * k);
                assert_eq!(table[k] % page_nodes, 0, "P={page_nodes} segment {k} not aligned");
                assert_eq!(
                    table[k + 1] - table[k],
                    region.max(page_nodes),
                    "P={page_nodes} segment {k} block",
                );
            }
        }
    }

    #[test]
    fn seg_off_tracks_the_column_page_size() {
        assert_eq!(P32::PAGE_NODES, 32);
        assert_eq!(P512::PAGE_NODES, 512);
        assert_eq!(P32::SEG_OFF, seg_off(32));
        assert_eq!(P512::SEG_OFF, seg_off(512));
        assert!(
            P32::SEG_OFF[MAX_SEGS] < P512::SEG_OFF[MAX_SEGS],
            "a smaller page must not need a larger node array",
        );
    }

    #[test]
    fn leaf_pos_flat_and_contiguous() {
        let format = TreeFormat::Progressive { last_seg: 5 };
        let data_start = format.data_start::<P32>();
        for chunk in 0..format.data_capacity() {
            assert_eq!(format.leaf_pos::<P32>(chunk), data_start + chunk, "chunk {chunk} not flat");
            assert!(format.leaf_pos::<P32>(chunk) < format.num_nodes::<P32>());
        }
        assert_eq!(data_start, P32::SEG_OFF[6], "data follows the last block");
    }

    #[test]
    fn internal_parent_in_block() {
        let format = TreeFormat::Progressive { last_seg: 5 };
        assert_eq!(
            progressive_internal_parent::<P32>(0),
            None,
            "segment 0 leaf has no internal parent",
        );
        for chunk in 1..format.data_capacity() {
            let k = progressive_segment_of_chunk(chunk) as usize;
            let (parent, off) = progressive_internal_parent::<P32>(chunk).unwrap();
            assert_eq!(off, P32::SEG_OFF[k]);
            let local = parent - off;
            assert!((1 << (2 * k - 1)..1 << (2 * k)).contains(&local), "chunk {chunk} parent");
        }
    }

    #[test]
    fn progressive_capacity_rounds_to_segment_boundary() {
        assert_eq!(progressive_last_seg_for_chunks(1), 0);
        assert_eq!(progressive_last_seg_for_chunks(2), 1);
        assert_eq!(progressive_last_seg_for_chunks(5), 1);
        assert_eq!(progressive_last_seg_for_chunks(6), 2);
        assert_eq!(TreeFormat::Progressive { last_seg: 2 }.data_capacity(), 21);
    }
}
