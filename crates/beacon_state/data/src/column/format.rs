use super::pool::PAGE_NODES;
use crate::{
    merkle::{ZERO_HASHES, hash_concat, mix_in_length},
    progressive::{
        PROGRESSIVE_SEGMENT_START, fold_progressive_spine, progressive_segment_of_chunk,
        progressive_segments_for,
    },
    types::{B256, VALIDATOR_REGISTRY_LIMIT},
};

pub(super) const MAX_SEGS: usize = 16;

/// Page-aligned offsets of progressive container subtree roots.
pub(super) const SEG_OFF: [usize; MAX_SEGS + 1] = {
    let mut t = [0usize; MAX_SEGS + 1];
    let mut k = 1;
    while k <= MAX_SEGS {
        let region = 1usize << (2 * (k - 1));
        t[k] = t[k - 1] + if region < PAGE_NODES { PAGE_NODES } else { region };
        k += 1;
    }
    t
};

/// Node ids are `u32` (`dirty_chunks`), so the node array must fit `u32`;
const _: () = assert!(SEG_OFF[MAX_SEGS] <= u32::MAX as usize);

pub(super) fn gloas_last_seg_for_chunks(cap_chunks: usize) -> u32 {
    progressive_segment_of_chunk(cap_chunks.saturating_sub(1))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TreeFormat {
    Fulu { max_elements: usize },
    Gloas { last_seg: u32 },
}

impl Default for TreeFormat {
    fn default() -> Self {
        TreeFormat::Fulu { max_elements: 0 }
    }
}

impl TreeFormat {
    pub(super) fn num_nodes(self) -> usize {
        match self {
            TreeFormat::Fulu { max_elements } => 2 * max_elements,
            TreeFormat::Gloas { .. } => self.data_start() + self.data_capacity(),
        }
    }

    pub(super) fn data_capacity(self) -> usize {
        match self {
            TreeFormat::Fulu { max_elements } => max_elements,
            TreeFormat::Gloas { last_seg } => PROGRESSIVE_SEGMENT_START[last_seg as usize + 1],
        }
    }

    #[inline]
    pub(super) fn data_start(self) -> usize {
        match self {
            TreeFormat::Fulu { max_elements } => max_elements,
            TreeFormat::Gloas { last_seg } => SEG_OFF[last_seg as usize + 1],
        }
    }

    #[inline]
    pub(super) fn leaf_pos(self, chunk: usize) -> usize {
        self.data_start() + chunk
    }

    pub(super) fn hash_root(
        self,
        count: usize,
        vals_per_chunk: usize,
        node: impl Fn(usize) -> B256,
    ) -> B256 {
        let root = match self {
            TreeFormat::Fulu { max_elements } => {
                let list_depth = (VALIDATOR_REGISTRY_LIMIT / vals_per_chunk).trailing_zeros();
                let mut root = node(1);
                for h in max_elements.trailing_zeros()..list_depth {
                    root = hash_concat(&root, &ZERO_HASHES[h as usize]);
                }
                root
            }
            TreeFormat::Gloas { .. } => {
                let num_chunks = count.div_ceil(vals_per_chunk);
                let data_start = self.data_start();
                fold_progressive_spine(progressive_segments_for(num_chunks), |k| {
                    node(if k == 0 { data_start } else { SEG_OFF[k] + 1 })
                })
            }
        };
        mix_in_length(&root, count)
    }
}

#[inline]
pub(super) fn gloas_internal_parent(chunk: usize) -> Option<(usize, usize)> {
    let k = progressive_segment_of_chunk(chunk) as usize;
    if k == 0 {
        return None;
    }
    let leaf_local = (1usize << (2 * k)) + (chunk - PROGRESSIVE_SEGMENT_START[k]);
    Some((SEG_OFF[k] + (leaf_local >> 1), SEG_OFF[k]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seg_off_page_aligned_and_contiguous() {
        assert_eq!(&SEG_OFF[..6], &[0, 128, 256, 384, 512, 768]);
        for k in 0..MAX_SEGS {
            assert_eq!(SEG_OFF[k] % PAGE_NODES, 0, "segment {k} not page-aligned");
            assert!(SEG_OFF[k + 1] - SEG_OFF[k] >= 1 << (2 * k), "segment {k} block too small");
        }
    }

    #[test]
    fn leaf_pos_flat_and_contiguous() {
        let format = TreeFormat::Gloas { last_seg: 5 };
        let data_start = format.data_start();
        for chunk in 0..format.data_capacity() {
            assert_eq!(format.leaf_pos(chunk), data_start + chunk, "chunk {chunk} not flat");
            assert!(format.leaf_pos(chunk) < format.num_nodes());
        }
        assert_eq!(data_start, SEG_OFF[6], "data section follows the last block");
    }

    #[test]
    fn internal_parent_in_block() {
        let format = TreeFormat::Gloas { last_seg: 5 };
        assert_eq!(gloas_internal_parent(0), None, "segment 0 leaf has no internal parent");
        for chunk in 1..format.data_capacity() {
            let k = progressive_segment_of_chunk(chunk) as usize;
            let (parent, seg_off) = gloas_internal_parent(chunk).unwrap();
            assert_eq!(seg_off, SEG_OFF[k]);
            let local = parent - seg_off;
            assert!((1 << (2 * k - 1)..1 << (2 * k)).contains(&local), "chunk {chunk} parent");
        }
    }

    #[test]
    fn progressive_capacity_rounds_to_segment_boundary() {
        assert_eq!(gloas_last_seg_for_chunks(1), 0);
        assert_eq!(gloas_last_seg_for_chunks(2), 1);
        assert_eq!(gloas_last_seg_for_chunks(5), 1);
        assert_eq!(gloas_last_seg_for_chunks(6), 2);
        assert_eq!(TreeFormat::Gloas { last_seg: 2 }.data_capacity(), 21);
    }
}
