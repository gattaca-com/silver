use silver_ssz::scalar::SszScalar;

use super::{
    format::{SEG_OFF, TreeFormat, gloas_last_seg_for_chunks},
    fulu::FuluTree,
    store::NodeStore,
    subtree::{NodeRange, build_subtree_hashes, rehash_subtree},
};
use crate::{
    merkle::ZERO_HASHES,
    progressive::{PROGRESSIVE_SEGMENT_START, progressive_segment_of_chunk},
    types::B256,
};

pub(super) struct GloasTree {
    pub(super) store: NodeStore,
    pub(super) last_seg: u32,
}

impl GloasTree {
    pub(super) fn from_leaves<V: SszScalar>(
        cap: usize,
        count: usize,
        leaves: impl Iterator<Item = B256>,
    ) -> Self {
        let last_seg = gloas_last_seg_for_chunks(cap.div_ceil(V::VALS_PER_CHUNK).max(1));
        let format = TreeFormat::Gloas { last_seg };
        let store = NodeStore::with_leaves(format.num_nodes(), count, format.data_start(), leaves);
        let mut tree = Self { store, last_seg };
        tree.rebuild_segments(count.div_ceil(V::VALS_PER_CHUNK));
        tree
    }

    fn rebuild_segments(&mut self, non_zero_chunks: usize) {
        let data_start = self.format().data_start();
        let (internals, data) = self.store.nodes.split_at_mut(data_start);
        for k in 0..=self.last_seg as usize {
            build_segment(internals, data, k, non_zero_chunks);
        }
    }

    pub(super) fn from_fulu<V: SszScalar>(fulu: &FuluTree) -> Self {
        debug_assert!(fulu.store.dirty_chunks.is_empty(), "unhashed batch pending at migration",);
        let count = fulu.store.count;
        let chunks = count.div_ceil(V::VALS_PER_CHUNK);
        let leaves =
            fulu.store.nodes[fulu.max_elements..fulu.max_elements + chunks].iter().copied();
        let mut tree = Self::from_leaves::<V>(fulu.max_elements * V::VALS_PER_CHUNK, count, leaves);
        tree.store.mark_all_dirty();
        tree
    }

    #[inline]
    pub(super) fn format(&self) -> TreeFormat {
        TreeFormat::Gloas { last_seg: self.last_seg }
    }

    pub(super) fn rehash(&mut self) {
        let data_start = self.format().data_start();
        let NodeStore { nodes, dirty_chunks, .. } = &mut self.store;
        let (internals, data) = nodes.split_at_mut(data_start);
        let mut start = 0;
        while start < dirty_chunks.len() {
            let k = progressive_segment_of_chunk(dirty_chunks[start].start as usize) as usize;
            let seg_start = PROGRESSIVE_SEGMENT_START[k];
            let seg_end = PROGRESSIVE_SEGMENT_START[k + 1] as u32;
            let end = start + dirty_chunks[start..].partition_point(|r| r.start < seg_end);

            // The last range may spill into the next segment, so cut it at the
            // boundary and hash only the head here. The tail goes back into the
            // head's slot afterwards, where the next pass picks it up as its
            // own first range.
            let tail = (dirty_chunks[end - 1].end > seg_end).then(|| {
                let tail = NodeRange { start: seg_end, end: dirty_chunks[end - 1].end };
                dirty_chunks[end - 1].end = seg_end;
                tail
            });

            for r in &mut dirty_chunks[start..end] {
                r.start -= seg_start as u32;
                r.end -= seg_start as u32;
            }
            rehash_subtree(
                &mut internals[SEG_OFF[k]..SEG_OFF[k] + (1 << (2 * k))],
                &data[seg_start..],
                &mut dirty_chunks[start..end],
            );
            start = end;
            if let Some(tail) = tail {
                start -= 1;
                dirty_chunks[start] = tail;
            }
        }
        dirty_chunks.clear();
    }

    pub(super) fn fill_zero(&mut self) {
        let data_start = self.format().data_start();
        self.store.nodes[data_start..].fill(ZERO_HASHES[0]);
        self.rebuild_segments(0);
    }

    pub(super) fn append_progressive_segment(&mut self) {
        let old = self.format();
        self.last_seg += 1;
        let new = self.format();

        self.store.nodes.resize(new.num_nodes(), [0u8; 32]);
        self.store.nodes.copy_within(
            old.data_start()..old.data_start() + old.data_capacity(),
            new.data_start(),
        );

        let (internals, data) = self.store.nodes.split_at_mut(new.data_start());
        build_segment(internals, data, self.last_seg as usize, 0);
        self.store.mark_all_dirty();
    }
}

fn build_segment(internals: &mut [B256], data: &[B256], k: usize, non_zero_chunks: usize) {
    let seg_chunks = 1usize << (2 * k);
    let seg_start = PROGRESSIVE_SEGMENT_START[k];
    let non_zero = non_zero_chunks.saturating_sub(seg_start).min(seg_chunks);
    build_subtree_hashes(
        &mut internals[SEG_OFF[k]..SEG_OFF[k] + seg_chunks],
        &data[seg_start..],
        non_zero,
    );
}

#[cfg(test)]
mod tests;
