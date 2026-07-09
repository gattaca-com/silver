use std::io::{self, Write};

use super::ColumnVal;
use crate::{
    ColumnLenMismatch,
    buffer::Reset,
    ssz_hash::{ZERO_HASHES, hash_concat, hash_concat_many, mix_in_length},
    types::B256,
};

#[derive(Default)]
pub struct ColumnTree {
    nodes: Vec<B256>,
    max_elements: usize,
    count: usize,
}

impl ColumnTree {
    pub fn new<V: ColumnVal>(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * size_of::<V>() {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        let cap = cap.next_multiple_of(V::VALS_PER_CHUNK);
        let max_elements = (cap / V::VALS_PER_CHUNK).next_power_of_two().max(1);

        let mut nodes = vec![[0u8; 32]; 2 * max_elements];
        nodes[max_elements..].as_flattened_mut()[..ssz_bytes.len()].copy_from_slice(ssz_bytes);

        let mut level = max_elements;
        while level > 1 {
            let parent = level >> 1;
            let (parents, children) = nodes.split_at_mut(level);
            hash_concat_many(&mut parents[parent..level], &children[..level]);
            level = parent;
        }
        Ok(Self { nodes, max_elements, count })
    }

    #[inline]
    pub(super) fn max_elements(&self) -> usize {
        self.max_elements
    }

    pub(super) fn prealloc(&mut self, max_elements: usize) {
        self.nodes = vec![[0u8; 32]; 2 * max_elements];
    }

    #[inline]
    pub fn get<V: ColumnVal>(&self, i: usize) -> V {
        let k = V::VALS_PER_CHUNK;
        V::lane(&self.nodes[self.max_elements + i / k], i % k)
    }

    #[inline]
    pub fn iter<V: ColumnVal>(&self) -> impl Iterator<Item = V> + '_ {
        let k = V::VALS_PER_CHUNK;
        (0..self.count).map(move |i| V::lane(&self.nodes[self.max_elements + i / k], i % k))
    }

    pub fn set_vals<V: ColumnVal>(&mut self, changes: &[(u32, V)]) {
        if changes.is_empty() {
            return;
        }
        debug_assert!(
            changes.windows(2).all(|w| w[0].0 < w[1].0),
            "set_vals needs ascending, distinct indices",
        );
        let k = V::VALS_PER_CHUNK as u32;

        let mut dirty: Vec<u32> = Vec::with_capacity(changes.len());
        for group in changes.chunk_by(|a, b| a.0 / k == b.0 / k) {
            let node = self.max_elements as u32 + group[0].0 / k;
            debug_assert!((node as usize) < 2 * self.max_elements, "index out of range");
            let leaf = &mut self.nodes[node as usize];
            for &(idx, v) in group {
                V::set_lane(leaf, (idx % k) as usize, v);
            }
            dirty.push(node);
        }
        self.rehash(&mut dirty);
    }

    fn rehash(&mut self, dirty: &mut Vec<u32>) {
        let mut level = self.max_elements as u32;
        while level > 1 {
            let mut n = 0;
            for i in 0..dirty.len() {
                let parent = dirty[i] >> 1;
                if n == 0 || dirty[n - 1] != parent {
                    dirty[n] = parent;
                    n += 1;
                }
            }
            dirty.truncate(n);

            let (parents, children) = self.nodes.split_at_mut(level as usize);
            let mut i = 0;
            while i < dirty.len() {
                let start = i;
                while i + 1 < dirty.len() && dirty[i + 1] == dirty[i] + 1 {
                    i += 1;
                }
                i += 1;
                let (lo, hi) = (dirty[start], dirty[i - 1] + 1);
                hash_concat_many(
                    &mut parents[lo as usize..hi as usize],
                    &children[(2 * lo - level) as usize..(2 * hi - level) as usize],
                );
            }
            level >>= 1;
        }
    }

    pub fn append<V: ColumnVal>(&mut self, v: V) -> u32 {
        let idx = self.count as u32;
        self.count += 1;
        debug_assert!(
            self.count <= self.max_elements * V::VALS_PER_CHUNK,
            "append past leaf capacity — cap headroom exhausted",
        );
        self.set_vals(&[(idx, v)]);
        idx
    }

    #[inline]
    pub fn hash_root(&self, list_depth: u32) -> B256 {
        let mut root = self.nodes[1];
        for h in self.max_elements.trailing_zeros()..list_depth {
            root = hash_concat(&root, &ZERO_HASHES[h as usize]);
        }
        mix_in_length(&root, self.count)
    }

    pub fn write_ssz<V: ColumnVal, W: Write>(&self, w: &mut W) -> io::Result<()> {
        let (k, size) = (V::VALS_PER_CHUNK, size_of::<V>());
        let leaves = &self.nodes[self.max_elements..];
        let (full, rem) = (self.count / k, self.count % k);
        w.write_all(leaves[..full].as_flattened())?;
        if rem > 0 {
            w.write_all(&leaves[full][..rem * size])?;
        }
        Ok(())
    }
}

impl Reset for ColumnTree {
    fn reset(&mut self) {
        self.nodes.clear();
        self.max_elements = 0;
        self.count = 0;
    }

    fn reset_from(&mut self, other: &Self) {
        self.nodes.clone_from(&other.nodes);
        self.max_elements = other.max_elements;
        self.count = other.count;
    }
}
