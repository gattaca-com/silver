//! Whole-tree-per-fork column storage: a 1-indexed flat segment tree
//! (`nodes[1]` root, `left(i)=2i`, `right(i)=2i+1`) whose leaf row
//! `nodes[max_elements..2*max_elements]` holds the SSZ-packed values. The leaf
//! row *is* the data — reads unpack a lane, `set_leaves` writes leaves and
//! recomputes only the touched ancestor path bottom-up. No base+delta split:
//! every fork owns its whole tree, so a ring roll is a memcpy (`Reset`) and
//! finalization is a copy of the winner with no rebase.

use std::io::{self, Write};

use super::ColumnVal;
use crate::{
    ColumnLenMismatch,
    buffer::Reset,
    ssz_hash::{ZERO_HASHES, hash_concat, mix_in_length},
    types::B256,
};

/// A `default()` tree is empty (no allocation) so the ring can pre-build its
/// `N` slots cheaply; a slot allocates its `nodes` only on first `reset_from`.
#[derive(Default)]
pub struct ColumnTree {
    /// 1-indexed flat tree, length `2 * max_elements` (or empty when default).
    /// `nodes[0]` unused, `nodes[1]` the physical root, leaves in
    /// `nodes[max_elements..]`.
    nodes: Vec<B256>,
    /// Power-of-two leaf (chunk) capacity.
    max_elements: usize,
    /// Logical element count; leaves past `count.div_ceil(k)` stay zero.
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
        for (slot, src) in nodes[max_elements..].iter_mut().zip(ssz_bytes.chunks(32)) {
            slot[..src.len()].copy_from_slice(src);
        }
        let mut tree = Self { nodes, max_elements, count };
        tree.rebuild_internals();
        Ok(tree)
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

    /// Current packed leaf for `chunk` — the seed a writer overwrites lanes on.
    #[inline]
    pub fn leaf(&self, chunk: u32) -> &B256 {
        &self.nodes[self.max_elements + chunk as usize]
    }

    /// Write each `(chunk, packed_leaf)` (ascending, distinct chunks) and
    /// recompute every touched ancestor bottom-up: at each layer take the
    /// dirty nodes' parents `n>>1` (a shared parent hashed once), rehash in
    /// place, and carry the parents up as the next layer's dirty set.
    pub fn set_leaves(&mut self, leaves: &[(u32, B256)]) {
        if leaves.is_empty() {
            return;
        }
        debug_assert!(
            leaves.windows(2).all(|w| w[0].0 < w[1].0),
            "set_leaves needs ascending, distinct chunks",
        );
        debug_assert!(
            (leaves.last().unwrap().0 as usize) < self.max_elements,
            "leaf chunk out of range",
        );

        let mut dirty: Vec<u32> = Vec::with_capacity(leaves.len());
        for &(chunk, leaf) in leaves {
            let node = self.max_elements as u32 + chunk;
            self.nodes[node as usize] = leaf;
            dirty.push(node);
        }

        while dirty[0] > 1 {
            let (mut w, mut r) = (0, 0);
            while r < dirty.len() {
                let p = dirty[r] >> 1;
                self.nodes[p as usize] =
                    hash_concat(&self.nodes[(2 * p) as usize], &self.nodes[(2 * p + 1) as usize]);
                dirty[w] = p;
                w += 1;
                r += 1;
                while r < dirty.len() && dirty[r] >> 1 == p {
                    r += 1;
                }
            }
            dirty.truncate(w);
        }
    }

    /// Append a value (+1 length) for a newly-registered validator, returning
    /// its index. The leaf row is sized from a headroomed cap, so appends stay
    /// within it across a finalization window (the base is rebuilt on
    /// decompose).
    pub fn append<V: ColumnVal>(&mut self, v: V) -> u32 {
        let idx = self.count as u32;
        self.count += 1;
        debug_assert!(
            self.count <= self.max_elements * V::VALS_PER_CHUNK,
            "append past leaf capacity — cap headroom exhausted",
        );
        let k = V::VALS_PER_CHUNK as u32;
        let chunk = idx / k;
        let mut leaf = *self.leaf(chunk);
        V::set_lane(&mut leaf, (idx % k) as usize, v);
        self.set_leaves(&[(chunk, leaf)]);
        idx
    }

    /// SSZ `hash_tree_root` for `List[T, 1<<list_depth]`: pad the physical root
    /// with zero subtrees up to `list_depth`, then mix in the element count.
    #[inline]
    pub fn ssz_list_root(&self, list_depth: u32) -> B256 {
        let mut root = self.nodes[1];
        for h in self.max_elements.trailing_zeros()..list_depth {
            root = hash_concat(&root, &ZERO_HASHES[h as usize]);
        }
        mix_in_length(&root, self.count)
    }

    pub fn write_ssz<V: ColumnVal, W: Write>(&self, w: &mut W) -> io::Result<()> {
        // Leaves already hold values SSZ-packed little-endian, so the leaf
        // bytes ARE the encoding — write them straight, trimming the final
        // partial chunk to its used lanes.
        let (k, size) = (V::VALS_PER_CHUNK, size_of::<V>());
        let leaves = &self.nodes[self.max_elements..];
        let (full, rem) = (self.count / k, self.count % k);
        for leaf in &leaves[..full] {
            w.write_all(leaf)?;
        }
        if rem > 0 {
            w.write_all(&leaves[full][..rem * size])?;
        }
        Ok(())
    }

    /// Recompute every internal node from the leaf row, one level at a time.
    /// Hashing a zero subtree yields its `ZERO_HASHES` entry, so unpopulated
    /// leaves need no special-casing. One-off per checkpoint build, so it
    /// favours simplicity over the batched/zero-skip build.
    fn rebuild_internals(&mut self) {
        let mut level = self.max_elements;
        while level > 1 {
            let parent = level >> 1;
            for p in parent..level {
                self.nodes[p] = hash_concat(&self.nodes[2 * p], &self.nodes[2 * p + 1]);
            }
            level = parent;
        }
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
