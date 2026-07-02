use std::io::{self, Write};

use super::ColumnVal;
use crate::{ColumnLenMismatch, hash_tree::FinalizedHashTree, types::B256};

pub struct FinalizedColumn<V> {
    pub(super) data: Box<[V]>,
    pub(super) hash: FinalizedHashTree,
    pub(super) count: usize,
}

impl<V: ColumnVal> FinalizedColumn<V> {
    pub(super) fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * size_of::<V>() {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        let cap = cap.next_multiple_of(V::VALS_PER_CHUNK);
        debug_assert!(count <= cap, "column count exceeds capacity");
        let mut data = vec![V::default(); cap].into_boxed_slice();
        V::read_ssz_slice(&mut data[..count], ssz_bytes);

        let hash = FinalizedHashTree::from_leaves(
            ssz_bytes.chunks(32).map(|src| {
                let mut leaf = [0u8; 32];
                leaf[..src.len()].copy_from_slice(src);
                leaf
            }),
            cap / V::VALS_PER_CHUNK,
        );
        Ok(Self { data, hash, count })
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn get(&self, i: usize) -> V {
        self.data[i]
    }

    /// The packed 32-byte group for `chunk` — its merkle leaf. Lanes past
    /// `count` read the spec-default zeros the base is padded with.
    #[inline]
    pub(super) fn group(&self, chunk: u32) -> B256 {
        let k = V::VALS_PER_CHUNK;
        let b = chunk as usize * k;
        V::pack_leaf(&self.data[b..b + k])
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        V::write_ssz_slice(&self.data[..self.count], w)
    }
}
