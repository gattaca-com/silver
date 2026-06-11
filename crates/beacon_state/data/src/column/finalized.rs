use std::io::{self, Write};

use super::{ColumnVal, delta::ColumnDelta};
use crate::ColumnLenMismatch;

/// Sized to validator capacity; `count` is the finalized list length (kept in
/// lockstep with the validator registry).
pub struct FinalizedColumn<V> {
    data: Box<[V]>,
    count: usize,
}

impl<V: ColumnVal> FinalizedColumn<V> {
    /// Base decoded from the column's SSZ byte range (`count` little-endian
    /// values) over a `cap`-sized buffer; `new(cap, 0, &[])` is the empty base.
    pub(super) fn new(
        cap: usize,
        count: usize,
        ssz_bytes: &[u8],
    ) -> Result<Self, ColumnLenMismatch> {
        if ssz_bytes.len() != count * V::SIZE {
            return Err(ColumnLenMismatch { bytes: ssz_bytes.len(), expected: count });
        }
        debug_assert!(count <= cap, "column count exceeds capacity");
        let mut data = vec![V::APPENDED_DEFAULT; cap].into_boxed_slice();
        V::read_ssz_slice(&mut data[..count], ssz_bytes);
        Ok(Self { data, count })
    }

    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        V::write_ssz_slice(&self.data[..self.count], w)
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    #[inline]
    pub fn get(&self, i: usize) -> V {
        self.data[i]
    }

    #[inline]
    pub(super) fn data(&self) -> &[V] {
        &self.data
    }

    /// Fold a fork's edits into the base, then adopt its length — the data
    /// half of finalization.
    pub(super) fn promote(&mut self, delta: &ColumnDelta<V>) {
        for &(idx, v) in delta.edits() {
            self.data[idx as usize] = v;
        }
        self.count = delta.total();
    }
}
