mod group;
mod tree;
mod view;

#[cfg(test)]
mod tests;

pub use group::ColumnGroup;
pub use view::{ColumnReader, ColumnWriteView};

use crate::{buffer::Id, types::B256};

/// Scalar element of a column: a fixed-size little-endian SSZ value. Its SSZ
/// byte size equals `size_of::<Self>()` (1 for `u8`, 8 for `u64`).
pub trait ColumnVal: Copy + PartialEq + Default + 'static {
    /// Values SSZ-packed into one 32-byte chunk / merkle leaf (32 for `u8`,
    /// 4 for `u64`).
    const VALS_PER_CHUNK: usize = 32 / size_of::<Self>();

    /// Decode `dst.len()` values from the little-endian SSZ byte range.
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]);

    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()>;

    /// SSZ-pack one chunk's `VALS_PER_CHUNK` values into its 32-byte leaf.
    fn pack_leaf(vals: &[Self]) -> B256 {
        debug_assert_eq!(vals.len(), Self::VALS_PER_CHUNK);
        let mut leaf = [0u8; 32];
        let mut w: &mut [u8] = &mut leaf;
        Self::write_ssz_slice(vals, &mut w).expect("leaf holds exactly one chunk");
        leaf
    }

    fn lane(group: &B256, lane: usize) -> Self {
        let sz = size_of::<Self>();
        let mut out = [Self::default()];
        Self::read_ssz_slice(&mut out, &group[lane * sz..lane * sz + sz]);
        out[0]
    }

    fn set_lane(group: &mut B256, lane: usize, v: Self) {
        let sz = size_of::<Self>();
        let mut w: &mut [u8] = &mut group[lane * sz..lane * sz + sz];
        Self::write_ssz_slice(&[v], &mut w).expect("lane fits its chunk");
    }
}

impl ColumnVal for u8 {
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]) {
        dst.copy_from_slice(src);
    }

    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()> {
        w.write_all(data)
    }
}

impl ColumnVal for u64 {
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]) {
        for (i, slot) in dst.iter_mut().enumerate() {
            *slot = u64::from_le_bytes(src[i * 8..i * 8 + 8].try_into().expect("8-byte window"));
        }
    }

    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()> {
        for v in data {
            w.write_all(&v.to_le_bytes())?;
        }
        Ok(())
    }
}

/// A column's marker: its scalar `Val` plus a distinct type identity, so ring
/// ids of different columns can't be mixed.
pub trait ColumnSpec {
    type Val: ColumnVal;
}

/// Column markers — one zero-sized type per registry-aligned column. Distinct
/// named types (rather than a discriminated `Col<V, ID>`) so ring ids of
/// different columns can't mix *and* `type_name` reads cleanly in perf frames
/// (`Balances`, not `Col<u64, 3>`).
pub struct Previous;
impl ColumnSpec for Previous {
    type Val = u8;
}

pub struct Current;
impl ColumnSpec for Current {
    type Val = u8;
}

pub struct Balances;
impl ColumnSpec for Balances {
    type Val = u64;
}

pub type PreviousParticipationGroup = ColumnGroup<Previous>;
pub type PreviousParticipationId = Id<PreviousParticipationGroup>;

pub type CurrentParticipationGroup = ColumnGroup<Current>;
pub type CurrentParticipationId = Id<CurrentParticipationGroup>;

pub type ParticipationView<'a, M> = ColumnReader<'a, M>;
pub type ParticipationWriteView<'a, M> = ColumnWriteView<'a, M>;

pub type BalancesGroup = ColumnGroup<Balances>;
pub type BalancesId = Id<BalancesGroup>;

pub type BalancesReader<'a> = ColumnReader<'a, Balances>;
pub type BalancesWriteView<'a> = ColumnWriteView<'a, Balances>;
