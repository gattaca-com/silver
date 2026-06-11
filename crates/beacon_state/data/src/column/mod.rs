mod delta;
mod finalized;

use std::marker::PhantomData;

use delta::ColumnDelta;
pub use delta::{ColumnView, ColumnWriteView};
pub use finalized::FinalizedColumn;

use crate::{
    buffer::{Id, Ring, reanchor_survivors},
    types::{ColumnLenMismatch, SLOTS_RING_N},
};

/// Scalar element of a column: a fixed-size little-endian SSZ value.
pub trait ColumnVal: Copy + PartialEq + 'static {
    const SIZE: usize;
    /// Value of a freshly-appended element (past the finalized state).
    const APPENDED_DEFAULT: Self;

    /// Decode `dst.len()` values from the little-endian SSZ byte range.
    fn read_ssz_slice(dst: &mut [Self], src: &[u8]);

    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()>;
}

impl ColumnVal for u8 {
    const SIZE: usize = 1;
    const APPENDED_DEFAULT: Self = 0;

    fn read_ssz_slice(dst: &mut [Self], src: &[u8]) {
        dst.copy_from_slice(src);
    }

    fn write_ssz_slice<W: std::io::Write>(data: &[Self], w: &mut W) -> std::io::Result<()> {
        w.write_all(data)
    }
}

impl ColumnVal for u64 {
    const SIZE: usize = 8;
    const APPENDED_DEFAULT: Self = 0;

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

/// Marker naming one concrete column: its scalar type plus a distinct
/// identity for the ring ids.
pub trait ColumnSpec: 'static {
    type Val: ColumnVal;
}

/// Column markers — one per column, so sibling ids can't be confused.
pub struct Previous;
impl ColumnSpec for Previous {
    type Val = u8;
}
pub struct Current;
impl ColumnSpec for Current {
    type Val = u8;
}
pub struct Inactivity;
impl ColumnSpec for Inactivity {
    type Val = u64;
}

pub type PreviousParticipationGroup = ColumnGroup<Previous>;
pub type PreviousParticipationId = Id<PreviousParticipationGroup>;
pub type CurrentParticipationGroup = ColumnGroup<Current>;
pub type CurrentParticipationId = Id<CurrentParticipationGroup>;
pub type ParticipationView<'a, M> = ColumnView<'a, M>;
pub type ParticipationWriteView<'a, M> = ColumnWriteView<'a, M>;
pub type FinalizedParticipation = FinalizedColumn<u8>;

pub type InactivityScoresGroup = ColumnGroup<Inactivity>;
pub type InactivityId = Id<InactivityScoresGroup>;
pub type InactivityView<'a> = ColumnView<'a, Inactivity>;
pub type InactivityWriteView<'a> = ColumnWriteView<'a, Inactivity>;
pub type FinalizedInactivityScores = FinalizedColumn<u64>;

pub struct ColumnGroup<C: ColumnSpec> {
    finalized: FinalizedColumn<C::Val>,
    deltas: Ring<Self, ColumnDelta<C::Val>, SLOTS_RING_N>,
    _marker: PhantomData<fn() -> C>,
}

impl<C: ColumnSpec> ColumnGroup<C> {
    #[inline]
    pub(crate) fn finalized(&self) -> &FinalizedColumn<C::Val> {
        &self.finalized
    }

    /// Group over a finalized state decoded from the column's SSZ byte range;
    /// `new(cap, 0, &[])` is the empty group.
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self {
            finalized: FinalizedColumn::new(cap, count, ssz_bytes)?,
            deltas: Ring::default(),
            _marker: PhantomData,
        })
    }

    #[inline]
    pub fn view(&self, id: Id<Self>) -> ColumnView<'_, C> {
        ColumnView::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        ColumnWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: Id<Self>) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        ColumnWriteView::new(finalized, deltas.roll_from(parent))
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot
    /// (pin + prune), pre-promotion. The survivor stays frozen — append-only.
    fn reanchor(&mut self, survivor: Id<Self>, winner: Id<Self>) -> ColumnWriteView<'_, C> {
        let Self { finalized, deltas, .. } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut fork, finalized, winner_delta);
        ColumnWriteView::new(finalized, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped for shared survivors), then promote the winner into the
    /// finalized state.
    pub fn finalize(&mut self, winner: Id<Self>, survivors: &[Id<Self>]) -> Vec<Id<Self>> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas, .. } = self;
        finalized.promote(deltas.get(winner));

        deltas.free_outdated(&fresh);

        fresh
    }
}
