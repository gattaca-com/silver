//! Balances group: the value array + merkle tree are coupled in one finalized
//! state ([`FinalizedBalances`]) and one per-fork delta ([`BalancesDelta`]);
//! the read view ([`BalancesView`]) exposes only the value side.
//! [`BalancesGroup`] owns the finalized state plus the delta ring — the
//! isolated, slot-cadence balances unit.

mod delta;
mod finalized;

#[cfg(test)]
mod tests;

// Not exported: the per-fork delta is an internal detail. The ring holds it,
// but all access flows through the read/write views above.
use delta::BalancesDelta;
pub use delta::{BalancesReader, BalancesView, BalancesWriteView};
pub use finalized::FinalizedBalances;

use crate::{
    buffer::{Id, Ring, reanchor_survivors},
    types::{B256, ColumnLenMismatch, SLOTS_RING_N},
};

/// Typed ring-slot handle into a [`BalancesGroup`] (see [`Id`]).
pub type BalancesId = Id<BalancesGroup>;

/// SSZ-pack four little-endian `u64`s into one 32-byte chunk leaf — the leaf
/// granularity for `List[uint64]` (4 elements share one merkle leaf).
fn pack_chunk(vals: [u64; 4]) -> B256 {
    let mut leaf = [0u8; 32];
    for (lane, v) in vals.iter().enumerate() {
        leaf[lane * 8..lane * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    leaf
}

pub struct BalancesGroup {
    finalized: FinalizedBalances,
    deltas: Ring<Self, BalancesDelta, SLOTS_RING_N>,
}

impl BalancesGroup {
    /// The finalized state (checkpoint encoding).
    #[inline]
    pub(crate) fn finalized(&self) -> &FinalizedBalances {
        &self.finalized
    }

    /// Group over a finalized state decoded from the SSZ `balances` byte range
    /// (little-endian `u64`s), merkle tree included; `new(cap, 0, &[])` is the
    /// empty group.
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self {
            finalized: FinalizedBalances::new(cap, count, ssz_bytes)?,
            deltas: Ring::default(),
        })
    }

    /// Read-only (writer-side) view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: BalancesId) -> BalancesReader<'_> {
        BalancesReader::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> BalancesWriteView<'_> {
        let Self { finalized, deltas } = self;
        let mut fork = deltas.roll_fresh();
        fork.anchor_at(finalized);
        BalancesWriteView::new(finalized, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: BalancesId) -> BalancesWriteView<'_> {
        let Self { finalized, deltas } = self;
        BalancesWriteView::new(finalized, deltas.roll_from(parent))
    }

    fn reanchor(&mut self, survivor: BalancesId, winner: BalancesId) -> BalancesWriteView<'_> {
        let Self { finalized, deltas } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut fork, finalized, winner_delta);
        BalancesWriteView::new(finalized, fork)
    }

    pub fn finalize(&mut self, winner: BalancesId, survivors: &[BalancesId]) -> Vec<BalancesId> {
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh = reanchor_survivors(survivors, |s| self.reanchor(s, winner).commit());

        let Self { finalized, deltas } = self;
        deltas.get(winner).promote_into_base(finalized);

        deltas.free_outdated(&fresh);

        fresh
    }
}
