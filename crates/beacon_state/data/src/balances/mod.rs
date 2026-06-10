//! Balances group: the value array + merkle tree are coupled in one base
//! ([`FinalizedBalances`]) and one per-fork delta ([`BalancesDelta`]); the read
//! view ([`BalancesView`]) exposes only the value side. [`BalancesGroup`] owns
//! the base plus the per-fork ring — the isolated, slot-cadence balances unit.

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
    buffer::{Id, Ring},
    types::{B256, ColumnLenMismatch, SLOTS_RING_N},
};

/// Typed ring-slot handle into a [`BalancesGroup`] (see [`Id`]).
pub type BalancesId = Id<BalancesGroup>;

/// SSZ-pack four little-endian `u64`s into one 32-byte chunk leaf — the leaf
/// granularity for `List[uint64]` (4 elements share one merkle leaf).
fn pack_chunk(vals: [u64; 4]) -> B256 {
    let mut leaf = [0u8; 32];
    for (slot, v) in vals.iter().enumerate() {
        leaf[slot * 8..slot * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    leaf
}

pub struct BalancesGroup {
    base: FinalizedBalances,
    forks: Ring<Self, BalancesDelta, SLOTS_RING_N>,
}

impl BalancesGroup {
    /// The finalized base (checkpoint encoding).
    #[inline]
    pub(crate) fn base(&self) -> &FinalizedBalances {
        &self.base
    }

    /// Group over a base decoded from the SSZ `balances` byte range
    /// (little-endian `u64`s), merkle tree included; `new(cap, &[])` is the
    /// empty group.
    pub fn new(cap: usize, count: usize, ssz_bytes: &[u8]) -> Result<Self, ColumnLenMismatch> {
        Ok(Self { base: FinalizedBalances::new(cap, count, ssz_bytes)?, forks: Ring::default() })
    }

    /// Read-only (writer-side) view over a fork — for the read views.
    #[inline]
    pub fn view(&self, id: BalancesId) -> BalancesReader<'_> {
        BalancesReader::new(&self.base, self.forks.get(id))
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> BalancesWriteView<'_> {
        let Self { base, forks } = self;
        let mut fork = forks.roll_fresh();
        fork.anchor_at(base);
        BalancesWriteView::new(base, fork)
    }

    #[inline]
    pub fn roll_from(&mut self, parent: BalancesId) -> BalancesWriteView<'_> {
        let Self { base, forks } = self;
        BalancesWriteView::new(base, forks.roll_from(parent))
    }

    fn reanchor(&mut self, survivor: BalancesId, winner: BalancesId) -> BalancesWriteView<'_> {
        let Self { base, forks } = self;
        let (mut fork, old, winner_delta) = forks.roll_fresh_deriving(survivor, winner);
        old.rebase_and_prune(&mut fork, base, winner_delta);
        BalancesWriteView::new(base, fork)
    }

    pub fn finalize(&mut self, winner: BalancesId, survivors: &[BalancesId]) -> Vec<BalancesId> {
        let mut fresh: Vec<BalancesId> = Vec::with_capacity(survivors.len());
        for (i, &s) in survivors.iter().enumerate() {
            let new_id = match survivors[..i].iter().position(|&p| p == s) {
                Some(seen) => fresh[seen],
                None => self.reanchor(s, winner).commit(),
            };
            fresh.push(new_id);
        }

        let Self { base, forks } = self;
        forks.get(winner).promote_into_base(base);

        if let Some(&oldest) = fresh.iter().min() {
            forks.free(oldest);
        }

        fresh
    }
}
