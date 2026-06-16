mod delta;
mod finalized;
mod group;
#[cfg(test)]
mod tests;

pub use delta::{PendingView, PendingWriteView, QueueView, QueueWriteView};
pub use finalized::QueueItem;
use group::QueueGroup;

use crate::{
    buffer::Id,
    types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
};

type DepositsGroup = QueueGroup<PendingDeposit>;
type PartialWithdrawalsGroup = QueueGroup<PendingPartialWithdrawal>;
type ConsolidationsGroup = QueueGroup<PendingConsolidation>;

/// A fork's id across the three pending queues — one isolated ring id each.
/// The queues roll in lockstep (the holder fans every roll out to all three),
/// so the bundle threads through the state as a single `pending_idx`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct PendingId {
    pub(crate) deposits: Id<DepositsGroup>,
    pub(crate) partial_withdrawals: Id<PartialWithdrawalsGroup>,
    pub(crate) consolidations: Id<ConsolidationsGroup>,
}

/// Holder of the three isolated pending-queue groups. Each queue is a
/// self-contained [`QueueGroup`] (own base, delta ring, persist lock); the
/// holder fans `view`/`roll`/`finalize` out to all three and bundles their ids.
pub struct PendingGroup {
    pub(crate) deposits: DepositsGroup,
    pub(crate) partial_withdrawals: PartialWithdrawalsGroup,
    pub(crate) consolidations: ConsolidationsGroup,
}

impl PendingGroup {
    /// Build from the three queues' SSZ byte ranges (validated by the caller);
    /// empty ranges yield empty queues.
    pub fn from_ssz(deposits: &[u8], partial_withdrawals: &[u8], consolidations: &[u8]) -> Self {
        Self {
            deposits: QueueGroup::from_ssz(deposits),
            partial_withdrawals: QueueGroup::from_ssz(partial_withdrawals),
            consolidations: QueueGroup::from_ssz(consolidations),
        }
    }

    #[inline]
    pub fn view(&self, id: PendingId) -> PendingView<'_> {
        PendingView {
            deposits: self.deposits.view(id.deposits),
            partial_withdrawals: self.partial_withdrawals.view(id.partial_withdrawals),
            consolidations: self.consolidations.view(id.consolidations),
        }
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PendingWriteView<'_> {
        PendingWriteView {
            deposits: self.deposits.roll_fresh(),
            partial_withdrawals: self.partial_withdrawals.roll_fresh(),
            consolidations: self.consolidations.roll_fresh(),
        }
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PendingId) -> PendingWriteView<'_> {
        PendingWriteView {
            deposits: self.deposits.roll_from(parent.deposits),
            partial_withdrawals: self.partial_withdrawals.roll_from(parent.partial_withdrawals),
            consolidations: self.consolidations.roll_from(parent.consolidations),
        }
    }

    /// Finalize all three queues against the promoted `winner` and bundle the
    /// re-anchored ids 1:1 with `survivors` (each queue's `finalize` preserves
    /// order, so the zip stays aligned).
    pub fn finalize(&mut self, winner: PendingId, survivors: &[PendingId]) -> Vec<PendingId> {
        let dep_ids = survivors.iter().map(|s| s.deposits).collect::<Vec<_>>();
        let pw_ids = survivors.iter().map(|s| s.partial_withdrawals).collect::<Vec<_>>();
        let cons_ids = survivors.iter().map(|s| s.consolidations).collect::<Vec<_>>();

        let deposits = self.deposits.finalize(winner.deposits, &dep_ids);
        let partial_withdrawals =
            self.partial_withdrawals.finalize(winner.partial_withdrawals, &pw_ids);
        let consolidations = self.consolidations.finalize(winner.consolidations, &cons_ids);

        deposits
            .into_iter()
            .zip(partial_withdrawals)
            .zip(consolidations)
            .map(|((deposits, partial_withdrawals), consolidations)| PendingId {
                deposits,
                partial_withdrawals,
                consolidations,
            })
            .collect()
    }
}
