mod delta;
mod finalized;
mod group;
mod hasher;
#[cfg(test)]
mod tests;

pub use delta::{PendingView, PendingWriteView, QueueView, QueueWriteView};
pub use finalized::QueueItem;
use flux_profiler::timed;
use group::QueueGroup;

use crate::{
    gloas::BuilderPendingWithdrawal,
    ring::Id,
    types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
};

type DepositsGroup = QueueGroup<PendingDeposit>;
type PartialWithdrawalsGroup = QueueGroup<PendingPartialWithdrawal>;
type ConsolidationsGroup = QueueGroup<PendingConsolidation>;
type BuilderWithdrawalsGroup = QueueGroup<BuilderPendingWithdrawal>;

/// A fork's id across the four pending queues — one isolated ring id each.
/// The queues roll in lockstep (the holder fans every roll out to all four),
/// so the bundle threads through the state as a single `pending_idx`.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct PendingId {
    pub(crate) deposits: Id<DepositsGroup>,
    pub(crate) partial_withdrawals: Id<PartialWithdrawalsGroup>,
    pub(crate) consolidations: Id<ConsolidationsGroup>,
    pub(crate) builder_withdrawals: Id<BuilderWithdrawalsGroup>,
}

/// Holder of the four isolated pending-queue groups. Each queue is a
/// self-contained [`QueueGroup`] (own base, delta ring, persist lock); the
/// holder fans `view`/`roll`/`finalize` out to all four and bundles their ids.
/// `builder_withdrawals` is empty pre-Gloas.
pub struct PendingGroup {
    pub(crate) deposits: DepositsGroup,
    pub(crate) partial_withdrawals: PartialWithdrawalsGroup,
    pub(crate) consolidations: ConsolidationsGroup,
    pub(crate) builder_withdrawals: BuilderWithdrawalsGroup,
}

impl PendingGroup {
    /// Build from the four queues' SSZ byte ranges (validated by the caller);
    /// empty ranges yield empty queues.
    pub fn from_ssz(
        deposits: &[u8],
        partial_withdrawals: &[u8],
        consolidations: &[u8],
        builder_withdrawals: &[u8],
    ) -> Self {
        Self {
            deposits: QueueGroup::from_ssz(deposits),
            partial_withdrawals: QueueGroup::from_ssz(partial_withdrawals),
            consolidations: QueueGroup::from_ssz(consolidations),
            builder_withdrawals: QueueGroup::from_ssz(builder_withdrawals),
        }
    }

    pub fn mark_gloas_base(&mut self) {
        self.deposits.mark_gloas_base();
        self.partial_withdrawals.mark_gloas_base();
        self.consolidations.mark_gloas_base();
        self.builder_withdrawals.mark_gloas_base();
    }

    #[inline]
    pub fn view(&self, id: PendingId) -> PendingView<'_> {
        PendingView {
            deposits: self.deposits.view(id.deposits),
            partial_withdrawals: self.partial_withdrawals.view(id.partial_withdrawals),
            consolidations: self.consolidations.view(id.consolidations),
            builder_withdrawals: self.builder_withdrawals.view(id.builder_withdrawals),
        }
    }

    #[inline]
    pub fn roll_fresh(&mut self) -> PendingWriteView<'_> {
        PendingWriteView {
            deposits: self.deposits.roll_fresh(),
            partial_withdrawals: self.partial_withdrawals.roll_fresh(),
            consolidations: self.consolidations.roll_fresh(),
            builder_withdrawals: self.builder_withdrawals.roll_fresh(),
        }
    }

    #[inline]
    pub fn roll_from(&mut self, parent: PendingId) -> PendingWriteView<'_> {
        PendingWriteView {
            deposits: self.deposits.roll_from(parent.deposits),
            partial_withdrawals: self.partial_withdrawals.roll_from(parent.partial_withdrawals),
            consolidations: self.consolidations.roll_from(parent.consolidations),
            builder_withdrawals: self.builder_withdrawals.roll_from(parent.builder_withdrawals),
        }
    }

    /// Finalize all four queues against the promoted `winner` and bundle the
    /// re-anchored ids 1:1 with `survivors` (each queue's `finalize` preserves
    /// order, so the zip stays aligned).
    #[timed]
    pub fn finalize(&mut self, winner: PendingId, survivors: &[PendingId]) -> Vec<PendingId> {
        let dep_ids = survivors.iter().map(|s| s.deposits).collect::<Vec<_>>();
        let pw_ids = survivors.iter().map(|s| s.partial_withdrawals).collect::<Vec<_>>();
        let cons_ids = survivors.iter().map(|s| s.consolidations).collect::<Vec<_>>();
        let bw_ids = survivors.iter().map(|s| s.builder_withdrawals).collect::<Vec<_>>();

        let deposits = self.deposits.finalize(winner.deposits, &dep_ids);
        let partial_withdrawals =
            self.partial_withdrawals.finalize(winner.partial_withdrawals, &pw_ids);
        let consolidations = self.consolidations.finalize(winner.consolidations, &cons_ids);
        let builder_withdrawals =
            self.builder_withdrawals.finalize(winner.builder_withdrawals, &bw_ids);

        deposits
            .into_iter()
            .zip(partial_withdrawals)
            .zip(consolidations)
            .zip(builder_withdrawals)
            .map(|(((deposits, partial_withdrawals), consolidations), builder_withdrawals)| {
                PendingId { deposits, partial_withdrawals, consolidations, builder_withdrawals }
            })
            .collect()
    }
}
