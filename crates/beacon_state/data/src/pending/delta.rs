use super::{PendingGroup, PendingId, finalized::PendingQueues};
use crate::{
    buffer::{Reset, Slot},
    types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
};

/// One pending queue's per-fork delta: drop the first `drain_offset` entries
/// of the base, then read the remainder followed by `appended`.
#[derive(Clone)]
pub(super) struct QueueDelta<T> {
    drain_offset: u32,
    appended: Vec<T>,
}

// Manual impl: the derive would spuriously bind `T: Default`.
impl<T> Default for QueueDelta<T> {
    fn default() -> Self {
        Self { drain_offset: 0, appended: Vec::new() }
    }
}

impl<T: Clone> QueueDelta<T> {
    /// Effective queue element at `ix`: the base remainder after the drain,
    /// then the appended tail.
    #[inline]
    fn get<'b>(&'b self, base: &'b [T], ix: usize) -> &'b T {
        let drain = self.drain_offset as usize;
        let remaining = base.len().saturating_sub(drain);
        if ix < remaining { &base[drain + ix] } else { &self.appended[ix - remaining] }
    }

    #[inline]
    fn len(&self, base_len: usize) -> usize {
        base_len.saturating_sub(self.drain_offset as usize) + self.appended.len()
    }

    /// Drop the first `n` items from the effective queue: bump `drain_offset`
    /// against the base, then trim `appended`.
    #[inline]
    fn drain(&mut self, base_len: usize, n: usize) {
        let already = self.drain_offset as usize;
        let from_appended = n.saturating_sub(base_len.saturating_sub(already));
        self.drain_offset += (n - from_appended) as u32;
        if from_appended > 0 {
            self.appended.drain(..from_appended);
        }
    }

    /// Re-base onto a freshly-promoted base: subtract the `winner`'s drain
    /// (now folded into the base), and drop the inherited promoted-`appended`
    /// prefix this delta hasn't already drained from its own copy.
    fn rebase(&mut self, winner: &Self, old_base_len: usize) {
        debug_assert!(
            self.drain_offset >= winner.drain_offset,
            "descendant must not drain less than the promoted delta",
        );
        let cur_drain = self.drain_offset as usize;
        let promoted_app_len = winner.appended.len();
        let drained_from_pf = cur_drain.saturating_sub(old_base_len).min(promoted_app_len);
        let drop_n = (promoted_app_len - drained_from_pf).min(self.appended.len());
        self.appended.drain(..drop_n);
        self.drain_offset = (cur_drain - winner.drain_offset as usize) as u32;
    }

    /// Fold into the base queue: drain the promoted prefix, append the new
    /// entries. The data half of finalization.
    pub(super) fn promote_into(&self, base: &mut Vec<T>) {
        let n = (self.drain_offset as usize).min(base.len());
        base.drain(..n);
        base.extend_from_slice(&self.appended);
    }

    fn reset(&mut self) {
        self.drain_offset = 0;
        self.appended.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.drain_offset = other.drain_offset;
        self.appended.clone_from(&other.appended);
    }
}

/// Per-fork delta on [`PendingQueues`], one [`QueueDelta`] per queue.
// size: ~88 B
#[derive(Clone, Default)]
pub(crate) struct PendingQueuesDelta {
    pub(super) deposits: QueueDelta<PendingDeposit>,
    pub(super) partial_withdrawals: QueueDelta<PendingPartialWithdrawal>,
    pub(super) consolidations: QueueDelta<PendingConsolidation>,
}

/// Pre-promotion base queue lengths — [`QueueDelta::rebase`] needs them to
/// recover how much of the promoted `appended` prefix a survivor's cumulative
/// `drain_offset` already consumed.
pub(super) struct OldBaseLens {
    pub deposits: usize,
    pub partial_withdrawals: usize,
    pub consolidations: usize,
}

impl OldBaseLens {
    #[inline]
    pub(super) fn snapshot(base: &PendingQueues) -> Self {
        Self {
            deposits: base.pending_deposits.len(),
            partial_withdrawals: base.pending_partial_withdrawals.len(),
            consolidations: base.pending_consolidations.len(),
        }
    }
}

impl PendingQueuesDelta {
    /// Re-base each queue's delta onto the (about-to-be) promoted base against
    /// the promoted `winner`. Run pre-promotion with `old_base_lens`
    /// snapshotted from the still-old base. `self` is mutated in place on a
    /// fresh copy.
    pub(super) fn rebase(&mut self, winner: &PendingQueuesDelta, old_base_lens: &OldBaseLens) {
        self.deposits.rebase(&winner.deposits, old_base_lens.deposits);
        self.partial_withdrawals
            .rebase(&winner.partial_withdrawals, old_base_lens.partial_withdrawals);
        self.consolidations.rebase(&winner.consolidations, old_base_lens.consolidations);
    }
}

impl Reset for PendingQueuesDelta {
    fn reset(&mut self) {
        self.deposits.reset();
        self.partial_withdrawals.reset();
        self.consolidations.reset();
    }

    fn reset_from(&mut self, other: &Self) {
        self.deposits.reset_from(&other.deposits);
        self.partial_withdrawals.reset_from(&other.partial_withdrawals);
        self.consolidations.reset_from(&other.consolidations);
    }
}

/// Value-layer read over the pending queues (base + a per-fork delta). Built
/// only from a published fork id (or a held writer) — the delta is always
/// present; pre-snapshot readers get no view at all.
#[derive(Clone, Copy)]
pub struct PendingView<'a> {
    base: &'a PendingQueues,
    delta: &'a PendingQueuesDelta,
}

impl<'a> PendingView<'a> {
    #[inline]
    pub(super) fn new(base: &'a PendingQueues, delta: &'a PendingQueuesDelta) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn pending_deposit(&self, ix: usize) -> &'a PendingDeposit {
        self.delta.deposits.get(&self.base.pending_deposits, ix)
    }

    #[inline]
    pub fn pending_deposits_len(&self) -> usize {
        self.delta.deposits.len(self.base.pending_deposits.len())
    }

    #[inline]
    pub fn pending_partial_withdrawal(&self, ix: usize) -> &'a PendingPartialWithdrawal {
        self.delta.partial_withdrawals.get(&self.base.pending_partial_withdrawals, ix)
    }

    #[inline]
    pub fn pending_partial_withdrawals_len(&self) -> usize {
        self.delta.partial_withdrawals.len(self.base.pending_partial_withdrawals.len())
    }

    #[inline]
    pub fn pending_consolidation(&self, ix: usize) -> &'a PendingConsolidation {
        self.delta.consolidations.get(&self.base.pending_consolidations, ix)
    }

    #[inline]
    pub fn pending_consolidations_len(&self) -> usize {
        self.delta.consolidations.len(self.base.pending_consolidations.len())
    }
}

pub struct PendingWriteView<'a> {
    base: &'a PendingQueues,
    fork: Slot<'a, PendingGroup, PendingQueuesDelta>,
}

impl<'a> PendingWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a PendingQueues,
        fork: Slot<'a, PendingGroup, PendingQueuesDelta>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> PendingId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> PendingView<'_> {
        PendingView { base: self.base, delta: &self.fork }
    }

    // Read-through conveniences (a `Deref` to `PendingView` is impossible — the
    // reader borrows the delta shared while we hold it `&mut`).
    #[inline]
    pub fn pending_deposit(&self, ix: usize) -> &PendingDeposit {
        self.reader().pending_deposit(ix)
    }

    #[inline]
    pub fn pending_deposits_len(&self) -> usize {
        self.reader().pending_deposits_len()
    }

    #[inline]
    pub fn pending_partial_withdrawal(&self, ix: usize) -> &PendingPartialWithdrawal {
        self.reader().pending_partial_withdrawal(ix)
    }

    #[inline]
    pub fn pending_partial_withdrawals_len(&self) -> usize {
        self.reader().pending_partial_withdrawals_len()
    }

    #[inline]
    pub fn pending_consolidation(&self, ix: usize) -> &PendingConsolidation {
        self.reader().pending_consolidation(ix)
    }

    #[inline]
    pub fn pending_consolidations_len(&self) -> usize {
        self.reader().pending_consolidations_len()
    }

    #[inline]
    pub fn push_pending_deposit(&mut self, d: PendingDeposit) {
        self.fork.deposits.appended.push(d);
    }

    #[inline]
    pub fn push_pending_partial_withdrawal(&mut self, w: PendingPartialWithdrawal) {
        self.fork.partial_withdrawals.appended.push(w);
    }

    #[inline]
    pub fn push_pending_consolidation(&mut self, c: PendingConsolidation) {
        self.fork.consolidations.appended.push(c);
    }

    /// Move postponed deposits back onto the queue (re-queue exited
    /// validators').
    #[inline]
    pub fn append_pending_deposits(&mut self, src: &mut Vec<PendingDeposit>) {
        self.fork.deposits.appended.append(src);
    }

    /// Drop the first `n` items from the effective queue: bump `drain_offset`
    /// against the base, then trim `appended`.
    #[inline]
    pub fn drain_pending_deposits(&mut self, n: usize) {
        self.fork.deposits.drain(self.base.pending_deposits.len(), n);
    }

    #[inline]
    pub fn drain_pending_partial_withdrawals(&mut self, n: usize) {
        self.fork.partial_withdrawals.drain(self.base.pending_partial_withdrawals.len(), n);
    }

    #[inline]
    pub fn drain_pending_consolidations(&mut self, n: usize) {
        self.fork.consolidations.drain(self.base.pending_consolidations.len(), n);
    }
}
