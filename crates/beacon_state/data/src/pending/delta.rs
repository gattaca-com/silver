use super::{PendingGroup, PendingId, finalized::PendingQueues};
use crate::{
    buffer::{Reset, Slot},
    types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
};

/// Per-fork delta on [`PendingQueues`]. Each queue: drop the first
/// `drain_offset` entries of the base, then read the remainder followed by
/// `appended`.
// size: ~88 B
#[derive(Clone, Default)]
pub(crate) struct PendingQueuesDelta {
    pub(super) deposits_drain_offset: u32,
    pub(super) deposits_appended: Vec<PendingDeposit>,
    pub(super) partial_withdrawals_drain_offset: u32,
    pub(super) partial_withdrawals_appended: Vec<PendingPartialWithdrawal>,
    pub(super) consolidations_drain_offset: u32,
    pub(super) consolidations_appended: Vec<PendingConsolidation>,
}

/// Pre-promotion base queue lengths — `prune_queue_delta` needs them to
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
        prune_queue_delta(
            &mut self.deposits_drain_offset,
            &mut self.deposits_appended,
            old_base_lens.deposits,
            winner.deposits_drain_offset,
            winner.deposits_appended.len(),
        );
        prune_queue_delta(
            &mut self.partial_withdrawals_drain_offset,
            &mut self.partial_withdrawals_appended,
            old_base_lens.partial_withdrawals,
            winner.partial_withdrawals_drain_offset,
            winner.partial_withdrawals_appended.len(),
        );
        prune_queue_delta(
            &mut self.consolidations_drain_offset,
            &mut self.consolidations_appended,
            old_base_lens.consolidations,
            winner.consolidations_drain_offset,
            winner.consolidations_appended.len(),
        );
    }
}

/// Re-base one queue's delta onto a freshly-promoted base: subtract
/// `promoted_drain` from `drain_offset` (now folded into the base), and drop
/// the inherited promoted-`appended` prefix the descendant hasn't already
/// drained from its own copy.
fn prune_queue_delta<T>(
    drain_offset: &mut u32,
    appended: &mut Vec<T>,
    old_base_len: usize,
    promoted_drain: u32,
    promoted_app_len: usize,
) {
    debug_assert!(
        *drain_offset >= promoted_drain,
        "descendant must not drain less than the promoted delta",
    );
    let cur_drain = *drain_offset as usize;
    let drained_from_pf = cur_drain.saturating_sub(old_base_len).min(promoted_app_len);
    let drop_n = (promoted_app_len - drained_from_pf).min(appended.len());
    appended.drain(..drop_n);
    *drain_offset = (cur_drain - promoted_drain as usize) as u32;
}

impl Reset for PendingQueuesDelta {
    fn reset(&mut self) {
        self.deposits_drain_offset = 0;
        self.deposits_appended.clear();
        self.partial_withdrawals_drain_offset = 0;
        self.partial_withdrawals_appended.clear();
        self.consolidations_drain_offset = 0;
        self.consolidations_appended.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.deposits_drain_offset = other.deposits_drain_offset;
        self.deposits_appended.clone_from(&other.deposits_appended);
        self.partial_withdrawals_drain_offset = other.partial_withdrawals_drain_offset;
        self.partial_withdrawals_appended.clone_from(&other.partial_withdrawals_appended);
        self.consolidations_drain_offset = other.consolidations_drain_offset;
        self.consolidations_appended.clone_from(&other.consolidations_appended);
    }
}

/// Effective queue element at `ix`: the base remainder after `drain`, then the
/// appended tail.
#[inline]
fn queue_get<'b, T>(base: &'b [T], drain: u32, appended: &'b [T], ix: usize) -> &'b T {
    let drain = drain as usize;
    let remaining = base.len().saturating_sub(drain);
    if ix < remaining { &base[drain + ix] } else { &appended[ix - remaining] }
}

#[inline]
fn queue_len(base_len: usize, drain: u32, appended_len: usize) -> usize {
    base_len.saturating_sub(drain as usize) + appended_len
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
        let d = self.delta;
        queue_get(&self.base.pending_deposits, d.deposits_drain_offset, &d.deposits_appended, ix)
    }

    #[inline]
    pub fn pending_deposits_len(&self) -> usize {
        let d = self.delta;
        queue_len(
            self.base.pending_deposits.len(),
            d.deposits_drain_offset,
            d.deposits_appended.len(),
        )
    }

    #[inline]
    pub fn pending_partial_withdrawal(&self, ix: usize) -> &'a PendingPartialWithdrawal {
        let d = self.delta;
        queue_get(
            &self.base.pending_partial_withdrawals,
            d.partial_withdrawals_drain_offset,
            &d.partial_withdrawals_appended,
            ix,
        )
    }

    #[inline]
    pub fn pending_partial_withdrawals_len(&self) -> usize {
        let d = self.delta;
        queue_len(
            self.base.pending_partial_withdrawals.len(),
            d.partial_withdrawals_drain_offset,
            d.partial_withdrawals_appended.len(),
        )
    }

    #[inline]
    pub fn pending_consolidation(&self, ix: usize) -> &'a PendingConsolidation {
        let d = self.delta;
        queue_get(
            &self.base.pending_consolidations,
            d.consolidations_drain_offset,
            &d.consolidations_appended,
            ix,
        )
    }

    #[inline]
    pub fn pending_consolidations_len(&self) -> usize {
        let d = self.delta;
        queue_len(
            self.base.pending_consolidations.len(),
            d.consolidations_drain_offset,
            d.consolidations_appended.len(),
        )
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
        let d = &*self.fork;
        queue_get(&self.base.pending_deposits, d.deposits_drain_offset, &d.deposits_appended, ix)
    }

    #[inline]
    pub fn pending_deposits_len(&self) -> usize {
        self.reader().pending_deposits_len()
    }

    #[inline]
    pub fn pending_partial_withdrawal(&self, ix: usize) -> &PendingPartialWithdrawal {
        let d = &*self.fork;
        queue_get(
            &self.base.pending_partial_withdrawals,
            d.partial_withdrawals_drain_offset,
            &d.partial_withdrawals_appended,
            ix,
        )
    }

    #[inline]
    pub fn pending_partial_withdrawals_len(&self) -> usize {
        self.reader().pending_partial_withdrawals_len()
    }

    #[inline]
    pub fn pending_consolidation(&self, ix: usize) -> &PendingConsolidation {
        let d = &*self.fork;
        queue_get(
            &self.base.pending_consolidations,
            d.consolidations_drain_offset,
            &d.consolidations_appended,
            ix,
        )
    }

    #[inline]
    pub fn pending_consolidations_len(&self) -> usize {
        self.reader().pending_consolidations_len()
    }

    #[inline]
    pub fn push_pending_deposit(&mut self, d: PendingDeposit) {
        self.fork.deposits_appended.push(d);
    }

    #[inline]
    pub fn push_pending_partial_withdrawal(&mut self, w: PendingPartialWithdrawal) {
        self.fork.partial_withdrawals_appended.push(w);
    }

    #[inline]
    pub fn push_pending_consolidation(&mut self, c: PendingConsolidation) {
        self.fork.consolidations_appended.push(c);
    }

    /// Move postponed deposits back onto the queue (re-queue exited
    /// validators').
    #[inline]
    pub fn append_pending_deposits(&mut self, src: &mut Vec<PendingDeposit>) {
        self.fork.deposits_appended.append(src);
    }

    /// Drop the first `n` items from the effective queue: bump `drain_offset`
    /// against the base, then trim `appended`.
    #[inline]
    pub fn drain_pending_deposits(&mut self, n: usize) {
        let base_len = self.base.pending_deposits.len();
        let f = &mut *self.fork;
        drain_queue(&mut f.deposits_drain_offset, &mut f.deposits_appended, base_len, n);
    }

    #[inline]
    pub fn drain_pending_partial_withdrawals(&mut self, n: usize) {
        let base_len = self.base.pending_partial_withdrawals.len();
        let f = &mut *self.fork;
        drain_queue(
            &mut f.partial_withdrawals_drain_offset,
            &mut f.partial_withdrawals_appended,
            base_len,
            n,
        );
    }

    #[inline]
    pub fn drain_pending_consolidations(&mut self, n: usize) {
        let base_len = self.base.pending_consolidations.len();
        let f = &mut *self.fork;
        drain_queue(
            &mut f.consolidations_drain_offset,
            &mut f.consolidations_appended,
            base_len,
            n,
        );
    }
}

#[inline]
fn drain_queue<T>(drain_offset: &mut u32, appended: &mut Vec<T>, base_len: usize, n: usize) {
    let already = *drain_offset as usize;
    let from_appended = n.saturating_sub(base_len.saturating_sub(already));
    *drain_offset += (n - from_appended) as u32;
    if from_appended > 0 {
        appended.drain(..from_appended);
    }
}
