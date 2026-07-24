use super::{
    PendingId,
    finalized::{Queue, QueueItem},
    group::QueueGroup,
    hasher::QueueHasher,
};
use crate::{
    B256,
    gloas::BuilderPendingWithdrawal,
    ring::{Id, Reset, Slot},
    types::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal},
};

/// One queue's per-fork delta — a pure data holder (mirror of
/// `ColumnDelta`'s backing): the first
/// `min(drain_offset, base len)` base entries are consumed and reads continue
/// into `appended`. `drain_offset` accumulates past the base (the excess came
/// off `appended` physically) so [`rebase`](Self::rebase) can recover how much
/// of an inherited prefix this fork already drained.
///
/// `hasher` is the [`QueueHasher`] over the effective queue's leaves
/// (`base[drain..] ++ appended`): appends extend it in place and the root
/// finalizes a clone (both O(log n)); only a front drain forces an O(n)
/// rebuild. Keyed by the leaf *sequence* — not base position — it's
/// base-swap-invariant: `rebase`/`promote` preserve the effective queue, so it
/// survives finalization untouched.
#[derive(Clone)]
pub(super) struct QueueDelta<Q> {
    pub(super) drain_offset: u32,
    appended: Queue<Q>,
    hasher: QueueHasher,
}

// Manual impl (not derived, which would spuriously bind `Q: Default`); the
// `QueueItem` bound is real — an empty fulu hasher needs `Q::SSZ_LIMIT`.
impl<Q: QueueItem> Default for QueueDelta<Q> {
    fn default() -> Self {
        Self {
            drain_offset: 0,
            appended: Queue::default(),
            hasher: QueueHasher::empty(false, Q::SSZ_LIMIT),
        }
    }
}

impl<Q: QueueItem> QueueDelta<Q> {
    /// (Re)build the hasher from `base[drain..] ++ appended`'s cached leaves.
    /// Called only when the front moves (a fresh anchor or a drain); appends
    /// extend it in place. The hasher parks one subtree root per set bit of
    /// the length, so [`root`](Self::root) is O(log n).
    pub(super) fn rebuild_hasher(&mut self, base: &Queue<Q>, gloas: bool) {
        let start = (self.drain_offset as usize).min(base.len());
        let mut hasher = QueueHasher::empty(gloas, Q::SSZ_LIMIT);
        for &leaf in base.leaves()[start..].iter().chain(self.appended.leaves()) {
            hasher.push(leaf);
        }
        self.hasher = hasher;
    }

    /// The fork block's EIP-7688 migration: rebuild this fork's hasher in
    /// the gloas shape. No-op if already gloas.
    pub(super) fn adopt_gloas(&mut self, base: &Queue<Q>) {
        if !self.hasher.is_gloas() {
            self.rebuild_hasher(base, true);
        }
    }

    pub(super) fn hasher_is_gloas(&self) -> bool {
        self.hasher.is_gloas()
    }

    #[inline]
    pub(super) fn push(&mut self, e: Q) {
        let leaf = self.appended.push(e);
        self.hasher.push(leaf);
    }

    /// Drop the first `n` items from the effective queue. `drain_offset` takes
    /// the full `n` (uncapped); the part past the base comes off `appended`
    /// physically. The front moved, so the hasher is rebuilt — skipped for a
    /// no-op drain (the common case: deposits too recent to process leave the
    /// front, and hence the hasher, untouched).
    pub(super) fn drain(&mut self, base: &Queue<Q>, n: usize) {
        if n == 0 {
            return;
        }
        let already = self.drain_offset as usize;
        let from_appended = (already + n).saturating_sub(base.len().max(already));
        self.drain_offset += n as u32;
        if from_appended > 0 {
            self.appended.drain_front(from_appended);
        }
        self.rebuild_hasher(base, self.hasher.is_gloas());
    }

    /// SSZ `hash_tree_root` of the queue at `len` items, in this fork's
    /// hasher shape (see [`QueueHasher::root`]),
    /// pad to the list depth, and mix in the length.
    pub(super) fn root(&self, len: usize) -> B256 {
        self.hasher.root(len)
    }

    /// Re-base onto a freshly-promoted base: subtract the `winner`'s drain
    /// (now folded into the base), and drop the inherited promoted-`appended`
    /// prefix this delta hasn't already drained from its own copy. The
    /// effective queue is unchanged, so the hasher needs no touch.
    pub(super) fn rebase(&mut self, winner: &Self, old_base_len: usize) {
        debug_assert!(
            self.drain_offset >= winner.drain_offset,
            "descendant must not drain less than the promoted delta",
        );
        let (d, w) = (self.drain_offset as usize, winner.drain_offset as usize);
        // Of the winner's (post-drain) `appended` — now the new base's tail —
        // how much this fork already drained out of its inherited copy. The
        // winner's own past-base drains never reached the copy: they were
        // removed from `winner.appended` before the fork inherited it.
        let over = |drain: usize| drain.saturating_sub(old_base_len);
        let consumed = (over(d) - over(w)).min(winner.appended.len());
        // The un-drained inherited remainder; everything after it is this
        // fork's own appends, which must survive.
        let drop_n = winner.appended.len() - consumed;
        self.appended.drain_front(drop_n);
        self.drain_offset = (d.min(old_base_len) - w.min(old_base_len) + consumed) as u32;
    }

    /// Fold into the base queue: drain the promoted prefix, append the new
    /// entries. The data half of finalization.
    pub(super) fn promote_into(&self, base: &mut Queue<Q>) {
        let n = (self.drain_offset as usize).min(base.len());
        base.drain_front(n);
        base.extend(&self.appended);
    }
}

impl<Q: QueueItem> Reset for QueueDelta<Q> {
    fn reset(&mut self) {
        self.drain_offset = 0;
        self.appended.clear();
        self.hasher = QueueHasher::empty(false, Q::SSZ_LIMIT);
    }

    fn reset_from(&mut self, other: &Self) {
        self.drain_offset = other.drain_offset;
        self.appended.clone_from(&other.appended);
        self.hasher.clone_from(&other.hasher);
    }
}

/// Read view over one queue: the finalized `base` overlaid by a fork's
/// `delta`. Holds the base+delta merge (effective element, length, SSZ root),
/// mirroring [`ColumnReader`](crate::ColumnReader). A [`PendingView`] exposes
/// one per queue as a public field.
#[derive(Clone, Copy)]
pub struct QueueView<'a, Q> {
    base: &'a Queue<Q>,
    delta: &'a QueueDelta<Q>,
}

impl<'a, Q: QueueItem> QueueView<'a, Q> {
    #[inline]
    pub(super) fn new(base: &'a Queue<Q>, delta: &'a QueueDelta<Q>) -> Self {
        Self { base, delta }
    }

    /// Effective element at `ix`: the base remainder after the drain, then the
    /// appended tail.
    #[inline]
    pub fn get(&self, ix: usize) -> &'a Q {
        let drain = self.delta.drain_offset as usize;
        let remaining = self.base.len().saturating_sub(drain);
        if ix < remaining {
            &self.base.entries()[drain + ix]
        } else {
            &self.delta.appended.entries()[ix - remaining]
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.base.len().saturating_sub(self.delta.drain_offset as usize) + self.delta.appended.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// SSZ `hash_tree_root` — folds the cached hasher, padding + length only
    /// (no per-element hashing).
    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.delta.root(self.len())
    }
}

/// Write view over one queue: the appends/drains, each keeping the delta's
/// hasher consistent, plus `commit` of the ring slot. Mirror of
/// [`ColumnWriteView`](crate::ColumnWriteView); held per queue by
/// [`PendingWriteView`].
pub struct QueueWriteView<'a, Q: QueueItem> {
    base: &'a Queue<Q>,
    fork: Slot<'a, QueueGroup<Q>, QueueDelta<Q>>,
}

impl<'a, Q: QueueItem> QueueWriteView<'a, Q> {
    #[inline]
    pub(super) fn new(base: &'a Queue<Q>, fork: Slot<'a, QueueGroup<Q>, QueueDelta<Q>>) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub(super) fn commit(self) -> Id<QueueGroup<Q>> {
        self.fork.commit()
    }

    pub fn adopt_gloas(&mut self) {
        self.fork.adopt_gloas(self.base);
    }

    #[inline]
    pub fn reader(&self) -> QueueView<'_, Q> {
        QueueView::new(self.base, &self.fork)
    }

    #[inline]
    pub fn push(&mut self, e: Q) {
        self.fork.push(e);
    }

    /// Re-queue exited validators' deposits onto the tail.
    pub fn append(&mut self, src: &mut Vec<Q>) {
        for e in src.drain(..) {
            self.fork.push(e);
        }
    }

    #[inline]
    pub fn drain(&mut self, n: usize) {
        self.fork.drain(self.base, n);
    }
}

/// Value-layer read over the pending queues — a methodless holder of one
/// [`QueueView`] per queue (mirror of [`StateReadView`](crate::StateReadView)):
/// callers read a queue directly, e.g. `pending.deposits.root()`.
#[derive(Clone, Copy)]
pub struct PendingView<'a> {
    pub deposits: QueueView<'a, PendingDeposit>,
    pub partial_withdrawals: QueueView<'a, PendingPartialWithdrawal>,
    pub consolidations: QueueView<'a, PendingConsolidation>,
    pub builder_withdrawals: QueueView<'a, BuilderPendingWithdrawal>,
}

/// Write view over the pending queues — a holder of one [`QueueWriteView`] per
/// queue (each queue owns its ring slot, so they split cleanly). Callers write
/// directly, e.g. `pending.deposits.push(d)`; reads go through
/// [`reader`](Self::reader); `commit` freezes the bundled id.
pub struct PendingWriteView<'a> {
    pub deposits: QueueWriteView<'a, PendingDeposit>,
    pub partial_withdrawals: QueueWriteView<'a, PendingPartialWithdrawal>,
    pub consolidations: QueueWriteView<'a, PendingConsolidation>,
    pub builder_withdrawals: QueueWriteView<'a, BuilderPendingWithdrawal>,
}

impl PendingWriteView<'_> {
    /// EIP-7688 hash migration of all four queues' hashers.
    pub fn adopt_gloas(&mut self) {
        self.deposits.adopt_gloas();
        self.partial_withdrawals.adopt_gloas();
        self.consolidations.adopt_gloas();
        self.builder_withdrawals.adopt_gloas();
    }

    #[inline]
    pub fn commit(self) -> PendingId {
        PendingId {
            deposits: self.deposits.commit(),
            partial_withdrawals: self.partial_withdrawals.commit(),
            consolidations: self.consolidations.commit(),
            builder_withdrawals: self.builder_withdrawals.commit(),
        }
    }

    #[inline]
    pub fn reader(&self) -> PendingView<'_> {
        PendingView {
            deposits: self.deposits.reader(),
            partial_withdrawals: self.partial_withdrawals.reader(),
            consolidations: self.consolidations.reader(),
            builder_withdrawals: self.builder_withdrawals.reader(),
        }
    }
}
