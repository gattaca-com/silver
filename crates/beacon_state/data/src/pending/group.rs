use parking_lot::Mutex;

use super::{
    delta::{QueueDelta, QueueView, QueueWriteView},
    finalized::{Queue, QueueItem},
};
use crate::{
    buffer::{Id, Reset, Ring, reanchor_survivors},
    types::SLOTS_RING_N,
};

/// One isolated pending queue: its finalized base + a per-fork delta ring,
/// generic over the element `Q`. The three queues are distinct instantiations
/// (distinct ring-id types), bundled by [`PendingGroup`](super::PendingGroup).
/// Mirrors [`ColumnGroup`](crate::ColumnGroup); the growable finalized `Vec` is
/// read by the checkpoint-persist thread, so it's guarded by `persist_lock`.
pub struct QueueGroup<Q: QueueItem> {
    finalized: Queue<Q>,
    deltas: Ring<Self, QueueDelta<Q>, SLOTS_RING_N>,
    persist_lock: Mutex<()>,
}

impl<Q: QueueItem> QueueGroup<Q> {
    /// Decode the finalized base from its SSZ byte range (validated by the
    /// caller); the delta ring starts empty.
    pub(super) fn from_ssz(bytes: &[u8]) -> Self {
        Self {
            finalized: Queue::from_ssz(bytes),
            deltas: Ring::default(),
            persist_lock: Mutex::new(()),
        }
    }

    /// Run `f` over the finalized base under the promote barrier — the
    /// checkpoint encoder's (only) way in. Keep `f` to a bounded memcpy.
    #[inline]
    pub(crate) fn with_finalized_locked<R>(&self, f: impl FnOnce(&Queue<Q>) -> R) -> R {
        let _g = self.persist_lock.lock();
        f(&self.finalized)
    }

    #[inline]
    pub(super) fn view(&self, id: Id<Self>) -> QueueView<'_, Q> {
        QueueView::new(&self.finalized, self.deltas.get(id))
    }

    #[inline]
    pub(super) fn roll_fresh(&mut self) -> QueueWriteView<'_, Q> {
        let Self { finalized, deltas, .. } = self;
        let mut fork = deltas.roll_fresh();
        fork.rebuild_frontier(finalized);
        QueueWriteView::new(finalized, fork)
    }

    #[inline]
    pub(super) fn roll_from(&mut self, parent: Id<Self>) -> QueueWriteView<'_, Q> {
        let Self { finalized, deltas, .. } = self;
        QueueWriteView::new(finalized, deltas.roll_from(parent))
    }

    /// Re-anchor a survivor against the promoted `winner` into a fresh slot,
    /// pre-promote (so lock-free readers stay unblocked). `old_base_len` is the
    /// still-old base length, snapshotted before any promote.
    fn reanchor(
        &mut self,
        survivor: Id<Self>,
        winner: Id<Self>,
        old_base_len: usize,
    ) -> QueueWriteView<'_, Q> {
        let Self { finalized, deltas, .. } = self;
        let (mut fork, old, winner_delta) = deltas.roll_fresh_deriving(survivor, winner);
        fork.reset_from(old);
        fork.rebase(winner_delta, old_base_len);
        QueueWriteView::new(finalized, fork)
    }

    /// Re-anchor each survivor against the promoted `winner` into fresh slots
    /// (deduped for shared survivors), then promote the winner into the
    /// finalized base. Mirrors [`ColumnGroup::finalize`](crate::ColumnGroup).
    pub(super) fn finalize(&mut self, winner: Id<Self>, survivors: &[Id<Self>]) -> Vec<Id<Self>> {
        let old_base_len = self.finalized.len();
        debug_assert!(survivors.contains(&winner), "winner must be among the survivors");
        self.deltas.free_outdated(survivors);

        let fresh =
            reanchor_survivors(survivors, |s| self.reanchor(s, winner, old_base_len).commit());

        {
            let _g = self.persist_lock.lock();
            self.deltas.get(winner).promote_into(&mut self.finalized);
        }

        self.deltas.free_outdated(&fresh);

        fresh
    }
}
