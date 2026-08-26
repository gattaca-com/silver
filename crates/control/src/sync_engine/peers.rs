use std::ops::RangeInclusive;

use fxhash::FxHashMap;
use silver_common::ssz_view::StatusView;
use silver_peer::{RejectedRoots, SyncingConfig};

use super::{SLOTS_PER_EPOCH, sync_window::Slot};

#[derive(Clone, Copy)]
struct HeadAgg {
    head_slot: u64,
    peer_count: u16,
}

#[derive(Clone, Copy)]
struct PeerClaim {
    finalized_epoch: u64,
    finalized_root: [u8; 32],
    head_root: [u8; 32],
    head_slot: u64,
    earliest_available_slot: Slot,
}

pub(super) struct PeerView {
    claims: FxHashMap<usize, PeerClaim>,
    finalized_counts: FxHashMap<(u64, [u8; 32]), u16>,
    head_counts: FxHashMap<[u8; 32], HeadAgg>,
    rejected: RejectedRoots,
    /// Roots whose chain stalled on a slot nobody served.
    unavailable: RejectedRoots,
}

impl PeerView {
    pub(super) fn new(cap: usize) -> Self {
        Self {
            claims: FxHashMap::default(),
            finalized_counts: FxHashMap::default(),
            head_counts: FxHashMap::default(),
            rejected: RejectedRoots::new(cap),
            unavailable: RejectedRoots::new(cap),
        }
    }

    pub(super) fn received_statuses(&self) -> bool {
        !self.claims.is_empty()
    }

    pub(super) fn claims_span(&self, peer: usize, span: RangeInclusive<Slot>) -> bool {
        self.claims.get(&peer).is_some_and(|c| {
            c.head_slot >= *span.end() && c.earliest_available_slot <= *span.start()
        })
    }

    pub(super) fn is_rejected(&self, root: &[u8; 32]) -> bool {
        self.rejected.contains(root)
    }

    pub(super) fn is_excluded(&self, root: &[u8; 32]) -> bool {
        self.rejected.contains(root) || self.unavailable.contains(root)
    }

    pub(super) fn mark_rejected(&mut self, root: [u8; 32]) {
        self.rejected.mark(root);
    }

    pub(super) fn mark_unavailable(&mut self, root: [u8; 32]) {
        self.unavailable.mark(root);
    }

    /// Record what `peer` claims. Returns true if this is the first we have
    /// heard from them.
    pub(super) fn upsert(&mut self, peer: usize, status: &[u8]) -> bool {
        let claim = PeerClaim {
            finalized_epoch: StatusView::finalized_epoch(status),
            finalized_root: *StatusView::finalized_root(status),
            head_root: *StatusView::head_root(status),
            head_slot: StatusView::head_slot(status),
            earliest_available_slot: StatusView::earliest_available_slot(status).unwrap_or(0),
        };
        let first_time = self.claims.insert(peer, claim).is_none();
        self.rebuild_counts();
        first_time
    }

    pub(super) fn remove(&mut self, peer: usize) -> bool {
        let removed = self.claims.remove(&peer).is_some();
        if removed {
            self.rebuild_counts();
        }
        removed
    }

    pub(super) fn retry_chains_backed_by(&mut self, peer: usize) {
        let Some(claim) = self.claims.get(&peer).copied() else { return };
        self.unavailable.unmark(&claim.head_root);
        self.unavailable.unmark(&claim.finalized_root);
    }

    fn rebuild_counts(&mut self) {
        self.finalized_counts.clear();
        self.head_counts.clear();
        for claim in self.claims.values() {
            *self
                .finalized_counts
                .entry((claim.finalized_epoch, claim.finalized_root))
                .or_insert(0) += 1;
            self.head_counts
                .entry(claim.head_root)
                .and_modify(|a| {
                    a.peer_count = a.peer_count.saturating_add(1);
                    a.head_slot = a.head_slot.max(claim.head_slot);
                })
                .or_insert(HeadAgg { head_slot: claim.head_slot, peer_count: 1 });
        }
    }

    pub(super) fn backs_finalized(&self, epoch: u64, root: &[u8; 32]) -> bool {
        self.finalized_counts.contains_key(&(epoch, *root))
    }

    pub(super) fn backs_head(&self, root: &[u8; 32]) -> bool {
        self.head_counts.contains_key(root)
    }

    pub(super) fn best_finalized_target(
        &self,
        our_epoch: u64,
        our_head_slot: u64,
        wall_slot: u64,
        cfg: &SyncingConfig,
        block_gap: bool,
    ) -> Option<(u64, [u8; 32])> {
        let lag = if block_gap { 0 } else { cfg.finalized_lag_threshold_epochs };
        let trigger_epoch = our_epoch.saturating_add(lag);
        self.finalized_counts
            .iter()
            .filter(|((epoch, root), _)| {
                let target_slot = epoch.saturating_mul(SLOTS_PER_EPOCH);
                *epoch >= trigger_epoch &&
                    target_slot > our_head_slot &&
                    !self.is_excluded(root) &&
                    target_slot <= wall_slot + cfg.wall_clock_tolerance_slots
            })
            .max_by(|a, b| {
                a.1.cmp(b.1).then_with(|| a.0.0.cmp(&b.0.0)).then_with(|| a.0.1.cmp(&b.0.1))
            })
            .map(|(&(e, r), _)| (e, r))
    }

    pub(super) fn best_head_target(
        &self,
        our_head_slot: u64,
        wall_slot: u64,
        cfg: &SyncingConfig,
        block_gap: bool,
    ) -> Option<([u8; 32], u64)> {
        let head_lag = if block_gap { 0 } else { cfg.head_lag_threshold_slots };
        self.head_counts
            .iter()
            .filter(|(root, a)| {
                a.head_slot > our_head_slot + head_lag &&
                    a.head_slot <= wall_slot + cfg.wall_clock_tolerance_slots &&
                    !self.is_excluded(root)
            })
            .max_by(|a, b| {
                a.1.peer_count
                    .cmp(&b.1.peer_count)
                    .then_with(|| a.1.head_slot.cmp(&b.1.head_slot))
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(&head_root, a)| (head_root, a.head_slot))
    }
}
