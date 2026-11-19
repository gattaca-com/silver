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

impl PeerClaim {
    fn new(status: &[u8]) -> Self {
        Self {
            finalized_epoch: StatusView::finalized_epoch(status),
            finalized_root: *StatusView::finalized_root(status),
            head_root: *StatusView::head_root(status),
            head_slot: StatusView::head_slot(status),
            earliest_available_slot: StatusView::earliest_available_slot(status).unwrap_or(0),
        }
    }

    /// No honest head is past the clock, and epoch `E` is finalized by the
    /// transition into `E + 2` at the earliest. A node fresh from a
    /// checkpoint reports its head at the finalized slot.
    fn is_plausible(&self, wall_slot: u64, cfg: &SyncingConfig) -> bool {
        let latest_slot = wall_slot.saturating_add(cfg.head_clock_tolerance_slots);
        let finalized_slot = self.finalized_epoch.saturating_mul(SLOTS_PER_EPOCH);
        let finality_known_at = finalized_slot.saturating_add(2 * SLOTS_PER_EPOCH);
        self.head_slot <= latest_slot &&
            finalized_slot <= self.head_slot &&
            (self.finalized_epoch == 0 || finality_known_at <= latest_slot)
    }
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

    pub(super) fn any_peer_ahead_of(&self, our_head_slot: u64, cfg: &SyncingConfig) -> bool {
        self.claims
            .values()
            .any(|c| c.head_slot > our_head_slot.saturating_add(cfg.head_lag_threshold_slots))
    }

    /// Whether a peer claims a head at most the configured lag behind ours, or
    /// ahead.
    pub(super) fn any_peer_level_with(&self, our_head_slot: u64, cfg: &SyncingConfig) -> bool {
        self.claims
            .values()
            .any(|c| c.head_slot.saturating_add(cfg.head_lag_threshold_slots) >= our_head_slot)
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

    /// Record what `peer` claims; an implausible claim also drops its last
    /// one. Returns true if this is the first we have heard from them.
    /// `wall_slot` is `None` until a clock or a local Status gives one.
    pub(super) fn upsert(
        &mut self,
        peer: usize,
        status: &[u8],
        wall_slot: Option<u64>,
        cfg: &SyncingConfig,
    ) -> bool {
        let claim = PeerClaim::new(status);
        if wall_slot.is_some_and(|wall_slot| !claim.is_plausible(wall_slot, cfg)) {
            silver_log::debug!(
                peer,
                head_slot = claim.head_slot,
                finalized_epoch = claim.finalized_epoch,
                ?wall_slot,
                "sync: implausible peer status dropped"
            );
            self.remove(peer);
            return false;
        }
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

    fn min_target_backers(&self, cfg: &SyncingConfig) -> u64 {
        (self.claims.len() as u64).checked_div(cfg.target_backing_divisor).unwrap_or(0).max(1)
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
        let min_backers = self.min_target_backers(cfg);
        self.finalized_counts
            .iter()
            .filter(|((epoch, root), backers)| {
                let target_slot = epoch.saturating_mul(SLOTS_PER_EPOCH);
                u64::from(**backers) >= min_backers &&
                    *epoch >= trigger_epoch &&
                    target_slot > our_head_slot &&
                    !self.is_excluded(root) &&
                    target_slot <= wall_slot.saturating_add(cfg.wall_clock_tolerance_slots)
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
        let min_backers = self.min_target_backers(cfg);
        self.head_counts
            .iter()
            .filter(|(root, a)| {
                u64::from(a.peer_count) >= min_backers &&
                    a.head_slot > our_head_slot.saturating_add(head_lag) &&
                    a.head_slot <= wall_slot.saturating_add(cfg.wall_clock_tolerance_slots) &&
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
