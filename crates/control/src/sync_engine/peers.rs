use std::collections::{HashMap, HashSet};

use silver_peer::SyncingConfig;

use super::SLOTS_PER_EPOCH;

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
}

#[derive(Default)]
pub(super) struct PeerView {
    claims: HashMap<usize, PeerClaim>,
    finalized_counts: HashMap<(u64, [u8; 32]), u16>,
    head_counts: HashMap<[u8; 32], HeadAgg>,
    rejected: HashSet<[u8; 32]>,
}

impl PeerView {
    pub(super) fn is_rejected(&self, root: &[u8; 32]) -> bool {
        self.rejected.contains(root)
    }

    pub(super) fn mark_rejected(&mut self, root: [u8; 32]) {
        self.rejected.insert(root);
    }

    pub(super) fn upsert(
        &mut self,
        peer: usize,
        finalized_epoch: u64,
        finalized_root: [u8; 32],
        head_root: [u8; 32],
        head_slot: u64,
    ) {
        let claim = PeerClaim { finalized_epoch, finalized_root, head_root, head_slot };
        if let Some(prev) = self.claims.insert(peer, claim) {
            self.decrement(prev);
        }
        *self.finalized_counts.entry((finalized_epoch, finalized_root)).or_insert(0) += 1;
        self.head_counts
            .entry(head_root)
            .and_modify(|a| {
                a.peer_count = a.peer_count.saturating_add(1);
                a.head_slot = a.head_slot.max(head_slot);
            })
            .or_insert(HeadAgg { head_slot, peer_count: 1 });
    }

    pub(super) fn remove(&mut self, peer: usize) -> bool {
        match self.claims.remove(&peer) {
            Some(claim) => {
                self.decrement(claim);
                true
            }
            None => false,
        }
    }

    pub(super) fn backs_finalized(&self, epoch: u64, root: &[u8; 32]) -> bool {
        self.finalized_counts.contains_key(&(epoch, *root))
    }

    pub(super) fn backs_head(&self, root: &[u8; 32]) -> bool {
        self.head_counts.contains_key(root)
    }

    pub(super) fn head_slot_of(&self, peer: usize) -> Option<u64> {
        self.claims.get(&peer).map(|c| c.head_slot)
    }

    pub(super) fn best_finalized_target(
        &self,
        our_epoch: u64,
        our_head_slot: u64,
        wall_slot: u64,
        cfg: &SyncingConfig,
        force_resync: bool,
    ) -> Option<(u64, [u8; 32])> {
        let lag = if force_resync { 0 } else { cfg.finalized_lag_threshold_epochs };
        let trigger_epoch = our_epoch.saturating_add(lag);
        self.finalized_counts
            .iter()
            .filter(|((epoch, root), _)| {
                let target_slot = epoch.saturating_mul(SLOTS_PER_EPOCH);
                *epoch >= trigger_epoch &&
                    target_slot > our_head_slot &&
                    !self.rejected.contains(root) &&
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
        force_resync: bool,
    ) -> Option<([u8; 32], u64)> {
        let head_lag = if force_resync { 0 } else { cfg.head_lag_threshold_slots };
        self.head_counts
            .iter()
            .filter(|(root, a)| {
                a.head_slot > our_head_slot + head_lag &&
                    a.head_slot <= wall_slot + cfg.wall_clock_tolerance_slots &&
                    !self.rejected.contains(*root)
            })
            .max_by(|a, b| {
                a.1.peer_count
                    .cmp(&b.1.peer_count)
                    .then_with(|| a.1.head_slot.cmp(&b.1.head_slot))
                    .then_with(|| a.0.cmp(b.0))
            })
            .map(|(&head_root, a)| (head_root, a.head_slot))
    }

    fn decrement(&mut self, claim: PeerClaim) {
        let key = (claim.finalized_epoch, claim.finalized_root);
        if let Some(c) = self.finalized_counts.get_mut(&key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.finalized_counts.remove(&key);
            }
        }
        if let Some(a) = self.head_counts.get_mut(&claim.head_root) {
            a.peer_count = a.peer_count.saturating_sub(1);
            if a.peer_count == 0 {
                self.head_counts.remove(&claim.head_root);
            }
        }
    }
}
