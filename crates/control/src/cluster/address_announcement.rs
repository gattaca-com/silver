use std::time::{Duration, Instant};

use silver_common::MemberAddress;

use super::membership::ClusterMembership;

/// Proposes this node's advertised address while the replicated one is
/// missing or differs. Bootstrap members start with none recorded, and an
/// added member's key is checked against the recorded ones only.
pub(super) struct AddressAnnouncement {
    stale: bool,
    next_at: Instant,
    /// Every node refuses an announcement under another key, so it is
    /// reported once instead of proposed again.
    foreign_key_reported: bool,
}

impl AddressAnnouncement {
    pub(super) fn new(now: Instant) -> Self {
        Self { stale: false, next_at: now, foreign_key_reported: false }
    }

    pub(super) fn is_due(&self, now: Instant) -> bool {
        self.stale && now >= self.next_at
    }

    pub(super) fn proposed(&mut self, now: Instant, retry_after: Duration) {
        self.next_at = now.checked_add(retry_after).unwrap_or(now);
    }

    pub(super) fn follow(
        &mut self,
        node_id: u64,
        advertised: MemberAddress,
        membership: &ClusterMembership,
    ) {
        if !membership.is_member(node_id) {
            self.stale = false;
            return;
        }
        let Some(recorded) = membership.address(node_id) else {
            self.stale = true;
            return;
        };
        self.stale = recorded.public_key == advertised.public_key && recorded != advertised;
        if recorded.public_key != advertised.public_key && !self.foreign_key_reported {
            self.foreign_key_reported = true;
            silver_log::warn!(
                node_id,
                ?recorded,
                address = ?advertised,
                "the cluster records this node under another key: its address is not announced"
            );
        }
    }
}
