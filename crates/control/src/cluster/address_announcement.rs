use std::time::{Duration, Instant};

use silver_common::MemberAddress;

/// Proposes this node's advertised address while the replicated one differs.
/// Only a node with a recorded address announces: the others are dialled at
/// their configured address.
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
        recorded: Option<MemberAddress>,
    ) {
        let Some(recorded) = recorded else {
            self.stale = false;
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
