use fxhash::FxHashMap;
use silver_common::PeerEvent;

/// A peer's first gossip frame can reach the manager before its connection
/// does: the subscription list is announced once, so dropping it loses those
/// topics for the session. 1024 covers a supernode's list: 128 column topics on
/// two digests, each with partial caps.
const MAX_PER_CONNECTION: usize = 1024;

#[derive(Default)]
pub(super) struct PendingAnnouncements(FxHashMap<usize, Vec<PeerEvent>>);

impl PendingAnnouncements {
    pub(super) fn connection_of(event: &PeerEvent) -> Option<usize> {
        match *event {
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer, .. } |
            PeerEvent::P2pGossipTopicUnsubscribe { p2p_peer, .. } |
            PeerEvent::P2pGossipExtensions { p2p_peer, .. } |
            PeerEvent::P2pGossipPartialCaps { p2p_peer, .. } => Some(p2p_peer),
            _ => None,
        }
    }

    pub(super) fn hold(&mut self, conn: usize, event: PeerEvent) {
        let held = self.0.entry(conn).or_default();
        if held.len() < MAX_PER_CONNECTION {
            held.push(event);
        }
    }

    pub(super) fn take(&mut self, conn: usize) -> Vec<PeerEvent> {
        self.0.remove(&conn).unwrap_or_default()
    }

    pub(super) fn forget(&mut self, conn: usize) {
        self.0.remove(&conn);
    }
}
