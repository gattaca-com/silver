use std::ops::Index;

use crate::state::PeerState;

/// Live peers keyed by p2p connection id. The ids are quinn-proto slab
/// indices, recycled and bounded by the connection cap, so each owns a slot
/// allocated once at startup and reused by whoever takes the id next.
pub(crate) struct PeerSlots {
    slots: Box<[PeerState]>,
    live: Box<[bool]>,
    len: usize,
}

impl PeerSlots {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            slots: (0..capacity).map(|_| PeerState::default()).collect(),
            live: vec![false; capacity].into_boxed_slice(),
            len: 0,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn contains_key(&self, conn: &usize) -> bool {
        self.live.get(*conn).copied().unwrap_or(false)
    }

    pub(crate) fn get(&self, conn: &usize) -> Option<&PeerState> {
        self.contains_key(conn).then(|| &self.slots[*conn])
    }

    pub(crate) fn get_mut(&mut self, conn: &usize) -> Option<&mut PeerState> {
        self.contains_key(conn).then(|| &mut self.slots[*conn])
    }

    /// The slot of `conn`, marked live, or `None` for an id beyond the
    /// table. The caller readies it with `PeerState::connect`.
    pub(crate) fn occupy(&mut self, conn: usize) -> Option<&mut PeerState> {
        let live = self.live.get_mut(conn)?;
        debug_assert!(!*live, "connection id {conn} occupied twice");
        if !*live {
            *live = true;
            self.len += 1;
        }
        Some(&mut self.slots[conn])
    }

    /// Marks `conn` free. Its state stays readable until the id is taken
    /// again.
    pub(crate) fn vacate(&mut self, conn: usize) -> Option<&mut PeerState> {
        if !self.contains_key(&conn) {
            return None;
        }
        self.live[conn] = false;
        self.len -= 1;
        Some(&mut self.slots[conn])
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (usize, &PeerState)> {
        self.slots
            .iter()
            .zip(&self.live)
            .enumerate()
            .filter(|(_, (_, live))| **live)
            .map(|(conn, (peer, _))| (conn, peer))
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (usize, &mut PeerState)> {
        self.slots
            .iter_mut()
            .zip(&self.live)
            .enumerate()
            .filter(|(_, (_, live))| **live)
            .map(|(conn, (peer, _))| (conn, peer))
    }
}

impl Index<&usize> for PeerSlots {
    type Output = PeerState;

    fn index(&self, conn: &usize) -> &PeerState {
        self.get(conn).expect("live connection")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use silver_common::{GossipTopic, MessageId, PeerControl};
    use silver_config::ScoreParams;

    use crate::manager::fixture::*;

    /// A recycled slot starts the next connection from defaults, apart from
    /// the msg cache and the archived counters of a returning peer.
    #[test]
    fn a_recycled_slot_holds_only_the_new_connection() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 5, 1, now);
        mgr.on_subscribe(5, topic, [0; 4], now, &mut |_| {});
        let seen = MessageId { id: [7; 20] };
        let peer = mgr.peers.get_mut(&5).unwrap();
        peer.application_score = -3.0;
        peer.goodbye_sent = true;
        peer.topic_stats.entry(topic).or_default().first_deliveries = 4.0;
        peer.msg_cache_insert(seen);
        mgr.on_disconnected(5, now, "test", &mut |_| {});
        assert!(mgr.peers.get(&5).is_none());

        connect(&mut mgr, &mut cap, 5, 2, now);
        let peer = &mgr.peers[&5];
        assert_eq!(peer.peer_id, peer_id(2));
        assert!(peer.subscriptions.is_empty() && peer.topic_stats.is_empty());
        assert_eq!(peer.application_score, 0.0);
        assert!(!peer.goodbye_sent);
        assert!(peer.msg_cache_contains(&seen), "the msg cache is recycled as is");
        mgr.on_disconnected(5, now, "test", &mut |_| {});

        connect(&mut mgr, &mut cap, 5, 1, now);
        let peer = &mgr.peers[&5];
        assert_eq!(peer.application_score, -3.0, "a returning peer gets its archive");
        assert_eq!(peer.topic_stats[&topic].first_deliveries, 4.0);
        assert_eq!(mgr.peers.len(), 1);
    }

    #[test]
    fn a_connection_id_beyond_the_table_is_refused() {
        let now = Instant::now();
        let params = ScoreParams::default();
        let beyond = 2 * params.max_connections();
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, beyond, 1, now);
        assert!(matches!(cap.0.as_slice(), [
            PeerControl::P2pDisconnect { p2p_connection, .. }
        ] if *p2p_connection == beyond));
        assert_eq!(mgr.peers.len(), 0);
    }
}
