use fxhash::FxHashMap;
use silver_common::GossipTopic;

type TopicKey = ([u8; 4], GossipTopic);

/// Live connections per `(digest, topic)` they announced SUBSCRIBE for: the
/// inverse of each peer's `subscriptions`, so a topic's subscribers are found
/// without a walk over every peer.
#[derive(Default)]
pub(super) struct TopicSubscribers(FxHashMap<TopicKey, Vec<usize>>);

impl TopicSubscribers {
    pub(super) fn of(&self, digest: [u8; 4], topic: GossipTopic) -> &[usize] {
        self.0.get(&(digest, topic)).map_or(&[], Vec::as_slice)
    }

    pub(super) fn add(&mut self, key: TopicKey, conn: usize) {
        let subscribers = self.0.entry(key).or_default();
        debug_assert!(!subscribers.contains(&conn), "{conn} subscribed twice to {key:?}");
        subscribers.push(conn);
    }

    pub(super) fn remove(&mut self, key: &TopicKey, conn: usize) {
        if let Some(subscribers) = self.0.get_mut(key) &&
            let Some(index) = subscribers.iter().position(|&c| c == conn)
        {
            subscribers.swap_remove(index);
        }
    }

    pub(super) fn remove_peer<'k>(
        &mut self,
        keys: impl Iterator<Item = &'k TopicKey>,
        conn: usize,
    ) {
        for key in keys {
            self.remove(key, conn);
        }
    }

    pub(super) fn retain_topics(&mut self, mut keep: impl FnMut(&TopicKey) -> bool) {
        self.0.retain(|key, _| keep(key));
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use silver_common::GossipTopic;
    use silver_config::ScoreParams;

    use crate::manager::{PeerManager, fixture::*};

    const OLD: [u8; 4] = [0; 4];
    const NEW: [u8; 4] = [1; 4];
    const TOPIC: GossipTopic = GossipTopic::BeaconBlock;

    /// The index holds exactly the live peers' announced subscriptions.
    fn assert_mirrors_peers(mgr: &PeerManager) {
        let mut announced = 0;
        for (conn, peer) in mgr.peers.iter() {
            for &(digest, topic) in peer.subscriptions.keys() {
                assert!(mgr.subscribers.of(digest, topic).contains(&conn), "{conn} {topic:?}");
                announced += 1;
            }
        }
        let indexed: usize = mgr.subscribers.0.values().map(Vec::len).sum();
        assert_eq!(indexed, announced);
    }

    #[test]
    fn index_follows_subscriptions_domains_and_disconnects() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![TOPIC], ScoreParams::default());
        mgr.set_active_domains(OLD, Some(NEW), &mut |_| {});
        for conn in 1..=3 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.on_subscribe(conn, TOPIC, OLD, now, &mut |_| {});
            mgr.on_subscribe(conn, TOPIC, NEW, now, &mut |_| {});
        }
        mgr.on_subscribe(1, TOPIC, OLD, now, &mut |_| {});
        assert_eq!(mgr.subscribers.of(OLD, TOPIC).len(), 3, "a repeat is not indexed twice");
        assert_mirrors_peers(&mgr);

        mgr.on_unsubscribe(2, TOPIC, OLD, now, &mut |_| {});
        assert_eq!(mgr.subscribers.of(OLD, TOPIC).len(), 2);
        assert_mirrors_peers(&mgr);

        mgr.on_disconnected(1, now, "test", &mut |_| {});
        mgr.on_p2p_peer_goodbye(3, now, 1, &mut |_| {});
        assert_eq!(mgr.subscribers.of(NEW, TOPIC), [2]);
        assert_mirrors_peers(&mgr);

        mgr.set_active_domains(NEW, None, &mut |_| {});
        mgr.run_sweep(now, &mut |_| {});
        assert!(mgr.subscribers.of(OLD, TOPIC).is_empty());
        assert_eq!(mgr.subscribers.of(NEW, TOPIC), [2]);
        assert_mirrors_peers(&mgr);
    }
}
