use std::{collections::HashMap, time::Instant};

use silver_common::{GossipTopic, Nanos, PeerId};

use super::PeerManager;
use crate::PeerCounters;

struct DeliveryCredit {
    credited: bool,
    last_invalid: Option<Nanos>,
    expires: Instant,
}

pub(super) struct ColumnDeliveries {
    entries: HashMap<(PeerId, [u8; 32], u64), DeliveryCredit>,
}

impl ColumnDeliveries {
    pub(super) fn new() -> Self {
        Self { entries: HashMap::with_capacity(8192) }
    }
    pub(super) fn expire(&mut self, now: Instant) {
        self.entries.retain(|_, credit| now < credit.expires);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PartialPeer {
    pub connection: usize,
    pub requests: bool,
    pub meshed: bool,
}

impl PeerManager {
    pub(super) fn on_column_verdict(
        &mut self,
        conn: usize,
        root: [u8; 32],
        column: u64,
        received: Nanos,
        accepted: bool,
        now: Instant,
    ) {
        if column >= 128 {
            return;
        }
        let Some(peer) = self.peers.get(&conn) else { return };
        let key = (peer.peer_id, root, column);
        if self.column_deliveries.entries.len() >= 8192 &&
            !self.column_deliveries.entries.contains_key(&key)
        {
            return;
        }
        let credit = self.column_deliveries.entries.entry(key).or_insert(DeliveryCredit {
            credited: false,
            last_invalid: None,
            expires: now + self.params.score_decay_interval * 2,
        });
        let topic = GossipTopic::DataColumnSidecar(column);
        if accepted {
            if credit.credited {
                return;
            }
            credit.credited = true;
            if let Some(peer) = self.peers.get_mut(&conn) {
                peer.topic_stats.entry(topic).or_default().first_deliveries += 1.0;
            }
            self.credit_mesh_delivery(conn, topic);
        } else if credit.last_invalid.is_none_or(|last| received.0 > last.0) {
            // Deferred cells can resolve out of order. Under-penalize older frames
            // rather than penalizing one frame repeatedly across validation batches.
            credit.last_invalid = Some(received);
            PeerCounters::GossipInvalidMsg.inc();
            self.add_invalid_delivery(conn, topic);
        }
    }

    pub fn partial_peer(
        &self,
        connection: usize,
        topic: GossipTopic,
        digest: [u8; 4],
    ) -> Option<PartialPeer> {
        if !self.active_gossip_digests.contains(&Some(digest)) || !self.our_topics.contains(&topic)
        {
            return None;
        }
        let peer = self.peers.get(&connection)?;
        let caps = peer.subscriptions.get(&(digest, topic))?;
        if !peer.partial_extensions ||
            !caps.supports_sending ||
            peer.gossip_gate_score() < self.params.gossip_threshold
        {
            return None;
        }
        Some(PartialPeer {
            connection,
            requests: caps.requests,
            meshed: self
                .mesh
                .get(&topic)
                .and_then(|m| m.get(digest))
                .is_some_and(|m| m.peers.contains(&connection)),
        })
    }

    pub fn partial_peers(
        &self,
        topic: GossipTopic,
        digest: [u8; 4],
    ) -> impl Iterator<Item = PartialPeer> + '_ {
        self.peers.keys().filter_map(move |&peer| self.partial_peer(peer, topic, digest))
    }

    pub fn lazy_gossip_limit(&self) -> usize {
        self.params.d_lazy as usize
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{MessageId, TCache, TCacheProducer};

    use super::*;
    use crate::manager::fixture::{connect, fixture};

    #[test]
    fn full_and_partial_deliveries_share_credit_and_reordered_invalid_cells_cannot_multiply_penalties()
     {
        let topic = GossipTopic::DataColumnSidecar(3);
        let now = Instant::now();
        let (mut manager, mut captured) = fixture(vec![topic], Default::default());
        connect(&mut manager, &mut captured, 1, 1, now);
        let root = [7; 32];
        manager.on_column_verdict(1, root, 3, Nanos(1), true, now);
        manager.on_column_verdict(1, root, 3, Nanos(2), true, now);
        let mut cache = TCache::producer("", 1 << 14);
        let idontwant = cache.reserve(1, false).unwrap().read();
        manager.on_new_gossip(
            1,
            topic,
            MessageId { id: [0; 20] },
            Nanos(3),
            idontwant,
            &mut |_| {},
        );
        assert_eq!(manager.peers[&1].topic_stats[&topic].first_deliveries, 1.0);
        for received in [4, 4, 5, 4, 5] {
            manager.on_column_verdict(1, root, 3, Nanos(received), false, now);
        }
        assert_eq!(manager.peers[&1].topic_stats[&topic].invalid_deliveries, 2.0);
        manager.on_column_verdict(1, [8; 32], 3, Nanos(6), true, now);
        assert_eq!(manager.peers[&1].topic_stats[&topic].first_deliveries, 2.0);
        manager.column_deliveries.expire(now + manager.params.score_decay_interval * 2);
        assert!(manager.column_deliveries.entries.is_empty());
    }
}
