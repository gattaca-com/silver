use std::{collections::HashMap, time::Instant};

use silver_common::{GossipTopic, Nanos, PeerId};

use super::PeerManager;
use crate::PeerCounters;

const MAX_COLUMN_DELIVERIES: usize = 8192;

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
        Self { entries: HashMap::with_capacity(MAX_COLUMN_DELIVERIES) }
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
        let topic = GossipTopic::DataColumnSidecar(column);
        // Rejections cost a sender nothing to produce, so they may only fill
        // half the table; credits keep the rest. Without an entry a rejection
        // still penalises, only without the per-frame dedup.
        let limit = if accepted { MAX_COLUMN_DELIVERIES } else { MAX_COLUMN_DELIVERIES / 2 };
        if self.column_deliveries.entries.len() >= limit &&
            !self.column_deliveries.entries.contains_key(&key)
        {
            if !accepted {
                PeerCounters::GossipInvalidMsg.inc();
                self.add_invalid_delivery(conn, topic);
            }
            return;
        }
        let credit = self.column_deliveries.entries.entry(key).or_insert(DeliveryCredit {
            credited: false,
            last_invalid: None,
            expires: now + self.params.score_decay_interval * 2,
        });
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
        self.subscribers
            .of(digest, topic)
            .iter()
            .filter_map(move |&peer| self.partial_peer(peer, topic, digest))
    }

    /// The peer offered cells for a partial request and did not send them in
    /// time. As a broken IHAVE promise, P7 absorbs the occasional honest miss.
    pub fn on_broken_partial_offer(&mut self, conn: usize) {
        self.add_behaviour_penalty(conn, 1.0, "partial offer not delivered");
    }

    pub fn lazy_gossip_limit(&self) -> usize {
        self.params.d_lazy as usize
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{MessageId, TCache, TCacheId, TCacheProducer};

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
        let mut cache = TCache::producer(TCacheId::NetworkIngress, 1 << 14);
        let idontwant = cache.reserve(1, false).unwrap().descriptor();
        manager.on_new_gossip(
            1,
            topic,
            MessageId { id: [0; 20] },
            Nanos(3),
            Some(idontwant),
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

    #[test]
    fn rejections_cannot_crowd_out_credit_or_escape_penalty() {
        let topic = GossipTopic::DataColumnSidecar(3);
        let now = Instant::now();
        let mut params = silver_config::ScoreParams::default();
        params.graylist_threshold = f64::MIN;
        let (mut manager, mut captured) = fixture(vec![topic], params);
        connect(&mut manager, &mut captured, 1, 1, now);
        connect(&mut manager, &mut captured, 2, 2, now);

        let root = |i: usize| {
            let mut root = [0; 32];
            root[..8].copy_from_slice(&i.to_le_bytes());
            root
        };
        let flood = MAX_COLUMN_DELIVERIES;
        for i in 0..flood {
            manager.on_column_verdict(1, root(i), 3, Nanos(1), false, now);
        }
        assert_eq!(manager.column_deliveries.entries.len(), MAX_COLUMN_DELIVERIES / 2);
        assert_eq!(
            manager.peers[&1].topic_stats[&topic].invalid_deliveries, flood as f64,
            "rejections past the table still penalise"
        );

        manager.on_column_verdict(2, root(flood), 3, Nanos(1), true, now);
        assert_eq!(manager.peers[&2].topic_stats[&topic].first_deliveries, 1.0);
    }
}
