use std::collections::HashMap;

use silver_common::{
    ClusterLinkStats, ClusterPeerStats, P2pConnectionStats, PeerId, PeerScores, PeerStats,
    PeerTopicScores,
};
use silver_observe_wire::Encoder;

use crate::exporter::streams::{cluster_peer_record, p2p_record, scores_record, topic_record};

/// Newest peer stats per key since the last `encode`. The node reports p2p
/// stats every 100 ms and scores every peer-manager tick; the dashboard shows
/// only current values and cumulative totals, so older records add nothing.
#[derive(Default)]
pub(super) struct LatestPeerStats {
    p2p: HashMap<(PeerId, usize), P2pConnectionStats>,
    scores: HashMap<PeerId, PeerScores>,
    topics: HashMap<(PeerId, usize), PeerTopicScores>,
    cluster: HashMap<u64, ClusterPeerStats>,
    /// Kept across encodes: a Raft row joins the newest link sample, which
    /// arrives from another tile on its own schedule.
    cluster_links: HashMap<u64, ClusterLinkStats>,
}

impl LatestPeerStats {
    pub fn record(&mut self, stats: &PeerStats) {
        match stats {
            PeerStats::P2p(s) => {
                self.p2p.insert((s.id, s.connection), *s);
            }
            PeerStats::Scores(s) => {
                self.scores.insert(s.id, *s);
            }
            PeerStats::Topic(s) => {
                self.topics.insert((s.id, s.topic.counter_slot()), *s);
            }
            PeerStats::Cluster(s) => {
                self.cluster.insert(s.node_id, *s);
            }
            PeerStats::ClusterLink(s) => {
                self.cluster_links.insert(s.node_id, *s);
            }
        }
    }

    /// Drains, so a peer that stops reporting stops being sent and ages out
    /// of the dashboard.
    pub fn encode(&mut self, enc: &mut Encoder, ts_ns: u64, emit: &mut impl FnMut(&[u8])) {
        for (_, s) in self.p2p.drain() {
            enc.peer_p2p(ts_ns, &p2p_record(&s), emit);
        }
        for (_, s) in self.scores.drain() {
            enc.peer_scores(ts_ns, &scores_record(&s), emit);
        }
        for (_, s) in self.topics.drain() {
            enc.peer_topic(ts_ns, &topic_record(&s), emit);
        }
        for (node_id, s) in self.cluster.drain() {
            let record = cluster_peer_record(&s, self.cluster_links.get(&node_id));
            enc.cluster_peer(ts_ns, &record, emit);
        }
    }
}
