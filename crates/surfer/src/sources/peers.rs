//! Per-peer stats, read from the node's `peer_stats` spine queue (broadcast
//! consumer with its own cursor; the tiles are untouched). Two producers feed
//! it: the network tile samples QUIC connection stats round-robin in small
//! batches, and the control tile emits gossipsub score breakdowns each PM
//! tick. Rows merge both by `PeerId`; each side is the latest sample, not a
//! synchronized snapshot.

use std::{collections::HashMap, path::Path};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    GossipTopic, Nanos, P2pConnectionStats, PeerId, PeerScores, PeerStats, PeerTopicScores,
    SilverSpine,
};

/// Rows not re-sampled within this window are dropped — covers a full
/// round-robin sweep of a large peer set plus slack.
const STALE_NS: Nanos = Nanos(10_000_000_000);

#[derive(Default)]
pub struct PeerRow {
    pub p2p: Option<P2pConnectionStats>,
    pub scores: Option<PeerScores>,
    pub topics: HashMap<GossipTopic, (PeerTopicScores, Nanos)>,
    seen: Nanos,
    scores_seen: Nanos,
}

impl PeerRow {
    /// Meshed topics, name-sorted for stable display.
    pub fn sorted_topics(&self) -> Vec<&PeerTopicScores> {
        let mut topics: Vec<_> = self.topics.values().map(|(t, _)| t).collect();
        topics.sort_by_key(|t| t.topic.to_string());
        topics
    }
}

#[derive(Default)]
struct PeersTile {
    rows: HashMap<PeerId, PeerRow>,
}

impl Tile<SilverSpine> for PeersTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|stats: PeerStats, _| {
            let id = match &stats {
                PeerStats::P2p(s) => s.id,
                PeerStats::Scores(s) => s.id,
                PeerStats::Topic(s) => s.id,
            };
            let now = Nanos::now();
            let row = self.rows.entry(id).or_default();
            row.seen = now;
            match stats {
                PeerStats::P2p(s) => row.p2p = Some(s),
                PeerStats::Scores(s) => {
                    row.scores = Some(s);
                    row.scores_seen = now;
                }
                PeerStats::Topic(s) => {
                    row.topics.insert(s.topic, (s, now));
                }
            }
        });
    }
}

pub struct Peers {
    tile: PeersTile,
    adapter: SpineAdapter<SilverSpine>,
}

impl Peers {
    pub fn open(base_dir: &Path) -> Self {
        let tile = PeersTile::default();
        let mut spine = SilverSpine::new_with_base_dir(base_dir, None);
        let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        Self { tile, adapter }
    }

    pub fn sample(&mut self) {
        self.tile.loop_body(&mut self.adapter);
        let now = Nanos::now();
        self.tile.rows.retain(|_, r| now.saturating_sub(r.seen) < STALE_NS);
        for r in self.tile.rows.values_mut() {
            r.topics.retain(|_, (_, seen)| now.saturating_sub(*seen) < STALE_NS);
            // A row kept alive by connection stats alone must not keep
            // showing a dead producer's last score snapshot.
            if r.scores.is_some() && now.saturating_sub(r.scores_seen) >= STALE_NS {
                r.scores = None;
            }
        }
    }

    pub fn rows(&self) -> impl Iterator<Item = (&PeerId, &PeerRow)> {
        self.tile.rows.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.tile.rows.is_empty()
    }
}
