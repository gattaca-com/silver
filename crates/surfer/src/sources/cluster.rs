//! Raft voters, from the same `peer_stats` queue as the gossip peers. The
//! control tile reports each voter's Raft progress and the network tile its
//! connection, both once a second; rows join the two by node id.

use std::collections::BTreeMap;

use silver_common::{ClusterLinkStats, ClusterPeerStats, Nanos};

const STALE_NS: Nanos = Nanos(5_000_000_000);

#[derive(Default)]
pub struct ClusterPeerRow {
    pub raft: Option<ClusterPeerStats>,
    pub link: Option<ClusterLinkStats>,
    raft_seen: Nanos,
    link_seen: Nanos,
}

#[derive(Default)]
pub struct ClusterRows {
    rows: BTreeMap<u64, ClusterPeerRow>,
}

impl ClusterRows {
    pub fn record_raft(&mut self, stats: ClusterPeerStats, now: Nanos) {
        let row = self.rows.entry(stats.node_id).or_default();
        row.raft = Some(stats);
        row.raft_seen = now;
    }

    pub fn record_link(&mut self, stats: ClusterLinkStats, now: Nanos) {
        let row = self.rows.entry(stats.node_id).or_default();
        row.link = Some(stats);
        row.link_seen = now;
    }

    pub fn expire(&mut self, now: Nanos) {
        for row in self.rows.values_mut() {
            if now.saturating_sub(row.raft_seen) >= STALE_NS {
                row.raft = None;
            }
            if now.saturating_sub(row.link_seen) >= STALE_NS {
                row.link = None;
            }
        }
        self.rows.retain(|_, row| row.raft.is_some() || row.link.is_some());
    }

    pub fn iter(&self) -> impl Iterator<Item = (&u64, &ClusterPeerRow)> {
        self.rows.iter()
    }
}
