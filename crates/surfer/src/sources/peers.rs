//! Per-peer QUIC connection stats, read from the node's `peer_stats` spine
//! queue (broadcast consumer with its own cursor; the tiles are untouched).
//! The network tile samples peers round-robin in small batches, so a row is
//! the latest sample for that connection, not a synchronized snapshot.

use std::{collections::HashMap, path::Path};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{Nanos, P2pConnectionStats, SilverSpine};

/// Rows not re-sampled within this window are dropped — covers a full
/// round-robin sweep of a large peer set plus slack.
const STALE_NS: Nanos = Nanos(10_000_000_000);

pub struct PeerRow {
    pub stats: P2pConnectionStats,
    pub seen: Nanos,
}

#[derive(Default)]
struct PeersTile {
    rows: HashMap<usize, PeerRow>,
}

impl Tile<SilverSpine> for PeersTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume(|stats: P2pConnectionStats, _| {
            self.rows.insert(stats.connection, PeerRow { stats, seen: Nanos::now() });
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
    }

    pub fn rows(&self) -> impl Iterator<Item = &PeerRow> {
        self.tile.rows.values()
    }

    pub fn is_empty(&self) -> bool {
        self.tile.rows.is_empty()
    }
}
