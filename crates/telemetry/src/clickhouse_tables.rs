use std::{net::SocketAddr, time::Duration};

use flux::spine::SpineAdapter;
use flux_clickhouse::{ClickHouse, Error};
use flux_network::Network;
use serde::Serialize;
use silver_common::{Nanos, NodeChain, SilverSpine};
use silver_log::{info, warn};
use silver_stages::StageReader;

use crate::{
    block_events::{self, BlockEventRow},
    counters::{self, Counters},
    log_counts::{self, LogCounts},
    node_meta::NodeMeta,
};

/// Bounds the daemon's memory while ClickHouse is unreachable; batches past it
/// are dropped.
const MAX_QUEUED_BYTES: usize = 64 << 20;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const UNKNOWN_TABLE: i32 = 60;

/// Every table the daemon feeds, over one non-blocking native-protocol
/// connection driven from the tile loop.
pub struct ClickHouseTables {
    net: Network,
    client: ClickHouse,
    meta: NodeMeta,
    slot: u64,
    stage_reader: StageReader,
    log_counts: LogCounts,
    counters: Counters,
}

impl ClickHouseTables {
    pub fn open(addr: SocketAddr, chain: &NodeChain) -> Self {
        let mut net = Network::default();
        let mut client = ClickHouse::new(addr, 1)
            .with_compression()
            .with_max_queued_bytes(MAX_QUEUED_BYTES)
            .with_request_timeout(REQUEST_TIMEOUT);
        client.connect(&mut net);
        let meta = NodeMeta::new(chain);
        info!(node = meta.node, network = meta.network, %addr, "clickhouse inserts open");

        let mut tables = Self {
            net,
            client,
            slot: meta.clock.slot_at(Nanos::now()),
            meta,
            stage_reader: StageReader::default(),
            log_counts: LogCounts::default(),
            counters: Counters::default(),
        };
        tables.create();
        tables
    }

    pub fn node_restarted(&mut self) {
        self.log_counts.node_restarted();
    }

    /// Every statement must be a no-op the second time it runs: all of them run
    /// again when an insert finds its table missing, so a table whose DDL was
    /// lost or that was dropped under the daemon comes back.
    fn create(&mut self) {
        for stmt in [block_events::DDL, log_counts::DDL, counters::DDL] {
            if self.client.query(stmt).is_none() {
                warn!(stmt, "clickhouse queue full; DDL dropped");
            }
        }
    }

    pub fn sample(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.net.poll_with(|event| {
            self.client.on_event(&event);
        });
        self.queue_block_events(adapter);
        self.queue_slot_counters();
        self.drive();
    }

    fn queue_block_events(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let rows: Vec<_> = self
            .stage_reader
            .consume(adapter)
            .map(|event| BlockEventRow::new(&event, &self.meta))
            .collect();
        queue(&mut self.client, block_events::TABLE, &rows);
    }

    /// Counts are read once per slot and filed under the slot that just ended.
    fn queue_slot_counters(&mut self) {
        let slot = self.meta.clock.slot_at(Nanos::now());
        if slot == self.slot {
            return;
        }
        let ended = self.slot;
        self.slot = slot;
        self.meta.refresh_version();
        let rows = self.log_counts.rows(ended, &self.meta);
        queue(&mut self.client, log_counts::TABLE, &rows);
        let rows = self.counters.rows(ended, &self.meta);
        queue(&mut self.client, counters::TABLE, &rows);
    }

    fn drive(&mut self) {
        let mut table_missing = false;
        self.client.drive(&mut self.net, |_, outcome| {
            if let Err(e) = outcome {
                warn!(?e, "clickhouse request failed");
                table_missing |= matches!(e, Error::Server { code: UNKNOWN_TABLE, .. });
            }
        });
        if table_missing {
            self.create();
        }
    }
}

fn queue<T: Serialize>(client: &mut ClickHouse, table: &str, rows: &[T]) {
    if !rows.is_empty() && client.insert_rows(table, rows).is_err() {
        warn!(table, rows = rows.len(), "clickhouse queue full; batch dropped");
    }
}
