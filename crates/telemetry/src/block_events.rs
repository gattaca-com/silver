//! One ClickHouse row per stage event: no joining at collection time,
//! every row carries the wall-clock event time and its offset into the slot
//! (`time_into_slot_ms`, NULL while syncing/replaying, when the wall clock says
//! nothing about the slot). Per-block timelines, dedup (repeat-head FCUs) and
//! deadline checks are ClickHouse queries over the events, not collector
//! logic.
//!
//! The `block_events_xatu` view renames the one comparable stage onto
//! ethPandaOps' Xatu columns, so these rows and Xatu's published parquet can be
//! read as one dataset.

use std::{
    mem::take,
    sync::mpsc::{SyncSender, sync_channel},
    thread,
};

use flux::spine::SpineAdapter;
use silver_common::SilverSpine;
use silver_config::ChainConfig;
use silver_stages::{SlotClock, Stage, StageEvent, StageReader};
use tracing::{info, warn};

use crate::clickhouse::ChTable;

const TABLE: &str = "block_events";

/// Run in order on every start, so a table an older build created catches up:
/// `CREATE TABLE IF NOT EXISTS` alone would no-op and leave the new columns
/// missing, which `input_format_skip_unknown_fields` then drops from each row
/// without failing the insert. Every statement has to be a no-op the second
/// time it runs, and a new one goes after the last `ALTER` but ahead of the
/// views, which read the columns the alters produce.
const DDL: &[&str] = &[
    TABLE_DDL,
    "ALTER TABLE block_events RENAME COLUMN IF EXISTS propagation_slot_start_diff TO time_into_slot_ms",
    "ALTER TABLE block_events ADD COLUMN IF NOT EXISTS slot_start_date_time Nullable(DateTime) AFTER slot",
    "ALTER TABLE block_events ADD COLUMN IF NOT EXISTS meta_network_name LowCardinality(String)",
    "ALTER TABLE block_events ADD COLUMN IF NOT EXISTS column_index Nullable(UInt64)",
    XATU_VIEW_DDL,
];

const TABLE_DDL: &str = "CREATE TABLE IF NOT EXISTS block_events (
    event_date_time      DateTime64(9)                    COMMENT 'Node-local wall clock at the observation',
    stage                LowCardinality(String)           COMMENT 'Point in the block path through the node this row observes',
    slot                 Nullable(UInt64)                 COMMENT 'NULL when the root was first seen before the collector attached',
    slot_start_date_time Nullable(DateTime)               COMMENT 'Wall clock the slot started at',
    time_into_slot_ms    Nullable(Float64)                COMMENT 'Milliseconds from slot start; NULL outside the live window (replay or backfill)',
    block_root           String                           COMMENT '0x-prefixed beacon block root; rows written before 2026-08-18 lack the prefix',
    source               LowCardinality(String)           COMMENT 'How the node obtained the block',
    verdict              LowCardinality(Nullable(String)) COMMENT 'Execution payload status; set on el_verdict rows only',
    column_index         Nullable(UInt64)                 COMMENT 'Data-column index; set on column_* rows only',
    meta_client_name     LowCardinality(String)           COMMENT 'Hostname of the node that produced the row',
    meta_network_name    LowCardinality(String)           COMMENT 'Ethereum network the node is running'
) ENGINE = MergeTree
ORDER BY (meta_client_name, event_date_time)";

/// The mapping onto Xatu's `beacon_api_eth_v1_events_block` columns, so a query
/// can union these rows with ethPandaOps' parquet. Only `received` is an
/// observation of the network; the other stages time silver's own pipeline, and
/// Xatu's `propagation_slot_start_diff` — arrival at a sentry — has no
/// counterpart for them.
const XATU_VIEW_DDL: &str = "CREATE OR REPLACE VIEW block_events_xatu AS
SELECT
    event_date_time,
    slot,
    slot_start_date_time,
    time_into_slot_ms AS propagation_slot_start_diff,
    block_root        AS block,
    meta_client_name,
    meta_network_name
FROM block_events
WHERE stage = 'received' AND time_into_slot_ms IS NOT NULL";

struct BlockEvents {
    reader: StageReader,
    formatter: RowFormatter,
    pending: Vec<String>,
}

impl BlockEvents {
    fn new(formatter: RowFormatter) -> Self {
        Self { reader: StageReader::default(), formatter, pending: Vec::new() }
    }

    fn consume(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        for event in self.reader.consume(adapter) {
            self.pending.push(self.formatter.row(&event));
        }
    }

    fn take_batch(&mut self) -> Option<String> {
        (!self.pending.is_empty()).then(|| take(&mut self.pending).join("\n"))
    }
}

/// The per-node constants joined onto every row.
struct RowFormatter {
    node: String,
    network: String,
    clock: SlotClock,
}

impl RowFormatter {
    /// Fills `node`, i.e. `meta_client_name`: rows from every machine land in
    /// one table.
    fn hostname() -> String {
        let mut buf = [0u8; 256];
        if unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) } != 0 {
            return "unknown".to_owned();
        }
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).into_owned()
    }

    fn row(&self, event: &StageEvent) -> String {
        let (source, verdict, column_index) = match event.stage {
            Stage::Received { source } | Stage::ElSent { source } => {
                (Some(format!("{source:?}")), None, None)
            }
            Stage::ColumnRecv { index, source } | Stage::ColumnValidated { index, source } => {
                (Some(format!("{source:?}")), None, Some(index))
            }
            Stage::ElVerdict { verdict } => (None, Some(format!("{verdict:?}")), None),
            Stage::Applied | Stage::DaAvailable => (None, None, None),
        };
        serde_json::json!({
            "event_date_time": event.ts.0,
            "stage": event.stage.name(),
            "slot": event.slot,
            "slot_start_date_time": event.slot.map(|s| self.clock.slot_start(s).as_secs_u64()),
            "time_into_slot_ms": event
                .slot
                .and_then(|s| self.clock.offset_in_slot(event.ts, s))
                .map(|d| d.0 as f64 / 1e6),
            "block_root": format!("0x{}", hex::encode(event.block_root)),
            "source": source,
            "verdict": verdict,
            "column_index": column_index,
            "meta_client_name": self.node,
            "meta_network_name": self.network,
        })
        .to_string()
    }
}

/// Turns the spine stage events into ClickHouse inserts. The HTTP leg
/// runs on its own thread: the collector's thread also drains the profiler
/// rings, and it must not stall behind an unreachable ClickHouse.
pub struct BlockEventsInserter {
    events: BlockEvents,
    batches: SyncSender<String>,
}

impl BlockEventsInserter {
    pub fn open(clickhouse_url: &str, chain: &ChainConfig) -> Self {
        let slot_ms = chain.slot_duration().as_millis() as u64;
        let events = BlockEvents::new(RowFormatter {
            node: RowFormatter::hostname(),
            network: chain.spec.network_name(),
            clock: SlotClock::new(chain.genesis_unix_secs, slot_ms),
        });
        let (batches, rx) = sync_channel::<String>(256);
        let mut table = ChTable::new(clickhouse_url, TABLE, DDL);
        // TODO: the only reason the daemon runs a second thread. `ureq` blocks
        // for up to its read timeout, which the drain loop cannot afford; a
        // non-blocking send would let this run inline like everything else.
        thread::spawn(move || {
            for batch in rx {
                table.insert(&batch);
            }
        });
        info!(
            node = events.formatter.node,
            network = events.formatter.network,
            url = clickhouse_url,
            "block-events inserter open"
        );
        Self { events, batches }
    }

    /// Whatever the loop drained this iteration is one batch.
    pub fn sample(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.events.consume(adapter);
        let Some(batch) = self.events.take_batch() else {
            return;
        };
        let bytes = batch.len();
        if self.batches.try_send(batch).is_err() {
            warn!(bytes, "insert queue full; batch dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{BlockSource, ColumnSource, Nanos, PayloadValidationStatus};

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;

    fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos::from_secs(GENESIS_SECS) + Nanos::from_millis(slot * SLOT_MS + ms_into_slot)
    }

    fn event(stage: Stage, ts: Nanos, slot: Option<u64>) -> StageEvent {
        StageEvent { stage, ts, block_root: [1u8; 32], slot }
    }

    fn json(event: &StageEvent) -> serde_json::Value {
        let formatter = RowFormatter {
            node: "test-node".into(),
            network: "test-net".into(),
            clock: SlotClock::new(GENESIS_SECS, SLOT_MS),
        };
        serde_json::from_str(&formatter.row(event)).unwrap()
    }

    #[test]
    fn event_becomes_a_row() {
        let received = Stage::Received { source: BlockSource::Gossip };
        let r = json(&event(received, at(2, 300), Some(2)));
        assert_eq!(r["stage"], "received");
        assert_eq!(r["slot"], 2);
        assert_eq!(r["source"], "Gossip");
        assert_eq!(r["time_into_slot_ms"], 300.0);
        assert_eq!(r["slot_start_date_time"], at(2, 0).as_secs_u64());
        assert_eq!(r["event_date_time"], at(2, 300).0);
        assert_eq!(r["block_root"], format!("0x{}", hex::encode([1u8; 32])));
        assert_eq!(r["meta_client_name"], "test-node");
        assert_eq!(r["meta_network_name"], "test-net");
    }

    #[test]
    fn optional_attributes_fill_their_columns() {
        let column = Stage::ColumnRecv { index: 48, source: ColumnSource::El };
        let r = json(&event(column, at(3, 1_400), Some(3)));
        assert_eq!(r["stage"], "column_recv");
        assert_eq!(r["source"], "El");
        assert_eq!(r["column_index"], 48);

        let verdict = Stage::ElVerdict { verdict: PayloadValidationStatus::Valid };
        let r = json(&event(verdict, at(3, 1_500), None));
        assert_eq!(r["verdict"], "Valid");
        assert_eq!(r["slot"], serde_json::Value::Null);
        assert_eq!(r["slot_start_date_time"], serde_json::Value::Null);
    }

    /// Replay/backfill arrivals record every stage but no slot offset — the
    /// wall clock says nothing about the slot, yet stage deltas (sync stf
    /// throughput) stay derivable from `event_date_time`.
    #[test]
    fn syncing_rows_have_no_offset() {
        let received = Stage::Received { source: BlockSource::Rpc };
        let r = json(&event(received, at(900, 4_000), Some(7)));
        assert_eq!(r["time_into_slot_ms"], serde_json::Value::Null);
        assert_eq!(r["event_date_time"], at(900, 4_000).0);
        // The slot is known, so its start is too — only the offset between the
        // two is meaningless here.
        assert_eq!(r["slot_start_date_time"], at(7, 0).as_secs_u64());
    }
}
