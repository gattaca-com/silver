//! One ClickHouse row per stage event: no joining at collection time,
//! every row carries the wall-clock event time and its offset into the slot
//! (`time_into_slot_ms`, NULL while syncing/replaying, when the wall clock says
//! nothing about the slot). Per-block timelines, dedup (repeat-head FCUs) and
//! deadline checks are ClickHouse queries over the events, not collector
//! logic.

use serde::Serialize;
use silver_stages::{Stage, StageEvent};

use crate::node_meta::NodeMeta;

pub const TABLE: &str = "block_events";

pub const DDL: &str = "CREATE TABLE IF NOT EXISTS block_events (
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

#[derive(Serialize)]
pub struct BlockEventRow<'a> {
    event_date_time: u64,
    stage: &'static str,
    slot: Option<u64>,
    slot_start_date_time: Option<u32>,
    time_into_slot_ms: Option<f64>,
    block_root: String,
    source: String,
    verdict: Option<String>,
    column_index: Option<u64>,
    meta_client_name: &'a str,
    meta_network_name: &'a str,
}

impl<'a> BlockEventRow<'a> {
    pub fn new(event: &StageEvent, meta: &'a NodeMeta) -> Self {
        let (source, verdict, column_index) = match event.stage {
            Stage::Received { source } | Stage::ElSent { source } => {
                (format!("{source:?}"), None, None)
            }
            Stage::ColumnRecv { index, origin } | Stage::ColumnValidated { index, origin } => {
                (format!("{origin:?}"), None, Some(index))
            }
            Stage::ElVerdict { verdict } => (String::new(), Some(format!("{verdict:?}")), None),
            Stage::StfDone | Stage::Attestable | Stage::DaAvailable | Stage::CustodyDone => {
                (String::new(), None, None)
            }
        };
        Self {
            event_date_time: event.ts.0,
            stage: event.stage.name(),
            slot: event.slot,
            slot_start_date_time: event.slot.map(|s| meta.clock.slot_start(s).as_secs_u64() as u32),
            time_into_slot_ms: event
                .slot
                .and_then(|s| meta.clock.offset_in_slot(event.ts, s))
                .map(|d| d.0 as f64 / 1e6),
            block_root: format!("0x{}", hex::encode(event.block_root)),
            source,
            verdict,
            column_index,
            meta_client_name: &meta.node,
            meta_network_name: &meta.network,
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{BlockSource, ColumnOrigin, Nanos, PayloadValidationStatus};
    use silver_stages::SlotClock;

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
        let meta = NodeMeta {
            node: "test-node".into(),
            network: "test-net".into(),
            clock: SlotClock::new(GENESIS_SECS, SLOT_MS),
            version: String::new(),
        };
        serde_json::to_value(BlockEventRow::new(event, &meta)).unwrap()
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
        let column = Stage::ColumnRecv { index: 48, origin: ColumnOrigin::El };
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
