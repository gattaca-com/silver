//! One ClickHouse row per stage observation, Xatu-style: no joining at
//! collection time, every row carries the wall-clock event time and its offset
//! into the slot (`propagation_slot_start_diff`, NULL while syncing/replaying,
//! when the wall clock says nothing about the slot). Per-block timelines,
//! dedup (repeat-head FCUs) and deadline checks are ClickHouse queries over
//! the events, not collector logic.
//!
//! Only `NewPayload` messages carry a slot, so the roots they name are kept
//! for the FCU and verdict rows that follow; a block whose `NewPayload`
//! predates attach records no slot and is left to the query's join.
//!
//! Stages, from the node's spine envelopes:
//! - `received` — `EngineReq::NewPayload` ingestion ≈ gossip arrival.
//! - `el_sent` — the same message's publish: CL validated, dispatched to EL.
//! - `applied` — `EngineReq::Fcu` publish: state transition + commit.
//! - `el_verdict` — `EngineResp::NewPayload` publish, carries the verdict.

use std::{
    mem::take,
    sync::mpsc::{SyncSender, sync_channel},
    thread,
};

use flux::{spine::SpineAdapter, timing::InternalMessage};
use rustc_hash::FxHashMap;
use silver_common::{EngineReq, EngineResp, Nanos, SilverSpine};
use silver_config::ChainConfig;
use tracing::{info, warn};

use crate::clickhouse::ChTable;

const TABLE: &str = "block_events";
const DDL: &str = "CREATE TABLE IF NOT EXISTS block_events (
    event_date_time             DateTime64(9),
    stage                       LowCardinality(String),
    slot                        Nullable(UInt64),
    propagation_slot_start_diff Nullable(Float64),
    block_root                  String,
    source                      LowCardinality(String),
    verdict                     LowCardinality(Nullable(String)),
    meta_client_name            LowCardinality(String)
) ENGINE = MergeTree
ORDER BY (meta_client_name, event_date_time)";

/// Beyond this many slots past the slot start, the wall clock says nothing
/// about the block's slot (replay/backfill); the second slot keeps genuinely
/// late arrivals.
const LIVE_ARRIVAL_SLOTS: u64 = 2;

/// Past this many slots a root is dropped, and an FCU naming it records none.
const TRACKED_SLOTS: u64 = 64;

struct BlockEvents {
    node: String,
    genesis: Nanos,
    slot_dur: Nanos,
    slots: FxHashMap<[u8; 32], u64>,
    pending: Vec<String>,
}

impl BlockEvents {
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

    fn new(node: String, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            node,
            genesis: Nanos::from_secs(genesis_unix_secs),
            slot_dur: Nanos::from_millis(slot_ms.max(1)),
            slots: FxHashMap::default(),
            pending: Vec::new(),
        }
    }

    fn consume(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineReq>, _| {
            self.on_engine_req(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineResp>, _| {
            self.on_engine_resp(m);
        });
    }

    fn offset_ms(&self, t: Nanos, slot: u64) -> Option<f64> {
        let start = self.genesis + self.slot_dur * slot;
        let live = start..start + self.slot_dur * LIVE_ARRIVAL_SLOTS;
        live.contains(&t).then(|| (t - start).0 as f64 / 1e6)
    }

    fn push(&mut self, stage: &str, slot: Option<u64>, root: [u8; 32], ts: Nanos, attrs: Attrs) {
        self.pending.push(
            serde_json::json!({
                "event_date_time": ts.0,
                "stage": stage,
                "slot": slot,
                "propagation_slot_start_diff": slot.and_then(|s| self.offset_ms(ts, s)),
                "block_root": hex::encode(root),
                "source": attrs.source,
                "verdict": attrs.verdict,
                "meta_client_name": self.node,
            })
            .to_string(),
        );
    }

    fn take_batch(&mut self) -> Option<String> {
        (!self.pending.is_empty()).then(|| take(&mut self.pending).join("\n"))
    }

    fn on_engine_req(&mut self, m: &InternalMessage<EngineReq>) {
        match *m.data() {
            EngineReq::NewPayload(req) => {
                self.slots.retain(|_, slot| req.slot.saturating_sub(*slot) < TRACKED_SLOTS);
                self.slots.insert(req.block_root, req.slot);
                let source = format!("{:?}", req.block_source);
                let attrs = Attrs { source: Some(&source), verdict: None };
                let received = m.ingestion_time().real();
                self.push("received", Some(req.slot), req.block_root, received, attrs);
                let el_sent = m.tracking_timestamp().publish_t();
                self.push("el_sent", Some(req.slot), req.block_root, el_sent, attrs);
            }
            EngineReq::Fcu(req) => {
                let slot = self.slots.get(&req.block_root).copied();
                let ts = m.tracking_timestamp().publish_t();
                self.push("applied", slot, req.block_root, ts, Attrs::default());
            }
            _ => {}
        }
    }

    fn on_engine_resp(&mut self, m: &InternalMessage<EngineResp>) {
        let EngineResp::NewPayload(resp) = *m.data() else {
            return;
        };
        let verdict = format!("{:?}", resp.status);
        let attrs = Attrs { source: None, verdict: Some(&verdict) };
        let slot = self.slots.get(&resp.block_root).copied();
        let ts = m.tracking_timestamp().publish_t();
        self.push("el_verdict", slot, resp.block_root, ts, attrs);
    }
}

#[derive(Clone, Copy, Default)]
struct Attrs<'a> {
    source: Option<&'a str>,
    verdict: Option<&'a str>,
}

/// Turns the spine's stage envelopes into ClickHouse inserts. The HTTP leg
/// runs on its own thread: the collector's thread also drains the profiler
/// rings, and it must not stall behind an unreachable ClickHouse.
pub struct BlockEventsInserter {
    events: BlockEvents,
    batches: SyncSender<String>,
}

impl BlockEventsInserter {
    pub fn open(clickhouse_url: &str, chain: &ChainConfig) -> Self {
        let slot_ms = chain.slot_duration().as_millis() as u64;
        let events = BlockEvents::new(BlockEvents::hostname(), chain.genesis_unix_secs, slot_ms);
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
        info!(node = events.node, url = clickhouse_url, "block-events inserter open");
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
    use flux::timing::{IngestionTime, Instant, PublishDelta, TrackingTimestamp};
    use silver_common::{
        BlockSource, EngineFcuReq, EngineNewPayloadReq, EngineNewPayloadResp,
        PayloadValidationStatus, TCache, TCacheProducer, TCacheRead,
    };

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;
    /// Internal-clock ticks between ingestion and publish. Ticks are TSC, so
    /// the nanoseconds they become are calibration-dependent — assert ordering
    /// against the ingestion time, not an exact value.
    const PUBLISH_TICKS: u64 = 10_000_000;

    fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos::from_secs(GENESIS_SECS) + Nanos::from_millis(slot * SLOT_MS + ms_into_slot)
    }

    fn msg<T>(data: T, ingestion: Nanos) -> InternalMessage<T> {
        let ts = TrackingTimestamp {
            ingestion_t: IngestionTime::new(ingestion, Instant(0)),
            publish_delta: PublishDelta::new(0)
                .from_ingestion_and_publish_t(Instant(0), Instant(PUBLISH_TICKS)),
        };
        InternalMessage::new(ts, data)
    }

    fn unread_payload() -> TCacheRead {
        let mut producer = TCache::producer("telemetry_events_test", 1 << 12);
        let mut r = producer.reserve(1, true).expect("tcache reserve");
        r.increment_offset(1);
        r.read()
    }

    fn new_payload(root: [u8; 32], slot: u64, block_source: BlockSource) -> EngineReq {
        EngineReq::NewPayload(EngineNewPayloadReq {
            data: unread_payload(),
            block_root: root,
            slot,
            block_source,
        })
    }

    fn fcu(root: [u8; 32]) -> EngineReq {
        EngineReq::Fcu(EngineFcuReq {
            block_root: root,
            head_block_hash: [0; 32],
            safe_block_hash: [0; 32],
            finalized_block_hash: [0; 32],
        })
    }

    fn verdict(root: [u8; 32], status: PayloadValidationStatus) -> EngineResp {
        EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: root,
            status,
            latest_valid_hash: [0; 32],
        })
    }

    fn events() -> BlockEvents {
        BlockEvents::new("test-node".into(), GENESIS_SECS, SLOT_MS)
    }

    fn json_rows(events: &mut BlockEvents) -> Vec<serde_json::Value> {
        let batch = events.take_batch().expect("rows pending");
        batch.lines().map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    fn row<'a>(rows: &'a [serde_json::Value], stage: &str) -> &'a serde_json::Value {
        rows.iter().find(|r| r["stage"] == stage).unwrap_or_else(|| panic!("no {stage} row"))
    }

    fn stages(rows: &[serde_json::Value]) -> Vec<&str> {
        let mut stages: Vec<_> = rows.iter().map(|r| r["stage"].as_str().unwrap()).collect();
        stages.sort_unstable();
        stages
    }

    #[test]
    fn stages_become_rows() {
        let mut ev = events();
        let root = [1u8; 32];

        ev.on_engine_req(&msg(new_payload(root, 2, BlockSource::Gossip), at(2, 300)));
        ev.on_engine_req(&msg(fcu(root), at(2, 460)));
        ev.on_engine_resp(&msg(verdict(root, PayloadValidationStatus::Valid), at(2, 520)));

        let rows = json_rows(&mut ev);
        assert_eq!(stages(&rows), ["applied", "el_sent", "el_verdict", "received"]);
        assert!(rows.iter().all(|r| r["block_root"] == hex::encode(root)));

        let received = row(&rows, "received");
        assert_eq!(received["slot"], 2);
        assert_eq!(received["source"], "Gossip");
        assert_eq!(received["propagation_slot_start_diff"], 300.0);
        assert_eq!(received["event_date_time"], at(2, 300).0, "arrival is the ingestion clock");

        // The remaining stages are publish observations of their message, so
        // each lands after the ingestion time it was built from.
        let after = |stage, ingested: Nanos| {
            let t = row(&rows, stage)["event_date_time"].as_u64().unwrap();
            assert!(t > ingested.0, "{stage} at {t} must follow its ingestion {}", ingested.0);
        };
        after("el_sent", at(2, 300));
        after("applied", at(2, 460));
        after("el_verdict", at(2, 520));

        assert_eq!(row(&rows, "applied")["slot"], 2);
        assert_eq!(row(&rows, "el_verdict")["slot"], 2);
        assert!(row(&rows, "applied")["propagation_slot_start_diff"].as_f64().unwrap() > 300.0);
        assert_eq!(row(&rows, "el_verdict")["verdict"], "Valid");
    }

    /// Replay/backfill arrivals record every stage but no slot offset — the
    /// wall clock says nothing about the slot, yet stage deltas (sync stf
    /// throughput) stay derivable from `event_date_time`.
    #[test]
    fn syncing_blocks_have_no_offset() {
        let mut ev = events();
        let root = [2u8; 32];

        ev.on_engine_req(&msg(new_payload(root, 7, BlockSource::Rpc), at(900, 4_000)));

        let rows = json_rows(&mut ev);
        let null = serde_json::Value::Null;
        assert!(rows.iter().all(|r| r["propagation_slot_start_diff"] == null), "no slot offset");
        assert_eq!(row(&rows, "received")["event_date_time"], at(900, 4_000).0);
        assert_eq!(row(&rows, "received")["slot"], 7);
    }

    /// FCUs for roots whose NewPayload predates attach are still recorded —
    /// the query resolves what it can and leaves the rest unjoined.
    #[test]
    fn unmatched_fcu_is_recorded() {
        let mut ev = events();
        ev.on_engine_req(&msg(fcu([9u8; 32]), at(2, 460)));

        let rows = json_rows(&mut ev);
        assert_eq!(stages(&rows), ["applied"]);
        assert_eq!(row(&rows, "applied")["block_root"], hex::encode([9u8; 32]));
        assert_eq!(row(&rows, "applied")["slot"], serde_json::Value::Null);
    }
}
