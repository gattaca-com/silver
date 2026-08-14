//! Per-block pipeline timeline, read from the node's own spine queues. Surfer
//! joins the spine as a broadcast consumer (its own cursor; the tiles are
//! untouched) and derives each stage's wall time from the `InternalMessage`
//! envelope: `ingestion_t` is copied verbatim as a block flows tile→tile, and
//! `publish_delta` records how long after ingestion each stage published.
//!
//! Two queues carry everything, keyed by block root:
//! - `EngineReq::NewPayload` — ingestion time ≈ gossip arrival (received),
//!   publish time = CL validated + dispatched to the EL (el sent).
//! - `EngineReq::Fcu` — the one right after STF commit (applied).
//! - `EngineResp::NewPayload` — the EL verdict (el verified).
//!
//! `EventsTile` is pure logic (no flux) so it stays trivially testable;
//! `Events` is the thin flux shell holding the spine adapter.

use std::{collections::VecDeque, path::Path};

use flux::{spine::SpineAdapter, tile::Tile, timing::InternalMessage};
use silver_common::{
    BlockSource, EngineReq, EngineResp, Nanos, PayloadValidationStatus, SilverSpine,
};

pub const MAINNET_GENESIS_UNIX_SECS: u64 = 1_606_824_023;
pub const MAINNET_SLOT_MS: u64 = 12_000;

const ROWS_CAP: usize = 64;

/// Replay and backfill ingest historical blocks at the current wall clock, so
/// beyond this much slack the arrival says nothing about the block's slot. The
/// second slot keeps genuinely late arrivals.
const LIVE_ARRIVAL_SLOTS: u64 = 2;

pub struct BlockRow {
    pub slot: u64,
    pub block_root: [u8; 32],
    pub source: BlockSource,
    /// Absolute arrival, for correlating with logs and as the delta baseline.
    received_at: Nanos,
    /// Arrival offset into the block's own slot.
    received: Option<Nanos>,
    el_sent: Nanos,
    applied: Option<Nanos>,
    verdict: Option<(PayloadValidationStatus, Nanos)>,
}

/// `stf` and `el` both begin at EL-sent and run concurrently, so they overlap
/// rather than sum into `total`.
pub struct Timeline {
    /// Absolute wall-clock arrival (unix epoch).
    pub received_at: Nanos,
    /// Slot start → block arrival; `None` once the arrival clock no longer
    /// belongs to the block's slot.
    pub received: Option<Nanos>,
    /// arrival → EL-sent: CL validation up to dispatching `newPayload`.
    pub validate: Nanos,
    /// EL-sent → applied: state transition + commit.
    pub stf: Option<Nanos>,
    /// EL-sent → verdict: `newPayload` round-trip (concurrent with stf).
    pub el: Option<Nanos>,
    pub verdict: Option<PayloadValidationStatus>,
    /// arrival → last observed event.
    pub total: Nanos,
}

impl BlockRow {
    pub fn timeline(&self) -> Timeline {
        let last = self
            .applied
            .into_iter()
            .chain(self.verdict.map(|(_, ts)| ts))
            .max()
            .unwrap_or(self.el_sent);
        Timeline {
            received_at: self.received_at,
            received: self.received,
            validate: self.el_sent.saturating_sub(self.received_at),
            stf: self.applied.map(|ts| ts.saturating_sub(self.el_sent)),
            el: self.verdict.map(|(_, ts)| ts.saturating_sub(self.el_sent)),
            verdict: self.verdict.map(|(status, _)| status),
            total: last.saturating_sub(self.received_at),
        }
    }
}

pub struct EventsTile {
    genesis: Nanos,
    slot_dur: Nanos,
    /// Joined per-block rows, newest at the back.
    rows: VecDeque<BlockRow>,
}

impl EventsTile {
    fn new(genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            genesis: Nanos(genesis_unix_secs * 1_000_000_000),
            slot_dur: Nanos(slot_ms.max(1) * 1_000_000),
            rows: VecDeque::with_capacity(ROWS_CAP),
        }
    }

    fn offset_in_slot(&self, t: Nanos, slot: u64) -> Option<Nanos> {
        let start = self.genesis + self.slot_dur * slot;
        let live = start..start + self.slot_dur * LIVE_ARRIVAL_SLOTS;
        live.contains(&t).then(|| t - start)
    }

    fn on_engine_req(&mut self, m: &InternalMessage<EngineReq>) {
        match *m.data() {
            EngineReq::NewPayload(req) => {
                let received = m.ingestion_time().real();
                if self.rows.len() == ROWS_CAP {
                    self.rows.pop_front();
                }
                self.rows.push_back(BlockRow {
                    slot: req.slot,
                    block_root: req.block_root,
                    source: req.block_source,
                    received_at: received,
                    received: self.offset_in_slot(received, req.slot),
                    el_sent: m.tracking_timestamp().publish_t(),
                    applied: None,
                    verdict: None,
                });
            }
            // The FCU right after a successful STF names the new head; ignore
            // tick-driven / repeat-head FCUs by filling `applied` only once.
            EngineReq::Fcu(req) => {
                if let Some(i) = self.row_idx(&req.block_root) &&
                    self.rows[i].applied.is_none()
                {
                    self.rows[i].applied = Some(m.tracking_timestamp().publish_t());
                }
            }
            _ => {}
        }
    }

    fn on_engine_resp(&mut self, m: &InternalMessage<EngineResp>) {
        let EngineResp::NewPayload(resp) = *m.data() else {
            return;
        };
        if let Some(i) = self.row_idx(&resp.block_root) {
            self.rows[i].verdict = Some((resp.status, m.tracking_timestamp().publish_t()));
        }
    }

    fn row_idx(&self, block_root: &[u8; 32]) -> Option<usize> {
        self.rows.iter().rposition(|r| &r.block_root == block_root)
    }
}

impl Tile<SilverSpine> for EventsTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineReq>, _| {
            self.on_engine_req(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineResp>, _| {
            self.on_engine_resp(m);
        });
    }
}

/// The node's spine, read-only. Everything flux-coupled lives here; the rest
/// of surfer sees only `sample()` / `rows()`.
pub struct Events {
    tile: EventsTile,
    adapter: SpineAdapter<SilverSpine>,
}

impl Events {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        let tile = EventsTile::new(genesis_unix_secs, slot_ms);
        // Queue handles are `Copy` and live in shmem, so the spine can drop
        // once the adapter has attached.
        let mut spine = SilverSpine::new_with_base_dir(base_dir, None);
        let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        Self { tile, adapter }
    }

    pub fn sample(&mut self) {
        self.tile.loop_body(&mut self.adapter);
    }

    pub fn rows(&self) -> &VecDeque<BlockRow> {
        &self.tile.rows
    }

    /// Offset into the slot by which validators are expected to have attested.
    /// Assumes the pre-Gloas fraction.
    pub fn attestation_deadline(&self) -> Nanos {
        self.tile.slot_dur / 3u64
    }
}

#[cfg(test)]
mod tests {
    use flux::timing::{IngestionTime, Instant, PublishDelta, TrackingTimestamp};
    use silver_common::{
        EngineFcuReq, EngineNewPayloadReq, EngineNewPayloadResp, TCache, TCacheProducer, TCacheRead,
    };

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;
    const MS: u64 = 1_000_000;

    /// Wall time at `ms_into_slot` of `slot`.
    fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos((GENESIS_SECS * 1_000 + slot * SLOT_MS + ms_into_slot) * MS)
    }

    /// Envelope with a controlled ingestion wall time and zero publish delta,
    /// so publish time == ingestion time.
    fn msg<T>(data: T, ingestion: Nanos) -> InternalMessage<T> {
        let ts = TrackingTimestamp {
            ingestion_t: IngestionTime::new(ingestion, Instant(0)),
            publish_delta: PublishDelta::new(0),
        };
        InternalMessage::new(ts, data)
    }

    fn tcache_read() -> TCacheRead {
        let mut producer = TCache::producer("surfer_events_test", 1 << 12);
        let mut r = producer.reserve(1, true).expect("tcache reserve");
        r.increment_offset(1);
        r.read()
    }

    fn new_payload(
        root: [u8; 32],
        slot: u64,
        source: BlockSource,
        ingestion: Nanos,
    ) -> InternalMessage<EngineReq> {
        msg(
            EngineReq::NewPayload(EngineNewPayloadReq {
                data: tcache_read(),
                block_root: root,
                slot,
                block_source: source,
            }),
            ingestion,
        )
    }

    fn fcu(root: [u8; 32], ingestion: Nanos) -> InternalMessage<EngineReq> {
        msg(
            EngineReq::Fcu(EngineFcuReq {
                block_root: root,
                head_block_hash: [0; 32],
                safe_block_hash: [0; 32],
                finalized_block_hash: [0; 32],
            }),
            ingestion,
        )
    }

    fn verdict(
        root: [u8; 32],
        status: PayloadValidationStatus,
        ingestion: Nanos,
    ) -> InternalMessage<EngineResp> {
        msg(
            EngineResp::NewPayload(EngineNewPayloadResp {
                block_root: root,
                status,
                latest_valid_hash: [0; 32],
            }),
            ingestion,
        )
    }

    /// Stage times are encoded via each message's ingestion (publish delta is
    /// zero), so `validate` is zero here.
    #[test]
    fn block_timeline() {
        let mut tile = EventsTile::new(GENESIS_SECS, SLOT_MS);
        let root = [1u8; 32];

        tile.on_engine_req(&new_payload(root, 2, BlockSource::Gossip, at(2, 300)));
        tile.on_engine_req(&fcu(root, at(2, 460)));
        tile.on_engine_resp(&verdict(root, PayloadValidationStatus::Valid, at(2, 520)));

        assert_eq!(tile.rows.len(), 1);
        assert_eq!(tile.rows[0].slot, 2);
        let t = tile.rows[0].timeline();
        assert_eq!(t.received_at, at(2, 300));
        assert_eq!(t.received, Some(Nanos(300 * MS)));
        assert_eq!(t.validate, Nanos(0));
        assert_eq!(t.stf, Some(Nanos(160 * MS)));
        assert_eq!(t.el, Some(Nanos(220 * MS)));
        assert_eq!(t.total, Nanos(220 * MS));
        assert_eq!(t.verdict, Some(PayloadValidationStatus::Valid));
    }

    /// A repeat-head FCU must not overwrite `applied` (stf stays 100ms, not
    /// 1100ms); a late verdict stays relative to the block's own slot,
    /// exceeding the slot duration.
    #[test]
    fn fcu_dedup_and_late_verdict() {
        let mut tile = EventsTile::new(GENESIS_SECS, SLOT_MS);
        let root = [2u8; 32];

        tile.on_engine_req(&new_payload(root, 7, BlockSource::Rpc, at(7, 11_900)));
        tile.on_engine_req(&fcu(root, at(7, 12_000)));
        tile.on_engine_req(&fcu(root, at(7, 13_000)));
        tile.on_engine_resp(&verdict(root, PayloadValidationStatus::Syncing, at(8, 500)));

        assert_eq!(tile.rows[0].slot, 7);
        let t = tile.rows[0].timeline();
        assert_eq!(t.stf, Some(Nanos(100 * MS)));
        assert_eq!(t.el, Some(Nanos(600 * MS)));
        assert_eq!(t.verdict, Some(PayloadValidationStatus::Syncing));
    }

    /// The stage deltas, being differences between the block's own stamps, hold
    /// even once the arrival clock is unrelated to the slot.
    #[test]
    fn replayed_block_has_no_slot_offset() {
        let mut tile = EventsTile::new(GENESIS_SECS, SLOT_MS);
        let root = [3u8; 32];

        tile.on_engine_req(&new_payload(root, 7, BlockSource::Rpc, at(900, 4_000)));
        tile.on_engine_req(&fcu(root, at(900, 4_050)));

        assert_eq!(tile.rows[0].slot, 7);
        let t = tile.rows[0].timeline();
        assert_eq!(t.received, None);
        assert_eq!(t.stf, Some(Nanos(50 * MS)));
    }
}
