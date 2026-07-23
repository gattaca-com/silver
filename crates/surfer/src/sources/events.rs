//! Per-block pipeline timeline, read from the node's own spine queues. Surfer
//! joins the spine as a broadcast consumer (its own cursor; the tiles are
//! untouched) and derives each stage's wall time from the `InternalMessage`
//! envelope: `ingestion_t` is copied verbatim as a block flows tile→tile, and
//! `publish_delta` records how long after ingestion each stage published. No
//! producer-side changes.
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
use silver_common::{BlockSource, EngineReq, EngineResp, PayloadValidationStatus, SilverSpine};

pub const MAINNET_GENESIS_UNIX_SECS: u64 = 1_606_824_023;
pub const MAINNET_SLOT_MS: u64 = 12_000;

const ROWS_CAP: usize = 64;

pub struct BlockRow {
    pub slot: u64,
    pub block_root: [u8; 32],
    pub source: BlockSource,
    /// ms from this block's slot start; may exceed the slot duration (late
    /// arrival, or a verdict for a previous-slot block).
    pub received_ms: u32,
    pub el_sent_ms: u32,
    pub applied_ms: Option<u32>,
    pub verdict: Option<(PayloadValidationStatus, u32)>,
}

pub struct EventsTile {
    genesis_ns: u64,
    slot_ns: u64,
    /// Joined per-block rows, newest at the back.
    rows: VecDeque<BlockRow>,
}

impl EventsTile {
    fn new(genesis_unix_secs: u64, slot_ms: u64) -> Self {
        Self {
            genesis_ns: genesis_unix_secs * 1_000_000_000,
            slot_ns: slot_ms.max(1) * 1_000_000,
            rows: VecDeque::with_capacity(ROWS_CAP),
        }
    }

    fn slot_of(&self, unix_ns: u64) -> u64 {
        unix_ns.saturating_sub(self.genesis_ns) / self.slot_ns
    }

    fn ms_into_slot(&self, unix_ns: u64, slot: u64) -> u32 {
        let ms = unix_ns.saturating_sub(self.genesis_ns + slot * self.slot_ns) / 1_000_000;
        ms.min(u32::MAX as u64) as u32
    }

    fn on_engine_req(&mut self, m: &InternalMessage<EngineReq>) {
        match *m.data() {
            EngineReq::NewPayload(req) => {
                let received_ns = m.ingestion_time().real().0;
                let slot = self.slot_of(received_ns);
                if self.rows.len() == ROWS_CAP {
                    self.rows.pop_front();
                }
                self.rows.push_back(BlockRow {
                    slot,
                    block_root: req.block_root,
                    source: req.block_source,
                    received_ms: self.ms_into_slot(received_ns, slot),
                    el_sent_ms: self.ms_into_slot(publish_ns(m), slot),
                    applied_ms: None,
                    verdict: None,
                });
            }
            // The FCU right after a successful STF names the new head; ignore
            // tick-driven / repeat-head FCUs by filling `applied` only once.
            EngineReq::Fcu(req) => {
                if let Some(i) = self.row_idx(&req.block_root) {
                    if self.rows[i].applied_ms.is_none() {
                        self.rows[i].applied_ms =
                            Some(self.ms_into_slot(publish_ns(m), self.rows[i].slot));
                    }
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
            self.rows[i].verdict =
                Some((resp.status, self.ms_into_slot(publish_ns(m), self.rows[i].slot)));
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
    slot_ms: u64,
}

impl Events {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        let tile = EventsTile::new(genesis_unix_secs, slot_ms);
        // Queue handles are `Copy` and live in shmem, so the spine can drop
        // once the adapter has attached.
        let mut spine = SilverSpine::new_with_base_dir(base_dir, None);
        let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        Self { tile, adapter, slot_ms }
    }

    pub fn sample(&mut self) {
        self.tile.loop_body(&mut self.adapter);
    }

    pub fn rows(&self) -> &VecDeque<BlockRow> {
        &self.tile.rows
    }

    pub fn slot_ms(&self) -> u64 {
        self.slot_ms
    }
}

/// Wall time a message was produced: pipeline ingestion + the producer's
/// recorded rdtsc delta.
fn publish_ns<T>(m: &InternalMessage<T>) -> u64 {
    let ts = m.tracking_timestamp();
    ts.ingestion_t.real().0 + ts.publish_delta.delta().as_delta_nanos().0
}

#[cfg(test)]
mod tests {
    use flux::timing::{IngestionTime, Instant, Nanos, PublishDelta, TrackingTimestamp};
    use silver_common::{
        EngineFcuReq, EngineNewPayloadReq, EngineNewPayloadResp, TCache, TCacheProducer, TCacheRead,
    };

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;

    fn unix_ns(slot: u64, ms_into_slot: u64) -> u64 {
        (GENESIS_SECS * 1_000 + slot * SLOT_MS + ms_into_slot) * 1_000_000
    }

    /// Envelope with a controlled ingestion wall time and zero publish delta,
    /// so publish time == ingestion time.
    fn msg<T>(data: T, ingestion_ns: u64) -> InternalMessage<T> {
        let ts = TrackingTimestamp {
            ingestion_t: IngestionTime::new(Nanos(ingestion_ns), Instant(0)),
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
        source: BlockSource,
        ingestion_ns: u64,
    ) -> InternalMessage<EngineReq> {
        msg(
            EngineReq::NewPayload(EngineNewPayloadReq {
                data: tcache_read(),
                block_root: root,
                block_source: source,
            }),
            ingestion_ns,
        )
    }

    fn fcu(root: [u8; 32], ingestion_ns: u64) -> InternalMessage<EngineReq> {
        msg(
            EngineReq::Fcu(EngineFcuReq {
                block_root: root,
                head_block_hash: [0; 32],
                safe_block_hash: [0; 32],
                finalized_block_hash: [0; 32],
            }),
            ingestion_ns,
        )
    }

    fn verdict(
        root: [u8; 32],
        status: PayloadValidationStatus,
        ingestion_ns: u64,
    ) -> InternalMessage<EngineResp> {
        msg(
            EngineResp::NewPayload(EngineNewPayloadResp {
                block_root: root,
                status,
                latest_valid_hash: [0; 32],
            }),
            ingestion_ns,
        )
    }

    /// Full lifecycle: received from ingestion time, every later stage as an
    /// offset from the block's own slot start.
    #[test]
    fn block_timeline() {
        let mut tile = EventsTile::new(GENESIS_SECS, SLOT_MS);
        let root = [1u8; 32];

        // NewPayload: ingestion at +300ms, published at +305ms.
        tile.on_engine_req(&new_payload(root, BlockSource::Gossip, unix_ns(2, 300)));
        // Publish delta is zero, so publish == ingestion: encode stage time in
        // the ingestion timestamp.
        tile.on_engine_req(&fcu(root, unix_ns(2, 460)));
        tile.on_engine_resp(&verdict(root, PayloadValidationStatus::Valid, unix_ns(2, 520)));

        assert_eq!(tile.rows.len(), 1);
        let row = &tile.rows[0];
        assert_eq!(row.slot, 2);
        assert_eq!(row.received_ms, 300);
        assert_eq!(row.el_sent_ms, 300);
        assert_eq!(row.applied_ms, Some(460));
        assert_eq!(row.verdict, Some((PayloadValidationStatus::Valid, 520)));
    }

    /// A repeat-head FCU must not overwrite `applied`; a late verdict stays
    /// relative to the block's own slot, exceeding the slot duration.
    #[test]
    fn fcu_dedup_and_late_verdict() {
        let mut tile = EventsTile::new(GENESIS_SECS, SLOT_MS);
        let root = [2u8; 32];

        tile.on_engine_req(&new_payload(root, BlockSource::Rpc, unix_ns(7, 11_900)));
        tile.on_engine_req(&fcu(root, unix_ns(7, 12_000)));
        tile.on_engine_req(&fcu(root, unix_ns(8, 0)));
        tile.on_engine_resp(&verdict(root, PayloadValidationStatus::Syncing, unix_ns(8, 500)));

        let row = &tile.rows[0];
        assert_eq!(row.slot, 7);
        assert_eq!(row.applied_ms, Some(12_000));
        assert_eq!(row.verdict, Some((PayloadValidationStatus::Syncing, 12_500)));
    }
}
