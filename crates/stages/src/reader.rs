use std::vec::Drain;

use flux::{spine::SpineAdapter, timing::InternalMessage};
use rustc_hash::FxHashMap;
use silver_common::{
    BeaconStateEvent, BlockStage, DataColumnsEvent, DataKind, EngineReq, EngineResp, Origin,
    SilverSpine, SyncNeed,
};

use crate::{Stage, StageEvent};

/// Past this many slots a root is dropped, and a later FCU naming it resolves
/// no slot.
const TRACKED_SLOTS: u64 = 64;

struct Tracked {
    slot: u64,
    received: bool,
    stf_done: bool,
    attestable: bool,
}

impl Tracked {
    fn new(slot: u64) -> Self {
        Self { slot, received: false, stf_done: false, attestable: false }
    }
}

#[derive(Default)]
pub struct StageReader {
    roots: FxHashMap<[u8; 32], Tracked>,
    out: Vec<StageEvent>,
}

impl StageReader {
    pub fn consume(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> Drain<'_, StageEvent> {
        adapter.consume_internal_message(|m: &mut InternalMessage<BeaconStateEvent>, _| {
            self.on_beacon_state(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineReq>, _| {
            self.on_engine_req(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineResp>, _| {
            self.on_engine_resp(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<DataColumnsEvent>, _| {
            self.on_data_columns(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<SyncNeed>, _| {
            self.on_sync_need(m);
        });
        self.out.drain(..)
    }

    /// A parked block is announced again from the replay that admits it, so
    /// only the first announcement is its arrival; an unparked block's one
    /// announcement carries its arrival, its post-state and its import.
    fn on_beacon_state(&mut self, m: &InternalMessage<BeaconStateEvent>) {
        let BeaconStateEvent::BlockReceived { slot, block_root, source, stage, .. } = *m.data()
        else {
            return;
        };

        self.roots.retain(|_, t| slot.saturating_sub(t.slot) < TRACKED_SLOTS);
        let tracked = self.roots.entry(block_root).or_insert(Tracked::new(slot));

        if !tracked.received {
            tracked.received = true;
            self.out.push(StageEvent {
                stage: Stage::Received { source },
                ts: m.ingestion_time().real(),
                block_root,
                slot: Some(slot),
            });
        }
        if stage != BlockStage::AwaitParent && !tracked.stf_done {
            tracked.stf_done = true;
            self.out.push(StageEvent {
                stage: Stage::StfDone,
                ts: m.tracking_timestamp().publish_t(),
                block_root,
                slot: Some(slot),
            });
        }
        if stage == BlockStage::Applied && !tracked.attestable {
            tracked.attestable = true;
            self.out.push(StageEvent {
                stage: Stage::Attestable,
                ts: m.tracking_timestamp().publish_t(),
                block_root,
                slot: Some(slot),
            });
        }
    }

    fn on_engine_req(&mut self, m: &InternalMessage<EngineReq>) {
        match *m.data() {
            EngineReq::NewPayload(req) => {
                self.roots.entry(req.block_root).or_insert(Tracked::new(req.slot));
                self.out.push(StageEvent {
                    stage: Stage::ElSent { source: req.block_source },
                    ts: m.tracking_timestamp().publish_t(),
                    block_root: req.block_root,
                    slot: Some(req.slot),
                });
            }
            _ => {}
        }
    }

    fn on_engine_resp(&mut self, m: &InternalMessage<EngineResp>) {
        let EngineResp::NewPayload(resp) = *m.data() else {
            return;
        };
        self.out.push(StageEvent {
            stage: Stage::ElVerdict { verdict: resp.status },
            ts: m.tracking_timestamp().publish_t(),
            block_root: resp.block_root,
            slot: self.roots.get(&resp.block_root).map(|t| t.slot),
        });
    }

    /// A sidecar is two events of one message: ingestion is its arrival
    /// on the wire, publish the moment it passed validation.
    fn on_data_columns(&mut self, m: &InternalMessage<DataColumnsEvent>) {
        match *m.data() {
            DataColumnsEvent::Persist { block_root, column_index, slot, source, .. } => {
                self.roots.entry(block_root).or_insert(Tracked::new(slot));
                let recv = StageEvent {
                    stage: Stage::ColumnRecv { index: column_index, source },
                    ts: m.ingestion_time().real(),
                    block_root,
                    slot: Some(slot),
                };
                self.out.push(recv);
                self.out.push(StageEvent {
                    stage: Stage::ColumnValidated { index: column_index, source },
                    ts: m.tracking_timestamp().publish_t(),
                    ..recv
                });
            }
            DataColumnsEvent::Available { block_root, slot } => {
                self.out.push(StageEvent {
                    stage: Stage::DaAvailable,
                    ts: m.tracking_timestamp().publish_t(),
                    block_root,
                    slot: Some(slot),
                });
            }
        }
    }

    /// Custody completion is the sync engine's need closing, so it rides
    /// `SyncNeed` rather than `DataColumnsEvent`; backfill answers are not
    /// a live block's tail.
    fn on_sync_need(&mut self, m: &InternalMessage<SyncNeed>) {
        let SyncNeed::Arrived { root, slot, kind: DataKind::Columns, origin: Origin::Live } =
            *m.data()
        else {
            return;
        };
        self.out.push(StageEvent {
            stage: Stage::CustodyDone,
            ts: m.tracking_timestamp().publish_t(),
            block_root: root,
            slot: Some(slot),
        });
    }
}

#[cfg(test)]
mod tests {
    use flux::timing::{IngestionTime, Instant, Nanos, PublishDelta, TrackingTimestamp};
    use silver_common::{
        BlockSource, BlockStage, ColumnSource, DataKind, EngineNewPayloadReq, EngineNewPayloadResp,
        Origin, PayloadValidationStatus, TCache, TCacheProducer, TCacheRead,
    };

    use super::*;
    use crate::test_clock::at;

    /// Internal-clock ticks between ingestion and publish. Ticks are TSC, so
    /// the nanoseconds they become are calibration-dependent — assert ordering
    /// against the ingestion time, not an exact value.
    const PUBLISH_TICKS: u64 = 10_000_000;

    fn msg<T>(data: T, ingestion: Nanos) -> InternalMessage<T> {
        let ts = TrackingTimestamp {
            ingestion_t: IngestionTime::new(ingestion, Instant(0)),
            publish_delta: PublishDelta::new(0)
                .from_ingestion_and_publish_t(Instant(0), Instant(PUBLISH_TICKS)),
        };
        InternalMessage::new(ts, data)
    }

    fn unread_payload() -> TCacheRead {
        let mut producer = TCache::producer("stages_test", 1 << 12);
        let mut r = producer.reserve(1, true).expect("tcache reserve");
        r.increment_offset(1);
        r.read()
    }

    fn block_received(
        root: [u8; 32],
        slot: u64,
        source: BlockSource,
        stage: BlockStage,
    ) -> BeaconStateEvent {
        BeaconStateEvent::BlockReceived { slot, block_root: root, stage, source, parent_slot: None }
    }

    fn parked(root: [u8; 32], slot: u64, source: BlockSource) -> BeaconStateEvent {
        block_received(root, slot, source, BlockStage::AwaitParent)
    }

    fn staged(root: [u8; 32], slot: u64, source: BlockSource) -> BeaconStateEvent {
        block_received(root, slot, source, BlockStage::Staged)
    }

    fn imported(root: [u8; 32], slot: u64, source: BlockSource) -> BeaconStateEvent {
        block_received(root, slot, source, BlockStage::Applied)
    }

    fn new_payload(root: [u8; 32], slot: u64, block_source: BlockSource) -> EngineReq {
        EngineReq::NewPayload(EngineNewPayloadReq {
            data: unread_payload(),
            block_root: root,
            slot,
            block_source,
        })
    }

    fn verdict(root: [u8; 32], status: PayloadValidationStatus) -> EngineResp {
        EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: root,
            status,
            latest_valid_hash: [0; 32],
        })
    }

    fn persist(root: [u8; 32], slot: u64, column_index: u64) -> DataColumnsEvent {
        DataColumnsEvent::Persist {
            ssz: unread_payload(),
            source: ColumnSource::Gossip,
            block_root: root,
            column_index,
            slot,
        }
    }

    fn stages(out: &[StageEvent]) -> Vec<&'static str> {
        out.iter().map(|o| o.stage.name()).collect()
    }

    fn find<'a>(out: &'a [StageEvent], stage: &str) -> &'a StageEvent {
        out.iter().find(|o| o.stage.name() == stage).unwrap_or_else(|| panic!("no {stage}"))
    }

    #[test]
    fn block_flow_stages() {
        let mut reader = StageReader::default();
        let root = [1u8; 32];

        reader.on_beacon_state(&msg(imported(root, 2, BlockSource::Gossip), at(2, 300)));
        reader.on_engine_req(&msg(new_payload(root, 2, BlockSource::Gossip), at(2, 300)));
        reader.on_engine_resp(&msg(verdict(root, PayloadValidationStatus::Valid), at(2, 520)));

        assert_eq!(stages(&reader.out), [
            "received",
            "stf_done",
            "attestable",
            "el_sent",
            "el_verdict"
        ]);
        assert!(reader.out.iter().all(|o| o.block_root == root));
        assert!(
            reader.out.iter().all(|o| o.slot == Some(2)),
            "the verdict slot resolves via the map"
        );

        let received = find(&reader.out, "received");
        assert_eq!(received.ts, at(2, 300), "arrival is the ingestion clock");
        assert!(matches!(received.stage, Stage::Received { source: BlockSource::Gossip }));
        assert!(matches!(find(&reader.out, "el_verdict").stage, Stage::ElVerdict {
            verdict: PayloadValidationStatus::Valid
        }));

        // The remaining stages are publish events of their message, so
        // each lands after the ingestion time it was built from.
        for (stage, ingested) in [
            ("stf_done", at(2, 300)),
            ("attestable", at(2, 300)),
            ("el_sent", at(2, 300)),
            ("el_verdict", at(2, 520)),
        ] {
            let t = find(&reader.out, stage).ts;
            assert!(t > ingested, "{stage} at {t} must follow its ingestion {ingested}");
        }
    }

    /// The replay that admits a parked block announces it again, at that
    /// replay's clock: the arrival keeps the park, the import is the release.
    #[test]
    fn parked_block_is_received_at_park_and_imported_at_release() {
        let mut reader = StageReader::default();
        let root = [3u8; 32];

        reader.on_beacon_state(&msg(parked(root, 5, BlockSource::Gossip), at(5, 400)));
        reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Gossip), at(5, 3_100)));

        assert_eq!(stages(&reader.out), ["received", "stf_done", "attestable"]);
        assert_eq!(reader.out[0].ts, at(5, 400), "one arrival per root");
        assert!(reader.out[1].ts > at(5, 3_100), "import is the release's publish");
        assert_eq!(reader.out[1].ts, reader.out[2].ts, "ungated: one publish carries both");
    }

    /// Data gated the import: the post-state lands with `Staged`, the import
    /// with the `Applied` that follows, and neither repeats.
    #[test]
    fn staged_block_splits_stf_done_from_attestable() {
        let mut reader = StageReader::default();
        let root = [10u8; 32];

        reader.on_beacon_state(&msg(staged(root, 5, BlockSource::Gossip), at(5, 400)));
        reader.on_beacon_state(&msg(staged(root, 5, BlockSource::Rpc), at(5, 500)));
        reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Gossip), at(5, 700)));

        assert_eq!(stages(&reader.out), ["received", "stf_done", "attestable"]);
        assert_eq!(reader.out[0].ts, at(5, 400));
        let stf_done = reader.out[1].ts;
        assert!(stf_done > at(5, 400) && stf_done < at(5, 500), "the first Staged publish");
        assert!(reader.out[2].ts > at(5, 700), "the Applied publish");
    }

    /// A duplicate of an imported block is announced `Applied` again.
    #[test]
    fn duplicate_import_announcements_emit_once() {
        let mut reader = StageReader::default();
        let root = [8u8; 32];

        reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Gossip), at(5, 400)));
        reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Rpc), at(5, 900)));

        assert_eq!(stages(&reader.out), ["received", "stf_done", "attestable"]);
        assert_eq!(reader.out[0].ts, at(5, 400));
        assert!(reader.out[2].ts < at(5, 900));
    }

    /// `NewPayload` carries the slot, so a verdict resolves even when the
    /// arrival predates attach.
    #[test]
    fn new_payload_seeds_the_slot() {
        let mut reader = StageReader::default();
        let root = [4u8; 32];

        reader.on_engine_req(&msg(new_payload(root, 6, BlockSource::Rpc), at(6, 500)));
        reader.on_engine_resp(&msg(verdict(root, PayloadValidationStatus::Valid), at(6, 600)));

        assert_eq!(find(&reader.out, "el_verdict").slot, Some(6));
    }

    #[test]
    fn roots_age_out_of_slot_resolution() {
        let mut reader = StageReader::default();
        let old = [5u8; 32];

        reader.on_beacon_state(&msg(parked(old, 0, BlockSource::Gossip), at(0, 300)));
        reader.on_beacon_state(&msg(parked([6u8; 32], 100, BlockSource::Gossip), at(100, 300)));
        reader.on_engine_resp(&msg(verdict(old, PayloadValidationStatus::Valid), at(100, 460)));

        assert_eq!(find(&reader.out, "el_verdict").slot, None, "evicted after 64 slots");
    }

    #[test]
    fn custody_completion_is_the_live_columns_arrival_only() {
        let mut reader = StageReader::default();
        let root = [9u8; 32];
        let arrived = |kind, origin| SyncNeed::Arrived { root, slot: 3, kind, origin };

        reader.on_sync_need(&msg(arrived(DataKind::Columns, Origin::Backfill), at(3, 100)));
        reader.on_sync_need(&msg(arrived(DataKind::Block, Origin::Live), at(3, 200)));
        reader.on_sync_need(&msg(arrived(DataKind::Columns, Origin::Live), at(3, 900)));

        assert_eq!(stages(&reader.out), ["custody_done"]);
        assert_eq!(reader.out[0].slot, Some(3));
        assert!(reader.out[0].ts > at(3, 900));
    }

    #[test]
    fn sidecars_record_arrival_then_validation() {
        let mut reader = StageReader::default();
        let root = [7u8; 32];

        reader.on_data_columns(&msg(persist(root, 3, 48), at(3, 1_400)));
        reader.on_data_columns(&msg(
            DataColumnsEvent::Available { block_root: root, slot: 3 },
            at(3, 1_500),
        ));

        assert_eq!(stages(&reader.out), ["column_recv", "column_validated", "da_available"]);
        assert!(reader.out.iter().all(|o| o.block_root == root && o.slot == Some(3)));

        let recv = find(&reader.out, "column_recv");
        assert!(matches!(recv.stage, Stage::ColumnRecv {
            index: 48,
            source: ColumnSource::Gossip
        }));
        assert_eq!(recv.ts, at(3, 1_400), "arrival is the ingestion clock");

        let validated = find(&reader.out, "column_validated");
        assert!(matches!(validated.stage, Stage::ColumnValidated { index: 48, .. }));
        assert!(validated.ts > recv.ts, "validation follows arrival");
    }
}
