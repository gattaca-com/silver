use std::vec::Drain;

use flux::{spine::SpineAdapter, timing::InternalMessage};
use rustc_hash::FxHashMap;
use silver_common::{BeaconStateEvent, DataColumnsEvent, EngineReq, EngineResp, SilverSpine};

use crate::{Stage, StageEvent};

/// Past this many slots a root is dropped, and a later FCU naming it resolves
/// no slot.
const TRACKED_SLOTS: u64 = 64;

struct Tracked {
    slot: u64,
    received: bool,
}

#[derive(Default)]
pub struct StageReader {
    roots: FxHashMap<[u8; 32], Tracked>,
    out: Vec<StageEvent>,
}

impl StageReader {
    /// Drains the stage-carrying queues and returns the events, oldest
    /// first.
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
        self.out.drain(..)
    }

    /// A parked block is announced again from the replay that admits it, so
    /// only the first announcement is its arrival.
    fn on_beacon_state(&mut self, m: &InternalMessage<BeaconStateEvent>) {
        let BeaconStateEvent::BlockReceived { slot, block_root, source, .. } = *m.data() else {
            return;
        };
        self.roots.retain(|_, t| slot.saturating_sub(t.slot) < TRACKED_SLOTS);
        let tracked = self.roots.entry(block_root).or_insert(Tracked { slot, received: false });
        if tracked.received {
            return;
        }
        tracked.received = true;
        self.out.push(StageEvent {
            stage: Stage::Received { source },
            ts: m.ingestion_time().real(),
            block_root,
            slot: Some(slot),
        });
    }

    fn on_engine_req(&mut self, m: &InternalMessage<EngineReq>) {
        match *m.data() {
            EngineReq::NewPayload(req) => {
                self.roots
                    .entry(req.block_root)
                    .or_insert(Tracked { slot: req.slot, received: false });
                self.out.push(StageEvent {
                    stage: Stage::ElSent { source: req.block_source },
                    ts: m.tracking_timestamp().publish_t(),
                    block_root: req.block_root,
                    slot: Some(req.slot),
                });
            }
            // Repeat-head and tick-driven FCUs re-name the root; every one
            // is emitted, and picking the first per root is the consumer's
            // dedup.
            EngineReq::Fcu(req) => {
                self.out.push(StageEvent {
                    stage: Stage::Applied,
                    ts: m.tracking_timestamp().publish_t(),
                    block_root: req.block_root,
                    slot: self.roots.get(&req.block_root).map(|t| t.slot),
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
                self.roots.entry(block_root).or_insert(Tracked { slot, received: false });
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
}

#[cfg(test)]
mod tests {
    use flux::timing::{IngestionTime, Instant, Nanos, PublishDelta, TrackingTimestamp};
    use silver_common::{
        BlockSource, BlockStage, ColumnSource, EngineFcuReq, EngineNewPayloadReq,
        EngineNewPayloadResp, PayloadValidationStatus, TCache, TCacheProducer, TCacheRead,
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
        let mut producer = TCache::producer("stages_test", 1 << 12);
        let mut r = producer.reserve(1, true).expect("tcache reserve");
        r.increment_offset(1);
        r.read()
    }

    fn block_received(root: [u8; 32], slot: u64, source: BlockSource) -> BeaconStateEvent {
        BeaconStateEvent::BlockReceived {
            slot,
            block_root: root,
            stage: BlockStage::AwaitParent,
            source,
            parent_slot: None,
        }
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

        reader.on_beacon_state(&msg(block_received(root, 2, BlockSource::Gossip), at(2, 300)));
        reader.on_engine_req(&msg(new_payload(root, 2, BlockSource::Gossip), at(2, 300)));
        reader.on_engine_req(&msg(fcu(root), at(2, 460)));
        reader.on_engine_resp(&msg(verdict(root, PayloadValidationStatus::Valid), at(2, 520)));

        assert_eq!(stages(&reader.out), ["received", "el_sent", "applied", "el_verdict"]);
        assert!(reader.out.iter().all(|o| o.block_root == root));
        assert!(
            reader.out.iter().all(|o| o.slot == Some(2)),
            "fcu/verdict slots resolve via the map"
        );

        let received = find(&reader.out, "received");
        assert_eq!(received.ts, at(2, 300), "arrival is the ingestion clock");
        assert!(matches!(received.stage, Stage::Received { source: BlockSource::Gossip }));
        assert!(matches!(find(&reader.out, "el_verdict").stage, Stage::ElVerdict {
            verdict: PayloadValidationStatus::Valid
        }));

        // The remaining stages are publish events of their message, so
        // each lands after the ingestion time it was built from.
        for (stage, ingested) in
            [("el_sent", at(2, 300)), ("applied", at(2, 460)), ("el_verdict", at(2, 520))]
        {
            let t = find(&reader.out, stage).ts;
            assert!(t > ingested, "{stage} at {t} must follow its ingestion {ingested}");
        }
    }

    /// The replay that admits a parked block announces it again, at that
    /// replay's clock.
    #[test]
    fn replayed_announcement_does_not_restamp_the_arrival() {
        let mut reader = StageReader::default();
        let root = [3u8; 32];

        reader.on_beacon_state(&msg(block_received(root, 5, BlockSource::Gossip), at(5, 400)));
        reader.on_beacon_state(&msg(block_received(root, 5, BlockSource::Gossip), at(5, 3_100)));

        assert_eq!(stages(&reader.out), ["received"], "one arrival per root");
        assert_eq!(reader.out[0].ts, at(5, 400));
    }

    /// Repeat-head FCUs each emit; keeping the first per root is the
    /// consumer's dedup.
    #[test]
    fn repeat_head_fcus_each_emit() {
        let mut reader = StageReader::default();
        let root = [2u8; 32];

        reader.on_beacon_state(&msg(block_received(root, 7, BlockSource::Rpc), at(7, 11_900)));
        reader.on_engine_req(&msg(fcu(root), at(7, 12_000)));
        reader.on_engine_req(&msg(fcu(root), at(7, 13_000)));

        assert_eq!(stages(&reader.out), ["received", "applied", "applied"]);
    }

    /// FCUs for roots whose block predates attach are still observed — slot
    /// resolution is left to the consumer's join.
    #[test]
    fn unmatched_fcu_is_observed_without_a_slot() {
        let mut reader = StageReader::default();

        reader.on_engine_req(&msg(fcu([9u8; 32]), at(2, 460)));

        assert_eq!(stages(&reader.out), ["applied"]);
        assert_eq!(reader.out[0].slot, None);
        assert!(reader.roots.is_empty(), "an FCU alone must not pin a root in the map");
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

        reader.on_beacon_state(&msg(block_received(old, 0, BlockSource::Gossip), at(0, 300)));
        reader.on_beacon_state(&msg(
            block_received([6u8; 32], 100, BlockSource::Gossip),
            at(100, 300),
        ));
        reader.on_engine_req(&msg(fcu(old), at(100, 460)));

        assert_eq!(find(&reader.out, "applied").slot, None, "evicted after 64 slots");
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
