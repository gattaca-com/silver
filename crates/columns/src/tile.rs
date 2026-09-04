use std::{
    mem,
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconStateReader, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    BeaconStateEvent, BlockSource, ColumnSource, DataColumnsEvent, DataKind, EngineResp,
    GossipTopic, IngestionTime, NewGossipMsg, Origin, P2pStreamId, PeerEvent, RequestId,
    RpcInbound, RpcSeverity, SilverSpine, SilverSpineProducers, StreamProtocol, SyncNeed,
    SyncUpdate, TCacheRead, TProducer, TRandomAccess, TRead, Wheel,
    column_util::{self as util, KzgScratch},
    ssz_view::{NUMBER_OF_COLUMNS, SignedBeaconBlockView, StatusView},
};

use crate::{
    BlockRoot, DataColumnCounters,
    availability::ColumnTracker,
    batch::{self, KzgBatch, PendingKzg, RelayMeta},
    el_blobs::ElBlobFetcher,
    sync::SyncStatus,
    validate::{ColumnOutcome, ColumnValidator, PendingColumn},
};

/// Only `Batched` sidecars can end up forwarded / republished on gossip
/// (their relay fires at flush if KZG passes): `Ignored` covers spec-IGNORE
/// cases (dup, post-wall, parent pending, buffered) whose sidecars must not
/// be relayed and whose senders are not culpable.
enum ColumnDisposition {
    Batched,
    Ignored,
    Rejected { block_root: BlockRoot, slot: u64, bitmask: u128 },
}

pub struct ColumnConsumers {
    pub gossip: TRandomAccess,
    pub persist_gossip: TRandomAccess,
    pub rpc: TRandomAccess,
    pub persist_rpc: TRandomAccess,
}

impl ColumnConsumers {
    fn free(&mut self) {
        self.gossip.free();
        self.rpc.free();
        self.persist_gossip.free();
        self.persist_rpc.free();
    }

    fn acquire_persisted(&mut self, source: BlockSource, ssz: TCacheRead) -> TRead {
        match source {
            BlockSource::Gossip => self.persist_gossip.acquire(ssz),
            BlockSource::Rpc => self.persist_rpc.acquire(ssz),
        }
    }
}

pub struct DataColumnsTile {
    consumers: ColumnConsumers,

    spec: Arc<SpecConfig>,

    validator: ColumnValidator,
    // Sidecars past every per-sidecar check, KZG-verified together at the
    // end of the pass.
    kzg_batch: KzgBatch,

    tracker: ColumnTracker,
    // Gloas: columns whose block (hence commitments) hasn't been seen yet.
    gloas_pending_columns: Wheel<BlockRoot, Vec<PendingColumn>, 4>,
    // Fulu: columns held until their parent block validates. Keyed by the
    // sidecar's parent_root; drained on Status head advances and on block
    // arrivals (the arriving block's own parent_root).
    parent_pending_columns: Wheel<BlockRoot, Vec<PendingColumn>, 4>,

    sync_state: SyncStatus,

    el_fetcher: ElBlobFetcher,
    el_column_producer: TProducer,

    kzg_scratch: KzgScratch,
}

impl DataColumnsTile {
    pub fn new(
        consumers: ColumnConsumers,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        spec: Arc<SpecConfig>,
        engine_resp_consumer: TRandomAccess,
        el_column_producer: TProducer,
    ) -> Self {
        let epoch_duration =
            Duration::from_millis(spec.slot_duration_ms()) * SLOTS_PER_EPOCH as u32;
        Self {
            consumers,
            validator: ColumnValidator::new(beacon_state, spec.clone(), epoch_duration),
            spec,
            kzg_batch: KzgBatch::new(),
            tracker: ColumnTracker::new(custody_group_columns, epoch_duration),
            gloas_pending_columns: Wheel::new(epoch_duration),
            parent_pending_columns: Wheel::new(Duration::from_secs(24)),
            sync_state: SyncStatus::default(),
            el_fetcher: ElBlobFetcher::new(engine_resp_consumer),
            el_column_producer,
            kzg_scratch: KzgScratch::default(),
        }
    }

    #[timed]
    fn beacon_block(
        &mut self,
        stream_id: P2pStreamId,
        block: TRead,
        producers: &mut SilverSpineProducers,
    ) -> Option<(B256, bool)> {
        let buffer = match block.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read beacon block cache buffer");
                return None;
            }
        };

        debug_assert!(SignedBeaconBlockView::check_size(buffer));

        let slot = SignedBeaconBlockView::slot(buffer);
        if slot <= self.sync_state.data_availability_floor() {
            return None;
        }

        let is_gloas = self.spec.is_gloas_at_slot(slot);
        let has_columns = SignedBeaconBlockView::has_data_columns(buffer, is_gloas);

        tracing::info!(slot, has_columns, "beacon block recv");

        let block_root = util::block_root(buffer, is_gloas);

        // Trivial coverage: no commitments, so no columns are owed.
        if !has_columns {
            producers.produce(DataColumnsEvent::Available { block_root, slot });
            return None;
        }

        if is_gloas {
            self.validator.cache_gloas_commitments(block_root, buffer);
        }

        // Custody columns only — silver floors cgc at SAMPLES_PER_SLOT, so the
        // custody set IS the sample set; no beyond-custody sampling needed.
        let to_request = self.tracker.to_request(&block_root);
        if to_request == 0 {
            return Some((block_root, is_gloas));
        }

        tracing::trace!(
            block = hex::encode(block_root),
            ?stream_id,
            "data columns by root request: {to_request:b}"
        );

        // EL blob reconstruction parses the Fulu body layout; gloas blobs are
        // fetched from peers by root/range instead.
        if !is_gloas && self.sync_state.is_synced() {
            self.el_fetcher.try_fetch(buffer, block_root, slot, to_request, producers);
        }

        producers.produce(SyncNeed::Missing {
            root: block_root,
            slot,
            kind: DataKind::Columns,
            columns: to_request,
            origin: Origin::Live,
        });
        Some((block_root, is_gloas))
    }

    #[timed]
    fn data_columns(
        &mut self,
        column: PendingColumn,
        relay: RelayMeta,
        producers: &mut SilverSpineProducers,
    ) -> ColumnDisposition {
        let validated = match column.sidecar.buffer() {
            Ok((buf, _)) => {
                self.validator.validate(&column, buf, &self.sync_state, &mut self.tracker)
            }
            Err(e) => {
                tracing::error!(
                    ?e,
                    stream_id = ?column.stream_id,
                    "failed to read data column sidecar buffer"
                );
                return ColumnDisposition::Ignored;
            }
        };
        let Some((outcome, is_gloas)) = validated else {
            return ColumnDisposition::Ignored;
        };
        self.handle_column(outcome, column, is_gloas, relay, producers)
    }

    fn handle_column(
        &mut self,
        outcome: ColumnOutcome,
        column: PendingColumn,
        is_gloas: bool,
        relay: RelayMeta,
        producers: &mut SilverSpineProducers,
    ) -> ColumnDisposition {
        match outcome {
            ColumnOutcome::Skip => ColumnDisposition::Ignored,
            ColumnOutcome::AlreadyHeld { block_root, column_index, slot } => {
                let is_gossip = column.stream_id.protocol() == StreamProtocol::GossipSub;
                producers.produce_with_ingestion(
                    DataColumnsEvent::Persist {
                        ssz: column.sidecar.read,
                        source: if is_gossip { ColumnSource::Gossip } else { ColumnSource::Rpc },
                        block_root,
                        column_index,
                        slot,
                    },
                    column.recv_ts,
                );

                if !is_gossip && self.tracker.custody_complete(&block_root) {
                    producers.produce(SyncNeed::Arrived {
                        root: block_root,
                        slot,
                        kind: DataKind::Columns,
                        origin: Origin::Live,
                    });
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::Reject { block_root, slot, bitmask } => {
                ColumnDisposition::Rejected { block_root, slot, bitmask }
            }
            ColumnOutcome::Buffer { block_root } => {
                let pending = self.gloas_pending_columns.entry(block_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::debug!(stream_id = ?column.stream_id, "gloas column before block — buffering");
                    pending.push(column);
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::AwaitParent { parent_root } => {
                let pending = self.parent_pending_columns.entry(parent_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::info!(stream_id = ?column.stream_id, "column parent pending — buffering");
                    pending.push(column);
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::Record { block_root, column_index, bitmask, slot, relay_eligible } => {
                let queued = self.kzg_batch.push(PendingKzg {
                    sidecar: column.sidecar,
                    stream_id: column.stream_id,
                    recv_ts: column.recv_ts,
                    block_root,
                    column_index,
                    bitmask,
                    slot,
                    is_gloas,
                    relay: if relay_eligible { relay } else { RelayMeta::None },
                });
                if queued { ColumnDisposition::Batched } else { ColumnDisposition::Ignored }
            }
        }
    }

    fn drain_pending_gloas_columns(
        &mut self,
        block_root: BlockRoot,
        producers: &mut SilverSpineProducers,
    ) {
        let pending = self.gloas_pending_columns.remove(&block_root);
        self.drain_entries(pending, producers);
    }

    #[timed]
    fn drain_parent_pending_columns(
        &mut self,
        parent_root: BlockRoot,
        producers: &mut SilverSpineProducers,
    ) {
        let pending = self.parent_pending_columns.remove(&parent_root);
        if pending.is_some() {
            tracing::info!(
                root = hex::encode(parent_root),
                "draining data columns for parent root"
            );
        }
        self.drain_entries(pending, producers);
    }

    /// Re-validated rejects from buffered columns are not penalized — the
    /// disposition is dropped, matching the pre-batch behaviour.
    fn drain_entries(
        &mut self,
        pending: Option<Vec<PendingColumn>>,
        producers: &mut SilverSpineProducers,
    ) {
        let Some(pending) = pending else {
            return;
        };
        for column in pending {
            self.data_columns(column, RelayMeta::None, producers);
        }
    }

    fn record_validated_column(&mut self, p: PendingKzg, producers: &mut SilverSpineProducers) {
        let PendingKzg {
            sidecar, stream_id, recv_ts, block_root, column_index, bitmask, slot, ..
        } = p;
        self.record_columns(block_root, slot, bitmask, recv_ts, producers);

        if self.tracker.wants(bitmask) {
            let source = if stream_id.protocol() == StreamProtocol::GossipSub {
                ColumnSource::Gossip
            } else {
                ColumnSource::Rpc
            };
            producers.produce_with_ingestion(
                DataColumnsEvent::Persist {
                    ssz: sidecar.read,
                    source,
                    block_root,
                    column_index,
                    slot,
                },
                recv_ts,
            );
        }
    }

    /// The only place `Available` and custody completion are announced; both
    /// fire on their threshold edge, so each lands once per block.
    fn record_columns(
        &mut self,
        block_root: BlockRoot,
        slot: u64,
        columns: u128,
        recv_ts: IngestionTime,
        producers: &mut SilverSpineProducers,
    ) {
        let (available, custody_complete) = self.tracker.record(block_root, columns);
        if available {
            DataColumnCounters::DataColumnsAvailableEmitted.inc();
            tracing::info!(block = hex::encode(block_root), slot, "DataColumnsAvailable");
            producers
                .produce_with_ingestion(DataColumnsEvent::Available { block_root, slot }, recv_ts);
        }
        if custody_complete {
            tracing::info!(block = hex::encode(block_root), slot, "custody set complete");
            producers.produce_with_ingestion(
                SyncNeed::Arrived {
                    root: block_root,
                    slot,
                    kind: DataKind::Columns,
                    origin: Origin::Live,
                },
                recv_ts,
            );
        }
    }

    #[timed]
    fn handle_beacon_block(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        producers: &mut SilverSpineProducers,
    ) {
        let parent_root = match t_read.buffer() {
            Ok((buf, _)) if SignedBeaconBlockView::check_size(buf) => {
                *SignedBeaconBlockView::parent_root(buf)
            }
            Ok((buf, _)) => {
                tracing::warn!(?stream_id, len = buf.len(), "malformed beacon block");
                return;
            }
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read beacon block cache buffer");
                return;
            }
        };

        let root = self.beacon_block(stream_id, t_read, producers);

        if let Some((block_root, is_gloas)) = root &&
            is_gloas
        {
            self.drain_pending_gloas_columns(block_root, producers);
        }
        self.drain_parent_pending_columns(parent_root, producers);
    }

    #[timed]
    fn gossip_sidecar(
        &mut self,
        custody_group: u64,
        gossip: NewGossipMsg,
        producers: &mut SilverSpineProducers,
    ) {
        tracing::debug!(custody_group, "data column sidecar over gossip");
        let relay = RelayMeta::Gossip {
            topic: gossip.topic,
            msg_hash: gossip.msg_hash,
            recv_ts: gossip.recv_ts,
            protobuf: gossip.protobuf,
        };
        let sidecar = self.consumers.gossip.acquire(gossip.ssz);
        self.handle_data_column_sidecar(
            PendingColumn {
                stream_id: gossip.stream_id,
                sidecar,
                gossip_subnet: Some(custody_group),
                recv_ts: gossip.recv_ts.into(),
            },
            relay,
            producers,
        );
    }

    #[timed]
    fn handle_data_column_sidecar(
        &mut self,
        column: PendingColumn,
        relay: RelayMeta,
        producers: &mut SilverSpineProducers,
    ) {
        let stream_id = column.stream_id;
        let disposition = self.data_columns(column, relay, producers);

        if let ColumnDisposition::Rejected { block_root, slot, bitmask } = disposition {
            producers.produce(PeerEvent::RpcMisbehaviour {
                p2p_peer: stream_id.peer(),
                severity: RpcSeverity::Fatal,
            });
            if bitmask != 0 {
                producers.produce(SyncNeed::Missing {
                    root: block_root,
                    slot,
                    kind: DataKind::Columns,
                    columns: bitmask,
                    origin: Origin::Live,
                });
            }
        }
    }

    /// End-of-pass KZG verification of every batched sidecar in one
    /// `verify_cell_kzg_proof_batch` call. On a combined failure each sidecar
    /// re-verifies alone so the reject lands on the culpable peer only —
    /// honest traffic never pays the fallback.
    #[timed]
    fn flush_kzg_batch(&mut self, producers: &mut SilverSpineProducers) {
        debug_assert!(!self.kzg_batch.is_empty());

        let pending_len = self.kzg_batch.pending.len();
        DataColumnCounters::KzgBatchesVerified.inc();
        DataColumnCounters::KzgBatchColumns.add(pending_len as u64);

        let all_ok = {
            let validator = &self.validator;
            util::kzg_verify_batch_multi(
                self.kzg_batch.pending.iter().filter_map(|p| batch::kzg_entry(p, validator)),
                &mut self.kzg_scratch,
            )
        };

        for _ in 0..pending_len {
            let p = self.kzg_batch.pending.swap_remove(0);
            if batch::kzg_entry(&p, &self.validator).is_none() {
                tracing::error!(stream_id = ?p.stream_id, "batched sidecar inputs unavailable at flush");
                continue;
            }
            if all_ok || self.reverify_single(&p) {
                self.resolve_validated(p, producers);
            } else {
                self.resolve_rejected(&p, producers);
            }
        }
    }

    fn reverify_single(&self, p: &PendingKzg) -> bool {
        let Ok((buf, _)) = p.sidecar.buffer() else { return false };
        if p.is_gloas {
            self.validator
                .gloas_commitments(&p.block_root)
                .is_some_and(|c| util::verify_data_column_sidecar_kzg_proofs_gloas(buf, c))
        } else {
            util::verify_data_column_sidecar_kzg_proofs_fulu(buf)
        }
    }

    fn resolve_validated(&mut self, mut p: PendingKzg, producers: &mut SilverSpineProducers) {
        match mem::replace(&mut p.relay, RelayMeta::None) {
            RelayMeta::Gossip { topic, msg_hash, recv_ts, protobuf } => {
                producers.produce(PeerEvent::SendGossip {
                    originator_stream_id: p.stream_id,
                    topic,
                    msg_hash,
                    recv_ts,
                    protobuf,
                });
            }
            RelayMeta::Rpc { ssz } if self.sync_state.is_synced() => {
                producers.produce(PeerEvent::PublishDataColumn {
                    originator: p.stream_id,
                    topic: GossipTopic::DataColumnSidecar(p.column_index),
                    ssz,
                });
            }
            _ => {}
        }
        self.record_validated_column(p, producers);
    }

    fn resolve_rejected(&mut self, p: &PendingKzg, producers: &mut SilverSpineProducers) {
        tracing::warn!(stream_id = ?p.stream_id, "failed to verify sidecar kzg proof");
        DataColumnCounters::KzgBatchRejects.inc();
        producers.produce(PeerEvent::RpcMisbehaviour {
            p2p_peer: p.stream_id.peer(),
            severity: RpcSeverity::Fatal,
        });
        producers.produce(SyncNeed::Missing {
            root: p.block_root,
            slot: p.slot,
            kind: DataKind::Columns,
            columns: p.bitmask,
            origin: Origin::Live,
        });
    }
}

impl DataColumnsTile {
    #[timed]
    fn handle_beacon_state_event(
        &mut self,
        event: BeaconStateEvent,
        producers: &mut SilverSpineProducers,
    ) -> Option<([u8; 92], u64)> {
        let mut latest_status_event: Option<([u8; 92], u64)> = None;
        match event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
                // Per-event (not latest-only): BS emits one Status per accepted
                // block, and each newly validated root may unblock buffered
                // children.
                self.drain_parent_pending_columns(*StatusView::head_root(&ssz), producers);
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock { ssz, source, .. } => {
                let t_read = self.consumers.acquire_persisted(source, ssz);

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let slot = SignedBeaconBlockView::slot(buf);
                        let block_root = util::block_root(buf, self.spec.is_gloas_at_slot(slot));

                        self.validator.note_persisted(block_root, slot);

                        self.drain_parent_pending_columns(block_root, producers);
                    }
                    Err(e) => {
                        tracing::error!(?e, seq=t_read.seq(), consumer=?self.consumers.persist_gossip, "persist consumer buffer acquire failed");
                    }
                }
            }
            _ => {}
        }
        latest_status_event
    }
}

impl Tile<SilverSpine> for DataColumnsTile {
    fn try_init(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        util::warm_kzg_settings();
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.consumers.free();

        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock if self.sync_state.is_synced() => {
                let t_read: TRead = self.consumers.gossip.acquire(gossip.ssz);
                self.handle_beacon_block(t_read, gossip.stream_id, producers);
            }
            silver_common::GossipTopic::DataColumnSidecar(custody_group)
                if self.sync_state.is_synced() =>
            {
                self.gossip_sidecar(custody_group, gossip, producers);
            }
            _ => {}
        });

        adapter.consume(|rpc: RpcInbound, producers| match rpc {
            RpcInbound::Request(_) => {}
            RpcInbound::Response(rsp) => {
                let id = RequestId::from(rsp.application_id);
                match rsp.response {
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                    if id.is(DataKind::Block, Origin::Live) =>
                {
                    let t_read = self.consumers.rpc.acquire(ssz);
                    self.handle_beacon_block(t_read, rsp.stream_id, producers);
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if id.is(DataKind::Columns, Origin::Live) => {
                    // TODO validate that originating peer has data column index in custody groups
                    tracing::debug!("data column sidecar over rpc");
                    let sidecar = self.consumers.rpc.acquire(ssz);
                    self.handle_data_column_sidecar(
                        PendingColumn {
                            stream_id: rsp.stream_id,
                            sidecar,
                            gossip_subnet: None,
                            recv_ts: IngestionTime::now(),
                        },
                        RelayMeta::Rpc { ssz },
                        producers,
                    );
                }
                silver_common::RpcResponse::Error { error, msg, len } if id.is(DataKind::Columns, Origin::Live) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "rpc error response");
                }
                other => {
                    tracing::trace!(?other, app_id=rsp.application_id, id=?rsp.stream_id, "ignoring rpc response");
                }
                }
            }
        });

        adapter.consume(|beacon_event: BeaconStateEvent, producers| {
            if let Some((ssz, wall_slot)) = self.handle_beacon_state_event(beacon_event, producers)
            {
                self.sync_state.update(ssz, wall_slot);
            }
        });

        adapter.consume(|sync_update: SyncUpdate, _| {
            self.sync_state.set_sync_target(sync_update);
        });

        adapter.consume(|resp: EngineResp, producers| {
            if let EngineResp::GetBlobs(r) = resp {
                let block_root = r.block_root;
                let built = self.el_fetcher.handle_response(
                    r,
                    &self.tracker,
                    &self.sync_state,
                    &mut self.el_column_producer,
                    producers,
                );
                if let Some((slot, built)) = built {
                    self.record_columns(block_root, slot, built, IngestionTime::now(), producers);
                }
            }
        });
        self.el_fetcher.free();

        if !self.kzg_batch.is_empty() {
            self.flush_kzg_batch(&mut adapter.producers);
        }

        let now = Instant::now();

        self.validator.rotate(now);
        self.tracker.maybe_rotate(now);
        self.parent_pending_columns.maybe_rotate(now);
        self.gloas_pending_columns.maybe_rotate(now);
        self.el_fetcher.rotate(now);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_beacon_state_data::BeaconStateOwner;
    use silver_common::{
        EngineReq, P2pStreamId, StreamProtocol, TCache, TCacheProducer, TCacheRead,
        ssz_view::{DATA_COLUMN_SIDECAR_MIN, NUMBER_OF_COLUMNS, SIGNED_BEACON_BLOCK_MIN},
    };
    use tempfile::TempDir;

    use super::*;

    const CUSTODY_COLUMNS: u128 = (1u128 << 3) | (1u128 << 7);

    /// A tile on its own spine, with an injector adapter to read what it
    /// produced. Tcaches are heap-allocated and leaked, so the producers need
    /// not outlive this. Declaration order is drop order: adapters before the
    /// spine, spine before the directory it is mapped in.
    struct Rig {
        inj: SpineAdapter<SilverSpine>,
        conn: SpineAdapter<SilverSpine>,
        tile: DataColumnsTile,
        _spine: Box<SilverSpine>,
        _dir: TempDir,
    }

    struct Injector;

    impl Tile<SilverSpine> for Injector {
        fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
    }

    impl Rig {
        fn new(custody: u128) -> Self {
            let gossip_tc = TCache::producer("gossip_blocks", 1024 * 1024);
            let gossip_consumer = gossip_tc.cache_ref().random_access("gossip_cons", true).unwrap();

            let persist_gossip_tc = TCache::producer("persist_gossip_blocks", 1024 * 1024);
            let persist_gossip_consumer =
                persist_gossip_tc.cache_ref().random_access("persist_gossip_cons", true).unwrap();

            let rpc_tc = TCache::producer("rpc_blocks", 1024 * 1024);
            let rpc_consumer = rpc_tc.cache_ref().random_access("rpc_cons", true).unwrap();

            let persist_rpc_tc = TCache::producer("persist_rpc_blocks", 1024 * 1024);
            let persist_rpc_consumer =
                persist_rpc_tc.cache_ref().random_access("persist_rpc_cons", true).unwrap();

            let engine_resp_tc = TCache::producer("engine_resp", 1024 * 1024);
            let engine_resp_consumer =
                engine_resp_tc.cache_ref().random_access("engine_resp_cons", true).unwrap();

            let tile = DataColumnsTile::new(
                ColumnConsumers {
                    gossip: gossip_consumer,
                    persist_gossip: persist_gossip_consumer,
                    rpc: rpc_consumer,
                    persist_rpc: persist_rpc_consumer,
                },
                BeaconStateOwner::empty_test(0).reader(),
                custody,
                Arc::new(SpecConfig::mainnet()),
                engine_resp_consumer,
                TCache::producer("el_columns", 1024 * 1024),
            );

            let dir = tempfile::tempdir().unwrap();
            let mut spine = Box::new(SilverSpine::new_with_base_dir(dir.path(), None));
            let conn = SpineAdapter::connect_tile(&tile, &mut spine);
            let mut inj = SpineAdapter::connect_tile(&Injector, &mut spine);
            // Cursors snap on their first consume, so prime them while empty.
            inj.consume(|_: DataColumnsEvent, _| {});
            inj.consume(|_: SyncNeed, _| {});
            inj.consume(|_: EngineReq, _| {});
            Self { inj, conn, tile, _spine: spine, _dir: dir }
        }

        fn drain(&mut self) -> Produced {
            let mut out = Produced::default();
            self.inj.consume(|ev: DataColumnsEvent, _| match ev {
                DataColumnsEvent::Available { .. } => out.available += 1,
                DataColumnsEvent::Persist { .. } => out.persisted += 1,
            });
            self.inj.consume(|need: SyncNeed, _| match need {
                SyncNeed::Missing { .. } => out.missing.push(need),
                SyncNeed::Arrived { kind: DataKind::Columns, origin: Origin::Live, .. } => {
                    out.custody_complete += 1
                }
                SyncNeed::Arrived { .. } | SyncNeed::BackfillGap { .. } => {}
            });
            self.inj.consume(|_: EngineReq, _| out.engine += 1);
            out
        }
    }

    #[derive(Default)]
    struct Produced {
        available: usize,
        custody_complete: usize,
        persisted: usize,
        engine: usize,
        missing: Vec<SyncNeed>,
    }

    /// Minimal fulu `SignedBeaconBlock` carrying blob commitments: message at
    /// offset 100, body at 184, commitments spanning body[400..500).
    fn blob_block_bytes(slot: u64) -> Vec<u8> {
        let mut block_bytes = vec![0u8; 784];
        block_bytes[0..4].copy_from_slice(&100u32.to_le_bytes());
        block_bytes[100..108].copy_from_slice(&slot.to_le_bytes());
        block_bytes[180..184].copy_from_slice(&84u32.to_le_bytes());
        block_bytes[184 + 388..184 + 392].copy_from_slice(&400u32.to_le_bytes());
        block_bytes[184 + 392..184 + 396].copy_from_slice(&500u32.to_le_bytes());
        block_bytes
    }

    /// Callers `acquire` the returned handle themselves: a `TRead` points back
    /// at the consumer's address, so it must not be acquired before the
    /// consumer reaches its final binding.
    fn produce_block(block_bytes: &[u8], cache: &'static str) -> (TRandomAccess, TCacheRead) {
        let mut producer = TCache::producer(cache, 1024 * 1024);
        let mut res = producer.reserve(block_bytes.len(), true).unwrap();
        res.write_all(block_bytes).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let consumer = producer.cache_ref().random_access("test_block_cons", true).unwrap();
        (consumer, ssz)
    }

    /// `Status` fixing only what [`SyncStatus::update`] reads.
    fn status_ssz(finalized_epoch: u64) -> [u8; 92] {
        let mut ssz = [0u8; 92];
        ssz[36..44].copy_from_slice(&finalized_epoch.to_le_bytes());
        ssz
    }

    #[test]
    fn block_reports_its_missing_custody_columns() {
        let block_bytes = blob_block_bytes(42);
        let block_root = util::block_root_fulu(&block_bytes);

        for (protocol, cache) in [
            (StreamProtocol::BeaconBlocksByRange, "need_block_rpc"),
            (StreamProtocol::GossipSub, "need_block_gossip"),
        ] {
            let mut rig = Rig::new(CUSTODY_COLUMNS);
            rig.tile.sync_state.set_sync_target(SyncUpdate::Following);
            let (mut consumer, ssz) = produce_block(&block_bytes, cache);
            let read = consumer.acquire(ssz);

            rig.tile.beacon_block(
                P2pStreamId::new(2, 2, protocol, true),
                read,
                &mut rig.conn.producers,
            );
            let out = rig.drain();

            assert_eq!(out.missing.len(), 1, "{protocol:?}");
            let SyncNeed::Missing { root, slot, kind, columns, origin } = out.missing[0] else {
                panic!("expected a missing-columns need from {protocol:?}");
            };
            assert_eq!(kind, DataKind::Columns);
            assert_eq!(columns, CUSTODY_COLUMNS);
            assert_eq!(root, block_root);
            assert_eq!(slot, 42, "the need carries the slot the engine suppresses against");
            assert_eq!(origin, Origin::Live, "tip need, not backfill");
            assert_eq!(out.available, 0, "commitments owed: nothing is available yet");
        }
    }

    /// A sidecar whose gossip checks could not all be completed is still
    /// imported, but must not reach the mesh with us as its relayer. The relay
    /// is dropped at batch time, so the flush has nothing to send.
    #[test]
    fn relay_ineligible_column_is_batched_without_a_relay() {
        for (relay_eligible, want_relay, cache) in
            [(true, true, "relay_ok"), (false, false, "relay_gated")]
        {
            // `consumer` is declared before `rig` so it outlives the batched
            // `TRead` that points back at it.
            let (mut consumer, ssz) = produce_block(&blob_block_bytes(7), cache);
            let mut rig = Rig::new(CUSTODY_COLUMNS);
            let read = consumer.acquire(ssz);

            let disposition = rig.tile.handle_column(
                ColumnOutcome::Record {
                    block_root: [4u8; 32],
                    column_index: 3,
                    bitmask: 1 << 3,
                    slot: 7,
                    relay_eligible,
                },
                PendingColumn {
                    stream_id: P2pStreamId::new(
                        2,
                        2,
                        StreamProtocol::DataColumnSidecarsByRange,
                        true,
                    ),
                    sidecar: read,
                    gossip_subnet: None,
                    recv_ts: IngestionTime::now(),
                },
                false,
                RelayMeta::Rpc { ssz },
                &mut rig.conn.producers,
            );

            assert!(
                matches!(disposition, ColumnDisposition::Batched),
                "relay_eligible={relay_eligible}: imported either way"
            );
            let queued = rig.tile.kzg_batch.pending.first().expect("batched");
            assert_eq!(
                !matches!(queued.relay, RelayMeta::None),
                want_relay,
                "relay_eligible={relay_eligible}"
            );
            rig.tile.kzg_batch.pending.clear();
        }
    }

    /// Fulu-layout sidecar with empty lists: enough for `SidecarLayout::of`
    /// and the index read, which is all these cases need.
    fn synth_fulu_sidecar(index: u64, slot: u64) -> Vec<u8> {
        let mut buf = vec![0u8; DATA_COLUMN_SIDECAR_MIN];
        buf[0..8].copy_from_slice(&index.to_le_bytes());
        for off in [8usize, 12, 16] {
            buf[off..off + 4].copy_from_slice(&(DATA_COLUMN_SIDECAR_MIN as u32).to_le_bytes());
        }
        buf[20..28].copy_from_slice(&slot.to_le_bytes());
        buf
    }

    fn feed_sidecar(rig: &mut Rig, bytes: &[u8], cache: &'static str) -> ColumnDisposition {
        let (mut consumer, ssz) = produce_block(bytes, cache);
        let read = consumer.acquire(ssz);
        rig.tile.data_columns(
            PendingColumn {
                stream_id: P2pStreamId::new(2, 2, StreamProtocol::DataColumnSidecarsByRange, true),
                sidecar: read,
                gossip_subnet: None,
                recv_ts: IngestionTime::now(),
            },
            RelayMeta::None,
            &mut rig.conn.producers,
        )
    }

    /// `1u128 << index` is only defined below 128, and `release-prod` masks an
    /// over-wide shift rather than trapping — so an out-of-range index used to
    /// reject while naming a different, innocent column to re-request.
    #[test]
    fn out_of_range_column_index_names_no_column_to_refetch() {
        for index in [NUMBER_OF_COLUMNS as u64, NUMBER_OF_COLUMNS as u64 + 3, u64::MAX] {
            let mut rig = Rig::new(CUSTODY_COLUMNS);
            let disposition = feed_sidecar(&mut rig, &synth_fulu_sidecar(index, 7), "oor_index");
            let out = rig.drain();

            assert!(
                matches!(disposition, ColumnDisposition::Rejected { bitmask: 0, .. }),
                "index {index}: rejected with no column named"
            );
            assert!(out.missing.is_empty(), "index {index}: nothing to re-own");
        }

        // Control: an in-range index does name its column, so the assertions
        // above are about the bound and not about a blanket empty bitmask.
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        let disposition = feed_sidecar(&mut rig, &synth_fulu_sidecar(3, 7), "in_range_index");
        assert!(
            matches!(disposition, ColumnDisposition::Rejected { bitmask, .. } if bitmask == 1 << 3),
            "an in-range index is re-owed"
        );
    }

    /// `handle_beacon_block` is the gossip and RPC entry, so it owns the size
    /// gate: every `SignedBeaconBlockView` accessor slices a compile-time
    /// offset and `unwrap`s, and `release-prod` aborts on panic.
    #[test]
    fn short_block_stops_at_the_entry_gate() {
        for len in [0, 1, 100, 107, SIGNED_BEACON_BLOCK_MIN - 1] {
            let mut rig = Rig::new(CUSTODY_COLUMNS);
            rig.tile.sync_state.set_sync_target(SyncUpdate::Following);
            let (mut consumer, ssz) = produce_block(&vec![0u8; len], "short_block_cons");
            let read = consumer.acquire(ssz);

            rig.tile.handle_beacon_block(
                read,
                P2pStreamId::new(2, 2, StreamProtocol::GossipSub, true),
                &mut rig.conn.producers,
            );
            let out = rig.drain();

            assert_eq!(
                out.available + out.persisted + out.engine + out.missing.len(),
                0,
                "len {len}: a malformed block says nothing"
            );
        }
    }

    /// A block at or below the DA floor owes no columns, and coverage there is
    /// unobservable — so nothing is emitted at all. Per-block events no
    /// consumer can act on are pure spam on the live path.
    #[test]
    fn block_below_da_floor_says_nothing() {
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        rig.tile.sync_state.set_sync_target(SyncUpdate::Following);
        // floor = 2 * 32 = 64, above the block's slot.
        rig.tile.sync_state.update(status_ssz(2), 100);

        let block_bytes = blob_block_bytes(42);
        let (mut consumer, ssz) = produce_block(&block_bytes, "floor_block_prod");
        let read = consumer.acquire(ssz);

        let ret = rig.tile.beacon_block(
            P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, true),
            read,
            &mut rig.conn.producers,
        );
        let out = rig.drain();

        assert!(ret.is_none(), "no column tracking below the floor");
        assert_eq!(out.available + out.persisted + out.engine + out.missing.len(), 0);
    }

    /// A sidecar this tile already validated is still offered to storage:
    /// storage dedupes against what it holds, so a copy it already has costs no
    /// write, and a second offer is the only thing that fills a hole left by
    /// one that lapsed. The chase answer is the rationed part — a copy nobody
    /// asked for tells the engine nothing it does not already have.
    #[test]
    fn held_sidecar_is_offered_again_but_answers_only_when_asked_for() {
        let block_root = [9u8; 32];
        for (protocol, cache, answers) in [
            (StreamProtocol::GossipSub, "held_gossip", 0),
            (StreamProtocol::DataColumnSidecarsByRange, "held_rpc", 1),
        ] {
            let mut rig = Rig::new(CUSTODY_COLUMNS);
            rig.tile.tracker.record(block_root, CUSTODY_COLUMNS);

            let (mut consumer, ssz) = produce_block(&blob_block_bytes(7), cache);
            let read = consumer.acquire(ssz);

            let disposition = rig.tile.handle_column(
                ColumnOutcome::AlreadyHeld { block_root, column_index: 3, slot: 7 },
                PendingColumn {
                    stream_id: P2pStreamId::new(2, 2, protocol, true),
                    sidecar: read,
                    gossip_subnet: None,
                    recv_ts: IngestionTime::now(),
                },
                false,
                RelayMeta::None,
                &mut rig.conn.producers,
            );
            let out = rig.drain();

            assert!(
                matches!(disposition, ColumnDisposition::Ignored),
                "{protocol:?}: a duplicate is never relayed"
            );
            assert_eq!(
                out.persisted, 1,
                "{protocol:?}: storage is the one that knows whether it landed"
            );
            assert_eq!(
                out.custody_complete, answers,
                "{protocol:?}: only a requested duplicate answers"
            );
            assert_eq!(out.available, 0, "{protocol:?}: availability is never re-announced");
        }
    }
}
