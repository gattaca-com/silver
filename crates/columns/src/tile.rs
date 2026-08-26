use std::{
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
    BeaconStateEvent, ColumnSource, DataColumnsEvent, DataKind, EngineReq, EngineResp, GossipTopic,
    IngestionTime, NewGossipMsg, Origin, P2pStreamId, PeerEvent, RequestId, RpcInbound,
    RpcSeverity, SilverSpine, SilverSpineProducers, StreamProtocol, SyncNeed, SyncUpdate,
    TProducer, TRandomAccess, TRead, Wheel,
    column_util::{self as util, KzgScratch},
    ssz_view::{NUMBER_OF_COLUMNS, SignedBeaconBlockView, StatusView},
};

use crate::{
    BlockRoot, DataColumnCounters,
    batch::{self, KzgBatch, PendingKzg, RelayMeta},
    el_blobs::ElBlobFetcher,
    sync::SyncStatus,
    validate::{ColumnOutcome, ColumnValidator},
};

/// A sidecar with the provenance its validation needs. Carrying `recv_ts` is
/// what lets a column buffered before its block still report its own receive
/// time rather than the drain's.
struct PendingColumn {
    stream_id: P2pStreamId,
    sidecar: TRead,
    gossip_subnet: Option<u64>,
    recv_ts: IngestionTime,
}

#[derive(Default)]
pub(crate) struct BlockValidation {
    pub(crate) columns: u128,
    /// Proposer signature already BLS-verified for this block root.
    /// `block_root` does not pin the signature, so the memo hits only on
    /// bytes-equality.
    pub(crate) signature: Option<[u8; 96]>,
}

impl BlockValidation {
    pub(crate) fn has_columns(&self, bitmask: u128) -> bool {
        self.columns & bitmask != 0
    }
}

/// `EngineReq` is large but short-lived here, so
/// boxing it would only add an alloc on the block path.
#[allow(clippy::large_enum_variant)]
pub(crate) enum StorageEmit {
    Need(SyncNeed),
    Engine(EngineReq),
    DataAvailability(DataColumnsEvent),
}

/// Only `Batched` sidecars can end up forwarded / republished on gossip
/// (their relay fires at flush if KZG passes): `Ignored` covers spec-IGNORE
/// cases (dup, post-wall, parent pending, buffered) whose sidecars must not
/// be relayed and whose senders are not culpable.
enum ColumnDisposition {
    Batched,
    Ignored,
    Rejected { block_root: BlockRoot, slot: u64, bitmask: u128 },
}

pub struct DataColumnsTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    // Gossip and rpc are read twice: 'live' and when we receive a request from
    // beacon state to persist - this require 2 consumers.
    gossip_consumer: TRandomAccess,
    persist_gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    persist_rpc_consumer: TRandomAccess,

    spec: Arc<SpecConfig>,

    validator: ColumnValidator,
    // Sidecars past every per-sidecar check, KZG-verified together at the
    // end of the pass.
    kzg_batch: KzgBatch,

    // keyed by block body root
    validated: Wheel<BlockRoot, BlockValidation, 4>,
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
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        gossip_consumer: TRandomAccess,
        persist_gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        persist_rpc_consumer: TRandomAccess,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        spec: Arc<SpecConfig>,
        engine_resp_consumer: TRandomAccess,
        el_column_producer: TProducer,
    ) -> Self {
        let epoch_duration = Duration::from_secs(spec.seconds_per_slot) * SLOTS_PER_EPOCH as u32;
        Self {
            custody_group_columns,
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            spec,
            validator: ColumnValidator::new(beacon_state, epoch_duration),
            kzg_batch: KzgBatch::new(),
            validated: Wheel::new(epoch_duration),
            gloas_pending_columns: Wheel::new(epoch_duration),
            parent_pending_columns: Wheel::new(Duration::from_secs(24)),
            sync_state: SyncStatus::default(),
            el_fetcher: ElBlobFetcher::new(engine_resp_consumer),
            el_column_producer,
            kzg_scratch: KzgScratch::default(),
        }
    }

    #[timed]
    fn beacon_block<F>(
        &mut self,
        stream_id: P2pStreamId,
        block: TRead,
        emit: &mut F,
    ) -> Option<(B256, bool)>
    where
        F: FnMut(StorageEmit),
    {
        let buffer = match block.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read beacon block cache buffer");
                return None;
            }
        };

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
            emit(StorageEmit::DataAvailability(DataColumnsEvent::Available { block_root, slot }));
            return None;
        }

        if is_gloas {
            self.validator.cache_gloas_commitments(block_root, buffer);
        }

        // Custody columns only — silver floors cgc at SAMPLES_PER_SLOT, so the
        // custody set IS the sample set; no beyond-custody sampling needed.
        let to_request = self.columns_to_request(&block_root);
        if to_request == 0 {
            // Already complete, and the block is only arriving now: the earlier
            // completion was announced before anything could attribute it to this
            // slot. Availability is pushed, never polled, so say it again.
            emit(StorageEmit::DataAvailability(DataColumnsEvent::Available { block_root, slot }));
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
            self.el_fetcher.try_fetch(buffer, block_root, slot, to_request, emit);
        }

        emit(StorageEmit::Need(SyncNeed::Missing {
            root: block_root,
            slot,
            kind: DataKind::Columns,
            columns: to_request,
            origin: Origin::Live,
        }));
        Some((block_root, is_gloas))
    }

    fn columns_to_request(&self, root: &BlockRoot) -> u128 {
        let validated = self.validated.get(root).map_or(0, |v| v.columns);
        self.custody_group_columns & !validated
    }

    #[timed]
    fn data_columns<F>(
        &mut self,
        column: PendingColumn,
        relay: RelayMeta,
        emit: &mut F,
    ) -> ColumnDisposition
    where
        F: FnMut(DataColumnsEvent),
    {
        let validated = match column.sidecar.buffer() {
            Ok((buf, _)) => self.validator.validate(
                column.stream_id,
                buf,
                column.gossip_subnet,
                column.recv_ts,
                &self.sync_state,
                &mut self.validated,
            ),
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
        self.handle_column(outcome, column, is_gloas, relay, emit)
    }

    fn handle_column<F>(
        &mut self,
        outcome: ColumnOutcome,
        column: PendingColumn,
        is_gloas: bool,
        relay: RelayMeta,
        emit: &mut F,
    ) -> ColumnDisposition
    where
        F: FnMut(DataColumnsEvent),
    {
        match outcome {
            ColumnOutcome::Skip => ColumnDisposition::Ignored,
            ColumnOutcome::AlreadyHeld { block_root, column_index, slot } => {
                let is_gossip = column.stream_id.protocol() == StreamProtocol::GossipSub;
                emit(DataColumnsEvent::Persist {
                    ssz: column.sidecar.read,
                    source: if is_gossip { ColumnSource::Gossip } else { ColumnSource::Rpc },
                    block_root,
                    column_index,
                    slot,
                });

                if !is_gossip && self.custody_set_complete(&block_root) {
                    DataColumnCounters::DataColumnsAvailableEmitted.inc();
                    tracing::info!(
                        block = hex::encode(block_root),
                        slot,
                        "DataColumnsAvailable: re-announced for a requested duplicate"
                    );
                    emit(DataColumnsEvent::Available { block_root, slot });
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
            ColumnOutcome::Record { block_root, column_index, bitmask, slot } => {
                let queued = self.kzg_batch.push(PendingKzg {
                    sidecar: column.sidecar,
                    stream_id: column.stream_id,
                    recv_ts: column.recv_ts,
                    block_root,
                    column_index,
                    bitmask,
                    slot,
                    is_gloas,
                    relay,
                });
                if queued { ColumnDisposition::Batched } else { ColumnDisposition::Ignored }
            }
        }
    }

    fn drain_pending_gloas_columns<F>(&mut self, block_root: BlockRoot, emit: &mut F)
    where
        F: FnMut(DataColumnsEvent),
    {
        let pending = self.gloas_pending_columns.remove(&block_root);
        self.drain_entries(pending, emit);
    }

    #[timed]
    fn drain_parent_pending_columns<F>(&mut self, parent_root: BlockRoot, emit: &mut F)
    where
        F: FnMut(DataColumnsEvent),
    {
        let pending = self.parent_pending_columns.remove(&parent_root);
        if pending.is_some() {
            tracing::info!(
                root = hex::encode(parent_root),
                "draining data columns for parent root"
            );
        }
        self.drain_entries(pending, emit);
    }

    /// Re-validated rejects from buffered columns are not penalized — the
    /// disposition is dropped, matching the pre-batch behaviour.
    fn drain_entries<F>(&mut self, pending: Option<Vec<PendingColumn>>, emit: &mut F)
    where
        F: FnMut(DataColumnsEvent),
    {
        let Some(pending) = pending else {
            return;
        };
        for column in pending {
            self.data_columns(column, RelayMeta::None, emit);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_validated_column<F>(
        &mut self,
        block_root: BlockRoot,
        column_index: u64,
        column_bitmask: u128,
        slot: u64,
        sidecar: TRead,
        is_gossip: bool,
        emit: &mut F,
    ) where
        F: FnMut(DataColumnsEvent),
    {
        let entry = self.validated.entry(block_root).or_default();
        entry.columns |= column_bitmask;
        let validated = entry.columns;

        if validated & self.custody_group_columns == self.custody_group_columns {
            // have all validated data columns for the block.
            DataColumnCounters::DataColumnsAvailableEmitted.inc();
            tracing::info!(
                block = hex::encode(block_root),
                slot,
                "DataColumnsAvailable: custody set complete"
            );
            emit(DataColumnsEvent::Available { block_root, slot })
        }

        if column_bitmask & self.custody_group_columns != 0 {
            // emit persist msg
            let source = if is_gossip { ColumnSource::Gossip } else { ColumnSource::Rpc };
            emit(DataColumnsEvent::Persist {
                ssz: sidecar.read,
                source,
                block_root,
                column_index,
                slot,
            })
        }
    }

    /// Whether every column of our custody set has been validated for a block.
    fn custody_set_complete(&self, block_root: &BlockRoot) -> bool {
        self.validated
            .get(block_root)
            .is_some_and(|v| v.columns & self.custody_group_columns == self.custody_group_columns)
    }

    #[timed]
    fn handle_beacon_block(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        producers: &mut SilverSpineProducers,
    ) {
        let parent_root = t_read
            .buffer()
            .ok()
            .filter(|(buf, _)| SignedBeaconBlockView::check_size(buf))
            .map(|(buf, _)| *SignedBeaconBlockView::parent_root(buf));

        let root = self.beacon_block(stream_id, t_read, &mut |emit| match emit {
            StorageEmit::Need(need) => {
                producers.sync_needs.produce(&need.into());
            }
            StorageEmit::Engine(req) => {
                producers.engine_reqs.produce(&req.into());
            }
            StorageEmit::DataAvailability(msg) => {
                producers.data_columns.produce(&msg.into());
            }
        });

        if let Some((block_root, is_gloas)) = root &&
            is_gloas
        {
            self.drain_pending_gloas_columns(block_root, &mut |msg| {
                producers.data_columns.produce(&msg.into());
            });
        }
        if let Some(parent_root) = parent_root {
            self.drain_parent_pending_columns(parent_root, &mut |msg| {
                producers.data_columns.produce(&msg.into());
            });
        }
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
        let sidecar = self.gossip_consumer.acquire(gossip.ssz);
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
        let disposition = self.data_columns(column, relay, &mut |msg: DataColumnsEvent| {
            producers.data_columns.produce(&msg.into());
        });

        if let ColumnDisposition::Rejected { block_root, slot, bitmask } = disposition {
            producers.peer_events.produce(
                &PeerEvent::RpcMisbehaviour {
                    p2p_peer: stream_id.peer(),
                    severity: RpcSeverity::Fatal,
                }
                .into(),
            );
            producers.sync_needs.produce(
                &SyncNeed::Missing {
                    root: block_root,
                    slot,
                    kind: DataKind::Columns,
                    columns: bitmask,
                    origin: Origin::Live,
                }
                .into(),
            );
        }
    }

    /// End-of-pass KZG verification of every batched sidecar in one
    /// `verify_cell_kzg_proof_batch` call. On a combined failure each sidecar
    /// re-verifies alone so the reject lands on the culpable peer only —
    /// honest traffic never pays the fallback.
    #[timed]
    fn flush_kzg_batch(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
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
                self.resolve_validated(p, adapter);
            } else {
                self.resolve_rejected(&p, adapter);
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

    fn resolve_validated(&mut self, p: PendingKzg, adapter: &mut SpineAdapter<SilverSpine>) {
        let PendingKzg {
            sidecar,
            stream_id,
            recv_ts,
            block_root,
            column_index,
            bitmask,
            slot,
            relay,
            ..
        } = p;
        match relay {
            RelayMeta::Gossip { topic, msg_hash, recv_ts, protobuf } => {
                adapter.produce(PeerEvent::SendGossip {
                    originator_stream_id: stream_id,
                    topic,
                    msg_hash,
                    recv_ts,
                    protobuf,
                });
            }
            RelayMeta::Rpc { ssz } if self.sync_state.is_synced() => {
                adapter.produce(PeerEvent::PublishDataColumn {
                    originator: stream_id,
                    topic: GossipTopic::DataColumnSidecar(column_index),
                    ssz,
                });
            }
            _ => {}
        }
        let is_gossip = stream_id.protocol() == StreamProtocol::GossipSub;
        self.record_validated_column(
            block_root,
            column_index,
            bitmask,
            slot,
            sidecar,
            is_gossip,
            &mut |msg| adapter.producers.produce_with_ingestion(msg, recv_ts),
        );
    }

    fn resolve_rejected(&mut self, p: &PendingKzg, adapter: &mut SpineAdapter<SilverSpine>) {
        tracing::warn!(stream_id = ?p.stream_id, "failed to verify sidecar kzg proof");
        DataColumnCounters::KzgBatchRejects.inc();
        adapter.produce(PeerEvent::RpcMisbehaviour {
            p2p_peer: p.stream_id.peer(),
            severity: RpcSeverity::Fatal,
        });
        adapter.produce(SyncNeed::Missing {
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
                self.drain_parent_pending_columns(*StatusView::head_root(&ssz), &mut |msg| {
                    producers.data_columns.produce(&msg.into());
                });
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock { ssz, source, .. } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let slot = SignedBeaconBlockView::slot(buf);
                        let block_root = util::block_root(buf, self.spec.is_gloas_at_slot(slot));

                        self.validator.note_persisted(block_root);

                        self.drain_parent_pending_columns(block_root, &mut |msg| {
                            producers.data_columns.produce(&msg.into());
                        });
                    }
                    Err(e) => {
                        tracing::error!(?e, seq=t_read.seq(), consumer=?self.persist_gossip_consumer, "persist consumer buffer acquire failed");
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
        self.gossip_consumer.free();
        self.rpc_consumer.free();
        self.persist_gossip_consumer.free();
        self.persist_rpc_consumer.free();

        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock if self.sync_state.is_synced() => {
                let t_read: TRead = self.gossip_consumer.acquire(gossip.ssz);
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
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.handle_beacon_block(t_read, rsp.stream_id, producers);
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if id.is(DataKind::Columns, Origin::Live) => {
                    // TODO validate that originating peer has data column index in custody groups
                    tracing::debug!("data column sidecar over rpc");
                    let sidecar = self.rpc_consumer.acquire(ssz);
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
                self.el_fetcher.handle_response(
                    r,
                    &mut self.validated,
                    &self.sync_state,
                    self.custody_group_columns,
                    &mut self.el_column_producer,
                    &mut |msg| {
                        producers.data_columns.produce(&msg.into());
                    },
                );
            }
        });
        self.el_fetcher.free();

        if !self.kzg_batch.is_empty() {
            self.flush_kzg_batch(adapter);
        }

        let now = Instant::now();

        self.validator.rotate(now);
        self.validated.maybe_rotate(now);
        self.parent_pending_columns.maybe_rotate(now);
        self.gloas_pending_columns.maybe_rotate(now);
        self.el_fetcher.rotate(now);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_beacon_state_data::BeaconStateOwner;
    use silver_common::{P2pStreamId, StreamProtocol, TCache, TCacheProducer, TCacheRead};

    use super::*;

    const CUSTODY_COLUMNS: u128 = (1u128 << 3) | (1u128 << 7);

    /// Tile with `CUSTODY_COLUMNS` custody and no EL path exercised. Tcaches
    /// are heap-allocated and leaked, so the producers need not outlive this.
    fn make_tile() -> DataColumnsTile {
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

        DataColumnsTile::new(
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            BeaconStateOwner::empty_test(0).reader(),
            CUSTODY_COLUMNS,
            Arc::new(SpecConfig::mainnet()),
            engine_resp_consumer,
            TCache::producer("el_columns", 1024 * 1024),
        )
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
            let mut tile = make_tile();
            tile.sync_state.set_sync_target(SyncUpdate::Following);
            let (mut consumer, ssz) = produce_block(&block_bytes, cache);
            let read = consumer.acquire(ssz);

            let mut events = Vec::new();
            tile.beacon_block(P2pStreamId::new(2, 2, protocol, true), read, &mut |emit| {
                if let StorageEmit::Need(need) = emit {
                    events.push(need);
                }
            });

            assert_eq!(events.len(), 1, "{protocol:?}");
            let SyncNeed::Missing { root, slot, kind, columns, origin } = events[0] else {
                panic!("expected a missing-columns need from {protocol:?}");
            };
            assert_eq!(kind, DataKind::Columns);
            assert_eq!(columns, CUSTODY_COLUMNS);
            assert_eq!(root, block_root);
            assert_eq!(slot, 42, "the need carries the slot the engine suppresses against");
            assert_eq!(origin, Origin::Live, "tip need, not backfill");
        }
    }

    /// A block at or below the DA floor owes no columns, and coverage there is
    /// unobservable — so nothing is emitted at all. Per-block events no
    /// consumer can act on are pure spam on the live path.
    #[test]
    fn block_below_da_floor_says_nothing() {
        let mut tile = make_tile();
        tile.sync_state.set_sync_target(SyncUpdate::Following);
        // floor = 2 * 32 = 64, above the block's slot.
        tile.sync_state.update(status_ssz(2), 100);

        let block_bytes = blob_block_bytes(42);
        let (mut consumer, ssz) = produce_block(&block_bytes, "floor_block_prod");
        let read = consumer.acquire(ssz);

        let mut events = 0;
        let ret = tile.beacon_block(
            P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, true),
            read,
            &mut |_| events += 1,
        );

        assert!(ret.is_none(), "no column tracking below the floor");
        assert_eq!(events, 0, "no coverage, no need, nothing");
    }

    /// A sidecar this tile already validated is still offered to storage:
    /// validated here says nothing about whether the persist landed, and a
    /// second offer is the only thing that fills a hole left by one that
    /// lapsed. Storage dedupes against what it holds, so a copy it already has
    /// costs no write. The *announcement* is the rationed part — a copy nobody
    /// asked for tells the engine nothing it does not already have.
    #[test]
    fn held_sidecar_is_offered_again_but_announced_only_when_asked_for() {
        let block_root = [9u8; 32];
        for (protocol, cache, announces) in [
            (StreamProtocol::GossipSub, "held_gossip", false),
            (StreamProtocol::DataColumnSidecarsByRange, "held_rpc", true),
        ] {
            let mut tile = make_tile();
            tile.validated
                .insert(block_root, BlockValidation { columns: CUSTODY_COLUMNS, signature: None });

            let (mut consumer, ssz) = produce_block(&blob_block_bytes(7), cache);
            let read = consumer.acquire(ssz);

            let mut events = Vec::new();
            let disposition = tile.handle_column(
                ColumnOutcome::AlreadyHeld { block_root, column_index: 3, slot: 7 },
                PendingColumn {
                    stream_id: P2pStreamId::new(2, 2, protocol, true),
                    sidecar: read,
                    gossip_subnet: None,
                    recv_ts: IngestionTime::now(),
                },
                false,
                RelayMeta::None,
                &mut |e| events.push(e),
            );

            assert!(
                matches!(disposition, ColumnDisposition::Ignored),
                "{protocol:?}: a duplicate is never relayed"
            );
            assert!(
                events.iter().any(|e| matches!(e, DataColumnsEvent::Persist { .. })),
                "{protocol:?}: storage is the one that knows whether it landed"
            );
            assert_eq!(
                events.iter().filter(|e| matches!(e, DataColumnsEvent::Available { .. })).count(),
                usize::from(announces),
                "{protocol:?}: only a requested duplicate re-announces"
            );
        }
    }
}
