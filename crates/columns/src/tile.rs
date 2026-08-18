use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconStateReader, SpecConfig};
use silver_common::{
    BASE_REQUEST_ID, BeaconStateEvent, ColumnSource, DataColumnsEvent, EngineReq, EngineResp,
    GossipTopic, Nanos, NewGossipMsg, P2pStreamId, PeerEvent, RpcInbound, RpcSeverity, SilverSpine,
    SilverSpineProducers, StreamProtocol, SyncUpdate, SyncingStrategy, TProducer, TRandomAccess,
    TRead, Wheel, column_util as util, msg_is_backfill, msg_is_live_column_request,
    msg_is_post_gloas,
    ssz_view::{NUMBER_OF_COLUMNS, SignedBeaconBlockView, StatusView},
};

use crate::{
    BlockRoot, DataColumnCounters, EPOCH_DURATION,
    batch::{self, KzgBatch, PendingKzg, RelayMeta},
    el_blobs::ElBlobFetcher,
    sync::SyncStatus,
    validate::{ColumnOutcome, ColumnValidator},
};
const MAX_RETRIES: u8 = 5;

type PendingColumn = (P2pStreamId, TRead, Option<u64>);

/// `EngineReq` is large but short-lived here, so
/// boxing it would only add an alloc on the block path.
#[allow(clippy::large_enum_variant)]
pub(crate) enum StorageEmit {
    Peer(PeerEvent),
    Engine(EngineReq),
}

/// Only `Batched` sidecars can end up forwarded / republished on gossip
/// (their relay fires at flush if KZG passes): `Ignored` covers spec-IGNORE
/// cases (dup, post-wall, parent pending, buffered) whose sidecars must not
/// be relayed and whose senders are not culpable.
enum ColumnDisposition {
    Batched,
    Ignored,
    Rejected { block_root: [u8; 32], bitmask: u128 },
}

pub struct DataColumnsTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    request_id: u64,
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
    validated_columns: Wheel<BlockRoot, u128, 4>,
    // Gloas: columns whose block (hence commitments) hasn't been seen yet.
    gloas_pending_columns: Wheel<BlockRoot, Vec<PendingColumn>, 4>,
    // Fulu: columns held until their parent block validates. Keyed by the
    // sidecar's parent_root; drained on Status head advances and on block
    // arrivals (the arriving block's own parent_root).
    parent_pending_columns: Wheel<BlockRoot, Vec<PendingColumn>, 4>,
    // outstanding requests - keyed by block body root
    // 16 x 500 millisecond buckets.
    outstanding_requests: Wheel<BlockRoot, (u128, u128, u8), 16>,

    sync_state: SyncStatus,

    /// Boot decision from control: `None` = waiting; gates `drive_replay` so we
    /// don't replay the on-disk fork tree before learning whether peers are
    /// finalized ahead (in which case we skip it and range-sync from them).
    syncing_strategy: Option<SyncingStrategy>,

    el_fetcher: ElBlobFetcher,
    el_column_producer: TProducer,
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
        Self {
            custody_group_columns,
            request_id: BASE_REQUEST_ID,
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            spec,
            validator: ColumnValidator::new(beacon_state),
            kzg_batch: KzgBatch::new(),
            validated_columns: Wheel::new(EPOCH_DURATION),
            gloas_pending_columns: Wheel::new(EPOCH_DURATION),
            parent_pending_columns: Wheel::new(Duration::from_secs(24)),
            outstanding_requests: Wheel::new(Duration::from_millis(100)),
            sync_state: SyncStatus::default(),
            syncing_strategy: None,
            el_fetcher: ElBlobFetcher::new(engine_resp_consumer),
            el_column_producer,
        }
    }

    fn column_request(&mut self, block_root: [u8; 32], columns: u128) -> PeerEvent {
        let id = self.request_id;
        self.request_id += 1;
        PeerEvent::SendDataColumnsByRootRequest { request_id: id, columns, block_root }
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
        let is_gloas = self.spec.is_gloas_at_slot(slot);
        let has_columns = SignedBeaconBlockView::has_data_columns(buffer, is_gloas);

        tracing::info!(slot, has_columns, "beacon block recv");

        if !has_columns {
            return None;
        }

        if slot <= self.sync_state.finalized_slot() {
            return None;
        }

        let block_root = util::block_root(buffer, is_gloas);

        if is_gloas {
            self.validator.cache_gloas_commitments(block_root, buffer);
        }

        if self.outstanding_requests.contains(&block_root) {
            return Some((block_root, is_gloas));
        }

        // Custody columns only — silver floors cgc at SAMPLES_PER_SLOT, so the
        // custody set IS the sample set; no beyond-custody sampling needed.
        // These by-root requests race gossip and serve as the fallback when a
        // sidecar isn't delivered on the subscribed subnet.
        let to_request = self.columns_to_request(&block_root);
        if to_request == 0 {
            return Some((block_root, is_gloas));
        }

        self.outstanding_requests.insert(block_root, (to_request, to_request, MAX_RETRIES));

        tracing::trace!(
            block = hex::encode(block_root),
            ?stream_id,
            "data columns by root request: {to_request:b}"
        );

        // EL blob reconstruction parses the Fulu body layout; gloas blobs are
        // fetched from peers by root/range instead.
        if !is_gloas {
            let slot = SignedBeaconBlockView::slot(buffer);
            self.el_fetcher.try_fetch(buffer, block_root, slot, to_request, emit);
        }

        if stream_id.protocol() != StreamProtocol::GossipSub {
            emit(StorageEmit::Peer(self.column_request(block_root, to_request)));
        }
        Some((block_root, is_gloas))
    }

    fn columns_to_request(&self, root: &BlockRoot) -> u128 {
        let validated = self.validated_columns.get(root).copied().unwrap_or(0);
        self.custody_group_columns & !validated
    }

    #[timed]
    fn data_columns(
        &mut self,
        stream_id: P2pStreamId,
        sidecar: TRead,
        is_gloas: bool,
        gossip_subnet: Option<u64>,
        recv_ts: Option<Nanos>,
        relay: RelayMeta,
    ) -> ColumnDisposition {
        let outcome = match sidecar.buffer() {
            Ok((buf, _)) => {
                if is_gloas {
                    self.validator.validate_gloas(
                        stream_id,
                        buf,
                        gossip_subnet,
                        &self.sync_state,
                        &self.validated_columns,
                    )
                } else {
                    self.validator.validate_fulu(
                        stream_id,
                        buf,
                        gossip_subnet,
                        recv_ts,
                        &self.sync_state,
                        &self.validated_columns,
                    )
                }
            }
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read data column sidecar buffer");
                return ColumnDisposition::Ignored;
            }
        };
        self.handle_column(outcome, stream_id, sidecar, gossip_subnet, is_gloas, relay)
    }

    fn handle_column(
        &mut self,
        outcome: ColumnOutcome,
        stream_id: P2pStreamId,
        sidecar: TRead,
        gossip_subnet: Option<u64>,
        is_gloas: bool,
        relay: RelayMeta,
    ) -> ColumnDisposition {
        match outcome {
            ColumnOutcome::Skip => ColumnDisposition::Ignored,
            ColumnOutcome::Reject { block_root, bitmask } => {
                ColumnDisposition::Rejected { block_root, bitmask }
            }
            ColumnOutcome::Buffer { block_root } => {
                let pending = self.gloas_pending_columns.entry(block_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::debug!(?stream_id, "gloas column before block — buffering");
                    pending.push((stream_id, sidecar, gossip_subnet));
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::AwaitParent { parent_root } => {
                let pending = self.parent_pending_columns.entry(parent_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::info!(?stream_id, "column parent pending — buffering");
                    pending.push((stream_id, sidecar, gossip_subnet));
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::Record { block_root, column_index, bitmask, slot } => {
                let queued = self.kzg_batch.push(PendingKzg {
                    sidecar,
                    stream_id,
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

    fn drain_pending_gloas_columns(&mut self, block_root: [u8; 32]) {
        let pending = self.gloas_pending_columns.remove(&block_root);
        self.drain_entries(pending, true);
    }

    #[timed]
    fn drain_parent_pending_columns(&mut self, parent_root: [u8; 32]) {
        let pending = self.parent_pending_columns.remove(&parent_root);
        if pending.is_some() {
            tracing::info!(
                root = hex::encode(parent_root),
                "draining data columns for parent root"
            );
        }
        self.drain_entries(pending, false);
    }

    /// Re-validated rejects from buffered columns are not penalized — the
    /// disposition is dropped, matching the pre-batch behaviour.
    fn drain_entries(&mut self, pending: Option<Vec<PendingColumn>>, is_gloas: bool) {
        let Some(pending) = pending else {
            return;
        };
        for (stream_id, sidecar, gossip_subnet) in pending {
            self.data_columns(stream_id, sidecar, is_gloas, gossip_subnet, None, RelayMeta::None);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_validated_column<F>(
        &mut self,
        block_root: [u8; 32],
        column_index: u64,
        column_bitmask: u128,
        slot: u64,
        sidecar: TRead,
        is_gossip: bool,
        emit: &mut F,
    ) where
        F: FnMut(DataColumnsEvent),
    {
        let mut completion_check = self.custody_group_columns;

        if let Some((mut requested, full_set, retries)) =
            self.outstanding_requests.remove(&block_root)
        {
            requested &= !column_bitmask;
            completion_check = full_set;
            if requested != 0 {
                // more column responses pending
                self.outstanding_requests.insert(block_root, (requested, full_set, retries));
            }
        }

        let validated = self.validated_columns.entry(block_root).or_default();
        *validated |= column_bitmask;
        let validated = *validated;

        if validated & completion_check == completion_check {
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
            StorageEmit::Peer(evt) => {
                producers.peer_events.produce(&evt.into());
            }
            StorageEmit::Engine(req) => {
                producers.engine_reqs.produce(&req.into());
            }
        });

        if let Some((block_root, is_gloas)) = root &&
            is_gloas
        {
            self.drain_pending_gloas_columns(block_root);
        }
        if let Some(parent_root) = parent_root {
            self.drain_parent_pending_columns(parent_root);
        }
    }

    #[timed]
    #[allow(clippy::too_many_arguments)]
    fn handle_data_column_sidecar(
        &mut self,
        t_read: TRead,
        stream_id: P2pStreamId,
        is_gloas: bool,
        gossip_subnet: Option<u64>,
        recv_ts: Option<Nanos>,
        relay: RelayMeta,
        producers: &mut SilverSpineProducers,
    ) {
        if let ColumnDisposition::Rejected { block_root, bitmask } =
            self.data_columns(stream_id, t_read, is_gloas, gossip_subnet, recv_ts, relay)
        {
            // Score down the peer and retransmit.
            producers.peer_events.produce(
                &PeerEvent::RpcMisbehaviour {
                    p2p_peer: stream_id.peer(),
                    severity: RpcSeverity::Fatal,
                }
                .into(),
            );
            producers.peer_events.produce(&self.column_request(block_root, bitmask).into());
        }
    }

    /// End-of-pass KZG verification of every batched sidecar in one
    /// `verify_cell_kzg_proof_batch` call. On a combined failure each sidecar
    /// re-verifies alone so the reject lands on the culpable peer only —
    /// honest traffic never pays the fallback.
    #[timed]
    fn flush_kzg_batch(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.kzg_batch.is_empty() {
            return;
        }
        let mut pending = self.kzg_batch.take();
        DataColumnCounters::KzgBatchesVerified.inc();
        DataColumnCounters::KzgBatchColumns.add(pending.len() as u64);

        let all_ok = {
            let validator = &self.validator;
            util::kzg_verify_batch_multi(
                pending.iter().filter_map(|p| batch::kzg_entry(p, validator)),
                &mut self.kzg_batch.scratch,
            )
        };

        for p in pending.drain(..) {
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
        self.kzg_batch.restore(pending);
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
            sidecar, stream_id, block_root, column_index, bitmask, slot, relay, ..
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
            &mut |msg| adapter.produce(msg),
        );
    }

    fn resolve_rejected(&mut self, p: &PendingKzg, adapter: &mut SpineAdapter<SilverSpine>) {
        tracing::warn!(stream_id = ?p.stream_id, "failed to verify sidecar kzg proof");
        DataColumnCounters::KzgBatchRejects.inc();
        adapter.produce(PeerEvent::RpcMisbehaviour {
            p2p_peer: p.stream_id.peer(),
            severity: RpcSeverity::Fatal,
        });
        let request = self.column_request(p.block_root, p.bitmask);
        adapter.produce(request);
    }
}

impl DataColumnsTile {
    #[timed]
    fn handle_beacon_state_event(&mut self, event: BeaconStateEvent) -> Option<([u8; 92], u64)> {
        let mut latest_status_event: Option<([u8; 92], u64)> = None;
        match event {
            BeaconStateEvent::Status { ssz, wall_slot, .. } => {
                // Per-event (not latest-only): BS emits one Status per accepted
                // block, and each newly validated root may unblock buffered
                // children.
                self.drain_parent_pending_columns(*StatusView::head_root(&ssz));
                latest_status_event = Some((ssz, wall_slot));
            }
            BeaconStateEvent::PersistBlock { ssz, source } => {
                let t_read = match source {
                    silver_common::BlockSource::Gossip => self.persist_gossip_consumer.acquire(ssz),
                    silver_common::BlockSource::Rpc => self.persist_rpc_consumer.acquire(ssz),
                };

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let block_root = util::block_root_fulu(buf);

                        // record persisted block roots for use in parent check
                        self.validator.note_persisted(block_root);

                        // This block just got BS-accepted: it may be the
                        // missing parent of buffered columns.
                        self.drain_parent_pending_columns(block_root);
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
        adapter.consume(|d: SyncingStrategy, _| self.syncing_strategy = Some(d));

        self.gossip_consumer.free();
        self.rpc_consumer.free();
        self.persist_gossip_consumer.free();
        self.persist_rpc_consumer.free();

        // Check for data columns and incoming blocks with data columns via gossip.
        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock if self.sync_state.is_synced() => {
                let t_read: TRead = self.gossip_consumer.acquire(gossip.ssz);
                self.handle_beacon_block(t_read, gossip.stream_id, producers);
            }
            silver_common::GossipTopic::DataColumnSidecar(custody_group)
                if self.sync_state.is_synced() =>
            {
                tracing::debug!(custody_group, "data column sidecar over gossip");

                let t_read = self.gossip_consumer.acquire(gossip.ssz);

                let is_gloas = self.spec.is_gloas_at_slot(self.sync_state.head_slot() + 1);
                let relay = RelayMeta::Gossip {
                    topic: gossip.topic,
                    msg_hash: gossip.msg_hash,
                    recv_ts: gossip.recv_ts,
                    protobuf: gossip.protobuf,
                };
                self.handle_data_column_sidecar(
                    t_read,
                    gossip.stream_id,
                    is_gloas,
                    Some(custody_group),
                    Some(gossip.recv_ts),
                    relay,
                    producers,
                );
            }
            _ => {}
        });

        // Check for data columns and incoming blocks via RPC.
        adapter.consume(|rpc: RpcInbound, producers| match rpc {
            RpcInbound::Request(_) => {}
            RpcInbound::Response(rsp) => match rsp.response {
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz }
                    if self.sync_state.is_synced() && !msg_is_backfill(rsp.application_id) =>
                {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.handle_beacon_block(t_read, rsp.stream_id, producers);
                }
                // Forward-sync (not synced): cache each gloas block's bid
                // commitments so its data columns can be KZG-verified as they
                // range-sync, then drain any columns that arrived before it.
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } if !msg_is_backfill(rsp.application_id) => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    if let Ok((buf, _)) = t_read.buffer() &&
                        SignedBeaconBlockView::check_size(buf)
                    {
                        let is_gloas = self.spec.is_gloas_at_slot(SignedBeaconBlockView::slot(buf));
                        let parent_root = *SignedBeaconBlockView::parent_root(buf);
                        if is_gloas {
                            let block_root = util::block_root(buf, is_gloas);
                            self.validator.cache_gloas_commitments(block_root, buf);
                            self.drain_pending_gloas_columns(block_root);
                        }
                        self.drain_parent_pending_columns(parent_root);
                    }
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } if msg_is_live_column_request(rsp.application_id) => {
                    // TODO validate that originating peer has data column index in custody groups
                    tracing::debug!("data column sidecar over rpc");
                    let t_read = self.rpc_consumer.acquire(ssz);
                    let is_gloas = msg_is_post_gloas(rsp.application_id);
                    self.handle_data_column_sidecar(
                        t_read,
                        rsp.stream_id,
                        is_gloas,
                        None,
                        None,
                        RelayMeta::Rpc { ssz },
                        producers,
                    );
                }
                silver_common::RpcResponse::Error { error, msg, len } if msg_is_live_column_request(rsp.application_id) => {
                    let err_msg = String::from_utf8_lossy(&msg[..len]).to_string();
                    tracing::error!(error, err_msg, "rpc error response");
                }
                other => {
                    tracing::trace!(?other, app_id=rsp.application_id, id=?rsp.stream_id, "ignoring rpc response");
                }
            },
        });

        adapter.consume(|beacon_event: BeaconStateEvent, _| {
            if let Some((ssz, wall_slot)) = self.handle_beacon_state_event(beacon_event) {
                self.sync_state.update(ssz, wall_slot);
            }
        });

        adapter.consume(|sync_update: SyncUpdate, _| match sync_update {
            SyncUpdate::Following => self.sync_state.update_synced(true),
            _ => self.sync_state.update_synced(false),
        });

        // EL-mempool blob responses (engine_getBlobsV2). Broadcast queue — we
        // only act on GetBlobs; the rest are the beacon-state tile's.
        adapter.consume(|resp: EngineResp, producers| {
            if let EngineResp::GetBlobs(r) = resp {
                self.el_fetcher.handle_response(
                    r,
                    &mut self.validated_columns,
                    &mut self.outstanding_requests,
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

        // Everything this pass delivered is collected; verify in one call.
        self.flush_kzg_batch(adapter);

        let now = Instant::now();

        // Age out validation caches (BLS memo, gloas commitments, persisted
        // roots) and validated columns.
        self.validator.rotate(now);
        self.validated_columns.maybe_rotate(now, &mut |_, _| true);
        // Age out cached columns.
        self.parent_pending_columns.maybe_rotate(now, &mut |_, _| true);
        self.gloas_pending_columns.maybe_rotate(now, &mut |_, _| true);

        // Age out EL blob fetches the engine never answered (the p2p race
        // covers those columns); answered ones are removed on response.
        self.el_fetcher.rotate(now);

        // Timeout any pending requests and re-issue
        let mut request_id = self.request_id;
        let mut wheel_resent = 0usize;
        self.outstanding_requests.maybe_rotate(now, &mut |block_root, (columns, _, retries)| {
            if *retries == 0 {
                return true; // remove
            }
            request_id += 1;
            wheel_resent += 1;
            tracing::info!(
                block_root = hex::encode(block_root),
                "resending outstanding data column request: {columns:b}"
            );
            adapter.produce(PeerEvent::SendDataColumnsByRootRequest {
                request_id,
                columns: *columns,
                block_root: *block_root,
            });

            *retries -= 1;
            false
        });

        self.request_id = request_id;
        // by-root wheel re-request volume per rotation (a large sustained
        // number is the ds_incoming_rpc flood source).
        if wheel_resent > 0 {
            tracing::debug!(wheel_resent, "by-root column wheel re-sent");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_beacon_state_data::BeaconStateOwner;
    use silver_common::{P2pStreamId, StreamProtocol, TCache, TCacheProducer};

    use super::*;

    #[test]
    fn test_beacon_block_rpc_requests_custody_columns() {
        let store_dir = format!("/tmp/test_storage_tile_gossip_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_dir);

        let custody_columns = (1u128 << 3) | (1u128 << 7);

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

        let el_columns_tc = TCache::producer("el_columns", 1024 * 1024);

        // Unused here (no EL path exercised); only satisfies the constructor.
        let engine_resp_tc = TCache::producer("engine_resp", 1024 * 1024);
        let engine_resp_consumer =
            engine_resp_tc.cache_ref().random_access("engine_resp_cons", true).unwrap();

        let beacon_state = BeaconStateOwner::empty_test(0).reader();

        let mut tile = DataColumnsTile::new(
            gossip_consumer,
            persist_gossip_consumer,
            rpc_consumer,
            persist_rpc_consumer,
            beacon_state,
            custody_columns,
            Arc::new(SpecConfig::mainnet()),
            engine_resp_consumer,
            el_columns_tc,
        );

        let mut block_bytes = vec![0u8; 784];
        // Set message offset to 100
        block_bytes[0..4].copy_from_slice(&100u32.to_le_bytes());
        // Set slot to 42 at [100..108)
        block_bytes[100..108].copy_from_slice(&42u64.to_le_bytes());
        // Body offset at [180..184) relative to 100: let's make it 84
        block_bytes[180..184].copy_from_slice(&84u32.to_le_bytes());

        // Inside body (starts at 184):
        // blob_kzg_commitments_offset at body[388..392]
        block_bytes[184 + 388..184 + 392].copy_from_slice(&400u32.to_le_bytes());
        // execution_requests_offset at body[392..396]
        block_bytes[184 + 392..184 + 396].copy_from_slice(&500u32.to_le_bytes());

        let mut producer = TCache::producer("test_block_prod", 1024 * 1024);
        let mut res = producer.reserve(block_bytes.len(), true).unwrap();
        res.write_all(&block_bytes).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut blocks_consumer =
            producer.cache_ref().random_access("test_block_cons", true).unwrap();
        let read = blocks_consumer.acquire(ssz);

        let block_root = util::block_root_fulu(&block_bytes);
        let rpc_stream = P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, true);

        // Once synced, an RPC block requests its custody columns by root.
        tile.sync_state.update_synced(true);
        let mut rpc_events = Vec::new();
        tile.beacon_block(rpc_stream, read.clone(), &mut |emit| {
            if let StorageEmit::Peer(evt) = emit {
                rpc_events.push(evt);
            }
        });
        assert_eq!(rpc_events.len(), 1);
        if let PeerEvent::SendDataColumnsByRootRequest { columns, block_root: req_root, .. } =
            rpc_events[0]
        {
            assert_eq!(columns, custody_columns);
            assert_eq!(req_root, block_root);
        } else {
            panic!("expected SendDataColumnsByRootRequest");
        }

        // Clean up outstanding request to allow requesting the same block root again
        tile.outstanding_requests.remove(&block_root);

        let _ = std::fs::remove_dir_all(&store_dir);
    }
}
