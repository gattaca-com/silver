use std::{
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};

use flux::{
    spine::{SpineAdapter, SpineProducers},
    tile::Tile,
};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BeaconStateReader, ForkName, SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    BeaconStateEvent, BlockSource, BlockStage, ColumnSource, DataColumnsEvent, DataKind,
    EngineResp, GossipTopic, IngestionTime, NewGossipMsg, Origin, P2pStreamId, PeerEvent,
    RequestId, RpcInbound, RpcSeverity, SilverSpine, SilverSpineProducers, SszSource, SyncNeed,
    SyncUpdate, TCacheRead, TProducer, TRandomAccess, TRead, Wheel,
    cell_store::{
        CellStoreConfig, CellStoreEvent, CellValidationOutcome, CellValidationRequest,
        CommitmentContext, ContextData, FuluContextSource, RetentionEvent, StoreError,
    },
    column_util::{self as util, KzgScratch},
    ssz_view::{
        BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView, NUMBER_OF_COLUMNS,
        SignedBeaconBlockView, StatusView,
    },
    ticker::SlotTicker,
};

use crate::{
    BlockRoot, DataColumnCounters,
    availability::ColumnTracker,
    batch::{self, GossipSidecarFrame, KzgBatch, PendingKzg},
    cell_store::CellStore,
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
    Rejected { block_root: BlockRoot, slot: u64, column: Option<u64> },
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

    cell_store: Option<CellStore>,

    kzg_scratch: KzgScratch,

    // Declared last so it drops last: a parked column's read releases through
    // the consumer it was acquired from.
    consumers: ColumnConsumers,
    data_columns_consumer: Option<Box<TRandomAccess>>,
}

impl DataColumnsTile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        consumers: ColumnConsumers,
        beacon_state: BeaconStateReader,
        custody_group_columns: u128,
        spec: Arc<SpecConfig>,
        engine_resp_consumer: TRandomAccess,
        el_column_producer: TProducer,
        ticker: SlotTicker,
    ) -> Self {
        let epoch_duration =
            Duration::from_millis(spec.slot_duration_ms()) * SLOTS_PER_EPOCH as u32;
        Self {
            consumers,
            validator: ColumnValidator::new(beacon_state, spec.clone(), epoch_duration, ticker),
            spec,
            kzg_batch: KzgBatch::new(),
            tracker: ColumnTracker::new(custody_group_columns, epoch_duration),
            gloas_pending_columns: Wheel::new(epoch_duration),
            parent_pending_columns: Wheel::new(Duration::from_secs(24)),
            sync_state: SyncStatus::default(),
            el_fetcher: ElBlobFetcher::new(engine_resp_consumer),
            el_column_producer,
            cell_store: None,
            kzg_scratch: KzgScratch::default(),
            data_columns_consumer: None,
        }
    }

    pub fn with_data_columns_cache(
        mut self,
        config: CellStoreConfig,
        consumer: TRandomAccess,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        assert!(consumer.is_retained());
        if consumer.cache_ref().capacity() < config.cache_capacity() {
            return Err(StoreError::CacheTooSmall);
        }
        self.cell_store = Some(CellStore::new(config, slot, slot_start)?);
        self.data_columns_consumer = Some(Box::new(consumer));
        Ok(self)
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
        if is_gloas && !SignedBeaconBlockView::check_gloas_size(buffer) {
            tracing::warn!(slot, ?stream_id, "beacon block bid out of bounds");
            return None;
        }
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
            self.admit_gloas_context(block_root, slot, producers);
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

        producers.produce(SyncNeed::missing_columns(block_root, slot, to_request));
        Some((block_root, is_gloas))
    }

    /// Children's sidecars validate against a staged block, and its custody
    /// columns are chased even when the block never passed through this tile.
    fn note_staged_block(
        &mut self,
        block_root: BlockRoot,
        slot: u64,
        producers: &mut SilverSpineProducers,
    ) {
        self.validator.note_validated(block_root, slot);
        self.admit_gloas_context(block_root, slot, producers);
        self.drain_pending_gloas_columns(block_root, producers);
        self.drain_parent_pending_columns(block_root, producers);

        let to_request = self.tracker.to_request(&block_root);
        if to_request != 0 {
            producers.produce(SyncNeed::missing_columns(block_root, slot, to_request));
        }
    }

    #[timed]
    fn data_columns(
        &mut self,
        column: PendingColumn,
        frame: Option<GossipSidecarFrame>,
        producers: &mut SilverSpineProducers,
    ) -> ColumnDisposition {
        let validated = match column.sidecar.buffer() {
            Ok((buf, _)) => {
                let verify_held = column.ssz_source == SszSource::DataColumns &&
                    self.cell_store.as_ref().is_some_and(|store| {
                        util::SidecarIdentity::of(buf).is_some_and(|identity| {
                            store
                                .availability(&identity.block_root, identity.column_index as usize)
                                .is_none_or(|column| column.full.is_none())
                        })
                    });
                self.validator.validate(
                    &column,
                    buf,
                    &self.sync_state,
                    &mut self.tracker,
                    verify_held,
                )
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
        self.handle_column(outcome, column, is_gloas, frame, producers)
    }

    fn handle_column(
        &mut self,
        outcome: ColumnOutcome,
        column: PendingColumn,
        is_gloas: bool,
        frame: Option<GossipSidecarFrame>,
        producers: &mut SilverSpineProducers,
    ) -> ColumnDisposition {
        match outcome {
            ColumnOutcome::Skip => ColumnDisposition::Ignored,
            ColumnOutcome::AlreadyHeld { block_root, column_index, slot } => {
                let source = ColumnSource::from_protocol(column.stream_id.protocol());
                if self.tracker.is_custody(column_index) {
                    producers.produce_with_ingestion(
                        DataColumnsEvent::Persist {
                            ssz: column.sidecar.read,
                            source,
                            block_root,
                            column_index,
                            slot,
                        },
                        column.recv_ts,
                    );
                }

                if source != ColumnSource::Gossip && self.tracker.custody_complete(&block_root) {
                    producers.produce(SyncNeed::Arrived {
                        root: block_root,
                        slot,
                        kind: DataKind::Columns,
                    });
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::Reject { block_root, slot, column } => {
                ColumnDisposition::Rejected { block_root, slot, column }
            }
            ColumnOutcome::Buffer { block_root } => {
                if self.gloas_pending_columns.len() >= 2 * SLOTS_PER_EPOCH as usize &&
                    !self.gloas_pending_columns.contains(&block_root)
                {
                    return ColumnDisposition::Ignored;
                }
                let pending = self.gloas_pending_columns.entry(block_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::debug!(stream_id = ?column.stream_id, "gloas column before block — buffering");
                    pending.push(column);
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::AwaitParent { parent_root } => {
                if self.parent_pending_columns.len() >= 2 * SLOTS_PER_EPOCH as usize &&
                    !self.parent_pending_columns.contains(&parent_root)
                {
                    return ColumnDisposition::Ignored;
                }
                let pending = self.parent_pending_columns.entry(parent_root).or_default();
                if pending.len() < NUMBER_OF_COLUMNS {
                    tracing::info!(stream_id = ?column.stream_id, "column parent pending — buffering");
                    pending.push(column);
                }
                ColumnDisposition::Ignored
            }
            ColumnOutcome::Record { block_root, column_index, slot, relay_eligible } => {
                let queued = self.kzg_batch.push(PendingKzg {
                    sidecar: column.sidecar,
                    ssz_source: column.ssz_source,
                    domain: column.domain.or_else(|| self.validator.domain_at(slot)),
                    context_eligible: relay_eligible,
                    stream_id: column.stream_id,
                    recv_ts: column.recv_ts,
                    block_root,
                    column_index,
                    slot,
                    is_gloas,
                    frame: if relay_eligible { frame } else { None },
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
            self.data_columns(column, None, producers);
        }
    }

    fn admit_gloas_context(
        &mut self,
        root: BlockRoot,
        slot: u64,
        producers: &SilverSpineProducers,
    ) {
        let Some(store) = &mut self.cell_store else { return };
        let Some(commitments) = self.validator.gloas_commitments(&root) else { return };
        let Some(domain) = self.validator.domain_at(slot) else { return };
        let context = CommitmentContext {
            block_root: root,
            slot,
            format: ForkName::Gloas,
            blob_count: commitments.len() / BYTES_PER_KZG_COMMITMENT,
        };
        if store.admit_context(context, domain, ContextData::Gloas { commitments }, None).is_ok() {
            if let Some(request) = store.request_assemblies(&root) {
                producers.produce(CellStoreEvent::Allocate(request));
            }
        }
    }

    fn retain_validated_column(&mut self, p: &PendingKzg, producers: &SilverSpineProducers) {
        if !p.context_eligible || p.ssz_source != SszSource::DataColumns {
            return;
        }
        let (Some(store), Some(consumer), Some(domain)) =
            (&mut self.cell_store, &mut self.data_columns_consumer, p.domain)
        else {
            return
        };
        let Ok((bytes, _)) = p.sidecar.buffer() else { return };
        let data = if p.is_gloas {
            let Some(commitments) = self.validator.gloas_commitments(&p.block_root) else { return };
            ContextData::Gloas { commitments }
        } else {
            ContextData::Fulu {
                signed_header: bytes[20..228].try_into().unwrap(),
                inclusion_proof: bytes[228..356].try_into().unwrap(),
                commitments: DataColumnSidecarFuluView::kzg_commitments(bytes),
            }
        };
        let context = CommitmentContext {
            block_root: p.block_root,
            slot: p.slot,
            format: domain.format(),
            blob_count: data.commitments().len() / BYTES_PER_KZG_COMMITMENT,
        };
        let source = (!p.is_gloas).then_some(FuluContextSource::Sidecar(p.sidecar.read));
        if let Err(e) = store.admit_context(context, domain, data, source) {
            tracing::debug!(?e, slot = p.slot, "cell context not admitted");
            return;
        }
        match store.retain_full(&p.block_root, p.column_index as usize, p.sidecar.read, consumer) {
            Ok(_) => store.mark_changed(&p.block_root, p.column_index as usize),
            Err(e) => tracing::debug!(?e, column = p.column_index, "full sidecar not retained"),
        }
        if let Some(request) = store.request_assemblies(&p.block_root) {
            producers.produce(CellStoreEvent::Allocate(request));
        }
    }

    fn handle_cell_event(
        &mut self,
        event: CellStoreEvent,
        now: Instant,
        producers: &mut SilverSpineProducers,
    ) {
        match event {
            CellStoreEvent::Allocated { request, set } => {
                let (Some(store), Some(consumer)) =
                    (&mut self.cell_store, &mut self.data_columns_consumer)
                else {
                    return
                };
                match set {
                    Some(set)
                        if set.request.id == request.id &&
                            set.request.context == request.context =>
                    {
                        match store.install(set, consumer) {
                            Ok(true) => {
                                let mut columns = request.columns;
                                while columns != 0 {
                                    let column = columns.trailing_zeros() as usize;
                                    columns &= columns - 1;
                                    store.mark_changed(&request.context.block_root, column);
                                }
                            }
                            Ok(false) => {}
                            Err(e) => {
                                store.allocation_failed(request);
                                tracing::debug!(?e, "cell allocation not installed");
                            }
                        }
                    }
                    _ => store.allocation_failed(request),
                }
            }
            CellStoreEvent::Validate(request) => {
                let outcome = self.validate_cell(request, now);
                producers.produce(CellStoreEvent::Validation { request, outcome });
            }
            CellStoreEvent::Cancel(pending) => {
                if let Some(consumer) = &mut self.data_columns_consumer {
                    let _ = pending.data.cancel(consumer);
                }
            }
            _ => {}
        }
    }

    fn validate_cell(
        &mut self,
        request: CellValidationRequest,
        now: Instant,
    ) -> CellValidationOutcome {
        let (Some(store), Some(consumer)) = (&mut self.cell_store, &mut self.data_columns_consumer)
        else {
            return CellValidationOutcome::Ignored
        };
        let key = request.pending.key;
        let eligible = store.availability(&key.block_root, key.column).is_some_and(|column| {
            now < request.deadline &&
                now < column.expires &&
                column.domain == request.domain &&
                column.assembly.is_some_and(|reference| {
                    reference.read().seq() == request.pending.data.reservation().read().seq()
                }) &&
                key.row == request.pending.data.part()
        });
        if !eligible {
            let _ = request.pending.data.cancel(consumer);
            return CellValidationOutcome::Ignored;
        }
        let Ok(validation) = request.pending.data.acquire(consumer) else {
            return CellValidationOutcome::Ignored
        };
        let (context, data) = store.context(&key.block_root).unwrap();
        if key.row >= context.blob_count {
            return CellValidationOutcome::Ignored;
        }
        let [cell, proof] = validation.buffers();
        let commitments = &data.commitments()
            [key.row * BYTES_PER_KZG_COMMITMENT..(key.row + 1) * BYTES_PER_KZG_COMMITMENT];
        let valid = util::kzg_verify_batch_multi(
            std::iter::once(util::KzgBatchEntry {
                column: cell,
                commitments,
                proofs: proof,
                index: key.column as u64,
            }),
            &mut self.kzg_scratch,
        );
        if !valid {
            return CellValidationOutcome::Rejected;
        }
        if validation.accept().is_err() {
            return CellValidationOutcome::Ignored;
        }
        store.mark_changed(&key.block_root, key.column);
        CellValidationOutcome::Accepted
    }

    fn flush_cell_updates(&mut self, producers: &mut SilverSpineProducers) {
        loop {
            let (Some(store), Some(consumer)) =
                (&mut self.cell_store, &mut self.data_columns_consumer)
            else {
                return
            };
            let Some((root, column)) = store.next_changed() else { return };
            let Ok(update) = store.refresh_column(&root, column, consumer) else { continue };
            let Some(available) = store.availability(&root, column) else { continue };
            producers.produce(CellStoreEvent::Available(available));
            if !update.column_completed || self.tracker.has_any(&root, 1u128 << column) {
                continue;
            }
            let Some(ssz) = update.complete_read else { continue };
            self.record_columns(
                root,
                available.slot,
                1u128 << column,
                IngestionTime::now(),
                producers,
            );
            if self.tracker.wants(1u128 << column) {
                producers.produce(DataColumnsEvent::Persist {
                    ssz,
                    source: ColumnSource::Assembly,
                    ssz_source: SszSource::DataColumns,
                    domain: Some(available.domain),
                    block_root: root,
                    column_index: column as u64,
                    slot: available.slot,
                });
            }
        }
    }

    fn record_validated_column(&mut self, p: PendingKzg, producers: &mut SilverSpineProducers) {
        let PendingKzg { sidecar, stream_id, recv_ts, block_root, column_index, slot, .. } = p;
        debug_assert!(
            !self.tracker.holds(&block_root, column_index),
            "a batched column is recorded before anything else can set its bit"
        );
        self.record_columns(block_root, slot, 1u128 << column_index, recv_ts, producers);

        let source = ColumnSource::from_protocol(stream_id.protocol());
        producers.produce_with_ingestion(
            DataColumnsEvent::Validated { block_root, column_index, slot, source },
            recv_ts,
        );
        if self.tracker.is_custody(column_index) {
            producers.produce_with_ingestion(
                DataColumnsEvent::Persist {
                    ssz: sidecar.read,
                    source,
                    ssz_source,
                    domain: p.domain,
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
                SyncNeed::Arrived { root: block_root, slot, kind: DataKind::Columns },
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
        let frame = Some(GossipSidecarFrame {
            domain: gossip.domain,
            msg_hash: gossip.msg_hash,
            protobuf: gossip.protobuf,
        });
        let sidecar = match gossip.ssz_source {
            SszSource::DataColumns => {
                let Some(consumer) = self.data_columns_consumer.as_mut() else { return };
                if !ptr::eq(&*consumer.cache_ref(), &*gossip.ssz.cache_ref()) {
                    return;
                }
                let Some(read) = consumer.acquire_strict(gossip.ssz) else { return };
                read
            }
            SszSource::Gossip => self.consumers.gossip.acquire(gossip.ssz),
            _ => return,
        };
        self.handle_data_column_sidecar(
            PendingColumn {
                stream_id: gossip.stream_id,
                sidecar,
                ssz_source: gossip.ssz_source,
                domain: Some(gossip.domain),
                gossip_subnet: Some(custody_group),
                recv_ts: gossip.recv_ts.into(),
            },
            frame,
            producers,
        );
    }

    #[timed]
    fn handle_data_column_sidecar(
        &mut self,
        column: PendingColumn,
        frame: Option<GossipSidecarFrame>,
        producers: &mut SilverSpineProducers,
    ) {
        let stream_id = column.stream_id;
        let disposition = self.data_columns(column, frame, producers);

        if let ColumnDisposition::Rejected { block_root, slot, column } = disposition {
            producers.produce(PeerEvent::RpcMisbehaviour {
                p2p_peer: stream_id.peer(),
                severity: RpcSeverity::Fatal,
            });
            if let Some(column) = column {
                producers.produce(SyncNeed::missing_column(block_root, slot, column));
            }
        }
    }

    /// Columns past a block's `Available` edge verify in a second call so the
    /// edge does not wait on them.
    #[timed]
    fn flush_kzg_batch(&mut self, producers: &mut SilverSpineProducers) {
        debug_assert!(!self.kzg_batch.is_empty());

        let count = self.kzg_batch.columns_until_available(&self.tracker);
        self.verify_kzg_batch(count, producers);
        if !self.kzg_batch.is_empty() {
            self.verify_kzg_batch(self.kzg_batch.pending.len(), producers);
        }
    }

    /// One pairing check over the first `count` queued sidecars; on failure
    /// each re-verifies alone so the reject lands on the culpable peer only.
    fn verify_kzg_batch(&mut self, count: usize, producers: &mut SilverSpineProducers) {
        DataColumnCounters::KzgBatchesVerified.inc();
        DataColumnCounters::KzgBatchColumns.add(count as u64);

        let all_ok = {
            let validator = &self.validator;
            util::kzg_verify_batch_multi(
                self.kzg_batch.pending[..count]
                    .iter()
                    .filter_map(|p| batch::kzg_entry(p, validator)),
                &mut self.kzg_scratch,
            )
        };

        // Back to front, so each swap pulls in an element at or past `i`, never
        // one still to be removed.
        for i in (0..count).rev() {
            let p = self.kzg_batch.pending.swap_remove(i);
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
        if let Some(GossipSidecarFrame { domain, msg_hash, protobuf }) = p.frame.take() {
            producers.produce(PeerEvent::SendGossip {
                originator_stream_id: p.stream_id,
                topic: GossipTopic::DataColumnSidecar(p.column_index),
                domain,
                ssz_source: p.ssz_source,
                msg_hash,
                recv_ts: p.recv_ts.into(),
                protobuf,
                ssz: p.sidecar.read,
            });
        }
        self.retain_validated_column(&p, producers);
        self.record_validated_column(p, producers);
    }

    fn resolve_rejected(&mut self, p: &PendingKzg, producers: &mut SilverSpineProducers) {
        tracing::warn!(stream_id = ?p.stream_id, "failed to verify sidecar kzg proof");
        DataColumnCounters::KzgBatchRejects.inc();
        producers.produce(PeerEvent::RpcMisbehaviour {
            p2p_peer: p.stream_id.peer(),
            severity: RpcSeverity::Fatal,
        });
        producers.produce(SyncNeed::missing_column(p.block_root, p.slot, p.column_index));
    }
}

/// EF `gossip_validation` verdict for one sidecar.
#[cfg(feature = "ef_tests")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EfVerdict {
    Valid,
    Ignore,
    Reject,
}

#[cfg(feature = "ef_tests")]
use silver_common::StreamProtocol;

/// EF `gossip_validation` harness API: the spine-fed inputs (clock, blocks)
/// set directly, and one sidecar carried through validation and its KZG batch.
#[cfg(feature = "ef_tests")]
impl DataColumnsTile {
    pub fn ef_set_status(&mut self, head_root: B256, finalized_slot: u64) {
        self.sync_state.ef_set(head_root, finalized_slot);
    }

    pub fn ef_tick(&mut self, since_genesis_ms: u64) {
        self.validator.ef_tick(since_genesis_ms);
    }

    /// A block the store holds, as both the gossip block and its persistence
    /// would have delivered it.
    pub fn ef_block(&mut self, ssz: TCacheRead, producers: &mut SilverSpineProducers) {
        let block = self.consumers.gossip.acquire(ssz);
        if let Ok((buf, _)) = block.buffer() {
            let slot = SignedBeaconBlockView::slot(buf);
            let root = util::block_root(buf, self.spec.is_gloas_at_slot(slot));
            self.validator.note_validated(root, slot);
        }
        let stream_id = P2pStreamId::new(0, 0, StreamProtocol::GossipSub, true);
        self.handle_beacon_block(block, stream_id, producers);
    }

    pub fn ef_gossip_sidecar(
        &mut self,
        ssz: TCacheRead,
        subnet: u64,
        producers: &mut SilverSpineProducers,
    ) -> EfVerdict {
        let column = PendingColumn {
            stream_id: P2pStreamId::new(1, 1, StreamProtocol::GossipSub, true),
            sidecar: self.consumers.gossip.acquire(ssz),
            ssz_source: SszSource::Gossip,
            domain: None,
            gossip_subnet: Some(subnet),
            recv_ts: IngestionTime::now(),
        };
        match self.data_columns(column, None, producers) {
            ColumnDisposition::Rejected { .. } => EfVerdict::Reject,
            ColumnDisposition::Ignored => EfVerdict::Ignore,
            ColumnDisposition::Batched => {
                let queued = self.kzg_batch.pending.last().expect("batched sidecar is pending");
                let (block_root, column_index) = (queued.block_root, queued.column_index);
                self.flush_kzg_batch(producers);
                if self.tracker.holds(&block_root, column_index) {
                    EfVerdict::Valid
                } else {
                    EfVerdict::Reject
                }
            }
        }
    }
}

impl DataColumnsTile {
    #[timed]
    fn handle_beacon_state_event(
        &mut self,
        event: BeaconStateEvent,
        producers: &mut SilverSpineProducers,
    ) -> Option<[u8; 92]> {
        let mut latest_status_event: Option<[u8; 92]> = None;
        match event {
            BeaconStateEvent::Status { ssz, .. } => {
                let root = *StatusView::head_root(&ssz);
                let slot = StatusView::head_slot(&ssz);
                self.validator.note_validated(root, slot);
                self.admit_gloas_context(root, slot, producers);
                self.drain_pending_gloas_columns(root, producers);
                // Per-event (not latest-only): BS emits one Status per accepted
                // block, and each newly validated root may unblock buffered
                // children.
                self.drain_parent_pending_columns(*StatusView::head_root(&ssz), producers);
                latest_status_event = Some(ssz);
            }
            BeaconStateEvent::BlockReceived {
                stage: BlockStage::AwaitData | BlockStage::Applied | BlockStage::AlreadyKnown,
                block_root,
                slot,
                ..
            } => {
                self.note_staged_block(block_root, slot, producers);
            }
            BeaconStateEvent::BlockRejected { block_root, .. } => {
                self.validator.note_rejected(&block_root);
                self.gloas_pending_columns.remove(&block_root);
                self.parent_pending_columns.remove(&block_root);
                if let Some(store) = &mut self.cell_store {
                    store.reject(&block_root);
                    producers.produce(CellStoreEvent::RejectedContext { block_root });
                }
            }
            BeaconStateEvent::PersistBlock { ssz, source, .. } => {
                let t_read = self.consumers.acquire_persisted(source, ssz);

                match t_read.buffer() {
                    Ok((buf, _)) => {
                        let slot = SignedBeaconBlockView::slot(buf);
                        let block_root = util::block_root(buf, self.spec.is_gloas_at_slot(slot));

                        if self.spec.is_gloas_at_slot(slot) {
                            self.validator.cache_gloas_commitments(block_root, buf);
                        }
                        self.note_staged_block(block_root, slot, producers);
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
        if let Some(store) = &mut self.cell_store {
            store.advance(Instant::now(), self.sync_state.data_availability_floor(), |_| {});
        }
        if let Some(consumer) = &mut self.data_columns_consumer {
            adapter.consume(|event: RetentionEvent, _| {
                if let Some(store) = &mut self.cell_store {
                    store.expire_through(event.expired_slot);
                }
                for pending in [&mut self.gloas_pending_columns, &mut self.parent_pending_columns] {
                    pending.retain(|_, columns| {
                        columns.retain(|column| {
                            column.ssz_source != SszSource::DataColumns ||
                                column.sidecar.seq() >= event.retain_from
                        });
                        !columns.is_empty()
                    });
                }
                consumer.advance_retention(event.retain_from);
            });
            consumer.free();
        }

        adapter.consume(|event: CellStoreEvent, producers| {
            self.handle_cell_event(event, Instant::now(), producers)
        });

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
                            ssz_source: SszSource::Rpc,
                            domain: None,
                            gossip_subnet: None,
                            recv_ts: IngestionTime::now(),
                        },
                        None,
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
            if let Some(ssz) = self.handle_beacon_state_event(beacon_event, producers) {
                self.sync_state.update(ssz);
            }
        });

        // Verified before the EL response is read, so `to_request` excludes
        // columns that arrived this iteration and no column is recorded twice.
        if !self.kzg_batch.is_empty() {
            self.flush_kzg_batch(&mut adapter.producers);
        }

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

        let now = Instant::now();

        self.validator.rotate(now);
        self.tracker.maybe_rotate(now);
        self.parent_pending_columns.maybe_rotate(now);
        self.gloas_pending_columns.maybe_rotate(now);
        self.flush_cell_updates(&mut adapter.producers);
        self.el_fetcher.rotate(now);
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::Path};

    use silver_beacon_state_data::{BeaconState, BeaconStateOwner};
    use silver_common::{
        BlockSource, BlockStage, EngineGetBlobsResp, EngineReq, HeadChange, HeadRoots,
        MESSAGE_ID_LEN, MessageId, Nanos, P2pStreamId, PayloadResolution, StreamProtocol, TCache,
        TCacheProducer, TCacheRead,
        column_util::SidecarIdentity,
        ssz_view::{
            DATA_COLUMN_SIDECAR_MIN, DataColumnSidecarFuluView, NUMBER_OF_COLUMNS,
            SIGNED_BEACON_BLOCK_MIN,
        },
        test_util::ShmemDir,
    };

    use super::*;

    mod publication;

    const CUSTODY_COLUMNS: u128 = (1u128 << 3) | (1u128 << 7);

    /// A tile on its own spine, with an injector adapter to read what it
    /// produced. Tcaches are heap-allocated and leaked, so the producers need
    /// not outlive this. Declaration order is drop order: adapters before the
    /// spine, spine before the directory it is mapped in.
    struct Rig {
        inj: SpineAdapter<SilverSpine>,
        conn: SpineAdapter<SilverSpine>,
        tile: DataColumnsTile,
        gossip_p: TProducer,
        rpc_p: TProducer,
        engine_p: TProducer,
        _spine: Box<SilverSpine>,
        _dir: ShmemDir,
    }

    struct Injector;

    impl Tile<SilverSpine> for Injector {
        fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
    }

    impl Rig {
        fn new(custody: u128) -> Self {
            Self::with_spec(custody, SpecConfig::mainnet())
        }

        fn gloas(custody: u128) -> Self {
            Self::with_spec(custody, SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() })
        }

        fn with_spec(custody: u128, spec: SpecConfig) -> Self {
            let mut state = BeaconStateOwner::empty_test(0);
            let anchor = state.roll_fresh();
            state.publish_state_id(anchor);
            Self::with_state(custody, state.reader(), spec)
        }

        fn with_state(custody: u128, beacon_state: BeaconStateReader, spec: SpecConfig) -> Self {
            let gossip_p = TCache::producer("gossip_blocks", 1024 * 1024);
            let gossip_consumer = gossip_p.cache_ref().random_access("gossip_cons", true).unwrap();

            let persist_gossip_tc = TCache::producer("persist_gossip_blocks", 1024 * 1024);
            let persist_gossip_consumer =
                persist_gossip_tc.cache_ref().random_access("persist_gossip_cons", true).unwrap();

            let rpc_p = TCache::producer("rpc_blocks", 1024 * 1024);
            let rpc_consumer = rpc_p.cache_ref().random_access("rpc_cons", true).unwrap();

            let persist_rpc_tc = TCache::producer("persist_rpc_blocks", 1024 * 1024);
            let persist_rpc_consumer =
                persist_rpc_tc.cache_ref().random_access("persist_rpc_cons", true).unwrap();

            let engine_p = TCache::producer("engine_resp", 1024 * 1024);
            let engine_resp_consumer =
                engine_p.cache_ref().random_access("engine_resp_cons", true).unwrap();

            let tile = DataColumnsTile::new(
                ColumnConsumers {
                    gossip: gossip_consumer,
                    persist_gossip: persist_gossip_consumer,
                    rpc: rpc_consumer,
                    persist_rpc: persist_rpc_consumer,
                },
                beacon_state,
                custody,
                Arc::new(spec),
                engine_resp_consumer,
                TCache::producer("el_columns", 1024 * 1024),
                SlotTicker::new(0, Duration::from_secs(12), Duration::from_secs(4)),
            );

            let dir = ShmemDir::new().unwrap();
            let mut spine = Box::new(SilverSpine::new_with_base_dir(dir.path(), None));
            let conn = SpineAdapter::connect_tile(&tile, &mut spine);
            let mut inj = SpineAdapter::connect_tile(&Injector, &mut spine);
            // Cursors snap on their first consume, so prime them while empty.
            inj.consume(|_: DataColumnsEvent, _| {});
            inj.consume(|_: SyncNeed, _| {});
            inj.consume(|_: EngineReq, _| {});
            inj.consume(|_: PeerEvent, _| {});
            inj.consume(|_: CellStoreEvent, _| {});
            Self { inj, conn, tile, gossip_p, rpc_p, engine_p, _spine: spine, _dir: dir }
        }

        fn turn(&mut self) {
            self.tile.loop_body(&mut self.conn);
        }

        fn engine_blobs(&mut self, block_root: BlockRoot, slot: u64, frame: &[u8]) {
            let data = tcache_write(&mut self.engine_p, frame);
            self.inj.produce(EngineResp::GetBlobs(EngineGetBlobsResp {
                block_root,
                slot,
                ok: true,
                blobs_present: 1,
                data,
            }));
        }

        fn follow(&mut self, head_root: BlockRoot) {
            self.tile.sync_state.set_sync_target(SyncUpdate::Following);
            let mut ssz = status_ssz(0);
            ssz[44..76].copy_from_slice(&head_root);
            self.tile.sync_state.update(ssz);
        }

        /// The protobuf placeholder cannot decode as a sidecar, exposing relays
        /// that substitute its handle for SSZ.
        fn gossip_sidecar(&mut self, index: u64, bytes: &[u8]) {
            let ssz = tcache_write(&mut self.gossip_p, bytes);
            let protobuf = tcache_write(&mut self.gossip_p, b"encoded frame");
            let recv_ts = Nanos::now();
            let mut id = [0u8; 20];
            id.copy_from_slice(&bytes[..20]);
            let gossip = NewGossipMsg {
                stream_id: P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
                topic: GossipTopic::DataColumnSidecar(index),
                domain: self
                    .tile
                    .validator
                    .domain_at(SidecarIdentity::of(bytes).unwrap().slot)
                    .unwrap(),
                ssz_source: SszSource::Gossip,
                msg_hash: MessageId { id },
                recv_ts,
                ssz,
                protobuf,
            };
            self.tile.gossip_sidecar(index, gossip, &mut self.conn.producers);
        }

        fn rpc_sidecar(&mut self, bytes: &[u8]) {
            let ssz = tcache_write(&mut self.rpc_p, bytes);
            let sidecar = self.tile.consumers.rpc.acquire(ssz);
            self.tile.handle_data_column_sidecar(
                PendingColumn {
                    stream_id: P2pStreamId::new(
                        1,
                        0,
                        StreamProtocol::DataColumnSidecarsByRange,
                        true,
                    ),
                    sidecar,
                    ssz_source: SszSource::Rpc,
                    domain: None,
                    gossip_subnet: None,
                    recv_ts: IngestionTime::now(),
                },
                None,
                &mut self.conn.producers,
            );
        }

        fn block(&mut self, bytes: &[u8]) {
            let ssz = tcache_write(&mut self.gossip_p, bytes);
            let read = self.tile.consumers.gossip.acquire(ssz);
            self.tile.handle_beacon_block(
                read,
                P2pStreamId::new(1, 0, StreamProtocol::GossipSub, true),
                &mut self.conn.producers,
            );
        }

        fn drain(&mut self) -> Produced {
            let mut out = Produced::default();
            self.inj.consume(|event: DataColumnsEvent, _| match event {
                DataColumnsEvent::Available { .. } => out.available += 1,
                DataColumnsEvent::Validated { column_index, .. } => {
                    out.validated |= 1u128 << column_index
                }
                DataColumnsEvent::Persist { .. } => out.receipts.push(event),
            });
            self.inj.consume(|need: SyncNeed, _| match need {
                SyncNeed::Missing { .. } => out.missing.push(need),
                SyncNeed::Arrived { kind: DataKind::Columns, .. } => out.custody_complete += 1,
                SyncNeed::Arrived { .. } |
                SyncNeed::Persisted { .. } |
                SyncNeed::BackfillPrefill(_) => {}
            });
            self.inj.consume(|_: EngineReq, _| out.engine += 1);
            let consumers = &mut self.tile.consumers;
            let data_columns = &mut self.tile.data_columns_consumer;
            self.inj.consume(|event: PeerEvent, _| {
                let (source, topic, domain, sidecar) = match event {
                    PeerEvent::SendGossip { topic, domain, ssz, ssz_source, .. } => {
                        let read = match ssz_source {
                            SszSource::DataColumns => {
                                data_columns.as_mut().unwrap().acquire_strict(ssz).unwrap()
                            }
                            SszSource::Gossip => consumers.gossip.acquire(ssz),
                            _ => panic!("unexpected gossip cache"),
                        };
                        (ColumnSource::Gossip, topic, domain, read)
                    }
                    _ => return,
                };
                let (bytes, _) = sidecar.buffer().expect("published bytes readable");
                let column = SidecarIdentity::of(bytes).expect("a published sidecar has a layout");
                out.publications.push((source, topic, column));
                out.domains.push(domain);
            });
            out
        }
    }

    fn tcache_write(producer: &mut TProducer, bytes: &[u8]) -> TCacheRead {
        let mut reservation = producer.reserve(bytes.len(), true).expect("tcache reserve");
        reservation.write_all(bytes).expect("tcache write");
        reservation.flush().expect("tcache flush");
        reservation.read()
    }

    #[derive(Default)]
    struct Produced {
        available: usize,
        custody_complete: usize,
        validated: u128,
        receipts: Vec<DataColumnsEvent>,
        publications: Vec<(ColumnSource, GossipTopic, SidecarIdentity)>,
        domains: Vec<silver_common::GossipDomain>,
        engine: usize,
        missing: Vec<SyncNeed>,
    }

    impl Produced {
        fn persisted(&self, root: BlockRoot, index: u64) -> bool {
            self.receipts.iter().any(|event| {
                matches!(event,
                    DataColumnsEvent::Persist { block_root, column_index, .. }
                        if *block_root == root && *column_index == index
                )
            })
        }
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

    fn block_received(stage: BlockStage, block_root: B256, slot: u64) -> BeaconStateEvent {
        BeaconStateEvent::BlockReceived {
            slot,
            block_root,
            stage,
            source: BlockSource::Rpc,
            parent_slot: None,
        }
    }

    /// EF fixtures run the fork under test from genesis; signatures verify
    /// against the fork version the config puts at the block's epoch.
    fn fulu_from_genesis() -> SpecConfig {
        SpecConfig { fulu_fork_epoch: 0, ..SpecConfig::mainnet() }
    }

    fn ef_sidecar(case: &str) -> Option<(Vec<u8>, Vec<u8>)> {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../beacon_state/tile/consensus-spec-tests/tests/mainnet/fulu");
        if !fixtures.try_exists().expect("check EF fixture directory") {
            eprintln!("EF sidecar coverage unavailable: run just ef-tests-download");
            return None;
        }
        let directory = fixtures.join(case);
        let sidecars: Vec<_> = std::fs::read_dir(&directory)
            .expect("installed EF fixtures must contain the sidecar case")
            .map(|entry| entry.expect("read EF case entry").path())
            .filter(|path| {
                let name = path.file_name().unwrap().to_string_lossy();
                name.starts_with("data_column_sidecar_") && name.ends_with(".ssz_snappy")
            })
            .collect();
        let [sidecar] = sidecars.as_slice() else {
            panic!("expected one sidecar in {}", directory.display());
        };
        let decode = |path: &Path| {
            let compressed = std::fs::read(path).expect("read EF fixture");
            snap::raw::Decoder::new().decompress_vec(&compressed).expect("decode EF fixture")
        };
        Some((decode(sidecar), decode(&directory.join("state.ssz_snappy"))))
    }

    fn reader_over(state_ssz: &[u8]) -> BeaconStateReader {
        let state = BeaconState::from_checkpoint(state_ssz, &fulu_from_genesis(), &[]).unwrap();
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        owner.reader()
    }

    /// A block the beacon state holds for its data columns may never have
    /// passed through this tile: dropped while unsynced, or lapped in its
    /// ring. The report alone must start the chase for its custody columns.
    #[test]
    fn staged_block_requests_its_columns() {
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        rig.tile.handle_beacon_state_event(
            block_received(BlockStage::AwaitData, [7u8; 32], 42),
            &mut rig.conn.producers,
        );
        let out = rig.drain();

        let [SyncNeed::Missing { root, slot, kind, columns, origin }] = out.missing[..] else {
            panic!("expected exactly one missing-columns need, got {}", out.missing.len());
        };
        assert_eq!((root, slot), ([7u8; 32], 42));
        assert_eq!(kind, DataKind::Columns);
        assert_eq!(columns, CUSTODY_COLUMNS, "nothing held yet: the whole custody set");
        assert_eq!(origin, Origin::Live);
    }

    /// A staged block vouches for its children's sidecars only while the
    /// beacon state holds it; the EL can still declare it invalid.
    #[test]
    fn rejected_block_stops_vouching_for_its_children() {
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        let root = [7u8; 32];
        rig.tile.handle_beacon_state_event(
            block_received(BlockStage::AwaitData, root, 42),
            &mut rig.conn.producers,
        );
        assert!(rig.tile.validator.is_validated(&root));

        rig.tile.handle_beacon_state_event(
            BeaconStateEvent::BlockRejected { block_root: root, source: BlockSource::Rpc },
            &mut rig.conn.producers,
        );
        assert!(!rig.tile.validator.is_validated(&root), "the rejection is forgotten with it");
    }

    /// A waiting sidecar becomes persistable when its parent is staged or
    /// observed as head, including when the head observation repeats.
    #[test]
    fn sidecar_of_observed_parent_is_accepted() {
        #[derive(Debug)]
        enum ParentObservation {
            BeforeSidecar,
            AfterSidecar,
            RepeatedStatus,
        }

        // A valid sidecar whose parent root names no block, over the state it
        // was built on.
        const CASE: &str = "networking/gossip_data_column_sidecar/pyspec_tests/\
                            gossip_data_column_sidecar__ignore_parent_not_seen";
        let Some((sidecar, state)) = ef_sidecar(CASE) else { return };
        let reader = reader_over(&state);
        let slot = DataColumnSidecarFuluView::slot(&sidecar);
        let index = DataColumnSidecarFuluView::index(&sidecar);
        let block_root = util::block_root_from_sidecar(&sidecar);
        let parent_root = *DataColumnSidecarFuluView::parent_root(&sidecar);
        let staged_parent = || block_received(BlockStage::AwaitData, parent_root, slot - 1);

        for observation in [
            ParentObservation::BeforeSidecar,
            ParentObservation::AfterSidecar,
            ParentObservation::RepeatedStatus,
        ] {
            let mut rig = Rig::with_state(1 << index, reader.clone(), fulu_from_genesis());
            rig.tile.sync_state.set_sync_target(SyncUpdate::Following);
            rig.tile.sync_state.update(status_ssz(0));

            if matches!(observation, ParentObservation::BeforeSidecar) {
                rig.tile.handle_beacon_state_event(staged_parent(), &mut rig.conn.producers);
            }
            rig.gossip_sidecar(index, &sidecar);
            match observation {
                ParentObservation::BeforeSidecar => {}
                ParentObservation::AfterSidecar => {
                    rig.tile.handle_beacon_state_event(staged_parent(), &mut rig.conn.producers);
                }
                ParentObservation::RepeatedStatus => {
                    rig.conn.consume(|_: BeaconStateEvent, _| {});
                    for _ in 0..2 {
                        rig.inj.producers.produce(head_status(parent_root, slot - 1));
                        rig.tile.loop_body(&mut rig.conn);
                    }
                }
            }
            rig.turn();
            let out = rig.drain();

            if matches!(observation, ParentObservation::BeforeSidecar) {
                assert_eq!(out.publications, [(
                    ColumnSource::Gossip,
                    GossipTopic::DataColumnSidecar(index),
                    SidecarIdentity { slot, block_root, column_index: index }
                )]);
            } else {
                assert!(out.publications.is_empty(), "a buffered copy is not relayed");
            }
            assert!(out.persisted(block_root, index), "{observation:?}: the sidecar was processed");
        }
    }

    /// `Validated` is the fact and fires once per column whether or not it is
    /// custody; `Persist` is the storage command, custody-gated, and a repeat
    /// copy re-offers it without restating the fact.
    #[test]
    fn validated_once_persist_for_custody() {
        const CASE: &str = "networking/gossip_data_column_sidecar/pyspec_tests/\
                            gossip_data_column_sidecar__ignore_parent_not_seen";
        let Some((sidecar, state)) = ef_sidecar(CASE) else { return };
        let reader = reader_over(&state);
        let slot = DataColumnSidecarFuluView::slot(&sidecar);
        let index = DataColumnSidecarFuluView::index(&sidecar);
        let parent_root = *DataColumnSidecarFuluView::parent_root(&sidecar);

        for (custody, receipts) in [(1u128 << index, 1usize), (0, 0)] {
            let mut rig = Rig::with_state(custody, reader.clone(), fulu_from_genesis());
            rig.tile.sync_state.set_sync_target(SyncUpdate::Following);
            rig.tile.sync_state.update(status_ssz(0));
            rig.tile.handle_beacon_state_event(
                block_received(BlockStage::AwaitData, parent_root, slot - 1),
                &mut rig.conn.producers,
            );

            rig.gossip_sidecar(index, &sidecar);
            rig.turn();
            let out = rig.drain();
            assert_eq!(out.validated, 1u128 << index, "custody {custody:b}: the fact fires");
            assert_eq!(
                out.receipts.len(),
                receipts,
                "custody {custody:b}: storage is custody-gated"
            );

            rig.gossip_sidecar(index, &sidecar);
            rig.turn();
            let out = rig.drain();
            assert_eq!(out.validated, 0, "custody {custody:b}: a repeat restates nothing");
            assert_eq!(
                out.receipts.len(),
                receipts,
                "custody {custody:b}: a repeat is re-offered to storage on the same terms"
            );
        }
    }

    fn head_status(head_root: BlockRoot, head_slot: u64) -> BeaconStateEvent {
        let mut ssz = status_ssz(0);
        ssz[44..76].copy_from_slice(&head_root);
        ssz[76..84].copy_from_slice(&head_slot.to_le_bytes());
        BeaconStateEvent::Status {
            ssz,
            latest_block_slot: head_slot,
            wall_slot: head_slot,
            head_optimistic: false,
            enr_fork_id: [0u8; 16],
            head_roots: HeadRoots::default(),
            head_payload: PayloadResolution::Full,
            head_change: HeadChange::None,
            epoch_transition: false,
        }
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
                    ssz_source: SszSource::Rpc,
                    domain: None,
                    gossip_subnet: None,
                    recv_ts: IngestionTime::now(),
                },
                false,
                Some(GossipSidecarFrame {
                    domain: silver_common::GossipDomain::new([0; 4], silver_common::ForkName::Fulu),
                    msg_hash: MessageId { id: [0; MESSAGE_ID_LEN] },
                    protobuf: ssz,
                }),
                &mut rig.conn.producers,
            );

            assert!(
                matches!(disposition, ColumnDisposition::Batched),
                "relay_eligible={relay_eligible}: imported either way"
            );
            let queued = rig.tile.kzg_batch.pending.first().expect("batched");
            assert_eq!(queued.frame.is_some(), want_relay, "relay_eligible={relay_eligible}");
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
                ssz_source: SszSource::Rpc,
                domain: None,
                gossip_subnet: None,
                recv_ts: IngestionTime::now(),
            },
            None,
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
                matches!(disposition, ColumnDisposition::Rejected { column: None, .. }),
                "index {index}: rejected with no column named"
            );
            assert!(out.missing.is_empty(), "index {index}: nothing to re-own");
        }

        // Control: an in-range index does name its column, so the assertions
        // above are about the bound and not about a blanket missing column.
        let mut rig = Rig::new(CUSTODY_COLUMNS);
        let disposition = feed_sidecar(&mut rig, &synth_fulu_sidecar(3, 7), "in_range_index");
        assert!(
            matches!(disposition, ColumnDisposition::Rejected { column: Some(3), .. }),
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
                out.available + out.receipts.len() + out.engine + out.missing.len(),
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
        rig.tile.sync_state.update(status_ssz(2));

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
        assert_eq!(out.available + out.receipts.len() + out.engine + out.missing.len(), 0);
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
                ColumnOutcome::AlreadyHeld { block_root, slot: 7 },
                PendingColumn {
                    stream_id: P2pStreamId::new(2, 2, protocol, true),
                    sidecar: read,
                    ssz_source: if protocol.is_gossip() {
                        SszSource::Gossip
                    } else {
                        SszSource::Rpc
                    },
                    domain: None,
                    gossip_subnet: None,
                    recv_ts: IngestionTime::now(),
                },
                false,
                None,
                &mut rig.conn.producers,
            );
            let out = rig.drain();

            assert!(
                matches!(disposition, ColumnDisposition::Ignored),
                "{protocol:?}: a duplicate is never relayed"
            );
            assert_eq!(
                out.receipts.len(),
                0,
                "{protocol:?}: unchecked duplicate bytes must not be persisted"
            );
            assert_eq!(
                out.custody_complete, answers,
                "{protocol:?}: only a requested duplicate answers"
            );
            assert_eq!(out.available, 0, "{protocol:?}: availability is never re-announced");
        }
    }
}
