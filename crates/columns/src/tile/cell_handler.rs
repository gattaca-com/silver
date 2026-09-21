use std::{
    ptr,
    time::{Duration, Instant},
};

use flux::spine::SpineProducers;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, ForkName, GossipTopic, IngestionTime, PeerEvent,
    SilverSpineProducers, SszCache, SyncNeed, TCacheRead, TRandomAccess, TRead, Wheel,
    cell_store::{
        CellOrigin, CellStoreConfig, CellStoreEvent, CellValidationOutcome, CellValidationRequest,
        CommitmentContext, ContextData, DataColumnCounters, FuluContextSource,
        HeaderValidationRequest, RetentionEvent, StoreError,
    },
    column_util::SidecarIdentity,
    ssz_view::{BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView},
};

use crate::{
    BlockRoot,
    availability::ColumnTracker,
    batch::{PendingCellKzg, PendingKzg, PreparedCells},
    cell_store::CellStore,
    sync::SyncStatus,
    validate::{ColumnValidator, HeaderOutcome, PendingColumn},
};

pub(super) struct CellHandler {
    store: CellStore,
    pending: Vec<CellValidationRequest>,
    headers: Vec<HeaderValidationRequest>,
    header_retry: Instant,
    header_cursor: usize,
    pending_limit: usize,
    pending_ready: bool,
    // The boxed consumer stays at a stable address while acquired reads exist.
    consumer: Box<TRandomAccess>,
}

impl CellHandler {
    pub(super) fn new(
        config: CellStoreConfig,
        consumer: TRandomAccess,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        assert!(consumer.is_retained());
        if consumer.cache_ref().capacity() < config.cache_capacity() {
            return Err(StoreError::CacheTooSmall);
        }
        let pending_limit = config.cell_capacity();
        Ok(Self {
            store: CellStore::new(config, slot, slot_start)?,
            consumer: Box::new(consumer),
            pending: Vec::with_capacity(pending_limit),
            headers: Vec::with_capacity(128),
            header_retry: slot_start,
            header_cursor: 0,
            pending_limit,
            pending_ready: false,
        })
    }

    #[inline]
    pub(super) fn acquire(&mut self, read: TCacheRead) -> Option<TRead> {
        if !ptr::eq(&*self.consumer.cache_ref(), &*read.cache_ref()) {
            return None;
        }
        self.consumer.acquire_strict(read)
    }

    #[inline]
    pub(super) fn needs_full_validation(&self, bytes: &[u8]) -> bool {
        SidecarIdentity::of(bytes).is_some_and(|identity| {
            self.store
                .availability(&identity.block_root, identity.column_index as usize)
                .is_none_or(|column| column.full.is_none())
        })
    }

    #[inline]
    pub(super) fn advance(&mut self, now: Instant, min_slot: u64) {
        self.store.advance(now, min_slot, |_| {});
    }

    pub(super) fn advance_retention(
        &mut self,
        event: RetentionEvent,
        pending: [&mut Wheel<BlockRoot, Vec<PendingColumn>, 4>; 2],
    ) {
        self.store.expire_through(event.expired_slot);
        self.pending.retain(|request| {
            let keep = request.pending.data.reservation().read().seq() >= event.retain_from;
            if !keep {
                DataColumnCounters::PartialCellsIgnored.inc();
            }
            keep
        });
        self.headers.retain(|request| request.ssz.seq() >= event.retain_from);
        for pending in pending {
            pending.retain(|_, columns| {
                columns.retain(|column| {
                    column.ssz_cache != SszCache::DataColumns ||
                        column.sidecar.seq() >= event.retain_from
                });
                !columns.is_empty()
            });
        }
        self.consumer.advance_retention(event.retain_from);
    }

    #[inline]
    pub(super) fn free(&mut self) {
        self.consumer.free();
    }

    pub(super) fn reject(&mut self, block_root: BlockRoot, producers: &SilverSpineProducers) {
        self.store.reject(&block_root);
        self.pending.retain(|request| {
            let keep = request.pending.key.block_root != block_root;
            if !keep {
                DataColumnCounters::PartialCellsIgnored.inc();
            }
            keep
        });
        self.headers.retain(|request| request.block_root != block_root);
        producers.produce(CellStoreEvent::RejectedContext { block_root });
    }

    pub(super) fn admit_gloas_context(
        &mut self,
        root: BlockRoot,
        slot: u64,
        validator: &ColumnValidator,
        producers: &SilverSpineProducers,
    ) {
        let Some(commitments) = validator.gloas_commitments(&root) else { return };
        let Some(domain) = validator.domain_at(slot) else { return };
        let context = CommitmentContext {
            block_root: root,
            slot,
            format: ForkName::Gloas,
            blob_count: commitments.len() / BYTES_PER_KZG_COMMITMENT,
        };
        if self
            .store
            .admit_context(context, domain, ContextData::Gloas { commitments }, None)
            .is_ok()
        {
            if let Some(request) = self.store.request_assemblies(&root) {
                producers.produce(CellStoreEvent::Allocate(request));
            }
        }
    }

    pub(super) fn retain_validated_column(
        &mut self,
        p: &PendingKzg,
        validator: &ColumnValidator,
        producers: &SilverSpineProducers,
    ) {
        if !p.context_eligible || p.ssz_cache != SszCache::DataColumns {
            return;
        }
        let Some(domain) = p.domain else { return };
        let Ok((bytes, _)) = p.sidecar.buffer() else { return };
        let data = if p.is_gloas {
            let Some(commitments) = validator.gloas_commitments(&p.block_root) else { return };
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
        if let Err(e) = self.store.admit_context(context, domain, data, source) {
            tracing::debug!(?e, slot = p.slot, "cell context not admitted");
            return;
        }
        match self.store.retain_full(
            &p.block_root,
            p.column_index as usize,
            p.sidecar.read,
            &mut self.consumer,
        ) {
            Ok(_) => self.store.mark_changed(&p.block_root, p.column_index as usize),
            Err(e) => tracing::debug!(?e, column = p.column_index, "full sidecar not retained"),
        }
        if let Some(request) = self.store.request_assemblies(&p.block_root) {
            producers.produce(CellStoreEvent::Allocate(request));
        }
    }

    pub(super) fn handle_event(
        &mut self,
        event: CellStoreEvent,
        now: Instant,
        producers: &mut SilverSpineProducers,
    ) {
        match event {
            CellStoreEvent::Allocated { request, set } => match set {
                Some(set)
                    if set.request.id == request.id && set.request.context == request.context =>
                {
                    match self.store.install(set, &mut self.consumer) {
                        Ok(true) => {
                            self.pending_ready = true;
                            let mut columns = request.columns;
                            while columns != 0 {
                                let column = columns.trailing_zeros() as usize;
                                columns &= columns - 1;
                                self.store.mark_changed(&request.context.block_root, column);
                            }
                        }
                        Ok(false) => {}
                        Err(e) => {
                            self.store.allocation_failed(request);
                            tracing::debug!(?e, "cell allocation not installed");
                        }
                    }
                }
                _ => self.store.allocation_failed(request),
            },
            CellStoreEvent::Validate(request) => {
                if now < request.deadline && self.pending.len() < self.pending_limit {
                    let root = request.pending.key.block_root;
                    if request.domain.format() == ForkName::Gloas &&
                        self.store.context(&root).is_none() &&
                        !self
                            .pending
                            .iter()
                            .any(|pending| pending.pending.key.block_root == root)
                    {
                        producers.produce(SyncNeed::missing_block(root, request.slot));
                    }
                    self.pending.push(request);
                    self.pending_ready = true;
                } else {
                    let _ = request.pending.data.cancel(&mut self.consumer);
                    Self::complete(request, CellValidationOutcome::Ignored, producers);
                }
            }
            CellStoreEvent::Header(request)
                if now < request.deadline && self.headers.len() < 128 =>
            {
                self.headers.push(request);
                self.header_retry = now;
            }
            CellStoreEvent::Cancel(pending) => {
                let _ = pending.data.cancel(&mut self.consumer);
            }
            _ => {}
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        self.pending_ready
    }

    pub(super) fn verify_headers(
        &mut self,
        validator: &ColumnValidator,
        sync: &SyncStatus,
        tracker: &mut ColumnTracker,
        now: Instant,
        producers: &SilverSpineProducers,
    ) {
        if now < self.header_retry {
            return;
        }
        self.header_retry = now + Duration::from_millis(20);
        for _ in 0..self.headers.len().min(4) {
            self.header_cursor %= self.headers.len();
            let index = self.header_cursor;
            self.header_cursor += 1;
            let request = self.headers[index];
            if now >= request.deadline {
                self.headers.swap_remove(index);
                continue;
            }
            let Some(read) = self.acquire(request.ssz) else {
                self.headers.swap_remove(index);
                continue;
            };
            let Ok((bytes, _)) = read.buffer() else {
                self.headers.swap_remove(index);
                continue;
            };
            if let Some((_, context)) = self.store.context(&request.block_root) {
                if !context.matches(bytes) {
                    DataColumnCounters::PartialHeadersRejected.inc();
                    Self::verdict(request.origin, request.block_root, false, producers);
                }
                self.headers.swap_remove(index);
                continue;
            }
            match validator.validate_partial_header(
                request.block_root,
                request.domain,
                bytes,
                sync,
                tracker,
            ) {
                HeaderOutcome::Valid(context) => {
                    self.headers.swap_remove(index);
                    let Some(data) = ContextData::from_encoded(bytes, ForkName::Fulu) else {
                        continue
                    };
                    if self
                        .store
                        .admit_context(
                            context,
                            request.domain,
                            data,
                            Some(FuluContextSource::Header(request.ssz)),
                        )
                        .is_ok()
                    {
                        DataColumnCounters::PartialHeadersAccepted.inc();
                        if let Some(allocation) = self.store.request_assemblies(&request.block_root)
                        {
                            producers.produce(CellStoreEvent::Allocate(allocation));
                        }
                        Self::verdict(request.origin, request.block_root, true, producers);
                    }
                }
                HeaderOutcome::Reject => {
                    DataColumnCounters::PartialHeadersRejected.inc();
                    self.headers.swap_remove(index);
                    Self::verdict(request.origin, request.block_root, false, producers);
                }
                HeaderOutcome::AwaitParent { root, slot } => {
                    producers.produce(SyncNeed::missing_block(root, slot))
                }
                HeaderOutcome::Ignore => {}
            }
        }
    }

    pub(super) fn prepare_cells(
        &mut self,
        now: Instant,
        producers: &SilverSpineProducers,
    ) -> PreparedCells {
        self.pending_ready = false;
        let mut ready = std::array::from_fn(|_| None);
        let mut count = 0;
        for index in (0..self.pending.len()).rev() {
            if count == ready.len() {
                self.pending_ready = true;
                break;
            }
            let request = self.pending[index];
            let key = request.pending.key;
            if now >= request.deadline {
                self.pending.swap_remove(index);
                let _ = request.pending.data.cancel(&mut self.consumer);
                Self::complete(request, CellValidationOutcome::Ignored, producers);
                continue;
            }
            let Some(column) = self.store.availability(&key.block_root, key.column) else {
                continue
            };
            let Some(assembly) = column.assembly else { continue };
            self.pending.swap_remove(index);
            if column.domain != request.domain ||
                now >= column.expires ||
                column.cell(key.row).is_some() ||
                key.row != request.pending.data.part() ||
                assembly.read().seq() != request.pending.data.reservation().read().seq()
            {
                let _ = request.pending.data.cancel(&mut self.consumer);
                Self::complete(request, CellValidationOutcome::Ignored, producers);
                continue;
            }
            let Ok(validation) = request.pending.data.acquire(&mut self.consumer) else {
                Self::complete(request, CellValidationOutcome::Ignored, producers);
                continue;
            };
            ready[count] = Some(PendingCellKzg { request, validation });
            count += 1;
        }
        ready
    }

    pub(super) fn resolve_cell(
        &mut self,
        pending: PendingCellKzg,
        valid: bool,
        producers: &SilverSpineProducers,
    ) {
        let request = pending.request;
        let outcome = if Instant::now() >= request.deadline {
            CellValidationOutcome::Ignored
        } else if !valid {
            Self::verdict(request.origin, request.pending.key.block_root, false, producers);
            CellValidationOutcome::Rejected
        } else if pending.validation.accept().is_ok() {
            let key = request.pending.key;
            self.store.mark_changed(&key.block_root, key.column);
            Self::verdict(request.origin, key.block_root, true, producers);
            CellValidationOutcome::Accepted
        } else {
            CellValidationOutcome::Ignored
        };
        Self::complete(request, outcome, producers);
    }

    fn complete(
        request: CellValidationRequest,
        outcome: CellValidationOutcome,
        producers: &SilverSpineProducers,
    ) {
        match outcome {
            CellValidationOutcome::Accepted => DataColumnCounters::PartialCellsAccepted.inc(),
            CellValidationOutcome::Rejected => DataColumnCounters::PartialCellsRejected.inc(),
            CellValidationOutcome::Ignored => DataColumnCounters::PartialCellsIgnored.inc(),
        }
        producers.produce(CellStoreEvent::Validation { request, outcome });
    }

    fn verdict(
        origin: CellOrigin,
        block_root: BlockRoot,
        accepted: bool,
        producers: &SilverSpineProducers,
    ) {
        if let CellOrigin::Gossip {
            stream_id,
            topic: GossipTopic::DataColumnSidecar(column),
            received,
        } = origin
        {
            producers.produce(PeerEvent::ColumnVerdict {
                p2p_peer: stream_id.peer(),
                block_root,
                column,
                recv_ts: received,
                accepted,
            });
        }
    }

    pub(super) fn flush_updates(
        &mut self,
        tracker: &mut ColumnTracker,
        producers: &mut SilverSpineProducers,
    ) {
        loop {
            let Some((root, column)) = self.store.next_changed() else { return };
            let Ok(update) = self.store.refresh_column(&root, column, &mut self.consumer) else {
                continue
            };
            let Some(available) = self.store.availability(&root, column) else { continue };
            producers.produce(CellStoreEvent::Available(available));
            if !update.column_completed || tracker.holds(&root, column as u64) {
                continue;
            }
            let Some(ssz) = update.complete_read else { continue };
            let recv_ts = IngestionTime::now();
            tracker.record_and_notify(root, available.slot, 1u128 << column, recv_ts, producers);
            producers.produce_with_ingestion(
                DataColumnsEvent::Validated {
                    block_root: root,
                    column_index: column as u64,
                    slot: available.slot,
                    origin: ColumnOrigin::Assembly,
                    ssz,
                    ssz_cache: SszCache::DataColumns,
                },
                recv_ts,
            );
            if tracker.is_custody(column as u64) {
                producers.produce(DataColumnsEvent::Persist {
                    ssz,
                    origin: ColumnOrigin::Assembly,
                    ssz_cache: SszCache::DataColumns,
                    domain: Some(available.domain),
                    block_root: root,
                    column_index: column as u64,
                    slot: available.slot,
                });
            }
        }
    }

    pub(super) fn store(&self) -> &CellStore {
        &self.store
    }

    #[cfg(test)]
    pub(super) fn store_mut(&mut self) -> &mut CellStore {
        &mut self.store
    }
}
