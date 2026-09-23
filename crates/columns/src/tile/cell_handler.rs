use std::{
    ptr,
    time::{Duration, Instant},
};

use flux::spine::SpineProducers;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, ForkName, GossipDomain, GossipTopic, IngestionTime, PeerEvent,
    SilverSpineProducers, SszCache, SyncNeed, TCacheError, TCacheId, TCacheRead, TCacheReader,
    TCacheTable, TRead, TReadMode, TileId, Wheel,
    cell_store::{
        CellOrigin, CellStoreConfig, CellStoreEvent, CellValidationOutcome, CellValidationRequest,
        ColumnRef, CommitmentContext, ContextData, DataColumnCounters, HeaderValidationRequest,
        RetentionEvent, StoreError,
    },
    column_util::{SidecarIdentity, columns_of},
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF},
};

use crate::{
    BlockRoot,
    availability::ColumnTracker,
    batch::{PendingCellKzg, PendingKzg, PreparedCells},
    cell_store::CellStore,
    sync::SyncStatus,
    validate::{ColumnValidator, HeaderOutcome, PendingColumn},
};

pub(crate) struct CellHandler {
    store: CellStore,
    pending: PendingCells,
    headers: PendingHeaders,
    reader: TCacheReader,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum CellWriteState {
    Unavailable,
    Pending,
    Ready,
}

struct PendingCells {
    requests: Vec<CellValidationRequest>,
    limit: usize,
    // A request was admitted or an assembly installed since the last prepare.
    ready: bool,
}

impl PendingCells {
    fn new(limit: usize) -> Self {
        Self { requests: Vec::with_capacity(limit), limit, ready: false }
    }

    fn is_full(&self) -> bool {
        self.requests.len() >= self.limit
    }

    fn admit(&mut self, request: CellValidationRequest, now: Instant) -> bool {
        if now >= request.deadline || self.is_full() {
            return false;
        }
        self.requests.push(request);
        self.ready = true;
        true
    }

    fn has_root(&self, root: &BlockRoot) -> bool {
        self.requests.iter().any(|request| request.pending.key.block_root == *root)
    }

    fn retain_from(&mut self, seq: u64) {
        self.retain(|request| request.pending.data.reservation().read().seq() >= seq);
    }

    fn remove_root(&mut self, root: &BlockRoot) {
        self.retain(|request| request.pending.key.block_root != *root);
    }

    fn retain(&mut self, keep: impl Fn(&CellValidationRequest) -> bool) {
        self.requests.retain(|request| {
            let keep = keep(request);
            if !keep {
                DataColumnCounters::PartialCellsIgnored.inc();
            }
            keep
        });
    }
}

struct PendingHeaders {
    requests: Vec<HeaderValidationRequest>,
    retry_at: Instant,
    cursor: usize,
}

impl PendingHeaders {
    const LIMIT: usize = 128;
    const PER_PASS: usize = 4;
    const RETRY: Duration = Duration::from_millis(20);

    fn new(now: Instant) -> Self {
        Self { requests: Vec::with_capacity(Self::LIMIT), retry_at: now, cursor: 0 }
    }

    fn admit(&mut self, request: HeaderValidationRequest, now: Instant) -> bool {
        if now >= request.deadline || self.requests.len() >= Self::LIMIT {
            return false;
        }
        self.requests.push(request);
        self.retry_at = now;
        true
    }

    fn retain_from(&mut self, seq: u64) {
        self.requests.retain(|request| request.ssz.seq() >= seq);
    }

    fn remove_root(&mut self, root: &BlockRoot) {
        self.requests.retain(|request| request.block_root != *root);
    }

    /// Headers to verify this pass; zero until the retry interval elapses.
    fn due(&mut self, now: Instant) -> usize {
        if now < self.retry_at {
            return 0;
        }
        self.retry_at = now + Self::RETRY;
        self.requests.len().min(Self::PER_PASS)
    }

    /// Round-robin index into `requests`, which must be non-empty.
    fn next_index(&mut self) -> usize {
        self.cursor %= self.requests.len();
        let index = self.cursor;
        self.cursor += 1;
        index
    }
}

impl CellHandler {
    pub(crate) fn el_write_state(
        &self,
        context: CommitmentContext,
        domain: GossipDomain,
        now: Instant,
    ) -> CellWriteState {
        if now >= self.store.slot_end() ||
            self.store.context(&context.block_root).is_none_or(|(known, _)| *known != context)
        {
            return CellWriteState::Unavailable;
        }
        let Some(column) = self.store.reservations(&context.block_root).next() else {
            return if self.store.awaiting_allocation(&context.block_root) {
                CellWriteState::Pending
            } else {
                CellWriteState::Unavailable
            };
        };
        if self
            .store
            .availability(&context.block_root, column.column)
            .is_none_or(|column| column.domain != domain)
        {
            return CellWriteState::Unavailable;
        }
        CellWriteState::Ready
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn stage_el_row(
        &mut self,
        context: CommitmentContext,
        domain: GossipDomain,
        columns: u128,
        row: usize,
        cells: &[c_kzg::Cell; c_kzg::CELLS_PER_EXT_BLOB],
        proofs: &[u8],
        request_id: u64,
        producers: &mut SilverSpineProducers,
    ) {
        let now = Instant::now();
        for column in columns_of(columns) {
            if self.pending.is_full() {
                break;
            }
            let Some(available) = self.store.availability(&context.block_root, column as usize)
            else {
                continue
            };
            if now >= available.expires || available.cell(row).is_some() {
                continue;
            }
            let Some(reservation) = available.assembly else { continue };
            let reference = ColumnRef {
                block_root: context.block_root,
                column: column as usize,
                reservation,
                slot: context.slot,
                expires: available.expires,
            };
            let offset = column as usize * BYTES_PER_KZG_PROOF;
            let Some(proof) = proofs
                .get(offset..offset + BYTES_PER_KZG_PROOF)
                .and_then(|proof| proof.try_into().ok())
            else {
                continue
            };
            // SAFETY: Cell is repr(C) over [u8; BYTES_PER_CELL].
            let cell: &[u8; BYTES_PER_CELL] =
                unsafe { &*ptr::from_ref(&cells[column as usize]).cast() };
            match reference.stage(&mut self.reader, row, cell, proof) {
                Ok(Some(pending)) => {
                    DataColumnCounters::ElCellsQueued.inc();
                    self.handle_event(
                        CellStoreEvent::Validate(CellValidationRequest {
                            pending,
                            slot: context.slot,
                            domain,
                            origin: CellOrigin::El { request_id },
                            deadline: available.expires,
                        }),
                        now,
                        producers,
                    );
                }
                Ok(None) => {}
                Err(error) => tracing::debug!(?error, column, row, "el cell staging failed"),
            }
        }
    }

    pub(super) fn new(
        config: CellStoreConfig,
        tcaches: TCacheTable,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        let cache = tcaches.get(TCacheId::ControlSlot).map_err(|_| StoreError::WrongCache)?;
        if cache.capacity() < config.cache_capacity() {
            return Err(StoreError::CacheTooSmall);
        }
        Ok(Self {
            pending: PendingCells::new(config.cell_capacity()),
            headers: PendingHeaders::new(slot_start),
            store: CellStore::new(config, slot, slot_start)?,
            reader: TCacheReader::new(tcaches),
        })
    }

    pub(super) fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open_forwarder(TileId::Columns, TCacheId::ControlSlot, TReadMode::Strict)
    }

    #[inline]
    pub(super) fn acquire(&mut self, read: TCacheRead) -> Option<TRead> {
        if read.id() != TCacheId::ControlSlot {
            return None;
        }
        self.reader.acquire_strict(read)
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
        self.pending.retain_from(event.retain_from);
        self.headers.retain_from(event.retain_from);
        for pending in pending {
            pending.retain(|_, columns| {
                columns.retain(|column| {
                    column.ssz_cache != SszCache::DataColumns ||
                        column.sidecar.seq() >= event.retain_from
                });
                !columns.is_empty()
            });
        }
    }

    #[inline]
    pub(super) fn free(&mut self) {
        self.reader.free();
    }

    pub(super) fn reject(&mut self, block_root: BlockRoot, producers: &SilverSpineProducers) {
        self.store.reject(&block_root);
        self.pending.remove_root(&block_root);
        self.headers.remove_root(&block_root);
        producers.produce(CellStoreEvent::RejectedContext { block_root });
    }

    pub(super) fn admit_current_context(
        &mut self,
        context: CommitmentContext,
        domain: GossipDomain,
        data: ContextData<'_>,
        producers: &SilverSpineProducers,
    ) -> bool {
        context.slot == self.store.current_slot() &&
            self.admit_context(context, domain, data, producers)
    }

    pub(crate) fn admit_context(
        &mut self,
        context: CommitmentContext,
        domain: GossipDomain,
        data: ContextData<'_>,
        producers: &SilverSpineProducers,
    ) -> bool {
        if let Err(error) = self.store.admit_context(context, domain, data) {
            tracing::debug!(?error, slot = context.slot, "cell context not admitted");
            return false;
        }
        if let Some(request) = self.store.request_assemblies(&context.block_root) {
            producers.produce(CellStoreEvent::Allocate(request));
        }
        true
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
            let Some(data) = ContextData::from_fulu_sidecar(bytes) else { return };
            data
        };
        let context = CommitmentContext {
            block_root: p.block_root,
            slot: p.slot,
            format: domain.format(),
            blob_count: data.commitments().len() / BYTES_PER_KZG_COMMITMENT,
        };
        if !self.admit_current_context(context, domain, data, producers) {
            return;
        }
        match self.store.retain_full(
            &p.block_root,
            p.column_index as usize,
            p.sidecar.to_read(),
            &mut self.reader,
        ) {
            Ok(_) => self.store.mark_changed(&p.block_root, p.column_index as usize),
            Err(e) => tracing::debug!(?e, column = p.column_index, "full sidecar not retained"),
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
                    match self.store.install(set, &mut self.reader) {
                        Ok(true) => {
                            self.pending.ready = true;
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
                let root = request.pending.key.block_root;
                let first_for_root = request.domain.format() == ForkName::Gloas &&
                    self.store.context(&root).is_none() &&
                    !self.pending.has_root(&root);
                if self.pending.admit(request, now) {
                    if first_for_root {
                        producers.produce(SyncNeed::missing_block(root, request.slot));
                    }
                } else {
                    let _ = request.pending.data.cancel(&mut self.reader);
                    Self::complete(request, CellValidationOutcome::Ignored, producers);
                }
            }
            CellStoreEvent::Header(request) => {
                self.headers.admit(request, now);
            }
            CellStoreEvent::Cancel(pending) => {
                let _ = pending.data.cancel(&mut self.reader);
            }
            _ => {}
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        self.pending.ready
    }

    pub(super) fn verify_headers(
        &mut self,
        validator: &ColumnValidator,
        sync: &SyncStatus,
        tracker: &mut ColumnTracker,
        now: Instant,
        producers: &SilverSpineProducers,
        mut on_context: impl FnMut(CommitmentContext, GossipDomain, ContextData<'_>, u128),
    ) {
        for _ in 0..self.headers.due(now) {
            let index = self.headers.next_index();
            let request = self.headers.requests[index];
            if now >= request.deadline {
                self.headers.requests.swap_remove(index);
                continue;
            }
            let Some(read) = self.acquire(request.ssz) else {
                self.headers.requests.swap_remove(index);
                continue;
            };
            let Ok((bytes, _)) = read.buffer() else {
                self.headers.requests.swap_remove(index);
                continue;
            };
            if let Some((_, context)) = self.store.context(&request.block_root) {
                if !context.matches(bytes) {
                    DataColumnCounters::PartialHeadersRejected.inc();
                    Self::verdict(request.origin, request.block_root, false, producers);
                }
                self.headers.requests.swap_remove(index);
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
                    self.headers.requests.swap_remove(index);
                    let Some(data) = ContextData::from_encoded(bytes, ForkName::Fulu) else {
                        continue
                    };
                    on_context(
                        context,
                        request.domain,
                        data,
                        tracker.to_request(&context.block_root),
                    );
                    if self.admit_current_context(context, request.domain, data, producers) {
                        DataColumnCounters::PartialHeadersAccepted.inc();
                        Self::verdict(request.origin, request.block_root, true, producers);
                    }
                }
                HeaderOutcome::Reject => {
                    DataColumnCounters::PartialHeadersRejected.inc();
                    self.headers.requests.swap_remove(index);
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
        self.pending.ready = false;
        let mut ready = std::array::from_fn(|_| None);
        let mut count = 0;
        for index in (0..self.pending.requests.len()).rev() {
            if count == ready.len() {
                self.pending.ready = true;
                break;
            }
            let request = self.pending.requests[index];
            let key = request.pending.key;
            if now >= request.deadline {
                self.pending.requests.swap_remove(index);
                let _ = request.pending.data.cancel(&mut self.reader);
                Self::complete(request, CellValidationOutcome::Ignored, producers);
                continue;
            }
            let Some(column) = self.store.availability(&key.block_root, key.column) else {
                continue
            };
            let Some(assembly) = column.assembly else { continue };
            self.pending.requests.swap_remove(index);
            if column.domain != request.domain ||
                now >= column.expires ||
                column.cell(key.row).is_some() ||
                key.row != request.pending.data.part() ||
                assembly.read().seq() != request.pending.data.reservation().read().seq()
            {
                let _ = request.pending.data.cancel(&mut self.reader);
                Self::complete(request, CellValidationOutcome::Ignored, producers);
                continue;
            }
            let Ok(validation) = request.pending.data.acquire(&mut self.reader) else {
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
            let Ok(update) = self.store.refresh_column(&root, column, &mut self.reader) else {
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
