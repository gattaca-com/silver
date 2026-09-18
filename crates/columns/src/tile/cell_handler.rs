use std::{iter::once, ptr, time::Instant};

use flux::spine::SpineProducers;
use silver_common::{
    ColumnOrigin, DataColumnsEvent, ForkName, IngestionTime, SilverSpineProducers, SszCache,
    TCacheRead, TRandomAccess, TRead, Wheel,
    cell_store::{
        CellStoreConfig, CellStoreEvent, CellValidationOutcome, CellValidationRequest,
        CommitmentContext, ContextData, FuluContextSource, RetentionEvent, StoreError,
    },
    column_util::{self as util, KzgBatchEntry, KzgScratch, SidecarIdentity},
    ssz_view::{BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView},
};

use crate::{
    BlockRoot,
    availability::ColumnTracker,
    batch::PendingKzg,
    cell_store::CellStore,
    validate::{ColumnValidator, PendingColumn},
};

pub(super) struct CellHandler {
    store: CellStore,
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
        Ok(Self { store: CellStore::new(config, slot, slot_start)?, consumer: Box::new(consumer) })
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
        scratch: &mut KzgScratch,
        producers: &mut SilverSpineProducers,
    ) {
        match event {
            CellStoreEvent::Allocated { request, set } => match set {
                Some(set)
                    if set.request.id == request.id && set.request.context == request.context =>
                {
                    match self.store.install(set, &mut self.consumer) {
                        Ok(true) => {
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
                let outcome = self.validate_cell(request, now, scratch);
                producers.produce(CellStoreEvent::Validation { request, outcome });
            }
            CellStoreEvent::Cancel(pending) => {
                let _ = pending.data.cancel(&mut self.consumer);
            }
            _ => {}
        }
    }

    pub(super) fn validate_cell(
        &mut self,
        request: CellValidationRequest,
        now: Instant,
        scratch: &mut KzgScratch,
    ) -> CellValidationOutcome {
        let key = request.pending.key;
        let eligible = self.store.availability(&key.block_root, key.column).is_some_and(|column| {
            now < request.deadline &&
                now < column.expires &&
                column.domain == request.domain &&
                column.assembly.is_some_and(|reference| {
                    reference.read().seq() == request.pending.data.reservation().read().seq()
                }) &&
                key.row == request.pending.data.part()
        });
        if !eligible {
            let _ = request.pending.data.cancel(&mut self.consumer);
            return CellValidationOutcome::Ignored;
        }
        let Ok(validation) = request.pending.data.acquire(&mut self.consumer) else {
            return CellValidationOutcome::Ignored
        };
        let (context, data) = self.store.context(&key.block_root).unwrap();
        if key.row >= context.blob_count {
            return CellValidationOutcome::Ignored;
        }
        let [cell, proof] = validation.buffers();
        let commitments = &data.commitments()
            [key.row * BYTES_PER_KZG_COMMITMENT..(key.row + 1) * BYTES_PER_KZG_COMMITMENT];
        let valid = util::kzg_verify_batch_multi(
            once(KzgBatchEntry {
                column: cell,
                commitments,
                proofs: proof,
                index: key.column as u64,
            }),
            scratch,
        );
        if !valid {
            return CellValidationOutcome::Rejected;
        }
        if validation.accept().is_err() {
            return CellValidationOutcome::Ignored;
        }
        self.store.mark_changed(&key.block_root, key.column);
        CellValidationOutcome::Accepted
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

    #[cfg(test)]
    pub(super) fn store(&self) -> &CellStore {
        &self.store
    }
}
