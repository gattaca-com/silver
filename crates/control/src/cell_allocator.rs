use std::{
    io::Write,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;
use silver_common::{
    ForkName, SLOTS_PER_EPOCH, SubLayout, SubReservationError, SubReservationList,
    SubReservationRef, TCacheProducer, TProducer,
    cell_store::{
        AssemblyRequest, AssemblySet, CellKey, CellStoreConfig, ColumnRef, CommitmentContext,
        ContextData, FuluContextSource, MAX_CONTEXT_BYTES, PendingCell, RetentionEvent, StoreError,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_PROOF, DATA_COLUMN_SIDECAR_GLOAS_MIN,
        DATA_COLUMN_SIDECAR_MIN, DataColumnSidecarFuluView,
    },
};

pub struct CellAllocator {
    producer: TProducer,
    config: CellStoreConfig,
    allocations: FxHashMap<[u8; 32], AssemblySet>,
    slot: u64,
    slot_end: Instant,
    now: Instant,
    min_slot: u64,
}

impl CellAllocator {
    pub fn new(
        config: CellStoreConfig,
        producer: TProducer,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        if producer.cache_ref().capacity() < config.cache_capacity() {
            return Err(StoreError::CacheTooSmall);
        }
        Ok(Self {
            allocations: FxHashMap::with_capacity_and_hasher(
                config.live_blocks(),
                Default::default(),
            ),
            slot,
            slot_end: slot_start + config.slot_duration(),
            now: slot_start,
            min_slot: 0,
            producer,
            config,
        })
    }

    pub fn producer_mut(&mut self) -> &mut TProducer {
        &mut self.producer
    }
    pub fn producer(&self) -> &TProducer {
        &self.producer
    }

    pub fn allocate(&mut self, request: AssemblyRequest) -> Result<AssemblySet, StoreError> {
        let context = request.context;
        if context.slot < self.min_slot {
            return Err(StoreError::BelowSlotFloor);
        }
        if context.slot != self.slot {
            return Err(StoreError::OutsideServingSlot);
        }
        if request.columns != self.config.columns() ||
            request.domain.format() != context.format ||
            !matches!(context.format, ForkName::Fulu | ForkName::Gloas) ||
            self.config.spec().fork_at_slot(context.slot) != context.format ||
            context.blob_count > self.config.max_blobs() ||
            context.blob_count >
                self.config
                    .spec()
                    .blob_params_at(context.slot / SLOTS_PER_EPOCH)
                    .max_blobs_per_block as usize
        {
            return Err(StoreError::InvalidContext);
        }
        if let Some(set) = self.allocations.get(&context.block_root) {
            return if set.request.id == request.id &&
                set.request.context == context &&
                set.request.domain == request.domain
            {
                Ok(*set)
            } else {
                Err(StoreError::ConflictingContext)
            };
        }
        if self.allocations.len() >= self.config.live_blocks() {
            return Err(StoreError::Full);
        }

        let mut scratch = [0; MAX_CONTEXT_BYTES];
        let data = match context.format {
            ForkName::Fulu => {
                let source = request.source.ok_or(StoreError::InvalidContext)?;
                let bytes = self
                    .producer
                    .read_buffer(source.read())
                    .map_err(|_| StoreError::ContextExpired)?;
                let data = match source {
                    FuluContextSource::Header(_) => {
                        ContextData::from_encoded(bytes, ForkName::Fulu)
                            .ok_or(StoreError::InvalidContext)?
                    }
                    FuluContextSource::Sidecar(_) => {
                        if !DataColumnSidecarFuluView::check_size(bytes) {
                            return Err(StoreError::InvalidContext);
                        }
                        ContextData::Fulu {
                            signed_header: bytes[20..228].try_into().unwrap(),
                            inclusion_proof: bytes[228..356].try_into().unwrap(),
                            commitments: DataColumnSidecarFuluView::kzg_commitments(bytes),
                        }
                    }
                };
                if !data.valid_for(context) {
                    return Err(StoreError::InvalidContext);
                }
                let len = data.encoded_len();
                data.write(&mut scratch[..len]);
                ContextData::from_encoded(&scratch[..len], ForkName::Fulu).unwrap()
            }
            ForkName::Gloas => ContextData::Gloas { commitments: &[] },
            _ => unreachable!(),
        };
        let mut references = [None; 128];
        let result = (|| {
            let header = if context.format == ForkName::Fulu {
                let mut write = self
                    .producer
                    .reserve(data.encoded_len(), false)
                    .ok_or(StoreError::CacheFull)?;
                data.write(write.buffer().map_err(|_| StoreError::ContextExpired)?);
                write.flush().map_err(|_| StoreError::ContextExpired)?;
                Some(write.read())
            } else {
                None
            };
            for (position, reference) in
                references[..self.config.column_indices().len()].iter_mut().enumerate()
            {
                let column = self.config.column_indices()[position];
                *reference = Some(self.reserve_column(data, context, column)?);
            }
            let reservations = SubReservationList::write(
                &mut self.producer,
                references[..self.config.column_indices().len()].iter().map(|entry| entry.unwrap()),
            )?;
            Ok(AssemblySet { request, reservations, header, expires: self.slot_end })
        })();
        match result {
            Ok(set) => {
                self.allocations.insert(context.block_root, set);
                Ok(set)
            }
            Err(error) => {
                for reference in references.into_iter().flatten() {
                    if let Ok(view) = self.producer.view_sub_reservation(reference) {
                        view.close();
                    }
                }
                Err(error)
            }
        }
    }

    fn reserve_column(
        &mut self,
        data: ContextData<'_>,
        context: CommitmentContext,
        column: usize,
    ) -> Result<SubReservationRef, SubReservationError> {
        let layout = SubLayout {
            parts: context.blob_count,
            first_len: BYTES_PER_CELL,
            second_len: BYTES_PER_KZG_PROOF,
        };
        let mut prefix = [0; DATA_COLUMN_SIDECAR_MIN];
        prefix[..8].copy_from_slice(&(column as u64).to_le_bytes());
        let (length, middle) = match data {
            ContextData::Fulu { signed_header, inclusion_proof, commitments } => {
                let cells_end = DATA_COLUMN_SIDECAR_MIN + context.blob_count * BYTES_PER_CELL;
                prefix[8..12].copy_from_slice(&(DATA_COLUMN_SIDECAR_MIN as u32).to_le_bytes());
                prefix[12..16].copy_from_slice(&(cells_end as u32).to_le_bytes());
                prefix[16..20]
                    .copy_from_slice(&((cells_end + commitments.len()) as u32).to_le_bytes());
                prefix[20..228].copy_from_slice(signed_header);
                prefix[228..356].copy_from_slice(inclusion_proof);
                (DATA_COLUMN_SIDECAR_MIN, commitments)
            }
            ContextData::Gloas { .. } => {
                prefix[8..12]
                    .copy_from_slice(&(DATA_COLUMN_SIDECAR_GLOAS_MIN as u32).to_le_bytes());
                prefix[12..16].copy_from_slice(
                    &((DATA_COLUMN_SIDECAR_GLOAS_MIN + context.blob_count * BYTES_PER_CELL) as u32)
                        .to_le_bytes(),
                );
                prefix[16..24].copy_from_slice(&context.slot.to_le_bytes());
                prefix[24..56].copy_from_slice(&context.block_root);
                (DATA_COLUMN_SIDECAR_GLOAS_MIN, &[][..])
            }
        };
        self.producer.sub_reservation(layout, &prefix[..length], middle)
    }

    pub fn column(&self, key: CellKey) -> Option<ColumnRef> {
        let set = self.allocations.get(&key.block_root)?;
        if key.row >= set.request.context.blob_count || set.request.context.slot < self.min_slot {
            return None;
        }
        let position = self.config.column_position(key.column)?;
        let reservation = set.reservations.view(&self.producer).ok()?.nth(position)?;
        Some(ColumnRef {
            block_root: key.block_root,
            column: key.column,
            reservation,
            slot: set.request.context.slot,
            expires: set.expires,
        })
    }

    pub fn stage(
        &self,
        key: CellKey,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<Option<PendingCell>, StoreError> {
        let column = self.column(key).ok_or(StoreError::UnknownCell)?;
        let view = self.producer.view_sub_reservation(column.reservation)?;
        let claim = match view.claim(key.row) {
            Ok(claim) => claim,
            Err(SubReservationError::Claimed | SubReservationError::Published) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(PendingCell { key, data: claim.write(cell, proof)? }))
    }

    pub fn cancel(&self, pending: PendingCell) -> Result<bool, StoreError> {
        let column = self.column(pending.key).ok_or(StoreError::UnknownCell)?;
        if pending.key.row != pending.data.part() ||
            pending.data.reservation().read().seq() != column.reservation.read().seq()
        {
            return Err(StoreError::UnknownCell);
        }
        self.producer
            .view_sub_reservation(column.reservation)?
            .cancel(pending.data)
            .map_err(Into::into)
    }

    pub fn advance(&mut self, now: Instant, min_slot: u64) -> Option<RetentionEvent> {
        assert!(now >= self.now, "cell allocator clock moved backwards");
        self.now = now;
        self.min_slot = self.min_slot.max(min_slot);
        if now < self.slot_end {
            return None;
        }
        let retain_from = self.producer.next_seq();
        let expired_slot = self.slot;
        self.close();
        self.allocations.clear();
        let elapsed = now.duration_since(self.slot_end).as_nanos();
        let duration = self.config.slot_duration().as_nanos();
        self.slot = self
            .slot
            .checked_add(
                u64::try_from(elapsed / duration + 1).expect("cell allocator slot overflow"),
            )
            .expect("cell allocator slot overflow");
        let remainder = elapsed % duration;
        self.slot_end = now + self.config.slot_duration() -
            Duration::new((remainder / 1_000_000_000) as u64, (remainder % 1_000_000_000) as u32);
        (retain_from != 0).then_some(RetentionEvent { expired_slot, retain_from })
    }

    fn close(&self) {
        for set in self.allocations.values() {
            self.close_set(*set);
        }
    }

    pub fn reject(&mut self, root: &[u8; 32]) {
        if let Some(set) = self.allocations.remove(root) {
            self.close_set(set);
        }
    }

    fn close_set(&self, set: AssemblySet) {
        if let Ok(references) = set.reservations.view(&self.producer) {
            for reference in references {
                if let Ok(view) = self.producer.view_sub_reservation(reference) {
                    view.close();
                }
            }
        }
    }
}

impl Drop for CellAllocator {
    fn drop(&mut self) {
        self.close();
    }
}
