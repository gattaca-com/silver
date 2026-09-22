use std::{
    io::Write,
    time::{Duration, Instant},
};

use fxhash::{FxHashMap, FxHashSet};
use silver_common::{
    ForkName, GossipDomain, SLOTS_PER_EPOCH, SubLayout, SubReservationError, SubReservationList,
    SubReservationRef, TCacheProducer, TCacheRead, TProducer,
    cell_store::{
        AssemblyRequest, AssemblySet, CellKey, CellStoreConfig, ColumnRef, CommitmentContext,
        ContextData, FuluContextSource, MAX_CONTEXT_BYTES, PendingCell, RetentionEvent, StoreError,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        DATA_COLUMN_SIDECAR_GLOAS_MIN, DATA_COLUMN_SIDECAR_MIN,
    },
};

pub struct CellAllocator {
    producer: TProducer,
    config: CellStoreConfig,
    allocations: FxHashMap<[u8; 32], Allocation>,
    provisional_peers: FxHashSet<usize>,
    provisional_count: usize,
    slot: u64,
    slot_end: Instant,
    now: Instant,
    min_slot: u64,
}

#[derive(Clone, Copy)]
struct Allocation {
    set: AssemblySet,
    provisional: bool,
    conflicted: bool,
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
                2 * config.live_blocks(),
                Default::default(),
            ),
            provisional_peers: FxHashSet::with_capacity_and_hasher(
                config.live_blocks(),
                Default::default(),
            ),
            provisional_count: 0,
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

    pub fn slot_window(&self) -> (u64, Instant) {
        (self.slot, self.slot_end)
    }

    pub(super) fn handles_column(&self, column: usize) -> bool {
        self.config.column_position(column).is_some()
    }

    pub(super) fn max_blobs_at(&self, slot: u64) -> usize {
        self.config.max_blobs().min(
            self.config.spec().blob_params_at(slot / SLOTS_PER_EPOCH).max_blobs_per_block as usize,
        )
    }

    pub(super) fn trusted_context(&self, root: &[u8; 32]) -> Option<CommitmentContext> {
        self.allocations
            .get(root)
            .filter(|allocation| !allocation.provisional)
            .map(|allocation| allocation.set.request.context)
    }

    fn check_request(&self, request: AssemblyRequest) -> Result<(), StoreError> {
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
        Ok(())
    }

    pub fn optimistic(
        &mut self,
        context: CommitmentContext,
        domain: GossipDomain,
        header: Option<TCacheRead>,
        peer: usize,
    ) -> Result<AssemblySet, StoreError> {
        let request = AssemblyRequest {
            id: 0,
            context,
            domain,
            columns: self.config.columns(),
            source: header.map(FuluContextSource::Header),
        };
        self.check_request(request)?;
        if let Some(allocation) = self.allocations.get_mut(&context.block_root) {
            let matches = allocation.set.request.context == context &&
                allocation.set.request.domain == domain &&
                match (allocation.set.header, header) {
                    (Some(first), Some(next)) => self
                        .producer
                        .read_buffer(first)
                        .ok()
                        .zip(self.producer.read_buffer(next).ok())
                        .is_some_and(|(a, b)| a == b),
                    _ => true,
                };
            if allocation.conflicted || !matches {
                allocation.conflicted |= allocation.provisional;
                return Err(StoreError::ConflictingContext);
            }
            if allocation.provisional && allocation.set.header.is_none() {
                allocation.set.header = header;
                allocation.set.request.source = request.source;
            }
            return Ok(allocation.set);
        }
        if self.provisional_count >= self.config.live_blocks() ||
            self.provisional_peers.contains(&peer)
        {
            return Err(StoreError::Full);
        }
        // Failed and replaced speculative reservations still occupy this slot's ring.
        self.provisional_count += 1;
        self.provisional_peers.insert(peer);
        let set = self.reserve_set(request, None, header)?;
        self.allocations.insert(context.block_root, Allocation {
            set,
            provisional: true,
            conflicted: false,
        });
        Ok(set)
    }

    pub fn allocate(
        &mut self,
        request: AssemblyRequest,
        external: Option<ContextData<'_>>,
    ) -> Result<AssemblySet, StoreError> {
        self.check_request(request)?;
        let context = request.context;
        if let Some(allocation) = self.allocations.get(&context.block_root) &&
            !allocation.provisional
        {
            return if allocation.set.request.id == request.id &&
                allocation.set.request.context == context &&
                allocation.set.request.domain == request.domain
            {
                Ok(allocation.set)
            } else {
                Err(StoreError::ConflictingContext)
            };
        }
        if self.allocations.values().filter(|a| !a.provisional).count() >= self.config.live_blocks()
        {
            return Err(StoreError::Full);
        }

        let mut scratch = [0; MAX_CONTEXT_BYTES];
        let data = match context.format {
            ForkName::Fulu => {
                let source = request.source.ok_or(StoreError::InvalidContext)?;
                let data = match source {
                    FuluContextSource::ElHeader(_) => external.ok_or(StoreError::ContextExpired)?,
                    FuluContextSource::Header(read) => {
                        let bytes = self
                            .producer
                            .read_buffer(read)
                            .map_err(|_| StoreError::ContextExpired)?;
                        ContextData::from_encoded(bytes, ForkName::Fulu)
                            .ok_or(StoreError::InvalidContext)?
                    }
                    FuluContextSource::Sidecar(read) => {
                        let bytes = self
                            .producer
                            .read_buffer(read)
                            .map_err(|_| StoreError::ContextExpired)?;
                        ContextData::from_fulu_sidecar(bytes).ok_or(StoreError::InvalidContext)?
                    }
                };
                if !data.valid_for(context) {
                    return Err(StoreError::InvalidContext);
                }
                let len = data.encoded_len();
                data.write(&mut scratch[..len]);
                ContextData::from_encoded(&scratch[..len], ForkName::Fulu)
                    .ok_or(StoreError::InvalidContext)?
            }
            ForkName::Gloas => ContextData::Gloas { commitments: &[] },
            _ => return Err(StoreError::InvalidContext),
        };
        if let Some(allocation) = self.allocations.get(&context.block_root).copied() {
            let set = allocation.set;
            let matches = set.request.context == context &&
                set.request.domain == request.domain &&
                set.header.is_none_or(|header| {
                    self.producer.read_buffer(header).is_ok_and(|bytes| data.matches(bytes))
                });
            if matches {
                let header = if context.format == ForkName::Fulu {
                    match set.header {
                        Some(header) => Some(header),
                        None => Some(self.write_header(data)?),
                    }
                } else {
                    None
                };
                if context.format == ForkName::Fulu {
                    if let Err(error) = self.initialize_set(set, data) {
                        self.close_set(set);
                        self.allocations.remove(&context.block_root);
                        return Err(error);
                    }
                }
                let set = AssemblySet { request, header, ..set };
                self.allocations.insert(context.block_root, Allocation {
                    set,
                    provisional: false,
                    conflicted: false,
                });
                return Ok(set);
            }
            self.close_set(set);
            self.allocations.remove(&context.block_root);
        }
        let header =
            if context.format == ForkName::Fulu { Some(self.write_header(data)?) } else { None };
        let set = self.reserve_set(request, Some(data), header)?;
        self.allocations.insert(context.block_root, Allocation {
            set,
            provisional: false,
            conflicted: false,
        });
        Ok(set)
    }

    fn initialize_set(&self, set: AssemblySet, data: ContextData<'_>) -> Result<(), StoreError> {
        for (position, reference) in set.reservations.view(&self.producer)?.enumerate() {
            let column = self.config.column_indices()[position];
            let (prefix, length) = Self::column_prefix(data, set.request.context, column);
            self.producer
                .view_sub_reservation(reference)?
                .initialize(&prefix[..length], data.commitments())?;
        }
        Ok(())
    }

    fn write_header(&mut self, data: ContextData<'_>) -> Result<TCacheRead, StoreError> {
        let mut write =
            self.producer.reserve(data.encoded_len(), false).ok_or(StoreError::CacheFull)?;
        data.write(write.buffer().map_err(|_| StoreError::ContextExpired)?);
        write.flush().map_err(|_| StoreError::ContextExpired)?;
        Ok(write.read())
    }

    fn reserve_set(
        &mut self,
        request: AssemblyRequest,
        data: Option<ContextData<'_>>,
        header: Option<TCacheRead>,
    ) -> Result<AssemblySet, StoreError> {
        let context = request.context;
        let mut references = [None; 128];
        let result = (|| {
            for (position, reference) in
                references[..self.config.column_indices().len()].iter_mut().enumerate()
            {
                let column = self.config.column_indices()[position];
                *reference = Some(if context.format == ForkName::Fulu && data.is_none() {
                    self.producer.uninitialized_sub_reservation(
                        SubLayout {
                            parts: context.blob_count,
                            first_len: BYTES_PER_CELL,
                            second_len: BYTES_PER_KZG_PROOF,
                        },
                        DATA_COLUMN_SIDECAR_MIN,
                        context.blob_count * BYTES_PER_KZG_COMMITMENT,
                    )?
                } else {
                    self.reserve_column(
                        data.unwrap_or(ContextData::Gloas { commitments: &[] }),
                        context,
                        column,
                    )?
                });
            }
            let reservations = SubReservationList::write(
                &mut self.producer,
                references[..self.config.column_indices().len()].iter().copied(),
            )?;
            Ok(AssemblySet { request, reservations, header, expires: self.slot_end })
        })();
        match result {
            Ok(set) => Ok(set),
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
        let (prefix, length) = Self::column_prefix(data, context, column);
        let middle = if context.format == ForkName::Fulu { data.commitments() } else { &[] };
        self.producer.sub_reservation(layout, &prefix[..length], middle)
    }

    fn column_prefix(
        data: ContextData<'_>,
        context: CommitmentContext,
        column: usize,
    ) -> ([u8; DATA_COLUMN_SIDECAR_MIN], usize) {
        let mut prefix = [0; DATA_COLUMN_SIDECAR_MIN];
        prefix[..8].copy_from_slice(&(column as u64).to_le_bytes());
        let length = match data {
            ContextData::Fulu { signed_header, inclusion_proof, commitments } => {
                let cells_end = DATA_COLUMN_SIDECAR_MIN + context.blob_count * BYTES_PER_CELL;
                prefix[8..12].copy_from_slice(&(DATA_COLUMN_SIDECAR_MIN as u32).to_le_bytes());
                prefix[12..16].copy_from_slice(&(cells_end as u32).to_le_bytes());
                prefix[16..20]
                    .copy_from_slice(&((cells_end + commitments.len()) as u32).to_le_bytes());
                prefix[20..228].copy_from_slice(signed_header);
                prefix[228..356].copy_from_slice(inclusion_proof);
                DATA_COLUMN_SIDECAR_MIN
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
                DATA_COLUMN_SIDECAR_GLOAS_MIN
            }
        };
        (prefix, length)
    }

    pub fn column(&self, key: CellKey) -> Option<ColumnRef> {
        let allocation = self.allocations.get(&key.block_root)?;
        if allocation.conflicted {
            return None;
        }
        let set = &allocation.set;
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
        self.provisional_count = 0;
        self.provisional_peers.clear();
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
        for allocation in self.allocations.values() {
            self.close_set(allocation.set);
        }
    }

    pub fn reject(&mut self, root: &[u8; 32]) {
        if let Some(allocation) = self.allocations.remove(root) {
            self.close_set(allocation.set);
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
