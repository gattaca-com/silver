use std::time::{Duration, Instant};

use fxhash::{FxHashMap, FxHashSet};
use silver_common::{
    ForkName, GossipDomain, SLOTS_PER_EPOCH, SubLayout, SubReservationError, SubReservationList,
    TCacheProducer, TCacheRead, TProducer,
    cell_store::{
        AssemblyRequest, AssemblySet, CellKey, CellStoreConfig, ColumnRef, CommitmentContext,
        PendingCell, RetentionEvent, StoreError,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        DATA_COLUMN_SIDECAR_GLOAS_MIN, DATA_COLUMN_SIDECAR_MIN,
        partial_column::PARTIAL_HEADER_FIXED,
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
    first_header: Option<TCacheRead>,
    provisional: bool,
    conflicted: bool,
}

impl CellAllocator {
    pub fn publish_head(&self) {
        self.producer.publish_head();
    }

    pub fn new(
        config: CellStoreConfig,
        producer: TProducer,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        if producer.cache_ref().capacity() < config.cache_capacity() {
            return Err(StoreError::CacheTooSmall);
        }
        // Cells are addressed and re-emitted for as long as their slot is
        // retained, so the retention boundary is this producer's floor.
        let mut producer = producer;
        producer.retain_from(producer.next_seq());
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
        if context.slot > self.slot {
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
        if context.slot != self.slot {
            return Err(StoreError::OutsideServingSlot);
        }
        let request = AssemblyRequest { id: 0, context, domain, columns: self.config.columns() };
        self.check_request(request)?;
        if let Some(allocation) = self.allocations.get_mut(&context.block_root) {
            let matches = allocation.set.request.context == context &&
                allocation.set.request.domain == domain &&
                match (allocation.first_header, header) {
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
            if allocation.provisional && allocation.first_header.is_none() {
                allocation.first_header = header;
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
        let set = self.reserve_set(request)?;
        self.allocations.insert(context.block_root, Allocation {
            set,
            first_header: header,
            provisional: true,
            conflicted: false,
        });
        Ok(set)
    }

    pub fn allocate(&mut self, request: AssemblyRequest) -> Result<AssemblySet, StoreError> {
        self.check_request(request)?;
        let context = request.context;
        if let Some(allocation) = self.allocations.get(&context.block_root).copied() {
            let matches = allocation.set.request.context == context &&
                allocation.set.request.domain == request.domain;
            let live = allocation.set.reservations.view(&self.producer).is_ok_and(|entries| {
                allocation.set.header.into_iter().chain(entries).all(|reference| {
                    self.producer
                        .view_sub_reservation(reference)
                        .is_ok_and(|view| !view.is_closed())
                })
            });
            if matches && live {
                let set = AssemblySet { request, ..allocation.set };
                self.allocations.insert(context.block_root, Allocation {
                    set,
                    first_header: None,
                    provisional: false,
                    conflicted: false,
                });
                return Ok(set);
            }
            if !matches && !allocation.provisional {
                return Err(StoreError::ConflictingContext);
            }
            self.close_set(allocation.set);
            self.allocations.remove(&context.block_root);
        }
        if self.allocations.values().filter(|a| !a.provisional).count() >= self.config.live_blocks()
        {
            return Err(StoreError::Full);
        }
        let set = self.reserve_set(request)?;
        self.allocations.insert(context.block_root, Allocation {
            set,
            first_header: None,
            provisional: false,
            conflicted: false,
        });
        Ok(set)
    }

    fn reserve_set(&mut self, request: AssemblyRequest) -> Result<AssemblySet, StoreError> {
        let context = request.context;
        let mut references = [None; 128];
        let mut header = None;
        let result = (|| {
            if context.format == ForkName::Fulu {
                header = Some(self.producer.sub_reservation(
                    SubLayout {
                        parts: 1,
                        first_len: PARTIAL_HEADER_FIXED +
                            context.blob_count * BYTES_PER_KZG_COMMITMENT,
                        second_len: 0,
                    },
                    b"",
                    b"",
                )?);
            }
            let (prefix_len, middle_len) = if context.format == ForkName::Fulu {
                (DATA_COLUMN_SIDECAR_MIN, context.blob_count * BYTES_PER_KZG_COMMITMENT)
            } else {
                (DATA_COLUMN_SIDECAR_GLOAS_MIN, 0)
            };
            for reference in &mut references[..self.config.column_indices().len()] {
                *reference = Some(self.producer.uninitialized_sub_reservation(
                    SubLayout {
                        parts: context.blob_count,
                        first_len: BYTES_PER_CELL,
                        second_len: BYTES_PER_KZG_PROOF,
                    },
                    prefix_len,
                    middle_len,
                )?);
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
                for reference in header.into_iter().chain(references.into_iter().flatten()) {
                    if let Ok(view) = self.producer.view_sub_reservation(reference) {
                        view.close();
                    }
                }
                Err(error)
            }
        }
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
        self.producer.retain_from(retain_from);
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
        if let Some(header) = set.header &&
            let Ok(view) = self.producer.view_sub_reservation(header)
        {
            view.close();
        }
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
