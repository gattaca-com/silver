use std::{
    ptr,
    time::{Duration, Instant},
};

pub use config::CellStoreConfig;
pub use context::{CommitmentContext, ContextData};
use fxhash::FxHashMap;
use silver_beacon_state_data::{ForkName, SLOTS_PER_EPOCH};
use silver_common::{
    AcquiredRange, PendingSubReservation, SubReservation, SubReservationError, SubReservationRef,
    SubValidation, TCacheProducer, TCacheRead, TProducer, TRandomAccess, TRead,
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_PROOF},
};
use slab::Slab;

use crate::{BlockRoot, DataColumnCounters};

mod config;
mod context;

#[cfg(test)]
mod tests;

pub const CELL_RECORD_BYTES: usize = BYTES_PER_CELL + BYTES_PER_KZG_PROOF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    InvalidConfig,
    UnsupportedBlobCount(u64),
    CapacityOverflow,
    CacheTooSmall,
    ConsumerUnavailable,
    InvalidContext,
    ConflictingContext,
    ContextExpired,
    OutsideServingSlot,
    BelowSlotFloor,
    UnknownCell,
    Full,
    CacheFull,
}

impl From<SubReservationError> for StoreError {
    fn from(error: SubReservationError) -> Self {
        match error {
            SubReservationError::CacheFull => {
                DataColumnCounters::CellStoreCacheFull.inc();
                Self::CacheFull
            }
            SubReservationError::Closed | SubReservationError::Stale => Self::ContextExpired,
            SubReservationError::WrongConsumer => Self::ConsumerUnavailable,
            _ => Self::InvalidContext,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CellKey {
    pub block_root: BlockRoot,
    pub column: usize,
    pub row: usize,
}

#[derive(Clone, Copy, Debug)]
enum CellSource {
    Full { read: TCacheRead, cell: usize, proof: usize },
    Assembly { reservation: SubReservationRef, row: usize },
}

#[derive(Clone, Copy, Debug)]
pub struct CellRef {
    source: CellSource,
    pub generation: u64,
    pub expires: Instant,
}

impl CellRef {
    pub fn read(self) -> TCacheRead {
        match self.source {
            CellSource::Full { read, .. } => read,
            CellSource::Assembly { reservation, .. } => reservation.read(),
        }
    }

    pub fn acquire(self, consumer: &mut TRandomAccess) -> Option<AcquiredCell> {
        let [cell, proof] = match self.source {
            CellSource::Assembly { reservation, row } => {
                reservation.acquire(consumer).ok()?.ranges(row)?
            }
            CellSource::Full { read, cell, proof } => {
                if !consumer.is_strict() || !ptr::eq(&*consumer.cache_ref(), &*read.cache_ref()) {
                    return None;
                }
                let pin = consumer.acquire_strict(read)?;
                [pin.with_range(cell, BYTES_PER_CELL)?, pin.with_range(proof, BYTES_PER_KZG_PROOF)?]
            }
        };
        Some(AcquiredCell { cell, proof })
    }
}

pub struct AcquiredCell {
    pub cell: AcquiredRange,
    pub proof: AcquiredRange,
}

#[derive(Clone, Copy, Debug)]
pub struct ColumnRef {
    pub block_root: BlockRoot,
    pub column: usize,
    pub reservation: SubReservationRef,
    pub generation: u64,
    pub expires: Instant,
}

impl ColumnRef {
    pub fn stage(
        self,
        consumer: &mut TRandomAccess,
        row: usize,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<Option<PendingCell>, StoreError> {
        let acquired = self.reservation.acquire(consumer)?;
        let claim = match acquired.claim(row) {
            Ok(claim) => claim,
            Err(SubReservationError::Claimed | SubReservationError::Published) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(PendingCell {
            key: CellKey { block_root: self.block_root, column: self.column, row },
            data: claim.write(cell, proof)?,
        }))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PendingCell {
    pub key: CellKey,
    pub data: PendingSubReservation,
}

#[derive(Clone, Copy, Debug)]
pub struct GenerationRef {
    pub id: u64,
    pub first: TCacheRead,
    pub expires: Instant,
}

struct Generation {
    reference: GenerationRef,
    _pin: TRead,
}

#[derive(Clone, Copy, Debug)]
pub enum CellAdmission {
    Inserted { cell: CellRef, column_completed: bool },
    Duplicate,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CellMask(u128);

impl CellMask {
    #[inline]
    pub fn bits(self) -> u128 {
        self.0
    }

    #[inline]
    pub fn contains(self, row: usize) -> bool {
        row < u128::BITS as usize && self.0 & (1u128 << row) != 0
    }

    #[inline]
    fn all(rows: usize) -> Self {
        Self(u128::MAX.checked_shr(u128::BITS - rows as u32).unwrap_or(0))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ColumnStatus {
    pub admitted: CellMask,
    pub available: CellMask,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct ColumnUpdate {
    pub new_cells: CellMask,
    pub column_completed: bool,
    pub complete_read: Option<TCacheRead>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreCounts {
    pub cells: usize,
    // Reserved assembly payload bytes include missing cells.
    pub bytes: usize,
    pub full_bytes: usize,
    pub contexts: usize,
    pub generations: usize,
    pub blocks: usize,
}

struct Block {
    context: CommitmentContext,
    pin: Option<TRead>,
}

struct FullColumn {
    pin: TRead,
    cell_offset: usize,
    proof_offset: usize,
}

#[derive(Default)]
struct Column {
    assembly: Option<SubReservation>,
    full: Option<FullColumn>,
    admitted: CellMask,
    complete: bool,
}

impl Column {
    fn available(&self, rows: usize) -> CellMask {
        if self.full.is_some() {
            CellMask::all(rows)
        } else {
            CellMask(self.assembly.as_ref().map_or(0, |reservation| reservation.acquired().ready()))
        }
    }
}

/// Context admission assumes prior validation. Ingress stages cells before
/// verification. Call `advance` before each batch; retained references require
/// their tile's consumer to outlive them.
pub struct CellStore {
    blocks: Slab<Block>,
    columns: Box<[Column]>,
    generation: Option<Generation>,
    // Pins above and acquired reads held by callers must drop before this consumer.
    consumer: Box<TRandomAccess>,
    producer: TProducer,
    config: CellStoreConfig,
    roots: FxHashMap<BlockRoot, usize>,
    context_count: usize,
    now: Instant,
    slot: u64,
    slot_end: Instant,
    min_slot: u64,
    dirty: bool,
}

impl CellStore {
    pub fn new(
        config: CellStoreConfig,
        producer: TProducer,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        if producer.cache_ref().capacity() < config.cache_capacity() {
            return Err(StoreError::CacheTooSmall);
        }
        let consumer = producer
            .cache_ref()
            .strict_random_access("retained_columns", true)
            .map_err(|_| StoreError::ConsumerUnavailable)?;
        let column_entries = config.block_capacity * config.column_indices.len();
        let store = Self {
            blocks: Slab::with_capacity(config.block_capacity),
            columns: std::iter::repeat_with(Column::default).take(column_entries).collect(),
            generation: None,
            consumer: Box::new(consumer),
            producer,
            roots: FxHashMap::with_capacity_and_hasher(
                config.block_capacity * 2,
                Default::default(),
            ),
            context_count: 0,
            now: slot_start,
            slot,
            slot_end: slot_start + config.slot_duration,
            min_slot: 0,
            dirty: false,
            config,
        };
        store.publish_gauges();
        Ok(store)
    }

    pub fn admit_context(
        &mut self,
        context: CommitmentContext,
        data: ContextData<'_>,
    ) -> Result<bool, StoreError> {
        if context.slot < self.min_slot {
            return Err(StoreError::BelowSlotFloor);
        }
        if context.slot != self.slot {
            return Err(StoreError::OutsideServingSlot);
        }
        if !matches!(context.format, ForkName::Fulu | ForkName::Gloas) ||
            self.config.spec.fork_at_slot(context.slot) != context.format ||
            context.blob_count > self.config.max_blobs ||
            context.blob_count >
                self.config.spec.blob_params_at(context.slot / SLOTS_PER_EPOCH).max_blobs_per_block
                    as usize ||
            !data.valid_for(context)
        {
            return Err(StoreError::InvalidContext);
        }
        if let Some(&index) = self.roots.get(&context.block_root) {
            let block = &self.blocks[index];
            if block.context != context {
                return Err(StoreError::ConflictingContext);
            }
            let pin = block.pin.as_ref().ok_or(StoreError::ContextExpired)?;
            if !data.matches(pin.buffer().expect("pinned context").0) {
                return Err(StoreError::ConflictingContext);
            }
            return Ok(false);
        }
        if self.blocks.len() >= self.config.block_capacity ||
            self.context_count >= self.config.live_blocks
        {
            DataColumnCounters::CellStoreFull.inc();
            return Err(StoreError::Full);
        }
        let Some(mut reservation) = self.producer.reserve(data.encoded_len(), true) else {
            DataColumnCounters::CellStoreCacheFull.inc();
            return Err(StoreError::CacheFull);
        };
        data.write(reservation.buffer().expect("new context reservation"));
        reservation.increment_offset(data.encoded_len());
        let pin = self.consumer.acquire_strict(reservation.read()).expect("new context pin");
        let index = self.blocks.vacant_key();
        let start = index * self.config.column_indices.len();
        for (position, &column) in self.config.column_indices.iter().enumerate() {
            match data
                .reserve_column(context, column, &mut self.producer)
                .and_then(|reference| reference.acquire(&mut self.consumer))
            {
                Ok(acquired) => {
                    let reservation = SubReservation::new(acquired);
                    let complete = context.blob_count == 0;
                    if complete {
                        reservation.finish().expect("empty column");
                    }
                    self.columns[start + position] =
                        Column { assembly: Some(reservation), complete, ..Column::default() };
                }
                Err(error) => {
                    for column in &mut self.columns[start..start + self.config.column_indices.len()]
                    {
                        *column = Column::default();
                    }
                    return Err(error.into());
                }
            }
        }
        if self.generation.is_none() {
            self.generation = Some(Generation {
                reference: GenerationRef { id: self.slot, first: pin.read, expires: self.slot_end },
                _pin: pin.clone(),
            });
        }
        assert_eq!(self.blocks.insert(Block { context, pin: Some(pin) }), index);
        self.roots.insert(context.block_root, index);
        self.context_count += 1;
        self.dirty = true;
        Ok(true)
    }

    pub fn stage_cell(
        &mut self,
        key: CellKey,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<Option<PendingCell>, StoreError> {
        let (block, index) = self.index(key).ok_or(StoreError::UnknownCell)?;
        let column = &self.columns[index];
        if (column.admitted.0 | column.available(self.blocks[block].context.blob_count).0) &
            (1u128 << key.row) !=
            0
        {
            DataColumnCounters::CellStoreDuplicates.inc();
            return Ok(None);
        }
        if self.blocks[block].context.slot < self.min_slot {
            return Err(StoreError::BelowSlotFloor);
        }
        let reference = self.column_ref(block, key.column).ok_or(StoreError::ContextExpired)?;
        reference.stage(&mut self.consumer, key.row, cell, proof)
    }

    pub fn begin_validation(&mut self, pending: PendingCell) -> Result<SubValidation, StoreError> {
        let (block, _) = self.index(pending.key).ok_or(StoreError::UnknownCell)?;
        let reference =
            self.column_ref(block, pending.key.column).ok_or(StoreError::ContextExpired)?;
        let read = pending.data.reservation().read();
        if pending.key.row != pending.data.part() ||
            read.seq() != reference.reservation.read().seq() ||
            !ptr::eq(&*read.cache_ref(), &*reference.reservation.read().cache_ref())
        {
            return Err(StoreError::UnknownCell);
        }
        pending.data.acquire(&mut self.consumer).map_err(Into::into)
    }

    /// Already verified input only. Network ingress uses `stage_cell` or the
    /// broadcast `ColumnRef`.
    pub fn admit_cell(
        &mut self,
        key: CellKey,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<CellAdmission, StoreError> {
        let Some(pending) = self.stage_cell(key, cell, proof)? else {
            return Ok(CellAdmission::Duplicate);
        };
        self.begin_validation(pending)?.accept()?;
        let update = self.refresh_column(&key.block_root, key.column)?;
        Ok(CellAdmission::Inserted {
            cell: self.cell(key).expect("published cell"),
            column_completed: update.column_completed,
        })
    }

    pub fn refresh_column(
        &mut self,
        root: &BlockRoot,
        column: usize,
    ) -> Result<ColumnUpdate, StoreError> {
        let block = *self.roots.get(root).ok_or(StoreError::UnknownCell)?;
        let position = self.config.column_position(column).ok_or(StoreError::UnknownCell)?;
        let entry = &mut self.columns[block * self.config.column_indices.len() + position];
        if entry.assembly.is_none() {
            return Err(StoreError::ContextExpired);
        }
        let available = entry.available(self.blocks[block].context.blob_count);
        let new_cells = CellMask(available.0 & !entry.admitted.0);
        let complete_read = match &entry.full {
            Some(full) => Some(full.pin.read),
            None => entry.assembly.as_ref().and_then(|reservation| reservation.finish().ok()),
        };
        let column_completed = !entry.complete && complete_read.is_some();
        entry.admitted = available;
        entry.complete |= column_completed;
        self.dirty |= new_cells.0 != 0 || column_completed;
        DataColumnCounters::CellStoreAdmissions.add(new_cells.0.count_ones() as u64);
        Ok(ColumnUpdate { new_cells, column_completed, complete_read })
    }

    /// The sidecar must already be verified. Its source consumer must be strict
    /// and outlive this store.
    pub fn retain_full(
        &mut self,
        root: &BlockRoot,
        column: usize,
        pin: TRead,
    ) -> Result<ColumnUpdate, StoreError> {
        let block = *self.roots.get(root).ok_or(StoreError::UnknownCell)?;
        let position = self.config.column_position(column).ok_or(StoreError::UnknownCell)?;
        let context = &self.blocks[block];
        let context_bytes = context
            .pin
            .as_ref()
            .ok_or(StoreError::ContextExpired)?
            .buffer()
            .map_err(|_| StoreError::ContextExpired)?
            .0;
        if !pin.is_strict() {
            return Err(StoreError::ConsumerUnavailable);
        }
        let bytes = pin.buffer().map_err(|_| StoreError::ContextExpired)?.0;
        let (cell_offset, proof_offset) = context
            .context
            .full_offsets(bytes, context_bytes, column)
            .ok_or(StoreError::InvalidContext)?;
        let entry = &mut self.columns[block * self.config.column_indices.len() + position];
        if entry.full.is_none() {
            entry.full = Some(FullColumn { pin, cell_offset, proof_offset });
            self.dirty = true;
        }
        self.refresh_column(root, column)
    }

    #[inline]
    pub fn cell(&self, key: CellKey) -> Option<CellRef> {
        let (block, index) = self.index(key)?;
        let column = &self.columns[index];
        if !column.available(self.blocks[block].context.blob_count).contains(key.row) {
            return None;
        }
        let source = match &column.full {
            Some(full) => CellSource::Full {
                read: full.pin.read,
                cell: full.cell_offset + key.row * BYTES_PER_CELL,
                proof: full.proof_offset + key.row * BYTES_PER_KZG_PROOF,
            },
            None => CellSource::Assembly {
                reservation: column.assembly.as_ref()?.reference(),
                row: key.row,
            },
        };
        Some(CellRef {
            source,
            generation: self.blocks[block].context.slot,
            expires: self.slot_end,
        })
    }

    pub fn acquire_cell(&mut self, key: CellKey) -> Option<AcquiredCell> {
        let (_, index) = self.index(key)?;
        if let Some(full) = &self.columns[index].full {
            return Some(AcquiredCell {
                cell: full
                    .pin
                    .with_range(full.cell_offset + key.row * BYTES_PER_CELL, BYTES_PER_CELL)?,
                proof: full.pin.with_range(
                    full.proof_offset + key.row * BYTES_PER_KZG_PROOF,
                    BYTES_PER_KZG_PROOF,
                )?,
            });
        }
        self.cell(key)?.acquire(&mut self.consumer)
    }

    fn column_ref(&self, block: usize, column: usize) -> Option<ColumnRef> {
        let position = self.config.column_position(column)?;
        Some(ColumnRef {
            block_root: self.blocks[block].context.block_root,
            column,
            reservation: self.columns[block * self.config.column_indices.len() + position]
                .assembly
                .as_ref()?
                .reference(),
            generation: self.blocks[block].context.slot,
            expires: self.slot_end,
        })
    }

    pub fn reservations(&self, root: &BlockRoot) -> impl Iterator<Item = ColumnRef> + '_ {
        self.roots.get(root).copied().into_iter().flat_map(move |block| {
            self.config
                .column_indices
                .iter()
                .filter_map(move |&column| self.column_ref(block, column))
        })
    }

    pub fn context(&self, root: &BlockRoot) -> Option<(&CommitmentContext, &TRead)> {
        let block = &self.blocks[*self.roots.get(root)?];
        Some((&block.context, block.pin.as_ref()?))
    }

    pub fn column(&self, root: &BlockRoot, column: usize) -> Option<ColumnStatus> {
        let block = *self.roots.get(root)?;
        let position = self.config.column_position(column)?;
        let entry = &self.columns[block * self.config.column_indices.len() + position];
        let available = entry.available(self.blocks[block].context.blob_count);
        Some(ColumnStatus {
            admitted: CellMask(entry.admitted.0 | available.0),
            available,
            complete: entry.complete ||
                (entry.assembly.is_some() &&
                    available == CellMask::all(self.blocks[block].context.blob_count)),
        })
    }

    pub fn generations(&self) -> impl Iterator<Item = GenerationRef> + '_ {
        self.generation.iter().map(|generation| generation.reference)
    }

    pub fn advance(&mut self, now: Instant, min_slot: u64, mut on_expired: impl FnMut(CellKey)) {
        assert!(now >= self.now, "cell store clock moved backwards");
        self.now = now;
        let floor_changed = min_slot > self.min_slot;
        self.min_slot = self.min_slot.max(min_slot);
        let slot_changed = now >= self.slot_end;
        if slot_changed {
            let elapsed = now.duration_since(self.slot_end).as_nanos();
            let slot_nanos = self.config.slot_duration.as_nanos();
            let slots = u64::try_from(elapsed / slot_nanos + 1).expect("cell store slot overflow");
            self.slot = self.slot.checked_add(slots).expect("cell store slot overflow");
            let remainder = elapsed % slot_nanos;
            let remainder = Duration::new(
                (remainder / 1_000_000_000) as u64,
                (remainder % 1_000_000_000) as u32,
            );
            self.slot_end = now + (self.config.slot_duration - remainder);
        }
        if floor_changed || slot_changed {
            self.blocks.retain(|index, block| {
                let start = index * self.config.column_indices.len();
                let columns = &mut self.columns[start..start + self.config.column_indices.len()];
                if block.context.slot < self.slot && block.pin.take().is_some() {
                    for (position, column) in columns.iter_mut().enumerate() {
                        if let Some(assembly) = &column.assembly {
                            assembly.close();
                        }
                        let available = column.available(block.context.blob_count);
                        column.admitted.0 |= available.0;
                        column.complete |= available == CellMask::all(block.context.blob_count);
                        let mut rows = available.0;
                        while rows != 0 {
                            let row = rows.trailing_zeros() as usize;
                            rows &= rows - 1;
                            on_expired(CellKey {
                                block_root: block.context.block_root,
                                column: self.config.column_indices[position],
                                row,
                            });
                        }
                        DataColumnCounters::CellStoreExpired.add(available.0.count_ones() as u64);
                        column.assembly = None;
                        column.full = None;
                    }
                    self.context_count -= 1;
                    self.dirty = true;
                }
                if block.context.slot < self.min_slot && block.pin.is_none() {
                    self.roots.remove(&block.context.block_root);
                    for column in columns {
                        *column = Column::default();
                    }
                    self.dirty = true;
                    return false;
                }
                true
            });
        }
        if slot_changed {
            self.generation = None;
        }
        if self.dirty {
            self.publish_gauges();
            self.dirty = false;
        }
    }

    pub fn counts(&self) -> StoreCounts {
        let mut counts = StoreCounts {
            cells: 0,
            bytes: 0,
            full_bytes: 0,
            contexts: self.context_count,
            generations: usize::from(self.generation.is_some()),
            blocks: self.blocks.len(),
        };
        for (index, block) in &self.blocks {
            if block.pin.is_none() {
                continue;
            }
            let start = index * self.config.column_indices.len();
            for column in &self.columns[start..start + self.config.column_indices.len()] {
                counts.cells += column.available(block.context.blob_count).0.count_ones() as usize;
                if let Some(assembly) = &column.assembly {
                    counts.bytes += assembly.acquired().len();
                }
                if let Some(full) = &column.full {
                    counts.full_bytes += full.pin.len().expect("pinned full column");
                }
            }
        }
        counts
    }

    #[inline]
    fn index(&self, key: CellKey) -> Option<(usize, usize)> {
        let block = *self.roots.get(&key.block_root)?;
        if key.row >= self.blocks[block].context.blob_count {
            return None;
        }
        let column =
            block * self.config.column_indices.len() + self.config.column_position(key.column)?;
        Some((block, column))
    }

    fn publish_gauges(&self) {
        let counts = self.counts();
        DataColumnCounters::CellStoreCapacity.set(self.producer.cache_ref().capacity() as u64);
        DataColumnCounters::CellStoreLiveCells.set(counts.cells as u64);
        DataColumnCounters::CellStoreLiveBytes.set(counts.bytes as u64);
        DataColumnCounters::CellStoreFullBytes.set(counts.full_bytes as u64);
        DataColumnCounters::CellStoreContexts.set(counts.contexts as u64);
        DataColumnCounters::CellStoreGenerations.set(counts.generations as u64);
        DataColumnCounters::CellStoreBlocks.set(counts.blocks as u64);
    }
}
