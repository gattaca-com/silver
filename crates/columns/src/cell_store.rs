use std::{
    io::Write,
    ptr,
    time::{Duration, Instant},
};

pub use config::CellStoreConfig;
pub use context::{CommitmentContext, ContextData};
use fxhash::FxHashMap;
use silver_beacon_state_data::{ForkName, SLOTS_PER_EPOCH};
pub use silver_common::cells::{AcquiredCell, CellKey, CellRef, ColumnRef, PendingCell};
use silver_common::{
    ScopedReservation, SubReservationError, SubReservationRef, TCacheProducer, TCacheRead,
    TProducer,
    cells::{CellSource, RetentionEvent},
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
    WrongCache,
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
            SubReservationError::WrongConsumer | SubReservationError::WrongProducer => {
                Self::WrongCache
            }
            _ => Self::InvalidContext,
        }
    }
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
    pub active_slots: usize,
    pub blocks: usize,
}

struct Block {
    context: CommitmentContext,
    ssz: Option<TCacheRead>,
}

struct FullColumn {
    read: TCacheRead,
    cell_offset: usize,
    proof_offset: usize,
}

#[derive(Default)]
struct Column {
    assembly: Option<SubReservationRef>,
    full: Option<FullColumn>,
    admitted: CellMask,
    complete: bool,
}

impl Column {
    fn available(&self, producer: &TProducer, rows: usize) -> CellMask {
        if self.full.is_some() {
            CellMask::all(rows)
        } else {
            CellMask(self.assembly.map_or(0, |reference| {
                producer.view_sub_reservation(reference).expect("retained assembly").ready()
            }))
        }
    }
}

/// Downstream retention boundaries protect stored descriptors between calls.
/// Local views borrow the sole producer, preventing allocation during access.
pub struct CellStore {
    blocks: Slab<Block>,
    columns: Box<[Column]>,
    retention_boundary: Option<RetentionEvent>,
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
        let column_entries = config
            .block_capacity
            .checked_mul(config.column_indices.len())
            .ok_or(StoreError::CapacityOverflow)?;
        let store = Self {
            blocks: Slab::with_capacity(config.block_capacity),
            columns: std::iter::repeat_with(Column::default).take(column_entries).collect(),
            retention_boundary: None,
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

    pub fn reserve_full(&mut self, len: usize) -> Result<ScopedReservation<'_>, StoreError> {
        if len >= self.producer.cache_ref().capacity() {
            return Err(StoreError::CacheFull);
        }
        self.producer.reserve_scoped(len).ok_or(StoreError::CacheFull)
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
            let read = block.ssz.ok_or(StoreError::ContextExpired)?;
            if !data.matches(self.producer.read_buffer(read).expect("retained context")) {
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
        let ssz = {
            let Some(mut reservation) = self.producer.reserve_scoped(data.encoded_len()) else {
                DataColumnCounters::CellStoreCacheFull.inc();
                return Err(StoreError::CacheFull);
            };
            data.write(reservation.buffer().expect("new context reservation"));
            reservation.flush().expect("new context reservation");
            reservation.read()
        };
        let index = self.blocks.vacant_key();
        let start = index * self.config.column_indices.len();
        for (position, &column) in self.config.column_indices.iter().enumerate() {
            match data.reserve_column(context, column, &mut self.producer) {
                Ok(reference) => {
                    let complete = context.blob_count == 0;
                    if complete {
                        self.producer
                            .view_sub_reservation(reference)
                            .expect("new assembly")
                            .finish()
                            .expect("empty column");
                    }
                    self.columns[start + position] =
                        Column { assembly: Some(reference), complete, ..Column::default() };
                }
                Err(error) => {
                    for column in &mut self.columns[start..start + self.config.column_indices.len()]
                    {
                        if let Some(reference) = column.assembly {
                            self.producer
                                .view_sub_reservation(reference)
                                .expect("new assembly")
                                .close();
                        }
                        *column = Column::default();
                    }
                    return Err(error.into());
                }
            }
        }
        assert_eq!(self.blocks.insert(Block { context, ssz: Some(ssz) }), index);
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
        if (column.admitted.0 |
            column.available(&self.producer, self.blocks[block].context.blob_count).0) &
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
        let view = self.producer.view_sub_reservation(reference.reservation)?;
        let claim = match view.claim(key.row) {
            Ok(claim) => claim,
            Err(SubReservationError::Claimed | SubReservationError::Published) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(PendingCell { key, data: claim.write(cell, proof)? }))
    }

    pub fn cancel_pending(&self, pending: PendingCell) -> Result<bool, StoreError> {
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
        self.producer
            .view_sub_reservation(reference.reservation)?
            .cancel(pending.data)
            .map_err(Into::into)
    }

    pub fn refresh_column(
        &mut self,
        root: &BlockRoot,
        column: usize,
    ) -> Result<ColumnUpdate, StoreError> {
        let block = *self.roots.get(root).ok_or(StoreError::UnknownCell)?;
        let position = self.config.column_position(column).ok_or(StoreError::UnknownCell)?;
        if self.columns[block * self.config.column_indices.len() + position].assembly.is_none() {
            return Err(StoreError::ContextExpired);
        }
        Ok(self.refresh_column_at(block, position))
    }

    #[inline]
    fn refresh_column_at(&mut self, block: usize, position: usize) -> ColumnUpdate {
        let entry = &mut self.columns[block * self.config.column_indices.len() + position];
        debug_assert!(entry.assembly.is_some());
        let available = entry.available(&self.producer, self.blocks[block].context.blob_count);
        let new_cells = CellMask(available.0 & !entry.admitted.0);
        let complete_read = match &entry.full {
            Some(full) => Some(full.read),
            None => entry.assembly.and_then(|reference| {
                self.producer
                    .view_sub_reservation(reference)
                    .expect("retained assembly")
                    .finish()
                    .ok()
            }),
        };
        let column_completed = !entry.complete && complete_read.is_some();
        entry.admitted = available;
        entry.complete |= column_completed;
        self.dirty |= new_cells.0 != 0 || column_completed;
        DataColumnCounters::CellStoreAdmissions.add(new_cells.0.count_ones() as u64);
        ColumnUpdate { new_cells, column_completed, complete_read }
    }

    /// The sidecar must already be verified; this checks its layout and
    /// context.
    pub fn retain_full(
        &mut self,
        root: &BlockRoot,
        column: usize,
        read: TCacheRead,
    ) -> Result<ColumnUpdate, StoreError> {
        if !ptr::eq(&*read.cache_ref(), &*self.producer.cache_ref()) {
            return Err(StoreError::WrongCache);
        }
        let block = *self.roots.get(root).ok_or(StoreError::UnknownCell)?;
        let position = self.config.column_position(column).ok_or(StoreError::UnknownCell)?;
        let context = &self.blocks[block];
        let context_bytes = self
            .producer
            .read_buffer(context.ssz.ok_or(StoreError::ContextExpired)?)
            .map_err(|_| StoreError::ContextExpired)?;
        let bytes = self.producer.read_buffer(read).map_err(|_| StoreError::ContextExpired)?;
        let (cell_offset, proof_offset) = context
            .context
            .full_offsets(bytes, context_bytes, column)
            .ok_or(StoreError::InvalidContext)?;
        let entry = &mut self.columns[block * self.config.column_indices.len() + position];
        if entry.assembly.is_none() {
            return Err(StoreError::ContextExpired);
        }
        if entry.full.is_none() {
            entry.full = Some(FullColumn { read, cell_offset, proof_offset });
            self.dirty = true;
        }
        Ok(self.refresh_column_at(block, position))
    }

    #[inline]
    pub fn cell(&self, key: CellKey) -> Option<CellRef> {
        let (block, index) = self.index(key)?;
        let column = &self.columns[index];
        if !column
            .available(&self.producer, self.blocks[block].context.blob_count)
            .contains(key.row)
        {
            return None;
        }
        let source = match &column.full {
            Some(full) => CellSource::Full {
                read: full.read,
                cell: full.cell_offset + key.row * BYTES_PER_CELL,
                proof: full.proof_offset + key.row * BYTES_PER_KZG_PROOF,
            },
            None => CellSource::Assembly { reservation: column.assembly?, row: key.row },
        };
        Some(CellRef { source, slot: self.blocks[block].context.slot, expires: self.slot_end })
    }

    fn column_ref(&self, block: usize, column: usize) -> Option<ColumnRef> {
        let position = self.config.column_position(column)?;
        Some(ColumnRef {
            block_root: self.blocks[block].context.block_root,
            column,
            reservation: self.columns[block * self.config.column_indices.len() + position]
                .assembly?,
            slot: self.blocks[block].context.slot,
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

    pub fn context(&self, root: &BlockRoot) -> Option<(&CommitmentContext, TCacheRead)> {
        let block = &self.blocks[*self.roots.get(root)?];
        Some((&block.context, block.ssz?))
    }

    pub fn column(&self, root: &BlockRoot, column: usize) -> Option<ColumnStatus> {
        let block = *self.roots.get(root)?;
        let position = self.config.column_position(column)?;
        let entry = &self.columns[block * self.config.column_indices.len() + position];
        let available = entry.available(&self.producer, self.blocks[block].context.blob_count);
        Some(ColumnStatus {
            admitted: CellMask(entry.admitted.0 | available.0),
            available,
            complete: entry.complete ||
                (entry.assembly.is_some() &&
                    available == CellMask::all(self.blocks[block].context.blob_count)),
        })
    }

    pub fn slot_end(&self) -> Instant {
        self.slot_end
    }

    pub fn take_retention_event(&mut self) -> Option<RetentionEvent> {
        self.retention_boundary.take()
    }

    pub fn advance(&mut self, now: Instant, min_slot: u64, mut on_expired: impl FnMut(CellKey)) {
        assert!(now >= self.now, "cell store clock moved backwards");
        self.now = now;
        let floor_changed = min_slot > self.min_slot;
        self.min_slot = self.min_slot.max(min_slot);
        let slot_changed = now >= self.slot_end;
        if slot_changed {
            let retain_from = self.producer.next_seq();
            if retain_from != 0 {
                self.retention_boundary =
                    Some(RetentionEvent { expired_slot: self.slot, retain_from });
            }
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
                if block.context.slot < self.slot && block.ssz.take().is_some() {
                    for (position, column) in columns.iter_mut().enumerate() {
                        if let Some(reference) = column.assembly {
                            self.producer
                                .view_sub_reservation(reference)
                                .expect("retained assembly")
                                .close();
                        }
                        let available = column.available(&self.producer, block.context.blob_count);
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
                if block.context.slot < self.min_slot && block.ssz.is_none() {
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
            active_slots: usize::from(self.context_count != 0),
            blocks: self.blocks.len(),
        };
        for (index, block) in &self.blocks {
            if block.ssz.is_none() {
                continue;
            }
            let start = index * self.config.column_indices.len();
            for column in &self.columns[start..start + self.config.column_indices.len()] {
                counts.cells +=
                    column.available(&self.producer, block.context.blob_count).0.count_ones()
                        as usize;
                if let Some(reference) = column.assembly {
                    counts.bytes += self
                        .producer
                        .view_sub_reservation(reference)
                        .expect("retained assembly")
                        .len();
                }
                if let Some(full) = &column.full {
                    counts.full_bytes +=
                        self.producer.read_buffer(full.read).expect("retained full column").len();
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
        DataColumnCounters::CellStoreActiveSlots.set(counts.active_slots as u64);
        DataColumnCounters::CellStoreBlocks.set(counts.blocks as u64);
    }
}

impl Drop for CellStore {
    fn drop(&mut self) {
        for column in &self.columns {
            if let Some(reference) = column.assembly {
                if let Ok(view) = self.producer.view_sub_reservation(reference) {
                    view.close();
                }
            }
        }
    }
}
