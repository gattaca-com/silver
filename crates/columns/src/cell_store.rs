use std::time::{Duration, Instant};

use fxhash::FxHashMap;
use silver_beacon_state_data::{ForkName, SLOTS_PER_EPOCH};
use silver_common::{
    GossipDomain, SubReservationRef, TCacheId, TCacheRead, TCacheReader,
    cell_store::{
        AssemblyRequest, AssemblySet, CellKey, CellRef, CellStoreConfig, ColumnAvailability,
        ColumnRef, CommitmentContext, ContextData, FuluContextSource, MAX_CONTEXT_BYTES,
        StoreError,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
        DATA_COLUMN_SIDECAR_GLOAS_MIN, DATA_COLUMN_SIDECAR_MIN, DataColumnSidecarFuluView,
        DataColumnSidecarGloasView,
    },
};
use slab::Slab;

use crate::{BlockRoot, DataColumnCounters};

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CellMask(u128);

impl CellMask {
    #[inline]
    pub fn bits(self) -> u128 {
        self.0
    }

    #[inline]
    pub fn contains(self, row: usize) -> bool {
        row < 128 && self.0 & (1u128 << row) != 0
    }

    #[inline]
    fn all(rows: usize) -> Self {
        Self(u128::MAX.checked_shr(128 - rows as u32).unwrap_or(0))
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StoreCounts {
    pub cells: usize,
    pub bytes: usize,
    pub full_bytes: usize,
    pub contexts: usize,
    pub active_slots: usize,
    pub blocks: usize,
}

struct Block {
    context: CommitmentContext,
    domain: GossipDomain,
    data: [u8; MAX_CONTEXT_BYTES],
    data_len: usize,
    source: Option<FuluContextSource>,
    ssz: Option<TCacheRead>,
    request: Option<u64>,
    attempts: u8,
    active: bool,
    changed: u128,
    assembly_bytes: usize,
    full_bytes: usize,
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

pub struct CellStore {
    blocks: Slab<Block>,
    columns: Box<[Column]>,
    config: CellStoreConfig,
    roots: FxHashMap<BlockRoot, usize>,
    counts: StoreCounts,
    now: Instant,
    slot: u64,
    slot_end: Instant,
    min_slot: u64,
    next_request: u64,
    dirty: bool,
    changed: Vec<usize>,
}

impl CellStore {
    pub fn new(
        config: CellStoreConfig,
        slot: u64,
        slot_start: Instant,
    ) -> Result<Self, StoreError> {
        let column_entries = config
            .block_capacity()
            .checked_mul(config.column_indices().len())
            .ok_or(StoreError::CapacityOverflow)?;
        let store = Self {
            blocks: Slab::with_capacity(config.block_capacity()),
            columns: std::iter::repeat_with(Column::default).take(column_entries).collect(),
            roots: FxHashMap::with_capacity_and_hasher(
                config.block_capacity() * 2,
                Default::default(),
            ),
            counts: StoreCounts::default(),
            now: slot_start,
            slot,
            slot_end: slot_start + config.slot_duration(),
            min_slot: 0,
            next_request: 0,
            dirty: false,
            changed: Vec::with_capacity(config.block_capacity()),
            config,
        };
        store.publish_gauges();
        Ok(store)
    }

    pub fn admit_context(
        &mut self,
        context: CommitmentContext,
        domain: GossipDomain,
        data: ContextData<'_>,
        source: Option<FuluContextSource>,
    ) -> Result<bool, StoreError> {
        if context.slot < self.min_slot {
            return Err(StoreError::BelowSlotFloor);
        }
        if context.slot != self.slot {
            return Err(StoreError::OutsideServingSlot);
        }
        if !matches!(context.format, ForkName::Fulu | ForkName::Gloas) ||
            domain.format() != context.format ||
            self.config.spec().fork_at_slot(context.slot) != context.format ||
            context.blob_count > self.config.max_blobs() ||
            context.blob_count >
                self.config
                    .spec()
                    .blob_params_at(context.slot / SLOTS_PER_EPOCH)
                    .max_blobs_per_block as usize ||
            !data.valid_for(context)
        {
            return Err(StoreError::InvalidContext);
        }
        if let Some(&index) = self.roots.get(&context.block_root) {
            let block = &mut self.blocks[index];
            if block.context != context ||
                block.domain != domain ||
                !data.matches(&block.data[..block.data_len])
            {
                return Err(StoreError::ConflictingContext);
            }
            if !block.active {
                return Err(StoreError::ContextExpired);
            }
            if source.is_some() {
                block.source = source;
            }
            return Ok(false);
        }
        if self.blocks.len() >= self.config.block_capacity() ||
            self.counts.contexts >= self.config.live_blocks()
        {
            DataColumnCounters::CellStoreFull.inc();
            return Err(StoreError::Full);
        }
        let mut bytes = [0; MAX_CONTEXT_BYTES];
        let data_len = data.encoded_len();
        data.write(&mut bytes[..data_len]);
        let index = self.blocks.insert(Block {
            context,
            domain,
            data: bytes,
            data_len,
            source,
            ssz: None,
            request: None,
            attempts: 0,
            active: true,
            changed: 0,
            assembly_bytes: 0,
            full_bytes: 0,
        });
        self.roots.insert(context.block_root, index);
        self.counts.contexts += 1;
        self.counts.active_slots = 1;
        self.counts.blocks += 1;
        self.dirty = true;
        Ok(true)
    }

    pub fn request_assemblies(&mut self, root: &BlockRoot) -> Option<AssemblyRequest> {
        let index = *self.roots.get(root)?;
        let block = &mut self.blocks[index];
        if !block.active ||
            block.request.is_some() ||
            block.attempts >= 3 ||
            self.columns[index * self.config.column_indices().len()].assembly.is_some() ||
            (block.context.format == ForkName::Fulu && block.source.is_none())
        {
            return None;
        }
        self.next_request = self.next_request.checked_add(1).expect("assembly request overflow");
        block.request = Some(self.next_request);
        block.attempts += 1;
        Some(AssemblyRequest {
            id: self.next_request,
            context: block.context,
            domain: block.domain,
            columns: self.config.columns(),
            source: block.source,
        })
    }

    pub fn allocation_failed(&mut self, request: AssemblyRequest) {
        if let Some(&index) = self.roots.get(&request.context.block_root) {
            let block = &mut self.blocks[index];
            if block.request == Some(request.id) {
                block.request = None;
            }
        }
    }

    pub(crate) fn awaiting_allocation(&self, root: &BlockRoot) -> bool {
        let Some(&index) = self.roots.get(root) else { return false };
        let block = &self.blocks[index];
        block.active &&
            block.request.is_some() &&
            self.columns[index * self.config.column_indices().len()].assembly.is_none()
    }

    pub fn install(
        &mut self,
        set: AssemblySet,
        reader: &mut TCacheReader,
    ) -> Result<bool, StoreError> {
        if !reader.is_retained(TCacheId::ControlSlot) {
            return Err(StoreError::WrongCache);
        }
        let request = set.request;
        let index = *self.roots.get(&request.context.block_root).ok_or(StoreError::UnknownCell)?;
        let block = &self.blocks[index];
        if !block.active || set.expires != self.slot_end || self.now >= set.expires {
            return Err(StoreError::ContextExpired);
        }
        if block.context != request.context ||
            block.domain != request.domain ||
            block.request != Some(request.id) ||
            request.columns != self.config.columns()
        {
            return Err(StoreError::ConflictingContext);
        }
        let start = index * self.config.column_indices().len();
        if self.columns[start].assembly.is_some() {
            return Ok(false);
        }
        let list = set.reservations.acquire(reader)?;
        if list.entries().len() != self.config.column_indices().len() {
            return Err(StoreError::InvalidContext);
        }
        let mut bytes = 0;
        for reference in list.entries() {
            bytes += reference.acquire(reader)?.len();
        }
        if let Some(header) = set.header {
            if header.id() != TCacheId::ControlSlot {
                return Err(StoreError::WrongCache);
            }
            let read = reader.acquire_strict(header).ok_or(StoreError::ContextExpired)?;
            let bytes = read.buffer().map_err(|_| StoreError::ContextExpired)?.0;
            if !self.context(&request.context.block_root).unwrap().1.matches(bytes) {
                return Err(StoreError::InvalidContext);
            }
        } else if request.context.format == ForkName::Fulu {
            return Err(StoreError::InvalidContext);
        }
        for (column, reference) in self.columns[start..start + self.config.column_indices().len()]
            .iter_mut()
            .zip(list.entries())
        {
            column.assembly = Some(reference);
        }
        self.blocks[index].ssz = set.header;
        self.blocks[index].assembly_bytes = bytes;
        self.counts.bytes += bytes;
        self.dirty = true;
        Ok(true)
    }

    pub fn refresh_column(
        &mut self,
        root: &BlockRoot,
        column: usize,
        reader: &mut TCacheReader,
    ) -> Result<ColumnUpdate, StoreError> {
        let (block, index) = self.column_index(root, column)?;
        let entry = &self.columns[index];
        let (available, complete_read) = if let Some(full) = &entry.full {
            (CellMask::all(self.blocks[block].context.blob_count), Some(full.read))
        } else {
            let acquired = entry.assembly.ok_or(StoreError::ContextExpired)?.acquire(reader)?;
            (CellMask(acquired.ready()), acquired.finish().ok())
        };
        Ok(self.refresh_column_at(index, available, complete_read))
    }

    fn refresh_column_at(
        &mut self,
        index: usize,
        available: CellMask,
        complete_read: Option<TCacheRead>,
    ) -> ColumnUpdate {
        let entry = &mut self.columns[index];
        let new_cells = CellMask(available.0 & !entry.admitted.0);
        let column_completed = !entry.complete && complete_read.is_some();
        entry.admitted = available;
        entry.complete |= column_completed;
        self.dirty |= new_cells.0 != 0 || column_completed;
        let added = new_cells.0.count_ones();
        self.counts.cells += added as usize;
        DataColumnCounters::CellStoreAdmissions.add(added as u64);
        ColumnUpdate { new_cells, column_completed, complete_read }
    }

    pub fn retain_full(
        &mut self,
        root: &BlockRoot,
        column: usize,
        read: TCacheRead,
        reader: &mut TCacheReader,
    ) -> Result<ColumnUpdate, StoreError> {
        if read.id() != TCacheId::ControlSlot || !reader.is_retained(read.id()) {
            return Err(StoreError::WrongCache);
        }
        let (block, index) = self.column_index(root, column)?;
        let pinned = reader.acquire_strict(read).ok_or(StoreError::ContextExpired)?;
        let bytes = pinned.buffer().map_err(|_| StoreError::ContextExpired)?.0;
        let context = &self.blocks[block];
        let (cell_offset, proof_offset) =
            context.full_offsets(bytes, column).ok_or(StoreError::InvalidContext)?;
        let rows = context.context.blob_count;
        let entry = &mut self.columns[index];
        if entry.full.is_none() {
            entry.full = Some(FullColumn { read, cell_offset, proof_offset });
            self.counts.full_bytes += bytes.len();
            self.blocks[block].full_bytes += bytes.len();
            self.dirty = true;
        }
        let read = entry.full.as_ref().unwrap().read;
        Ok(self.refresh_column_at(index, CellMask::all(rows), Some(read)))
    }

    pub fn availability(&self, root: &BlockRoot, column: usize) -> Option<ColumnAvailability> {
        let (block, index) = self.column_index(root, column).ok()?;
        let context = &self.blocks[block];
        let entry = &self.columns[index];
        Some(ColumnAvailability {
            block_root: *root,
            column,
            slot: context.context.slot,
            blob_count: context.context.blob_count,
            domain: context.domain,
            available: entry.admitted.0,
            full: entry.full.as_ref().map(|f| (f.read, f.cell_offset, f.proof_offset)),
            assembly: entry.assembly,
            header: context.ssz,
            expires: self.slot_end,
        })
    }

    pub fn cell(&self, key: CellKey) -> Option<CellRef> {
        self.availability(&key.block_root, key.column)?.cell(key.row)
    }

    pub fn reservations(&self, root: &BlockRoot) -> impl Iterator<Item = ColumnRef> + '_ {
        let root = *root;
        self.config.column_indices().iter().filter_map(move |&column| {
            let update = self.availability(&root, column)?;
            Some(ColumnRef {
                block_root: root,
                column,
                reservation: update.assembly?,
                slot: update.slot,
                expires: update.expires,
            })
        })
    }

    pub fn context(&self, root: &BlockRoot) -> Option<(&CommitmentContext, ContextData<'_>)> {
        let block = &self.blocks[*self.roots.get(root)?];
        if !block.active {
            return None;
        }
        Some((
            &block.context,
            ContextData::from_encoded(&block.data[..block.data_len], block.context.format)?,
        ))
    }

    pub fn column(&self, root: &BlockRoot, column: usize) -> Option<ColumnStatus> {
        let block = *self.roots.get(root)?;
        let position = self.config.column_position(column)?;
        let entry = &self.columns[block * self.config.column_indices().len() + position];
        Some(ColumnStatus {
            admitted: entry.admitted,
            available: if self.blocks[block].active { entry.admitted } else { CellMask::default() },
            complete: entry.complete,
        })
    }

    pub fn slot_end(&self) -> Instant {
        self.slot_end
    }

    pub fn advance(&mut self, now: Instant, min_slot: u64, mut on_expired: impl FnMut(CellKey)) {
        assert!(now >= self.now, "cell store clock moved backwards");
        self.now = now;
        let floor_changed = min_slot > self.min_slot;
        self.min_slot = self.min_slot.max(min_slot);
        let slot_changed = now >= self.slot_end;
        if now >= self.slot_end {
            let elapsed = now.duration_since(self.slot_end).as_nanos();
            let duration = self.config.slot_duration().as_nanos();
            self.slot = self
                .slot
                .checked_add(
                    u64::try_from(elapsed / duration + 1).expect("cell store slot overflow"),
                )
                .expect("cell store slot overflow");
            let remainder = elapsed % duration;
            self.slot_end = now + self.config.slot_duration() -
                Duration::new(
                    (remainder / 1_000_000_000) as u64,
                    (remainder % 1_000_000_000) as u32,
                );
            self.expire_before(self.slot, &mut on_expired);
        }
        if floor_changed || slot_changed {
            self.changed.retain(|&index| self.blocks.get(index).is_some_and(|block| block.active));
            self.blocks.retain(|index, block| {
                if !block.active && block.context.slot < self.min_slot {
                    self.roots.remove(&block.context.block_root);
                    let start = index * self.config.column_indices().len();
                    for column in
                        &mut self.columns[start..start + self.config.column_indices().len()]
                    {
                        *column = Column::default();
                    }
                    self.dirty = true;
                    return false;
                }
                true
            });
        }
        self.counts.blocks = self.blocks.len();
        if self.dirty {
            self.publish_gauges();
            self.dirty = false;
        }
    }

    pub fn expire_through(&mut self, slot: u64) {
        self.expire_before(slot.saturating_add(1), &mut |_| {});
    }

    pub fn reject(&mut self, root: &BlockRoot) {
        let Some(&index) = self.roots.get(root) else { return };
        let start = index * self.config.column_indices().len();
        self.blocks[index].expire(
            &mut self.columns[start..start + self.config.column_indices().len()],
            self.config.column_indices(),
            &mut self.counts,
            &mut |_| {},
        );
        self.changed.retain(|&changed| changed != index);
        self.dirty = true;
    }

    fn expire_before(&mut self, slot: u64, on_expired: &mut impl FnMut(CellKey)) {
        for (index, block) in &mut self.blocks {
            if !block.active || block.context.slot >= slot {
                continue;
            }
            let start = index * self.config.column_indices().len();
            block.expire(
                &mut self.columns[start..start + self.config.column_indices().len()],
                self.config.column_indices(),
                &mut self.counts,
                on_expired,
            );
            self.dirty = true;
        }
    }

    fn column_index(&self, root: &BlockRoot, column: usize) -> Result<(usize, usize), StoreError> {
        let block = *self.roots.get(root).ok_or(StoreError::UnknownCell)?;
        if !self.blocks[block].active {
            return Err(StoreError::ContextExpired);
        }
        let position = self.config.column_position(column).ok_or(StoreError::UnknownCell)?;
        Ok((block, block * self.config.column_indices().len() + position))
    }

    fn publish_gauges(&self) {
        let counts = self.counts;
        DataColumnCounters::CellStoreCapacity.set(self.config.cache_capacity() as u64);
        DataColumnCounters::CellStoreLiveCells.set(counts.cells as u64);
        DataColumnCounters::CellStoreLiveBytes.set(counts.bytes as u64);
        DataColumnCounters::CellStoreFullBytes.set(counts.full_bytes as u64);
        DataColumnCounters::CellStoreContexts.set(counts.contexts as u64);
        DataColumnCounters::CellStoreActiveSlots.set(counts.active_slots as u64);
        DataColumnCounters::CellStoreBlocks.set(counts.blocks as u64);
    }

    pub fn counts(&self) -> StoreCounts {
        self.counts
    }

    pub fn mark_changed(&mut self, root: &BlockRoot, column: usize) {
        let Ok((index, _)) = self.column_index(root, column) else { return };
        let block = &mut self.blocks[index];
        if block.changed == 0 {
            self.changed.push(index);
        }
        block.changed |= 1u128 << column;
    }

    pub fn next_changed(&mut self) -> Option<(BlockRoot, usize)> {
        loop {
            let index = *self.changed.last()?;
            let Some(block) = self.blocks.get_mut(index) else {
                self.changed.pop();
                continue
            };
            if block.changed == 0 || !block.active {
                self.changed.pop();
                continue;
            }
            let column = block.changed.trailing_zeros() as usize;
            block.changed &= block.changed - 1;
            if block.changed == 0 {
                self.changed.pop();
            }
            return Some((block.context.block_root, column));
        }
    }
}

impl Block {
    fn full_offsets(&self, bytes: &[u8], column: usize) -> Option<(usize, usize)> {
        let context = self.context;
        let rows = context.blob_count;
        match ContextData::from_encoded(&self.data[..self.data_len], context.format).unwrap() {
            ContextData::Fulu { signed_header, inclusion_proof, commitments } => {
                if !DataColumnSidecarFuluView::check_size(bytes) ||
                    DataColumnSidecarFuluView::index(bytes) != column as u64 ||
                    DataColumnSidecarFuluView::column(bytes).len() != rows * BYTES_PER_CELL ||
                    DataColumnSidecarFuluView::kzg_commitments(bytes) != commitments ||
                    DataColumnSidecarFuluView::kzg_proofs(bytes).len() !=
                        rows * BYTES_PER_KZG_PROOF ||
                    bytes[20..228] != *signed_header ||
                    bytes[228..356] != *inclusion_proof
                {
                    return None;
                }
                Some((
                    DATA_COLUMN_SIDECAR_MIN,
                    DATA_COLUMN_SIDECAR_MIN + rows * (BYTES_PER_CELL + BYTES_PER_KZG_COMMITMENT),
                ))
            }
            ContextData::Gloas { .. } => {
                if !DataColumnSidecarGloasView::check_size(bytes) ||
                    DataColumnSidecarGloasView::index(bytes) != column as u64 ||
                    DataColumnSidecarGloasView::slot(bytes) != context.slot ||
                    DataColumnSidecarGloasView::beacon_block_root(bytes) != &context.block_root ||
                    DataColumnSidecarGloasView::column(bytes).len() != rows * BYTES_PER_CELL ||
                    DataColumnSidecarGloasView::kzg_proofs(bytes).len() !=
                        rows * BYTES_PER_KZG_PROOF
                {
                    return None;
                }
                Some((
                    DATA_COLUMN_SIDECAR_GLOAS_MIN,
                    DATA_COLUMN_SIDECAR_GLOAS_MIN + rows * BYTES_PER_CELL,
                ))
            }
        }
    }

    fn expire(
        &mut self,
        columns: &mut [Column],
        indices: &[usize],
        counts: &mut StoreCounts,
        on_expired: &mut impl FnMut(CellKey),
    ) {
        if !self.active {
            return;
        }
        self.active = false;
        self.ssz = None;
        self.source = None;
        self.changed = 0;
        for (column, &index) in columns.iter_mut().zip(indices) {
            let mut rows = column.admitted.0;
            let cells = rows.count_ones() as usize;
            counts.cells -= cells;
            DataColumnCounters::CellStoreExpired.add(cells as u64);
            while rows != 0 {
                let row = rows.trailing_zeros() as usize;
                rows &= rows - 1;
                on_expired(CellKey { block_root: self.context.block_root, column: index, row });
            }
            column.full = None;
            column.assembly = None;
        }
        counts.bytes -= self.assembly_bytes;
        counts.full_bytes -= self.full_bytes;
        counts.contexts -= 1;
        counts.active_slots = usize::from(counts.contexts != 0);
    }
}
