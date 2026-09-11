use std::{io::Write, sync::Arc, time::Duration};

use silver_beacon_state_data::{BlobParameters, FAR_FUTURE_EPOCH, SpecConfig};
use silver_common::{
    TCache, TCacheRef, TRandomAccess, column_util::push_data_column_sidecar_prefix,
};

use super::*;

const ROOT: BlockRoot = [1; 32];
const CELL: [u8; BYTES_PER_CELL] = [0x11; BYTES_PER_CELL];
const PROOF: [u8; BYTES_PER_KZG_PROOF] = [0x22; BYTES_PER_KZG_PROOF];

struct Harness {
    store: CellStore,
    consumer: Box<TRandomAccess>,
    cache: TCacheRef,
    start: Instant,
}

#[derive(Debug)]
enum CellAdmission {
    Inserted { cell: CellRef, column_completed: bool },
    Duplicate,
}

impl Harness {
    fn spec(rows: u64) -> SpecConfig {
        SpecConfig {
            fulu_fork_epoch: 0,
            gloas_fork_epoch: 2,
            max_blobs_per_block_electra: rows,
            blob_schedule: Vec::new(),
            ..SpecConfig::mainnet()
        }
    }

    fn new(rows: u64, columns: u128) -> Self {
        let config =
            CellStoreConfig::new(Arc::new(Self::spec(rows)), columns, Duration::from_secs(11))
                .unwrap();
        Self::configured(config)
    }

    fn configured(config: CellStoreConfig) -> Self {
        Self::at_slot(config, 0)
    }

    fn at_slot(config: CellStoreConfig, slot: u64) -> Self {
        let producer = TCache::producer("", config.cache_capacity());
        let cache = producer.cache_ref();
        let consumer = Box::new(cache.retained_random_access("").unwrap());
        let start = Instant::now();
        Self {
            store: CellStore::new(config, producer, slot, start).unwrap(),
            consumer,
            cache,
            start,
        }
    }

    fn context(&mut self, root: BlockRoot, slot: u64, rows: usize) -> CommitmentContext {
        let context = CommitmentContext {
            block_root: root,
            slot,
            format: self.store.config.spec.fork_at_slot(slot),
            blob_count: rows,
        };
        assert!(self.admit(context, 0x33).unwrap());
        context
    }

    fn admit(&mut self, context: CommitmentContext, value: u8) -> Result<bool, StoreError> {
        let mut header = [value; 208];
        header[..8].copy_from_slice(&context.slot.to_le_bytes());
        let proof = [value; 128];
        let commitments = [value; 128 * 48];
        let commitments = &commitments[..context.blob_count.min(128) * 48];
        let data = match context.format {
            ForkName::Gloas => ContextData::Gloas { commitments },
            _ => ContextData::Fulu { signed_header: &header, inclusion_proof: &proof, commitments },
        };
        self.store.admit_context(context, data)
    }

    fn insert(&mut self, key: CellKey) -> (CellRef, bool) {
        let CellAdmission::Inserted { cell, column_completed } =
            self.admit_cell(key, &CELL, &PROOF).unwrap()
        else {
            panic!("expected a new cell")
        };
        (cell, column_completed)
    }

    fn assert_counts(&self) {
        let mut expected =
            StoreCounts { blocks: self.store.blocks.len(), ..StoreCounts::default() };
        for (index, block) in &self.store.blocks {
            if block.ssz.is_none() {
                continue;
            }
            expected.contexts += 1;
            expected.active_slots = 1;
            let start = index * self.store.config.column_indices.len();
            for column in &self.store.columns[start..start + self.store.config.column_indices.len()]
            {
                expected.cells += column.admitted.0.count_ones() as usize;
                if let Some(reference) = column.assembly {
                    expected.bytes +=
                        self.store.producer.view_sub_reservation(reference).unwrap().len();
                }
                if let Some(full) = &column.full {
                    expected.full_bytes +=
                        self.store.producer.read_buffer(full.read).unwrap().len();
                }
            }
        }
        assert_eq!(self.store.counts(), expected);
    }

    fn advance_ms(&mut self, elapsed: u64) {
        self.advance(self.start + Duration::from_millis(elapsed), 0, |_| {});
    }

    fn advance(&mut self, now: Instant, min_slot: u64, on_expired: impl FnMut(CellKey)) {
        self.store.advance(now, min_slot, on_expired);
        if let Some(event) = self.store.take_retention_event() {
            self.consumer.advance_retention(event.retain_from);
        }
    }

    fn admit_cell(
        &mut self,
        key: CellKey,
        cell: &[u8; BYTES_PER_CELL],
        proof: &[u8; BYTES_PER_KZG_PROOF],
    ) -> Result<CellAdmission, StoreError> {
        let Some(pending) = self.store.stage_cell(key, cell, proof)? else {
            return Ok(CellAdmission::Duplicate);
        };
        pending.data.acquire(&mut self.consumer)?.accept()?;
        let update = self.store.refresh_column(&key.block_root, key.column)?;
        Ok(CellAdmission::Inserted {
            cell: self.store.cell(key).unwrap(),
            column_completed: update.column_completed,
        })
    }

    fn acquire_cell(&mut self, key: CellKey) -> Option<AcquiredCell> {
        self.store.cell(key)?.acquire(&mut self.consumer)
    }

    fn full_bytes(&self, root: &BlockRoot, column: usize) -> Vec<u8> {
        let block = &self.store.blocks[self.store.roots[root]];
        let context = block.context;
        let bytes = self.store.producer.read_buffer(block.ssz.unwrap()).unwrap();
        let mut full = Vec::new();
        match context.format {
            ForkName::Fulu => push_data_column_sidecar_prefix(
                &mut full,
                column as u64,
                context.blob_count,
                bytes[4..212].try_into().unwrap(),
                bytes[212..340].try_into().unwrap(),
            ),
            ForkName::Gloas => {
                full.extend_from_slice(&(column as u64).to_le_bytes());
                full.extend_from_slice(&56u32.to_le_bytes());
                full.extend_from_slice(
                    &((56 + context.blob_count * BYTES_PER_CELL) as u32).to_le_bytes(),
                );
                full.extend_from_slice(&context.slot.to_le_bytes());
                full.extend_from_slice(root);
            }
            _ => unreachable!(),
        }
        for row in 0..context.blob_count {
            full.extend_from_slice(&[0x11 + row as u8; BYTES_PER_CELL]);
        }
        if context.format == ForkName::Fulu {
            full.extend_from_slice(&bytes[340..]);
        }
        for row in 0..context.blob_count {
            full.extend_from_slice(&[0x22 + row as u8; BYTES_PER_KZG_PROOF]);
        }
        full
    }
}

fn key(column: usize, row: usize) -> CellKey {
    CellKey { block_root: ROOT, column, row }
}

#[test]
fn capacity_uses_the_entire_blob_schedule_and_selected_columns() {
    let mut spec = Harness::spec(3);
    spec.blob_schedule = vec![BlobParameters { epoch: 1, max_blobs_per_block: 17 }];
    let one = CellStoreConfig::new(Arc::new(spec.clone()), 1, Duration::from_secs(11)).unwrap();
    let two = CellStoreConfig::new(Arc::new(spec), 3, Duration::from_secs(11)).unwrap();
    assert_eq!(one.max_blobs(), 17);
    assert_eq!(one.cell_capacity(), 3 * 17);
    assert_eq!(two.cell_capacity(), one.cell_capacity() * 2);
    assert!(two.cache_capacity() >= one.cache_capacity());
    assert!(two.cache_capacity().is_power_of_two());

    let fallback = CellStoreConfig::new(Arc::new(Harness::spec(3)), 1, Duration::ZERO).unwrap();
    assert_eq!(fallback.max_blobs(), 3);
    assert_eq!(fallback.cell_capacity(), 2 * 3);
}

#[test]
fn mainnet_and_hoodi_capacity_use_their_configured_schedule() {
    for spec in [SpecConfig::mainnet(), SpecConfig::hoodi()] {
        let expected = spec
            .blob_schedule
            .iter()
            .map(|entry| entry.max_blobs_per_block)
            .fold(spec.max_blobs_per_block_electra, u64::max);
        let config =
            CellStoreConfig::new(Arc::new(spec), u128::MAX, Duration::from_secs(11)).unwrap();
        assert_eq!(config.max_blobs(), expected as usize);
        assert_eq!(config.cell_capacity(), 3 * 128 * expected as usize);
    }
}

#[test]
fn larger_delivery_window_provisions_more_cells() {
    let spec = Arc::new(Harness::spec(21));
    let short = CellStoreConfig::new(spec.clone(), 3, Duration::ZERO).unwrap();
    let long = CellStoreConfig::new(spec, 3, Duration::from_secs(60)).unwrap();
    assert!(long.cell_capacity() > short.cell_capacity());
    assert!(long.cache_capacity() >= short.cache_capacity());
}

#[test]
fn unsupported_future_blob_counts_are_rejected_at_construction() {
    let mut spec = Harness::spec(3);
    spec.blob_schedule = vec![BlobParameters { epoch: 100, max_blobs_per_block: 129 }];
    assert!(matches!(
        CellStoreConfig::new(Arc::new(spec), 1, Duration::ZERO),
        Err(StoreError::UnsupportedBlobCount(129))
    ));
    assert!(matches!(
        CellStoreConfig::new(Arc::new(Harness::spec(129)), 1, Duration::ZERO),
        Err(StoreError::UnsupportedBlobCount(129))
    ));
}

#[test]
fn unscheduled_blob_entries_do_not_inflate_capacity() {
    let mut spec = Harness::spec(3);
    spec.blob_schedule =
        vec![BlobParameters { epoch: FAR_FUTURE_EPOCH, max_blobs_per_block: u64::MAX }];
    let config = CellStoreConfig::new(Arc::new(spec), 1, Duration::ZERO).unwrap();
    assert_eq!(config.max_blobs(), 3);
}

#[test]
fn invalid_and_overflowing_configurations_are_rejected() {
    assert!(matches!(
        CellStoreConfig::new(Arc::new(Harness::spec(3)), 0, Duration::ZERO),
        Err(StoreError::InvalidConfig)
    ));
    let mut spec = Harness::spec(3);
    spec.slot_duration_ms = Some(0);
    assert!(matches!(
        CellStoreConfig::new(Arc::new(spec), 1, Duration::ZERO),
        Err(StoreError::InvalidConfig)
    ));
    assert!(matches!(
        CellStoreConfig::new(Arc::new(Harness::spec(3)), 1, Duration::MAX),
        Err(StoreError::CapacityOverflow)
    ));
}

#[test]
fn an_undersized_cache_is_rejected() {
    let config =
        CellStoreConfig::new(Arc::new(Harness::spec(21)), u128::MAX, Duration::ZERO).unwrap();
    let producer = TCache::producer("", 1 << 16);
    assert_eq!(producer.cache_ref().capacity(), 1 << 16);
    assert!(matches!(
        CellStore::new(config, producer, 0, Instant::now()),
        Err(StoreError::CacheTooSmall)
    ));
}

#[test]
fn cell_and_proof_share_one_record() {
    let mut h = Harness::new(2, 1);
    h.context(ROOT, 0, 2);
    let (reference, complete) = h.insert(key(0, 0));
    assert!(!complete);
    assert_eq!(reference.read().len().unwrap_err().to_string(), "reservation is incomplete");
    let acquired = h.acquire_cell(key(0, 0)).unwrap();
    let cell = acquired.cell;
    let proof = acquired.proof;
    assert_eq!(cell.as_ref(), &CELL);
    assert_eq!(proof.as_ref(), &PROOF);
    assert_eq!(h.store.counts().cells, 1);
    assert_eq!(h.store.counts().bytes, 356 + 2 * (CELL_RECORD_BYTES + 48));
    assert_eq!(h.store.counts().contexts, 1);
}

#[test]
fn incremental_counts_track_refresh_duplicates_full_columns_and_expiry() {
    for slot in [0, 64] {
        let config = CellStoreConfig::new(Arc::new(Harness::spec(2)), 3, Duration::ZERO).unwrap();
        let mut h = Harness::at_slot(config, slot);
        h.assert_counts();
        let context = h.context(ROOT, slot, 2);
        h.assert_counts();
        let admitted = h.store.counts();
        assert!(!h.admit(context, 0x33).unwrap());
        assert_eq!(h.store.counts(), admitted);

        let pending = h.store.stage_cell(key(0, 0), &CELL, &PROOF).unwrap().unwrap();
        pending.data.acquire(&mut h.consumer).unwrap().accept().unwrap();
        assert_eq!(h.store.column(&ROOT, 0).unwrap().available.bits(), 1);
        assert_eq!(h.store.counts().cells, 0);
        h.assert_counts();
        assert_eq!(h.store.refresh_column(&ROOT, 0).unwrap().new_cells.bits(), 1);
        assert_eq!(h.store.counts().cells, 1);
        h.assert_counts();
        assert_eq!(h.store.refresh_column(&ROOT, 0).unwrap().new_cells.bits(), 0);
        h.assert_counts();

        let full = h.full_bytes(&ROOT, 0);
        let mut write = h.store.reserve_full(full.len()).unwrap();
        write.write_all(&full).unwrap();
        write.flush().unwrap();
        let read = write.read();
        assert_eq!(h.store.retain_full(&ROOT, 0, read).unwrap().new_cells.bits(), 2);
        assert_eq!(h.store.counts().cells, 2);
        assert_eq!(h.store.counts().full_bytes, full.len());
        h.assert_counts();
        assert_eq!(h.store.retain_full(&ROOT, 0, read).unwrap().new_cells.bits(), 0);
        h.assert_counts();

        let pending = h.store.stage_cell(key(1, 0), &CELL, &PROOF).unwrap().unwrap();
        pending.data.acquire(&mut h.consumer).unwrap().accept().unwrap();
        h.context([2; 32], slot, 1);
        h.assert_counts();
        let mut expired = 0;
        h.advance(h.start + Duration::from_secs(12), 0, |_| expired += 1);
        assert_eq!(expired, 3);
        assert_eq!(h.store.counts(), StoreCounts { blocks: 2, ..StoreCounts::default() });
        h.assert_counts();
        assert!(matches!(h.store.refresh_column(&ROOT, 1), Err(StoreError::ContextExpired)));
        h.advance(h.start + Duration::from_secs(12), slot + 1, |_| panic!("already expired"));
        assert_eq!(h.store.counts(), StoreCounts::default());
        h.assert_counts();
    }
}

#[test]
fn failed_context_reservation_does_not_change_incremental_counts() {
    let mut h = Harness::new(1, 3);
    let mut pressure = h.store.reserve_full(h.cache.capacity() - 4096).unwrap();
    pressure.buffer().unwrap().fill(0);
    pressure.flush().unwrap();
    let context =
        CommitmentContext { block_root: ROOT, slot: 0, format: ForkName::Fulu, blob_count: 1 };
    assert_eq!(h.admit(context, 0x33), Err(StoreError::CacheFull));
    assert_eq!(h.store.counts(), StoreCounts::default());
    h.assert_counts();
    assert!(h.store.columns.iter().all(|column| column.assembly.is_none()));
    h.advance_ms(12_000);
    h.context(ROOT, 1, 1);
    h.assert_counts();
    h.insert(key(0, 0));
    h.assert_counts();
}

#[test]
fn duplicates_do_not_copy_or_refresh_deadlines() {
    let mut h = Harness::new(2, 1);
    let context = h.context(ROOT, 0, 2);
    let (first, _) = h.insert(key(0, 0));
    h.advance_ms(11_000);
    assert!(!h.admit(context, 0x33).unwrap());
    assert!(matches!(h.admit_cell(key(0, 0), &CELL, &PROOF), Ok(CellAdmission::Duplicate)));
    assert_eq!(h.store.cell(key(0, 0)).unwrap().expires, first.expires);
    assert_eq!(h.store.cell(key(0, 0)).unwrap().read().seq(), first.read().seq());
    h.advance_ms(12_000);
    assert!(h.store.cell(key(0, 0)).is_none());
    assert!(matches!(h.admit_cell(key(0, 0), &CELL, &PROOF), Ok(CellAdmission::Duplicate)));
    assert_eq!(h.store.counts().cells, 0);
}

#[test]
fn slot_deadline_advances_without_contexts() {
    let mut h = Harness::new(1, 1);
    assert_eq!(h.store.slot_end(), h.start + Duration::from_secs(12));
    assert_eq!(h.store.counts().active_slots, 0);
    h.advance_ms(12_000);
    assert_eq!(h.store.slot_end(), h.start + Duration::from_secs(24));
    assert_eq!(h.store.counts().active_slots, 0);
}

#[test]
fn late_slot_admission_expires_at_the_slot_boundary() {
    let mut h = Harness::new(1, 1);
    h.advance_ms(11_999);
    h.context(ROOT, 0, 1);
    let (cell, complete) = h.insert(key(0, 0));
    assert!(complete);
    assert_eq!(cell.expires, h.start + Duration::from_secs(12));
    assert_eq!(h.store.slot_end(), cell.expires);
    h.advance_ms(12_000);
    assert!(h.store.cell(key(0, 0)).is_none());
    assert!(h.store.context(&ROOT).is_none());
    assert_eq!(h.store.counts().active_slots, 0);
}

#[test]
fn slot_duration_uses_milliseconds_at_fixed_boundaries() {
    let mut spec = Harness::spec(1);
    spec.slot_duration_ms = Some(500);
    let config = CellStoreConfig::new(Arc::new(spec), 1, Duration::ZERO).unwrap();
    let mut h = Harness::configured(config);
    h.context(ROOT, 0, 1);
    h.advance_ms(499);
    let (cell, _) = h.insert(key(0, 0));
    assert_eq!(cell.expires, h.start + Duration::from_millis(500));
    assert_eq!(h.store.slot_end(), cell.expires);
    h.advance_ms(500);
    assert!(h.store.cell(key(0, 0)).is_none());
    assert_eq!(h.store.counts().active_slots, 0);
}

#[test]
fn cells_and_fork_siblings_share_the_slot_deadline() {
    let mut h = Harness::new(3, 1);
    h.context(ROOT, 0, 3);
    let (first, _) = h.insert(key(0, 0));
    h.advance_ms(500);
    let (second, _) = h.insert(key(0, 1));
    assert_eq!(first.slot, second.slot);
    assert_eq!(h.store.counts().active_slots, 1);
    h.advance_ms(1000);
    let (third, _) = h.insert(key(0, 2));
    h.advance_ms(11_000);
    h.context([2; 32], 0, 3);
    let other = CellKey { block_root: [2; 32], column: 0, row: 0 };
    let (sibling, _) = h.insert(other);
    assert_eq!(second.slot, third.slot);
    assert_eq!(third.slot, sibling.slot);
    assert_eq!(first.expires, second.expires);
    assert_eq!(second.expires, third.expires);
    assert_eq!(third.expires, sibling.expires);
    assert_eq!(h.store.counts().active_slots, 1);
    assert_eq!(h.store.slot_end(), sibling.expires);
    h.advance_ms(11_999);
    assert_eq!(h.store.column(&ROOT, 0).unwrap().available.bits(), 7);
    assert!(h.store.cell(other).is_some());
    h.advance_ms(12_000);
    assert_eq!(h.store.column(&ROOT, 0).unwrap().available.bits(), 0);
    assert_eq!(h.store.column(&other.block_root, 0).unwrap().available.bits(), 0);
    assert_eq!(h.store.counts().cells, 0);
    assert_eq!(h.store.counts().contexts, 0);
    assert_eq!(h.store.counts().active_slots, 0);
}

#[test]
fn completion_survives_serving_expiry_without_reopening_admission() {
    let mut h = Harness::new(2, 1);
    h.context(ROOT, 0, 2);
    assert!(!h.insert(key(0, 0)).1);
    assert!(h.insert(key(0, 1)).1);
    h.advance_ms(13_000);
    let column = h.store.column(&ROOT, 0).unwrap();
    assert!(column.complete);
    assert_eq!(column.available.bits(), 0);
    assert_eq!(column.admitted.bits(), 3);
    assert!(matches!(h.admit_cell(key(0, 1), &CELL, &PROOF), Ok(CellAdmission::Duplicate)));
    assert_eq!(h.store.counts().cells, 0);
}

#[test]
fn unfinished_columns_cannot_continue_in_the_next_slot() {
    let mut h = Harness::new(3, 1);
    h.context(ROOT, 0, 3);
    h.insert(key(0, 0));
    h.advance_ms(11_000);
    h.insert(key(0, 1));
    h.advance_ms(13_000);
    assert!(matches!(h.admit_cell(key(0, 2), &CELL, &PROOF), Err(StoreError::ContextExpired)));
    let status = h.store.column(&ROOT, 0).unwrap();
    assert_eq!(status.admitted.bits(), 3);
    assert_eq!(status.available.bits(), 0);
    assert!(!status.complete);
}

#[test]
fn context_survives_until_the_slot_boundary() {
    let mut h = Harness::new(2, 1);
    h.context(ROOT, 0, 2);
    h.insert(key(0, 0));
    h.advance_ms(11_000);
    h.insert(key(0, 1));
    h.advance_ms(11_999);
    let read = h.store.context(&ROOT).unwrap().1;
    assert_eq!(&h.store.producer.read_buffer(read).unwrap()[12..20], &[0x33; 8]);
    h.advance_ms(12_000);
    assert!(h.store.context(&ROOT).is_none());
    assert_eq!(h.store.counts().contexts, 0);
}

#[test]
fn expired_incomplete_context_requires_full_sidecar_recovery() {
    let mut h = Harness::new(2, 1);
    let context = h.context(ROOT, 0, 2);
    h.insert(key(0, 0));
    h.advance_ms(13_000);
    assert!(matches!(h.admit_cell(key(0, 1), &CELL, &PROOF), Err(StoreError::ContextExpired)));
    assert_eq!(h.admit(context, 0x33), Err(StoreError::OutsideServingSlot));
    assert!(!h.store.column(&ROOT, 0).unwrap().complete);
}

#[test]
fn schedule_and_fork_boundaries_use_the_blocks_slot() {
    let mut spec = Harness::spec(2);
    spec.blob_schedule = vec![BlobParameters { epoch: 1, max_blobs_per_block: 4 }];
    let config = CellStoreConfig::new(Arc::new(spec), 1, Duration::ZERO).unwrap();
    let mut h = Harness::at_slot(config, 31);
    let mut context =
        CommitmentContext { block_root: ROOT, slot: 31, format: ForkName::Fulu, blob_count: 4 };
    assert_eq!(h.admit(context, 0x33), Err(StoreError::InvalidContext));
    h.advance_ms(12_000);
    context.slot = 32;
    assert!(h.admit(context, 0x33).unwrap());
    let old = h.insert(key(0, 0)).0;
    let sent = h.acquire_cell(key(0, 0)).unwrap();
    h.advance_ms(33 * 12_000);
    context.block_root = [2; 32];
    context.slot = 64;
    assert_eq!(h.admit(context, 0x33), Err(StoreError::InvalidContext));
    context.format = ForkName::Gloas;
    assert!(h.admit(context, 0x33).unwrap());
    h.insert(CellKey { block_root: [2; 32], column: 0, row: 3 });
    assert_eq!(h.store.blocks[h.store.roots[&ROOT]].context.format, ForkName::Fulu);
    assert!(h.store.cell(key(0, 0)).is_none());
    assert_eq!(old.expires, h.start + Duration::from_secs(24));
    assert_eq!(sent.cell.as_ref(), CELL);
}

#[test]
fn non_current_slots_are_not_admitted() {
    let config = CellStoreConfig::new(Arc::new(Harness::spec(2)), 1, Duration::ZERO).unwrap();
    let mut h = Harness::at_slot(config, 40);
    for slot in [39, 41] {
        let context =
            CommitmentContext { block_root: ROOT, slot, format: ForkName::Fulu, blob_count: 2 };
        assert_eq!(h.admit(context, 0x33), Err(StoreError::OutsideServingSlot));
    }
    assert_eq!(h.store.counts().blocks, 0);
    h.advance_ms(4000);
    h.context(ROOT, 40, 2);
    assert_eq!(h.insert(key(0, 0)).0.expires, h.start + Duration::from_secs(12));
}

#[test]
fn conflicting_and_oversized_contexts_do_not_replace_descriptors() {
    let mut h = Harness::new(2, 1);
    let context = h.context(ROOT, 0, 2);
    let seq = h.store.context(&ROOT).unwrap().1.seq();
    assert_eq!(h.admit(context, 0x44), Err(StoreError::ConflictingContext));
    assert_eq!(
        h.admit(CommitmentContext { blob_count: 1, ..context }, 0x33),
        Err(StoreError::ConflictingContext)
    );
    let mut header = [0x33; 208];
    header[..8].copy_from_slice(&context.slot.to_le_bytes());
    let data = ContextData::Fulu {
        signed_header: &header,
        inclusion_proof: &[0x33; 128],
        commitments: &[0; 3 * 48],
    };
    assert_eq!(h.store.admit_context(context, data), Err(StoreError::InvalidContext));
    assert_eq!(h.store.context(&ROOT).unwrap().1.seq(), seq);
}

#[test]
fn zero_and_128_blob_masks_are_supported() {
    assert_eq!(CellMask::all(0).bits(), 0);
    assert_eq!(CellMask::all(128).bits(), u128::MAX);
    assert!(!CellMask::all(128).contains(128));
    let mut h = Harness::new(128, 1);
    h.context(ROOT, 0, 128);
    for row in 0..128 {
        assert_eq!(h.insert(key(0, row)).1, row == 127);
    }
    assert_eq!(h.store.column(&ROOT, 0).unwrap().available.bits(), u128::MAX);

    let mut h = Harness::new(0, 1);
    h.context(ROOT, 0, 0);
    assert!(h.store.column(&ROOT, 0).unwrap().complete);
    assert!(matches!(h.admit_cell(key(0, 0), &CELL, &PROOF), Err(StoreError::UnknownCell)));
}

#[test]
fn sparse_columns_and_invalid_indices_are_isolated() {
    let mut h = Harness::new(2, (1 << 3) | (1 << 127));
    h.context(ROOT, 0, 2);
    let first = h.insert(key(3, 0)).0;
    let second = h.insert(key(127, 1)).0;
    assert_ne!(first.read().seq(), second.read().seq());
    assert_eq!(h.store.column(&ROOT, 3).unwrap().available.bits(), 1);
    assert_eq!(h.store.column(&ROOT, 127).unwrap().available.bits(), 2);
    for invalid in [key(0, 0), key(128, 0), key(usize::MAX, 0), key(3, 2), key(3, usize::MAX)] {
        assert!(h.store.cell(invalid).is_none());
        assert!(matches!(h.admit_cell(invalid, &CELL, &PROOF), Err(StoreError::UnknownCell)));
    }
    assert_eq!(h.store.counts().cells, 2);
}

#[test]
fn admission_pressure_does_not_publish_failed_cells() {
    let mut config = CellStoreConfig::new(Arc::new(Harness::spec(2)), 1, Duration::ZERO).unwrap();
    config.live_blocks = 1;
    let mut h = Harness::configured(config);
    h.context(ROOT, 0, 2);
    h.insert(key(0, 0));
    let context =
        CommitmentContext { block_root: [2; 32], slot: 0, format: ForkName::Fulu, blob_count: 2 };
    assert!(matches!(h.admit(context, 0x33), Err(StoreError::Full)));
    assert_eq!(h.store.column(&ROOT, 0).unwrap().admitted.bits(), 1);
    assert_eq!(h.store.counts().cells, 1);
}

#[test]
fn slot_jumps_expire_the_previous_slot() {
    let mut h = Harness::new(2, 1);
    h.context(ROOT, 0, 2);
    h.insert(key(0, 0));
    h.advance_ms(100_001);
    assert_eq!(h.store.counts().active_slots, 0);
    assert_eq!(h.store.counts().cells, 0);
    assert_eq!(h.store.counts().contexts, 0);
    assert_eq!(h.store.column(&ROOT, 0).unwrap().admitted.bits(), 1);
    h.context([2; 32], 8, 2);
    let cell = h.insert(CellKey { block_root: [2; 32], column: 0, row: 0 }).0;
    assert_eq!(cell.expires, h.start + Duration::from_secs(108));
    assert_eq!(cell.slot, 8);
}

#[test]
fn context_table_pressure_preserves_existing_blocks() {
    let mut config = CellStoreConfig::new(Arc::new(Harness::spec(1)), 1, Duration::ZERO).unwrap();
    config.block_capacity = 1;
    let mut h = Harness::configured(config);
    h.store.blocks.reserve(4);
    let capacity = h.store.blocks.capacity();
    assert!(capacity > h.store.config.block_capacity);
    let context = h.context(ROOT, 0, 1);
    assert_eq!(
        h.admit(CommitmentContext { block_root: [2; 32], ..context }, 0x33),
        Err(StoreError::Full)
    );
    assert_eq!(h.store.context(&ROOT).unwrap().0, &context);
    assert!(!h.admit(context, 0x33).unwrap());
    assert_eq!(h.store.blocks.len(), 1);
    assert_eq!(h.store.blocks.capacity(), capacity);
}

#[test]
fn expiry_reports_rows_and_slot_floor_prevents_readmission() {
    let mut h = Harness::new(2, 1);
    let context = h.context(ROOT, 0, 2);
    h.insert(key(0, 0));
    h.advance(h.start + Duration::from_secs(1), 1, |_| {});
    assert!(h.store.cell(key(0, 0)).is_some(), "slot floor must not shorten serving");
    let mut expired = Vec::new();
    h.advance(h.start + Duration::from_secs(13), 1, |key| expired.push(key));
    assert_eq!(expired, [key(0, 0)]);
    assert!(h.store.column(&ROOT, 0).is_none());
    h.advance(h.start + Duration::from_secs(14), 0, |_| {});
    assert_eq!(h.admit(context, 0x33), Err(StoreError::BelowSlotFloor));
}

#[test]
fn block_slot_reuse_does_not_alias_expired_cell_indices() {
    let mut config = CellStoreConfig::new(Arc::new(Harness::spec(2)), 1, Duration::ZERO).unwrap();
    config.block_capacity = 1;
    let mut h = Harness::configured(config);
    h.context(ROOT, 0, 2);
    h.insert(key(0, 0));
    h.advance(h.start + Duration::from_secs(13), 1, |_| {});
    h.context([2; 32], 1, 2);
    let missing = CellKey { block_root: [2; 32], column: 0, row: 0 };
    assert!(h.store.cell(missing).is_none());
    let new = CellKey { row: 1, ..missing };
    h.insert(new);
    assert!(h.store.cell(missing).is_none());
    assert!(h.store.cell(key(0, 0)).is_none());
    assert!(h.store.cell(new).is_some());
}

#[test]
fn slab_reuses_holes_without_moving_live_blocks() {
    let mut config =
        CellStoreConfig::new(Arc::new(Harness::spec(2)), 3, Duration::from_secs(11)).unwrap();
    config.block_capacity = 3;
    let mut h = Harness::configured(config);
    h.context(ROOT, 0, 2);
    h.advance_ms(12_000);
    h.context([2; 32], 1, 2);
    let removed_index = h.store.roots[&[2; 32]];
    h.insert(CellKey { block_root: [2; 32], column: 0, row: 0 });
    h.advance(h.start + Duration::from_secs(24), 1, |_| {});
    h.context([3; 32], 2, 2);
    h.context([4; 32], 2, 2);
    let live_indices = [h.store.roots[&[3; 32]], h.store.roots[&[4; 32]]];
    let first_key = CellKey { block_root: [3; 32], column: 0, row: 0 };
    let first = h.insert(first_key).0;
    let other = CellKey { block_root: [4; 32], column: 1, row: 1 };
    let second = h.insert(other).0;

    h.advance(h.start + Duration::from_secs(25), 2, |_| {});
    assert!(!h.store.roots.contains_key(&[2; 32]));
    assert_eq!([h.store.roots[&[3; 32]], h.store.roots[&[4; 32]]], live_indices);
    h.context([5; 32], 2, 2);
    assert_eq!(h.store.roots[&[5; 32]], removed_index);
    let new = CellKey { block_root: [5; 32], column: 0, row: 0 };
    assert!(h.store.cell(new).is_none());
    assert_eq!(h.store.column(&new.block_root, 0).unwrap().admitted.bits(), 0);
    h.insert(new);

    assert_eq!(h.store.counts().blocks, 3);
    assert_eq!(h.store.cell(first_key).unwrap().read().seq(), first.read().seq());
    assert_eq!(h.store.cell(other).unwrap().read().seq(), second.read().seq());
    assert_eq!(h.acquire_cell(other).unwrap().cell.as_ref(), CELL);
}

#[test]
fn acquired_send_outlives_expiry_and_blocks_overwrite() {
    let mut h = Harness::new(1, 1);
    let mut outbound = Box::new(h.cache.strict_random_access("", true).unwrap());
    h.context(ROOT, 0, 1);
    let reference = h.insert(key(0, 0)).0;
    let sent = reference.acquire(&mut outbound).unwrap();
    let mut blocked = false;
    let mut next_context = None;
    for slot in 1..128 {
        h.advance(h.start + Duration::from_secs(slot * 12), slot, |_| {});
        let context = CommitmentContext {
            block_root: [slot as u8 + 1; 32],
            slot,
            format: h.store.config.spec.fork_at_slot(slot),
            blob_count: 1,
        };
        match h.admit(context, 0x33) {
            Err(StoreError::CacheFull) => {
                blocked = true;
                next_context = Some(context);
                break;
            }
            Ok(true) => {}
            result => panic!("unexpected context admission: {result:?}"),
        }
        let key = CellKey { block_root: context.block_root, column: 0, row: 0 };
        match h.admit_cell(key, &CELL, &PROOF) {
            Ok(CellAdmission::Inserted { cell, .. }) => drop(cell.acquire(&mut outbound).unwrap()),
            Err(StoreError::CacheFull) => {
                blocked = true;
                next_context = Some(context);
                break;
            }
            result => panic!("unexpected cell admission: {result:?}"),
        }
    }
    assert!(blocked, "an ACK-held record must eventually block the producer");
    assert_eq!(sent.cell.as_ref(), CELL);
    assert!(h.store.cell(key(0, 0)).is_none());
    drop(sent);
    outbound.free();
    let context = next_context.unwrap();
    h.admit(context, 0x33).unwrap();
    h.admit_cell(CellKey { block_root: context.block_root, column: 0, row: 0 }, &CELL, &PROOF)
        .unwrap();
}

#[test]
fn ingress_is_copied_before_validation_and_can_be_reused_immediately() {
    let mut ingress = TCache::producer("", 1 << 17);
    let mut incoming = Box::new(ingress.cache_ref().strict_random_access("", true).unwrap());
    let mut h = Harness::new(1, 1);
    h.context(ROOT, 0, 1);
    let mut reservation = ingress.reserve(CELL_RECORD_BYTES, true).unwrap();
    let bytes = reservation.buffer().unwrap();
    bytes[..BYTES_PER_CELL].copy_from_slice(&CELL);
    bytes[BYTES_PER_CELL..].copy_from_slice(&PROOF);
    reservation.increment_offset(CELL_RECORD_BYTES);
    let old = reservation.read();
    let read = incoming.acquire_strict(old).unwrap();
    let bytes = read.buffer().unwrap().0;
    let pending = h
        .store
        .stage_cell(
            key(0, 0),
            bytes[..BYTES_PER_CELL].try_into().unwrap(),
            bytes[BYTES_PER_CELL..].try_into().unwrap(),
        )
        .unwrap()
        .unwrap();
    drop(read);
    drop(reservation);
    assert!(h.store.cell(key(0, 0)).is_none());
    assert_eq!(h.store.counts().cells, 0);

    for _ in 0..64 {
        let mut reservation = ingress.reserve(4096, true).unwrap();
        reservation.buffer().unwrap().fill(0xcc);
        reservation.increment_offset(4096);
        drop(incoming.acquire_strict(reservation.read()).unwrap());
    }
    assert!(old.len().is_err(), "the ingress buffer must actually have been reused");
    let validation = pending.data.acquire(&mut h.consumer).unwrap();
    assert_eq!(validation.buffers(), [&CELL[..], &PROOF[..]]);
    validation.accept().unwrap();
    let update = h.store.refresh_column(&ROOT, 0).unwrap();
    assert_eq!(update.new_cells.bits(), 1);
    assert!(update.column_completed);
    assert_eq!(h.acquire_cell(key(0, 0)).unwrap().cell.as_ref(), CELL);
}

#[test]
fn independent_ingress_writers_ignore_duplicates_and_retry_failed_validation() {
    let mut h = Harness::new(2, 3);
    let mut el = Box::new(h.cache.retained_random_access("").unwrap());
    h.context(ROOT, 0, 2);
    let columns: Vec<_> = h.store.reservations(&ROOT).collect();
    assert_eq!(columns.len(), 2);
    assert_eq!(columns[0].expires, h.start + Duration::from_secs(12));
    let old = h.store.stage_cell(key(0, 0), &[0; BYTES_PER_CELL], &PROOF).unwrap().unwrap();
    assert!(columns[0].stage(&mut el, 0, &CELL, &PROOF).unwrap().is_none());
    let validation = old.data.acquire(&mut h.consumer).unwrap();
    assert!(h.store.cell(key(0, 0)).is_none());
    assert!(!old.data.cancel(&mut el).unwrap());
    drop(validation);
    let retry = columns[0].stage(&mut el, 0, &CELL, &PROOF).unwrap().unwrap();
    assert!(!h.store.cancel_pending(old).unwrap());
    assert!(matches!(old.data.acquire(&mut h.consumer), Err(SubReservationError::Stale)));
    let validation = retry.data.acquire(&mut h.consumer).unwrap();
    assert_eq!(validation.buffers(), [&CELL[..], &PROOF[..]]);
    validation.accept().unwrap();
    assert!(h.store.stage_cell(key(0, 0), &CELL, &PROOF).unwrap().is_none());
    assert_eq!(h.store.refresh_column(&ROOT, 0).unwrap().new_cells.bits(), 1);
    assert_eq!(h.store.refresh_column(&ROOT, 0).unwrap().new_cells.bits(), 0);
    assert_eq!(h.store.column(&ROOT, 1).unwrap().available.bits(), 0);
}

#[test]
fn pending_validation_and_writes_survive_slot_expiry_without_publishing() {
    let mut h = Harness::new(3, 1);
    let mut writer = Box::new(h.cache.strict_random_access("", true).unwrap());
    h.context(ROOT, 0, 3);
    let column = h.store.reservations(&ROOT).next().unwrap();
    let pending = column.stage(&mut writer, 0, &CELL, &PROOF).unwrap().unwrap();
    let queued = column.stage(&mut writer, 1, &CELL, &PROOF).unwrap().unwrap();
    let validation = pending.data.acquire(&mut h.consumer).unwrap();
    let acquired = column.reservation.acquire(&mut writer).unwrap();
    let writing = acquired.claim(2).unwrap();
    h.advance_ms(12_000);
    assert_eq!(h.store.counts().cells, 0);
    assert!(h.store.cell(key(0, 0)).is_none());
    assert_eq!(validation.buffers(), [&CELL[..], &PROOF[..]]);
    assert_eq!(validation.accept(), Err(SubReservationError::Closed));
    assert!(matches!(queued.data.acquire(&mut writer), Err(SubReservationError::Closed)));
    assert!(matches!(writing.write(&CELL, &PROOF), Err(SubReservationError::Closed)));
    assert_eq!(acquired.ready(), 0);
}

#[test]
fn full_sidecars_are_retained_without_copying_and_match_completed_assemblies() {
    for slot in [0, 64] {
        let config =
            CellStoreConfig::new(Arc::new(Harness::spec(2)), 1 << 3, Duration::ZERO).unwrap();
        let mut h = Harness::at_slot(config, slot);
        let mut network = Box::new(h.cache.retained_random_access("").unwrap());
        h.context(ROOT, slot, 2);
        let (old_cell, _) = h.insert(key(3, 0));
        let assembly_send = old_cell.acquire(&mut network).unwrap();
        let pending = h
            .store
            .stage_cell(key(3, 1), &[0x12; BYTES_PER_CELL], &[0x23; BYTES_PER_KZG_PROOF])
            .unwrap()
            .unwrap();
        let validation = pending.data.acquire(&mut h.consumer).unwrap();
        let full = h.full_bytes(&ROOT, 3);
        let mut write = h.store.reserve_full(full.len()).unwrap();
        write.write_all(&full).unwrap();
        write.flush().unwrap();
        let read = write.read();
        drop(write);
        let update = h.store.retain_full(&ROOT, 3, read).unwrap();
        assert!(update.column_completed);
        assert_eq!(update.new_cells.bits(), 2);
        assert_eq!(update.complete_read.unwrap().seq(), read.seq());
        let column = h.store.reservations(&ROOT).next().unwrap();
        assert_eq!(column.reservation.acquire(&mut network).unwrap().ready(), 1);
        let cell = h.store.cell(key(3, 1)).unwrap();
        assert!(ptr::eq(&*cell.read().cache_ref(), &*h.cache));
        assert_eq!(cell.read().seq(), read.seq());
        let full_send = cell.acquire(&mut network).unwrap();
        assert_eq!(full_send.cell.as_ref(), &[0x12; BYTES_PER_CELL]);
        assert_eq!(full_send.proof.as_ref(), &[0x23; BYTES_PER_KZG_PROOF]);
        assert_eq!(h.store.counts().full_bytes, full.len());
        assert!(h.store.stage_cell(key(3, 1), &CELL, &PROOF).unwrap().is_none());

        validation.accept().unwrap();
        assert!(!h.store.refresh_column(&ROOT, 3).unwrap().column_completed);
        let entry = &h.store.columns[h.store.roots[&ROOT]];
        let complete = h
            .store
            .producer
            .view_sub_reservation(entry.assembly.unwrap())
            .unwrap()
            .finish()
            .unwrap();
        let assembled = h.consumer.acquire_strict(complete).unwrap();
        assert_eq!(assembled.buffer().unwrap().0, full);
        drop(assembled);
        h.advance_ms(12_000);
        assert!(h.store.cell(key(3, 1)).is_none());
        assert_eq!(h.store.counts().full_bytes, 0);
        assert_eq!(assembly_send.cell.as_ref(), CELL);
        assert_eq!(full_send.cell.as_ref(), &[0x12; BYTES_PER_CELL]);
    }
}

#[test]
fn mismatched_full_sidecars_cannot_replace_the_context_or_cell_source() {
    for slot in [0, 64] {
        let config = CellStoreConfig::new(Arc::new(Harness::spec(2)), 1, Duration::ZERO).unwrap();
        let mut h = Harness::at_slot(config, slot);
        h.context(ROOT, slot, 2);
        let original = h.insert(key(0, 0)).0;
        let full = h.full_bytes(&ROOT, 0);
        for corrupt_offset in [0, 8, 12, 24] {
            let mut write = h.store.reserve_full(full.len()).unwrap();
            let bytes = write.buffer().unwrap();
            bytes.copy_from_slice(&full);
            bytes[corrupt_offset] ^= 1;
            write.flush().unwrap();
            let read = write.read();
            drop(write);
            assert!(matches!(h.store.retain_full(&ROOT, 0, read), Err(StoreError::InvalidContext)));
            assert_eq!(h.store.cell(key(0, 0)).unwrap().read().seq(), original.read().seq());
            assert_eq!(h.store.counts().full_bytes, 0);
        }
    }
}

#[test]
fn expired_context_rejects_full_sidecars_without_changing_state() {
    for slot in [0, 64] {
        let config = CellStoreConfig::new(Arc::new(Harness::spec(2)), 1, Duration::ZERO).unwrap();
        let mut h = Harness::at_slot(config, slot);
        h.context(ROOT, slot, 2);
        h.insert(key(0, 0));
        let full = h.full_bytes(&ROOT, 0);
        let mut write = h.store.reserve_full(full.len()).unwrap();
        write.write_all(&full).unwrap();
        write.flush().unwrap();
        let read = write.read();
        drop(write);
        let pin = h.consumer.acquire_strict(read).unwrap();

        h.advance_ms(12_000);
        assert_eq!(pin.buffer().unwrap().0, full);
        let before = h.store.counts();
        assert!(matches!(h.store.retain_full(&ROOT, 0, read), Err(StoreError::ContextExpired)));
        assert_eq!(h.store.counts(), before);
        assert!(!h.store.dirty);
        assert!(h.store.columns[h.store.roots[&ROOT]].full.is_none());
        assert!(h.store.context(&ROOT).is_none());
        assert!(h.store.cell(key(0, 0)).is_none());
        let status = h.store.column(&ROOT, 0).unwrap();
        assert_eq!(status.admitted.bits(), 1);
        assert_eq!(status.available.bits(), 0);
        assert!(!status.complete);
    }
}

#[test]
fn rpc_sidecars_do_not_become_sendable_cells() {
    let mut h = Harness::new(2, 1);
    h.context(ROOT, 0, 2);
    let full = h.full_bytes(&ROOT, 0);
    let mut rpc = TCache::producer("", 1 << 16);
    let mut reservation = rpc.reserve(full.len(), true).unwrap();
    reservation.write_all(&full).unwrap();
    assert!(matches!(
        h.store.retain_full(&ROOT, 0, reservation.read()),
        Err(StoreError::WrongCache)
    ));
    assert_eq!(h.store.counts().full_bytes, 0);
    assert!(h.store.cell(key(0, 0)).is_none());
}

#[test]
fn dropping_the_store_closes_descriptors_without_invalidating_active_validation() {
    let mut h = Harness::new(1, 1);
    h.context(ROOT, 0, 1);
    let column = h.store.reservations(&ROOT).next().unwrap();
    let pending = h.store.stage_cell(key(0, 0), &CELL, &PROOF).unwrap().unwrap();
    let Harness { store, mut consumer, .. } = h;
    let validation = pending.data.acquire(&mut consumer).unwrap();
    drop(store);
    assert!(matches!(column.reservation.acquire(&mut consumer), Err(SubReservationError::Closed)));
    assert_eq!(validation.buffers(), [&CELL[..], &PROOF[..]]);
    assert_eq!(validation.accept(), Err(SubReservationError::Closed));
}
