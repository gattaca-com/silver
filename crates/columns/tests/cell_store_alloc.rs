use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    hint::black_box,
    io::Write,
    sync::Arc,
    time::{Duration, Instant},
};

use silver_beacon_state_data::{ForkName, SpecConfig};
use silver_columns::cell_store::{
    CellKey, CellStore, CellStoreConfig, CommitmentContext, ContextData,
};
use silver_common::{
    TCache, TCacheProducer,
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_PROOF},
};

thread_local! {
    static ALLOCATION_EVENTS: Cell<u64> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_EVENTS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATION_EVENTS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATION_EVENTS.with(|count| count.set(count.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn cell_admission_expiry_and_block_churn_allocate_nothing() {
    let spec = Arc::new(SpecConfig {
        fulu_fork_epoch: 0,
        max_blobs_per_block_electra: 2,
        blob_schedule: Vec::new(),
        slot_duration_ms: Some(1000),
        ..SpecConfig::mainnet()
    });
    let config = CellStoreConfig::new(spec, 3, Duration::ZERO).unwrap();
    let producer = TCache::producer("", config.cache_capacity());
    let mut writer = Box::new(producer.cache_ref().retained_random_access("").unwrap());
    let mut network = Box::new(producer.cache_ref().retained_random_access("").unwrap());
    let now = Instant::now();
    let mut store = CellStore::new(config, producer, 0, now).unwrap();
    let cell = [0x11; BYTES_PER_CELL];
    let proof = [0x22; BYTES_PER_KZG_PROOF];
    let before = ALLOCATION_EVENTS.with(Cell::get);
    assert!(before > 0);

    for slot in 0u64..512 {
        store.advance(now + Duration::from_secs(slot), slot.saturating_sub(63), |_| {});
        if let Some(event) = store.take_retention_event() {
            writer.advance_retention(event.retain_from);
            network.advance_retention(event.retain_from);
        }
        let mut block_root = [0; 32];
        block_root[..8].copy_from_slice(&slot.to_le_bytes());
        let context = CommitmentContext { block_root, slot, format: ForkName::Fulu, blob_count: 2 };
        let mut header = [0x33; 208];
        header[..8].copy_from_slice(&slot.to_le_bytes());
        let data = ContextData::Fulu {
            signed_header: &header,
            inclusion_proof: &[0x33; 128],
            commitments: &[0x33; 2 * 48],
        };
        assert!(store.admit_context(context, data).unwrap());
        for column in 0..2 {
            let reservation = store.reservations(&block_root).nth(column).unwrap();
            for row in 0..2 {
                let key = CellKey { block_root, column, row };
                let pending = store.stage_cell(key, &cell, &proof).unwrap().unwrap();
                drop(pending.data.acquire(&mut writer).unwrap());
                let retry = reservation.stage(&mut writer, row, &cell, &proof).unwrap().unwrap();
                assert!(!store.cancel_pending(pending).unwrap());
                let validation = retry.data.acquire(&mut writer).unwrap();
                black_box(validation.buffers());
                validation.accept().unwrap();
                assert_eq!(
                    store.refresh_column(&block_root, column).unwrap().column_completed,
                    row == 1
                );
                assert!(reservation.stage(&mut writer, row, &cell, &proof).unwrap().is_none());
                let acquired = store.cell(key).unwrap().acquire(&mut network).unwrap();
                black_box(acquired.cell.as_ref());
                black_box(acquired.proof.as_ref());
            }
            let completed =
                store.refresh_column(&block_root, column).unwrap().complete_read.unwrap();
            let assembly = writer.acquire_strict(completed).unwrap();
            let bytes = assembly.buffer().unwrap().0;
            let mut full = store.reserve_full(bytes.len()).unwrap();
            full.write_all(bytes).unwrap();
            full.flush().unwrap();
            let read = full.read();
            drop(full);
            assert!(!store.retain_full(&block_root, column, read).unwrap().column_completed);
            let cell = store.cell(CellKey { block_root, column, row: 0 }).unwrap();
            let send = cell.acquire(&mut network).unwrap();
            black_box(send.cell.as_ref());
            black_box(send.proof.as_ref());
        }
        black_box(store.column(&block_root, 0).unwrap());
    }
    store.advance(now + Duration::from_secs(512), 512, |_| {});
    let event = store.take_retention_event().unwrap();
    writer.advance_retention(event.retain_from);
    network.advance_retention(event.retain_from);
    assert_eq!(store.counts().cells, 0);
    assert_eq!(store.counts().blocks, 0);
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}
