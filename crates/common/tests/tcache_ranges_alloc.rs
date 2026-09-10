use std::{
    alloc::{GlobalAlloc, Layout, System},
    array,
    cell::Cell,
    hint::black_box,
    io::Write,
};

use silver_common::{TCache, TCacheProducer};

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
fn range_creation_cloning_and_dropping_allocates_nothing() {
    let mut producer = TCache::producer("", 1 << 16);
    let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
    let mut reservation = producer.reserve(2096, true).unwrap();
    reservation.buffer().unwrap().fill(0xab);
    reservation.increment_offset(2096);

    let before = ALLOCATION_EVENTS.with(Cell::get);
    assert!(before > 0);

    let acquired = consumer.acquire_strict(reservation.read()).unwrap();
    let cell = acquired.with_range(0, 2048).unwrap();
    let proof = acquired.with_range(2048, 48).unwrap();
    let clone = cell.clone();
    let suffix = acquired.with_offset(2048).unwrap();
    assert!(acquired.with_range(1, usize::MAX).is_none());

    black_box(cell.as_ref());
    black_box(proof.as_ref());
    black_box(suffix.as_ref());
    drop(acquired);
    drop(cell);
    drop(proof);
    drop(suffix);
    black_box(clone.as_ref());
    drop(clone);

    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}

#[test]
fn slot_retention_acquisition_and_expiry_allocate_nothing_after_construction() {
    let mut producer = TCache::producer("", 1 << 18);
    let mut readers = array::from_fn::<_, 2, _>(|_| {
        Box::new(producer.cache_ref().retained_random_access("").unwrap())
    });
    let before = ALLOCATION_EVENTS.with(Cell::get);

    for _ in 0..512 {
        let boundary = producer.next_seq();
        for reader in &mut readers {
            reader.advance_retention(boundary);
        }
        let mut reservation = producer.reserve(8192, false).unwrap();
        reservation.buffer().unwrap().fill(0xab);
        reservation.flush().unwrap();
        for reader in &mut readers {
            let acquired = reader.acquire_strict(reservation.read()).unwrap();
            let range = acquired.with_range(7, 31).unwrap();
            let clone = range.clone();
            black_box(clone.as_ref());
        }
    }
    assert_eq!(ALLOCATION_EVENTS.with(Cell::get) - before, 0);
}
