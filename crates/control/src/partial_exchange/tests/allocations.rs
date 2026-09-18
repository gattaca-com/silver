use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use super::*;

thread_local! {
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn serving_and_drop_recovery_allocate_nothing_after_construction() {
    ControlCounters::init().unwrap();
    for format in [ForkName::Fulu, ForkName::Gloas] {
        let mut rig = Rig::new(format);
        rig.connect(1, true, true);
        let before = ALLOCATIONS.with(Cell::get);
        rig.publish(0);
        for attempt in 0..MAX_FRAMES_PER_GROUP {
            let mut frame = None;
            rig.exchange.spin(&rig.ingress, &rig.peers, &mut rig.output, rig.now, &mut |send| {
                let P2pSend::SegmentedGossip { frame: next, .. } = send else {
                    panic!("unexpected send")
                };
                assert!(frame.replace(next).is_none());
            });
            rig.dropped(1, frame.unwrap());
            rig.request(1, 0, 1 << (attempt % ROWS as u8));
            rig.now += RETRY;
        }
        assert_eq!(ALLOCATIONS.with(Cell::get) - before, 0);
    }
}
