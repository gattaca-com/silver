use std::{
    cell::UnsafeCell,
    sync::atomic::{AtomicU32, Ordering},
};

use flux::communication::ShmemData;

/// Fixed-capacity pool of `N` entries of type `T`, ring-allocated.
///
/// SPMC: a **single producer** calls `alloc` / `copy_from` / `set` /
/// `set_cursor`; any number of consumers call `get` / `generation`.
///
/// `next` wraps `mod N` and supplies the next allocated index.
/// `generation` is a monotonic count of allocations, used by consumers
/// (e.g. cold storage) to detect mutation across a long window where
/// `next` would wrap multiple times.
///
/// # Ring-wrap contract
/// `alloc` and `copy_from` silently overwrite slot `next % N` on each
/// call; there is no free-tracking. **Caller-enforced invariant:** the
/// number of concurrently-referenced indices must never exceed `N`.
#[repr(C, align(64))]
pub struct TierPool<T, const N: usize> {
    next: AtomicU32,
    generation: AtomicU32,
    _pad: [u8; 56],
    entries: [UnsafeCell<T>; N],
}

unsafe impl<T: Send, const N: usize> Send for TierPool<T, N> {}
unsafe impl<T: Sync, const N: usize> Sync for TierPool<T, N> {}

impl<T, const N: usize> TierPool<T, N> {
    /// # Safety
    /// `ptr` must be non-null, aligned to `align_of::<TierPool<T, N>>()`,
    /// and point to a validly-initialised instance that outlives `'a`.
    pub unsafe fn from_ptr<'a>(ptr: *mut u8) -> &'a Self {
        debug_assert!(!ptr.is_null());
        debug_assert_eq!(ptr as usize % core::mem::align_of::<Self>(), 0);
        unsafe { &*(ptr as *const Self) }
    }

    pub fn alloc(&self) -> usize {
        let curr = self.next.load(Ordering::Relaxed) as usize;
        let next = ((curr + 1) % N) as u32;
        self.next.store(next, Ordering::Relaxed);
        self.generation.fetch_add(1, Ordering::Relaxed);
        curr
    }

    pub fn generation(&self) -> u32 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn copy_from(&self, src_idx: usize) -> usize {
        let dst = self.alloc();
        debug_assert!(src_idx < N);
        debug_assert_ne!(dst, src_idx, "pool cap too small for COW");
        // SAFETY: src and dst are distinct indices
        unsafe {
            let src = self.entries[src_idx].get() as *const T;
            let d = self.entries[dst].get();
            core::ptr::copy_nonoverlapping(src, d, 1);
        }
        dst
    }

    pub fn get(&self, idx: usize) -> &T {
        unsafe { &*self.entries[idx].get() }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn get_mut(&self, idx: usize) -> &mut T {
        unsafe { &mut *self.entries[idx].get() }
    }

    pub fn set(&self, idx: usize, value: &T) {
        unsafe {
            core::ptr::copy_nonoverlapping(value as *const T, self.entries[idx].get(), 1);
        }
    }

    pub fn set_cursor(&self, idx: usize) {
        self.next.store((idx % N) as u32, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub struct ArenaPtr<A>(*const A);

unsafe impl<A: Sync> Send for ArenaPtr<A> {}
unsafe impl<A: Sync> Sync for ArenaPtr<A> {}

impl<A> ArenaPtr<A> {
    /// # Safety
    /// `ptr` must remain valid and aligned for the lifetime of the `ArenaPtr`.
    pub const unsafe fn from_raw(ptr: *const A) -> Self {
        Self(ptr)
    }
}

impl<A> core::ops::Deref for ArenaPtr<A> {
    type Target = A;

    fn deref(&self) -> &A {
        unsafe { &*self.0 }
    }
}

impl<A> core::fmt::Debug for ArenaPtr<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ArenaPtr({:p})", self.0)
    }
}

/// # Safety
/// `A` must be zero-valid. Composing an arena from `TierPool`s of
/// `repr(C)` plain-data tiers satisfies this.
pub unsafe fn open_or_create_shm<A: 'static>(app_name: &str) -> ShmemData<A> {
    ShmemData::open_or_init(app_name, || unsafe { core::mem::zeroed::<A>() })
        .expect("arena shm init failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    struct Entry {
        x: u64,
        y: u64,
    }

    type Pool = TierPool<Entry, 4>;

    /// Back the pool with a Box<[u8]> to simulate a shm region.
    fn new_backed() -> (Box<[u8]>, *mut u8) {
        let size = core::mem::size_of::<Pool>();
        let align = core::mem::align_of::<Pool>();
        // Over-allocate and find an aligned offset.
        let mut buf = vec![0u8; size + align].into_boxed_slice();
        let base = buf.as_mut_ptr();
        let pad = base.align_offset(align);
        let ptr = unsafe { base.add(pad) };
        (buf, ptr)
    }

    #[test]
    fn alloc_wraps() {
        let (_buf, ptr) = new_backed();
        let pool: &Pool = unsafe { TierPool::from_ptr(ptr) };

        assert_eq!(pool.alloc(), 0);
        assert_eq!(pool.alloc(), 1);
        assert_eq!(pool.alloc(), 2);
        assert_eq!(pool.alloc(), 3);
        assert_eq!(pool.alloc(), 0); // wraps
    }

    #[test]
    fn copy_bytes() {
        let (_buf, ptr) = new_backed();
        let pool: &Pool = unsafe { TierPool::from_ptr(ptr) };

        let a = pool.alloc();
        pool.set(a, &Entry { x: 42, y: 99 });

        let b = pool.copy_from(a);
        assert_ne!(a, b);
        assert_eq!(pool.get(b).x, 42);
        assert_eq!(pool.get(b).y, 99);
    }

    #[test]
    fn set_cursor_reclaims() {
        let (_buf, ptr) = new_backed();
        let pool: &Pool = unsafe { TierPool::from_ptr(ptr) };

        let _ = pool.alloc(); // 0
        let _ = pool.alloc(); // 1
        pool.set_cursor(0); // reclaim
        assert_eq!(pool.alloc(), 0);
    }
}
