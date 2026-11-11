use std::{
    alloc::{self, Layout},
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
    ptr, slice,
    sync::atomic::{AtomicPtr, AtomicUsize, Ordering},
};

/// Heads every allocation; the elements follow at [`RetainedVec::DATA`].
struct Header {
    len: AtomicUsize,
    capacity: usize,
}

/// Proof that no reader holds a slice into a retired block.
pub struct Quiescent(());

impl Quiescent {
    /// # Safety
    /// Every read that began before this call has ended, and every later read
    /// loads its pointers afresh.
    pub unsafe fn assume() -> Self {
        Self(())
    }
}

/// A `Vec` for storage that optimistic readers race with.
///
/// A reader loads one pointer and takes the length from that allocation's own
/// header, so the slice it builds never exceeds the allocation it points into,
/// whatever the writer does meanwhile. Growth publishes a new allocation and
/// retains the old one until [`Self::free_retired`] or drop. Element contents
/// are not synchronized: a racing reader may see torn or stale values and must
/// discard them.
pub struct RetainedVec<T: Copy> {
    /// Null until the first allocation.
    live: AtomicPtr<Header>,
    retired: Vec<*mut Header>,
    _owns: PhantomData<T>,
}

// SAFETY: owns its allocations; shared access hands out `&[T]` only.
unsafe impl<T: Copy + Send> Send for RetainedVec<T> {}
unsafe impl<T: Copy + Sync> Sync for RetainedVec<T> {}

impl<T: Copy> Drop for RetainedVec<T> {
    fn drop(&mut self) {
        for &block in self.retired.iter().chain(Some(&*self.live.get_mut())) {
            if !block.is_null() {
                // SAFETY: allocated by `alloc` with this layout.
                unsafe { alloc::dealloc(block.cast(), Self::layout((*block).capacity)) };
            }
        }
    }
}

impl<T: Copy> Default for RetainedVec<T> {
    fn default() -> Self {
        Self { live: AtomicPtr::new(ptr::null_mut()), retired: Vec::new(), _owns: PhantomData }
    }
}

impl<T: Copy> From<&[T]> for RetainedVec<T> {
    fn from(values: &[T]) -> Self {
        let mut v = Self::default();
        v.copy_from_slice(values);
        v
    }
}

impl<T: Copy> From<Vec<T>> for RetainedVec<T> {
    fn from(values: Vec<T>) -> Self {
        Self::from(&values[..])
    }
}

impl<T: Copy> FromIterator<T> for RetainedVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut v = Self::default();
        v.extend(iter);
        v
    }
}

impl<T: Copy> RetainedVec<T> {
    const DATA: usize = size_of::<Header>().next_multiple_of(align_of::<T>());

    fn layout(capacity: usize) -> Layout {
        let size = capacity
            .checked_mul(size_of::<T>())
            .and_then(|bytes| bytes.checked_add(Self::DATA))
            .expect("capacity overflow");
        Layout::from_size_align(size, align_of::<Header>().max(align_of::<T>()))
            .expect("capacity overflow")
    }

    /// An empty block; its elements are uninitialized.
    fn alloc(capacity: usize) -> *mut Header {
        let layout = Self::layout(capacity);
        // SAFETY: the layout covers at least the header, so it is not zero-sized.
        let block = unsafe { alloc::alloc(layout) }.cast::<Header>();
        if block.is_null() {
            alloc::handle_alloc_error(layout);
        }
        // SAFETY: freshly allocated for a `Header`.
        unsafe { block.write(Header { len: AtomicUsize::new(0), capacity }) };
        block
    }

    /// # Safety
    /// `block` must come from [`Self::alloc`].
    #[inline]
    unsafe fn data(block: *mut Header) -> *mut T {
        // SAFETY: the allocation extends `DATA` bytes past its start.
        unsafe { block.cast::<u8>().add(Self::DATA).cast() }
    }

    /// Writer-side view of the live block: `(block, len, capacity)`.
    #[inline]
    fn parts(&mut self) -> (*mut Header, usize, usize) {
        let block = *self.live.get_mut();
        if block.is_null() {
            return (block, 0, 0);
        }
        // SAFETY: a published block stays allocated until drop.
        unsafe { (block, (*block).len.load(Ordering::Relaxed), (*block).capacity) }
    }

    /// Readers holding the old block keep reading it. `SeqCst` here and on
    /// the reader's load orders both against a reader count, which is how a
    /// caller obtains [`Quiescent`].
    fn publish(&mut self, block: *mut Header) {
        let old = self.live.swap(block, Ordering::SeqCst);
        if !old.is_null() {
            self.retired.push(old);
        }
    }

    pub fn free_retired(&mut self, _: &Quiescent) {
        for block in self.retired.drain(..) {
            // SAFETY: allocated by `alloc` with this layout; `Quiescent`
            // rules out a reader still inside it.
            unsafe { alloc::dealloc(block.cast(), Self::layout((*block).capacity)) };
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        let mut v = Self::default();
        v.grow_to(capacity);
        v
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        let block = self.live.load(Ordering::Acquire);
        // SAFETY: a published block stays allocated until drop.
        if block.is_null() { 0 } else { unsafe { (*block).capacity } }
    }

    /// Moves the elements to a block of exactly `capacity` slots.
    pub fn grow_to(&mut self, capacity: usize) {
        let (old, len, _) = self.parts();
        assert!(len <= capacity);
        let block = Self::alloc(capacity);
        // SAFETY: `block` holds `capacity >= len` slots; `old` holds `len`.
        unsafe {
            if len > 0 {
                ptr::copy_nonoverlapping(Self::data(old), Self::data(block), len);
            }
            (*block).len.store(len, Ordering::Relaxed);
        }
        self.publish(block);
    }

    /// New slots hold `fill`, written before the length covers them.
    pub fn resize(&mut self, len: usize, fill: T) {
        let (_, old_len, _) = self.parts();
        self.reserve(len.saturating_sub(old_len));
        let (block, ..) = self.parts();
        if block.is_null() {
            return;
        }
        // SAFETY: `reserve` left room for `len` elements.
        unsafe {
            for i in old_len..len {
                Self::data(block).add(i).write(fill);
            }
            (*block).len.store(len, Ordering::Release);
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        let block = self.live.load(Ordering::SeqCst);
        if block.is_null() {
            return &[];
        }
        // SAFETY: the block stays allocated while a reader can hold it, and
        // its `len` never exceeds its own capacity.
        unsafe { slice::from_raw_parts(Self::data(block), (*block).len.load(Ordering::Acquire)) }
    }

    #[inline]
    pub fn clear(&mut self) {
        let (block, ..) = self.parts();
        if !block.is_null() {
            // SAFETY: as in `parts`.
            unsafe { (*block).len.store(0, Ordering::Release) };
        }
    }

    /// # Safety
    /// Every element below `len` must be initialized, and `len` must fit the
    /// allocation.
    #[inline]
    pub unsafe fn set_len(&mut self, len: usize) {
        let (block, _, capacity) = self.parts();
        assert!(len <= capacity);
        if !block.is_null() {
            // SAFETY: initialization is the caller's obligation; capacity is checked above.
            unsafe { (*block).len.store(len, Ordering::Release) };
        }
    }

    fn grown_capacity(capacity: usize, required: usize) -> usize {
        required.max(capacity.saturating_mul(2)).max(4)
    }

    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        let (old, len, capacity) = self.parts();
        let required = len.checked_add(additional).expect("capacity overflow");
        if required > capacity {
            let block = Self::alloc(Self::grown_capacity(capacity, required));
            // SAFETY: the new block holds more than `len` slots; `old` holds `len`.
            unsafe {
                if len > 0 {
                    ptr::copy_nonoverlapping(Self::data(old), Self::data(block), len);
                }
                (*block).len.store(len, Ordering::Relaxed);
            }
            self.publish(block);
        }
    }

    pub fn copy_from_slice(&mut self, source: &[T]) {
        let (mut block, _, capacity) = self.parts();
        if source.is_empty() {
            return self.clear();
        }
        let grow = source.len() > capacity;
        if grow {
            block = Self::alloc(Self::grown_capacity(capacity, source.len()));
        }
        // SAFETY: `block` holds at least `source.len()` slots, and `source`
        // cannot alias storage this `&mut self` owns.
        unsafe {
            ptr::copy_nonoverlapping(source.as_ptr(), Self::data(block), source.len());
            (*block).len.store(source.len(), Ordering::Release);
        }
        if grow {
            self.publish(block);
        }
    }

    #[inline]
    pub fn push(&mut self, value: T) {
        self.reserve(1);
        let (block, len, _) = self.parts();
        // SAFETY: `reserve` left room for one more element.
        unsafe {
            Self::data(block).add(len).write(value);
            (*block).len.store(len + 1, Ordering::Release);
        }
    }
}

impl<T: Copy> Extend<T> for RetainedVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        self.reserve(iter.size_hint().0);
        for value in iter {
            self.push(value);
        }
    }
}

impl<T: Copy> Clone for RetainedVec<T> {
    fn clone(&self) -> Self {
        Self::from(self.as_slice())
    }

    fn clone_from(&mut self, source: &Self) {
        self.copy_from_slice(source);
    }
}

impl<T: Copy> Deref for RetainedVec<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy> DerefMut for RetainedVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        let (block, len, _) = self.parts();
        if block.is_null() {
            return &mut [];
        }
        // SAFETY: as in `as_slice`; `&mut self` makes this the only writer.
        unsafe { slice::from_raw_parts_mut(Self::data(block), len) }
    }
}

impl<'a, T: Copy> IntoIterator for &'a RetainedVec<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: Copy + fmt::Debug> fmt::Debug for RetainedVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_slice().fmt(f)
    }
}

impl<T: Copy + PartialEq> PartialEq for RetainedVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + Eq> Eq for RetainedVec<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_and_copy_keep_all_previous_allocations() {
        let mut values = RetainedVec::from(vec![11u64, 22]);
        let first = values.as_ptr();
        values.reserve(100);
        let second = values.as_ptr();
        assert_ne!(first, second);
        values.copy_from_slice(&vec![33; 200]);
        assert_ne!(second, values.as_ptr());
        values.clear();
        values.clone_from(&RetainedVec::from(vec![44; 400]));

        // SAFETY: growth retains both allocations until `values` drops.
        unsafe {
            assert_eq!(slice::from_raw_parts(first, 2), &[11, 22]);
            assert_eq!(slice::from_raw_parts(second, 2), &[11, 22]);
        }
        assert_eq!(&*values, &[44; 400]);
    }

    #[test]
    fn copying_within_capacity_reuses_storage_and_keeps_older_allocations() {
        let mut values = RetainedVec::from(vec![7u64]);
        let retired = values.as_ptr();
        values.reserve(10);
        let current = values.as_ptr();
        values.copy_from_slice(&[8, 9]);
        values.clear();
        values.push(10);
        assert_eq!(current, values.as_ptr());
        // SAFETY: clearing and copying preserve the retired allocation.
        assert_eq!(unsafe { *retired }, 7);
    }

    #[test]
    fn free_retired_releases_old_blocks_and_keeps_the_live_one() {
        let mut values = RetainedVec::from(vec![7u64]);
        values.reserve(10);
        values.reserve(100);
        assert_eq!(values.retired.len(), 2);

        // SAFETY: no reader exists.
        values.free_retired(&unsafe { Quiescent::assume() });
        assert!(values.retired.is_empty());
        assert_eq!(values[0], 7);

        values.reserve(1000);
        assert_eq!(values.retired.len(), 1);
    }

    #[test]
    fn a_clone_has_independent_storage_and_retirement_history() {
        let mut source = RetainedVec::from(vec![5u64]);
        source.reserve(10);
        let mut cloned = source.clone();
        assert_ne!(source.as_ptr(), cloned.as_ptr());
        let retained = cloned.as_ptr();
        cloned.reserve(20);
        drop(source);
        // SAFETY: the clone owns its own retired allocation.
        assert_eq!(unsafe { *retained }, 5);
    }

    #[test]
    fn resize_fills_within_capacity_and_grow_to_retains_the_old_block() {
        let mut column = RetainedVec::with_capacity(8);
        column.resize(4, 7u64);
        column[1] = 9;
        let address = column.as_ptr().addr();
        column.resize(6, 1);
        let block = column.as_ptr();
        assert_eq!(address, block.addr(), "spare capacity is used in place");
        assert_eq!(&*column, &[7, 9, 7, 7, 1, 1]);

        column.grow_to(16);
        assert_eq!((column.len(), column.capacity()), (6, 16));
        assert_eq!(&*column, &[7, 9, 7, 7, 1, 1]);
        // SAFETY: growth retains the replaced allocation.
        assert_eq!(unsafe { slice::from_raw_parts(block, 6) }, &[7, 9, 7, 7, 1, 1]);

        column.resize(2, 0);
        assert_eq!(&*column, &[7, 9]);
    }

    /// A reader's slice must stay inside one allocation while the writer
    /// grows, shrinks and refills; an overrun shows up under ASan. Miri rejects
    /// the optimistic `&`/`&mut` overlap itself, so it skips this.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn racing_readers_see_a_length_that_fits_their_allocation() {
        use std::{
            sync::{
                Arc,
                atomic::{AtomicBool, Ordering},
            },
            thread,
        };

        struct Shared(std::cell::UnsafeCell<RetainedVec<u64>>);
        // SAFETY: test-only single writer racing optimistic readers.
        unsafe impl Sync for Shared {}

        let shared = Arc::new(Shared(std::cell::UnsafeCell::new(RetainedVec::default())));
        let stop = Arc::new(AtomicBool::new(false));
        let readers: Vec<_> = (0..2)
            .map(|_| {
                let (shared, stop) = (shared.clone(), stop.clone());
                thread::spawn(move || {
                    let mut sum = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        // SAFETY: shared read under the optimistic discipline.
                        let values = unsafe { &*shared.0.get() };
                        sum = values.iter().fold(sum, |s, &x| s.wrapping_add(x));
                    }
                    sum
                })
            })
            .collect();

        for round in 0..50_000u64 {
            // SAFETY: the only writer.
            let values = unsafe { &mut *shared.0.get() };
            values.extend(0..1 + round % 64);
            if round % 7 == 0 {
                values.copy_from_slice(&vec![round; (round % 300) as usize]);
            }
            if round % 50 == 0 {
                values.clear();
            }
        }

        stop.store(true, Ordering::Relaxed);
        for reader in readers {
            reader.join().expect("reader panicked");
        }
    }
}
