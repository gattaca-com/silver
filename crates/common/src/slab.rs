use std::ops::Index;

/// Slots sized once and handed out by index; it never allocates after
/// `new`.
pub struct Slab<T> {
    slots: Box<[T]>,
    /// Removes push back at most what was popped, so it never outgrows its
    /// capacity.
    free: Vec<u32>,
}

impl<T: Copy> Slab<T> {
    /// `blank` fills the slots until they are first used.
    pub fn new(len: usize, blank: T) -> Self {
        debug_assert!(len <= u32::MAX as usize);
        let mut free = Vec::with_capacity(len);
        free.extend((0..len as u32).rev());
        Self { slots: vec![blank; len].into_boxed_slice(), free }
    }

    pub fn insert(&mut self, value: T) -> Option<u32> {
        let i = self.free.pop()?;
        self.slots[i as usize] = value;
        Some(i)
    }

    pub fn remove(&mut self, i: u32) {
        debug_assert!((i as usize) < self.slots.len());
        debug_assert!(self.free.len() < self.slots.len());
        self.free.push(i);
    }
}

impl<T> Index<u32> for Slab<T> {
    type Output = T;

    fn index(&self, i: u32) -> &T {
        &self.slots[i as usize]
    }
}
