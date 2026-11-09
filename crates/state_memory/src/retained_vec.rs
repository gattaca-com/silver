use std::{
    fmt,
    ops::{Deref, DerefMut},
    slice,
};

use crate::RetiredColumns;

/// Growth retains the old allocation; clearing and copying preserve retirement
/// history. The owner must keep this wrapper alive while readers might
/// reference any of its allocations.
pub struct RetainedVec<T: Copy> {
    values: Vec<T>,
    retired: RetiredColumns,
}

impl<T: Copy> Default for RetainedVec<T> {
    fn default() -> Self {
        Self { values: Vec::new(), retired: RetiredColumns::default() }
    }
}

impl<T: Copy> From<Vec<T>> for RetainedVec<T> {
    fn from(values: Vec<T>) -> Self {
        Self { values, retired: RetiredColumns::default() }
    }
}

impl<T: Copy> FromIterator<T> for RetainedVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        Self::from(Vec::from_iter(iter))
    }
}

impl<T: Copy> RetainedVec<T> {
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }

    #[inline]
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// # Safety
    /// Every element below `len` must be initialized, and `len` must fit the
    /// allocation.
    #[inline]
    pub unsafe fn set_len(&mut self, len: usize) {
        assert!(len <= self.values.capacity());
        // SAFETY: initialization is the caller's obligation; capacity is checked above.
        unsafe { self.values.set_len(len) };
    }
}

impl<T: Copy + Send + Sync + 'static> RetainedVec<T> {
    fn grown_capacity(&self, required: usize) -> usize {
        required.max(self.values.capacity().saturating_mul(2)).max(4)
    }

    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        let required = self.values.len().checked_add(additional).expect("capacity overflow");
        if required > self.values.capacity() {
            let mut grown = Vec::with_capacity(self.grown_capacity(required));
            grown.extend_from_slice(&self.values);
            self.replace_allocation(grown);
        }
    }

    fn replace_allocation(&mut self, replacement: Vec<T>) {
        if self.values.capacity() == 0 {
            self.values = replacement;
        } else {
            self.retired.replace(&mut self.values, replacement);
        }
    }

    pub fn copy_from_slice(&mut self, source: &[T]) {
        if source.len() > self.values.capacity() {
            let mut grown = Vec::with_capacity(self.grown_capacity(source.len()));
            grown.extend_from_slice(source);
            self.replace_allocation(grown);
        } else {
            self.values.clear();
            self.values.extend_from_slice(source);
        }
    }

    #[inline]
    pub fn push(&mut self, value: T) {
        self.reserve(1);
        self.values.push(value);
    }
}

impl<T: Copy + Send + Sync + 'static> Extend<T> for RetainedVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        self.reserve(iter.size_hint().0);
        for value in iter {
            self.push(value);
        }
    }
}

impl<T: Copy + Send + Sync + 'static> Clone for RetainedVec<T> {
    fn clone(&self) -> Self {
        Self::from(self.values.clone())
    }

    fn clone_from(&mut self, source: &Self) {
        self.copy_from_slice(&source.values);
    }
}

impl<T: Copy> Deref for RetainedVec<T> {
    type Target = [T];

    #[inline]
    fn deref(&self) -> &[T] {
        &self.values
    }
}

impl<T: Copy> DerefMut for RetainedVec<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut [T] {
        &mut self.values
    }
}

impl<'a, T: Copy> IntoIterator for &'a RetainedVec<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.iter()
    }
}

impl<T: Copy + fmt::Debug> fmt::Debug for RetainedVec<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.values.fmt(f)
    }
}

impl<T: Copy + PartialEq> PartialEq for RetainedVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
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
}
