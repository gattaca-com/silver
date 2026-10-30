use std::{
    hash::{BuildHasher, Hash, Hasher},
    marker::PhantomData,
};

pub struct CountingWitherFilter<T, S, const N: usize>
where
    T: Copy + Default + Hash + Eq,
    S: Default + BuildHasher,
{
    slots: Box<[(T, u32)]>,
    hash_state: S,
}

impl<T, S, const N: usize> Default for CountingWitherFilter<T, S, N>
where
    T: Copy + Default + Hash + Eq,
    S: Default + BuildHasher,
{
    fn default() -> Self {
        assert!(N.is_power_of_two());
        Self { slots: vec![(T::default(), 0); N].into_boxed_slice(), hash_state: S::default() }
    }
}

impl<T, S, const N: usize> CountingWitherFilter<T, S, N>
where
    T: Copy + Default + Hash + Eq,
    S: Default + BuildHasher,
{
    /// Insert or update count for the specified key, returning the previous
    /// value.
    pub fn upsert(&mut self, val: T) -> u32 {
        let index = self.index(&val);

        if val == self.slots[index].0 {
            let prev = self.slots[index].1;
            self.slots[index].1 = prev + 1;
            prev
        } else {
            // collision
            self.slots[index] = (val, 1);
            0
        }
    }

    pub fn contains(&self, val: &T) -> bool {
        let index = self.index(val);
        self.slots[index].0 == *val
    }

    fn index(&self, val: &T) -> usize {
        (self.hash_state.hash_one(val) as usize) & (N - 1)
    }
}

pub struct WitherFilter<T, H, const N: usize>
where
    T: Copy + Hash + Eq,
    H: Default + Hasher,
{
    slots: Box<[T]>,
    default_value: T,
    _hasher: PhantomData<H>,
}

impl<T, H, const N: usize> WitherFilter<T, H, N>
where
    T: Copy + Hash + Eq,
    H: Default + Hasher,
{
    pub fn new(default_value: T) -> Self {
        assert!(N.is_power_of_two());
        Self {
            slots: vec![default_value; N].into_boxed_slice(),
            default_value,
            _hasher: PhantomData,
        }
    }

    /// Insert the specified key, return `true` if not already present.
    pub fn insert(&mut self, val: T) -> bool {
        let index = self.index(&val);
        if val == self.slots[index] {
            false
        } else {
            self.slots[index] = val;
            true
        }
    }

    pub fn contains(&self, val: &T) -> bool {
        let index = self.index(val);
        self.slots[index] == *val
    }

    pub fn remove(&mut self, val: &T) -> bool {
        let index = self.index(val);
        if *val == self.slots[index] {
            self.slots[index] = self.default_value;
            true
        } else {
            false
        }
    }

    fn index(&self, val: &T) -> usize {
        let mut hasher = H::default();
        val.hash(&mut hasher);
        let hash = hasher.finish();
        (hash as usize) & (N - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageId, MessageIdHashState};

    type F = CountingWitherFilter<MessageId, MessageIdHashState, 4096>;

    fn id(b0: u8, b1: u8, tail: u8) -> MessageId {
        let mut bytes = [tail; 20];
        bytes[0] = b0;
        bytes[1] = b1;
        MessageId { id: bytes }
    }

    #[test]
    fn upsert_returns_previous_count_for_same_key() {
        let mut f = F::default();
        let a = id(0x42, 0x07, 0xAA);
        // 1st: prev=0 (slot starts empty). 2nd: prev=1. 3rd: prev=2.
        assert_eq!(f.upsert(a), 0);
        assert_eq!(f.upsert(a), 1);
        assert_eq!(f.upsert(a), 2);
        assert!(f.contains(&a));
    }

    #[test]
    fn contains_returns_false_for_unseen() {
        let f = F::default();
        assert!(!f.contains(&id(0x42, 0x07, 0xAA)));
    }

    #[test]
    fn collision_overwrites_old_key() {
        let mut f = F::default();
        let a = id(0x42, 0x07, 0x11);
        let b = (0..=u8::MAX)
            .flat_map(|b0| (0..=u8::MAX).map(move |b1| id(b0, b1, 0x22)))
            .find(|b| f.index(b) == f.index(&a))
            .unwrap();

        f.upsert(a);
        f.upsert(a);
        assert!(f.contains(&a));

        // Colliding insert: returns 0 (treats as fresh) and evicts a.
        assert_eq!(f.upsert(b), 0);
        assert!(!f.contains(&a), "a should have been evicted by colliding b");
        assert!(f.contains(&b));
    }

    #[test]
    fn non_colliding_keys_are_independent() {
        let mut f = F::default();
        let a = id(0x42, 0x07, 0xAA);
        let b =
            (0..=u8::MAX).map(|b0| id(b0, 0x08, 0xBB)).find(|b| f.index(b) != f.index(&a)).unwrap();
        f.upsert(a);
        f.upsert(b);
        f.upsert(b);
        assert!(f.contains(&a));
        assert!(f.contains(&b));
    }
}
