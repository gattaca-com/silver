use std::{
    hash::{Hash, Hasher},
    marker::PhantomData,
};

pub struct CountingWitherFilter<T, H, const N: usize>
where
    T: Copy + Default + Hash + Eq,
    H: Default + Hasher,
{
    slots: Box<[(T, u32)]>,
    _hasher: PhantomData<H>,
}

impl<T, H, const N: usize> CountingWitherFilter<T, H, N>
where
    T: Copy + Default + Hash + Eq,
    H: Default + Hasher,
{
    pub fn new() -> Self {
        assert!(N.is_power_of_two());
        Self { slots: vec![(T::default(), 0); N].into_boxed_slice(), _hasher: PhantomData }
    }

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
        let mut hasher = H::default();
        val.hash(&mut hasher);
        let hash = hasher.finish();
        (hash as usize) & (N - 1)
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{MessageId, MessageIdHasher};

    use super::*;

    type F = CountingWitherFilter<MessageId, MessageIdHasher, 4096>;

    fn id(b0: u8, b1: u8, tail: u8) -> MessageId {
        let mut bytes = [tail; 20];
        bytes[0] = b0;
        bytes[1] = b1;
        MessageId { id: bytes }
    }

    #[test]
    fn upsert_returns_previous_count_for_same_key() {
        let mut f = F::new();
        let a = id(0x42, 0x07, 0xAA);
        // 1st: prev=0 (slot starts empty). 2nd: prev=1. 3rd: prev=2.
        assert_eq!(f.upsert(a), 0);
        assert_eq!(f.upsert(a), 1);
        assert_eq!(f.upsert(a), 2);
        assert!(f.contains(&a));
    }

    #[test]
    fn contains_returns_false_for_unseen() {
        let f = F::new();
        assert!(!f.contains(&id(0x42, 0x07, 0xAA)));
    }

    #[test]
    fn collision_overwrites_old_key() {
        // MessageIdHasher reads bytes[0..8] as native-endian u64; index is the
        // low 12 bits of that. On x86_64 (LE) that's all of byte[0] + low 4
        // bits of byte[1]. Two ids sharing those bits collide.
        let mut f = F::new();
        let a = id(0x42, 0x07, 0x11);
        let b = id(0x42, 0x07, 0x22);
        assert_ne!(a, b);

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
        let mut f = F::new();
        // Different byte[0] → different low-12-bit index.
        let a = id(0x42, 0x07, 0xAA);
        let b = id(0x99, 0x08, 0xBB);
        f.upsert(a);
        f.upsert(b);
        f.upsert(b);
        assert!(f.contains(&a));
        assert!(f.contains(&b));
    }
}
