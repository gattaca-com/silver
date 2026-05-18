use std::{
    hash::Hash,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;

/// A rotating list of buckets.
pub struct Wheel<K: Hash + Eq, V, const N: usize> {
    interval: Duration,
    last_rotation: Instant,
    buckets: Box<[FxHashMap<K, V>]>,
    head: usize,
}

impl<K: Hash + Eq, V, const N: usize> Wheel<K, V, N> {
    /// Create a wheel that rotates at the specified interval.
    pub fn new(interval: Duration) -> Self {
        assert!(N.is_power_of_two());
        Self {
            interval,
            last_rotation: Instant::now(),
            buckets: Vec::from_iter((0..N).map(|_| FxHashMap::default())).into_boxed_slice(),
            head: 0,
        }
    }

    pub fn maybe_rotate<F>(&mut self, now: Instant, on_expired: &mut F)
    where
        F: FnMut(K, V),
    {
        if self.last_rotation + self.interval < now {
            self.head = (self.head + 1) & (N - 1);
            self.buckets[self.head].drain().for_each(|(k, v)| on_expired(k, v));
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.buckets[self.head].insert(key, value)
    }

    pub fn contains(&self, key: &K) -> bool {
        self.buckets.iter().any(|b| b.contains_key(key))
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        // tail first iteration
        let mut i = (self.head + 1) & (N - 1);
        while i != self.head {
            let removed = self.buckets[i].remove(key);
            if removed.is_some() {
                return removed;
            }
            i = (self.head + 1) & (N - 1);
        }
        self.buckets[self.head].remove(key)
    }
}
