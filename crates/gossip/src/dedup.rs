use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasher,
    time::{Duration, Instant},
};

use foldhash::fast::RandomState;
use silver_common::{MessageId, MessageIdHashState};

const ROTATION_INTERVAL: Duration = Duration::from_secs(48);
const FAST_ROTATION_INTERVAL: Duration = Duration::from_secs(12);
const BUCKETS: usize = 16;

pub(crate) struct DedupCache {
    /// Rotating sets of message ids for deduplicating. We must keep
    /// 2 epocks worth of messages = 768s.
    /// 768s / 16 = 48s per bucket.
    dedup_sets: Box<[HashSet<MessageId, MessageIdHashState>; BUCKETS]>,
    last_rotation: Instant,
    current_bucket: usize,
    /// Rotating set of pre-decompress fast hash maps. These are shorter lived
    /// and used for pre-decompression fast duplicate checking.
    fast_sets: Box<[HashMap<u64, MessageId, RandomState>; 16]>,
    last_fast_rotation: Instant,
    current_fast_bucket: usize,
    // Keyed, because a hit counts as a duplicate without comparing content.
    fast_hash_state: RandomState,
}

impl DedupCache {
    pub(crate) fn insert(&mut self, fast_hash: u64, msg_id: MessageId) -> bool {
        self.fast_sets[self.current_fast_bucket].insert(fast_hash, msg_id);
        self.dedup_sets[self.current_bucket].insert(msg_id)
    }

    pub(crate) fn remove(&mut self, fast_hash: u64, msg_id: &MessageId) {
        self.fast_sets[self.current_fast_bucket].remove(&fast_hash);
        self.dedup_sets[self.current_bucket].remove(msg_id);
    }

    /// Returns `Ok(fh)` if the hash was NOT found (i.e. message is new
    /// and the caller should proceed with processing), `Err(msg_id)` with
    /// the stored canonical id if it was already present across any
    /// rotation bucket (= duplicate).
    pub(crate) fn contains_fast(&self, topic: &str, data: &[u8]) -> Result<u64, MessageId> {
        let fh = self.fast_hash_state.hash_one((topic, data));
        match self.fast_sets.iter().find_map(|fs| fs.get(&fh)) {
            Some(msg_id) => Err(*msg_id),
            None => Ok(fh),
        }
    }

    pub(crate) fn has(&self, msg_id: &MessageId) -> bool {
        self.dedup_sets.iter().any(|s| s.contains(msg_id))
    }

    pub(crate) fn maybe_rotate(&mut self, now: Instant) {
        if self.last_rotation.elapsed() > ROTATION_INTERVAL {
            self.current_bucket = (self.current_bucket + 1) & (BUCKETS - 1);
            self.dedup_sets[self.current_bucket].clear();
            self.last_rotation = now;
        }
        if self.last_fast_rotation.elapsed() > FAST_ROTATION_INTERVAL {
            self.current_fast_bucket = (self.current_fast_bucket + 1) & (BUCKETS - 1);
            self.fast_sets[self.current_fast_bucket].clear();
            self.last_fast_rotation = now;
        }
    }
}

impl Default for DedupCache {
    fn default() -> Self {
        Self {
            dedup_sets: Default::default(),
            last_rotation: Instant::now(),
            current_bucket: 0,
            fast_sets: Default::default(),
            last_fast_rotation: Instant::now(),
            current_fast_bucket: 0,
            fast_hash_state: RandomState::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_hash_is_keyed_per_cache() {
        let (a, b) = (DedupCache::default(), DedupCache::default());
        assert_ne!(a.contains_fast("topic", b"payload"), b.contains_fast("topic", b"payload"));
    }
}
