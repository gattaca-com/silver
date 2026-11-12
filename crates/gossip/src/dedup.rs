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
/// Four times the estimated honest peak of a node on every attestation
/// subnet: 2M ids per 768s window, 125k per bucket. The estimate is not
/// measured. A full bucket rotates early, so a flood shortens the window
/// instead of growing memory.
const MAX_BUCKET_IDS: usize = 500_000;
const MAX_FAST_BUCKET_IDS: usize =
    MAX_BUCKET_IDS / (ROTATION_INTERVAL.as_secs() / FAST_ROTATION_INTERVAL.as_secs()) as usize;

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
        // Before the insert, so a `remove` that follows finds its bucket.
        if self.dedup_sets[self.current_bucket].len() >= MAX_BUCKET_IDS ||
            self.fast_sets[self.current_fast_bucket].len() >= MAX_FAST_BUCKET_IDS
        {
            self.rotate_full_buckets();
        }
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
            self.rotate(now);
        }
        if self.last_fast_rotation.elapsed() > FAST_ROTATION_INTERVAL {
            self.rotate_fast(now);
        }
    }

    #[cold]
    fn rotate_full_buckets(&mut self) {
        let now = Instant::now();
        if self.dedup_sets[self.current_bucket].len() >= MAX_BUCKET_IDS {
            silver_log::warn!(
                window = ?now.duration_since(self.last_rotation) * BUCKETS as u32,
                "gossip dedup bucket full; rotating early"
            );
            self.rotate(now);
        }
        if self.fast_sets[self.current_fast_bucket].len() >= MAX_FAST_BUCKET_IDS {
            self.rotate_fast(now);
        }
    }

    fn rotate(&mut self, now: Instant) {
        self.current_bucket = (self.current_bucket + 1) & (BUCKETS - 1);
        self.dedup_sets[self.current_bucket].clear();
        self.last_rotation = now;
    }

    fn rotate_fast(&mut self, now: Instant) {
        self.current_fast_bucket = (self.current_fast_bucket + 1) & (BUCKETS - 1);
        self.fast_sets[self.current_fast_bucket].clear();
        self.last_fast_rotation = now;
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

    fn id(n: u64) -> MessageId {
        let mut id = MessageId::default();
        id.id[..8].copy_from_slice(&n.to_le_bytes());
        id
    }

    #[test]
    fn a_full_bucket_rotates_early() {
        let mut cache = DedupCache::default();
        let inserted = MAX_BUCKET_IDS as u64 + 1;
        for n in 0..inserted {
            assert!(cache.insert(n, id(n)));
        }

        assert_eq!(cache.current_bucket, 1);
        assert_eq!(cache.dedup_sets[0].len(), MAX_BUCKET_IDS);
        assert!(cache.fast_sets.iter().all(|set| set.len() <= MAX_FAST_BUCKET_IDS));
        assert!(cache.has(&id(0)), "earlier buckets keep their ids");

        cache.remove(inserted - 1, &id(inserted - 1));
        assert!(!cache.has(&id(inserted - 1)), "a remove finds the bucket its insert used");
    }

    #[test]
    fn fast_hash_is_keyed_per_cache() {
        let (a, b) = (DedupCache::default(), DedupCache::default());
        assert_ne!(a.contains_fast("topic", b"payload"), b.contains_fast("topic", b"payload"));
    }
}
