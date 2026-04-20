use std::{collections::{HashMap, HashSet}, hash::{BuildHasherDefault, Hash, Hasher}, time::{Duration, Instant}};

use fxhash::FxHasher;

use crate::hash::MessageId;

const ROTATION_INTERVAL: Duration = Duration::from_secs(48);
const FAST_ROTATION_INTERVAL: Duration = Duration::from_secs(12);
const BUCKETS: usize = 16;

pub(crate) struct DedupCache {
    /// Rotating sets of message ids for deduplicating. We must keep
    /// 2 epocks worth of messages = 768s. 
    /// 768s / 16 = 48s per bucket. 
    dedup_sets: [HashSet<MessageId, BuildHasherDefault<IdHasher>>; BUCKETS],
    last_rotation: Instant, 
    current_bucket: usize,
    /// Rotating set of pre-decompress fast hash maps. These are shorter lived 
    /// and used for pre-decompression fast duplicate checking. 
    fast_sets: [HashMap<u64, MessageId, BuildHasherDefault<IdHasher>>; 16],
    last_fast_rotation: Instant, 
    current_fast_bucket: usize,
}

impl DedupCache {
    pub(crate) fn insert(&mut self, fast_hash: u64, msg_id: MessageId) -> bool {
        self.fast_sets[self.current_fast_bucket].insert(fast_hash, msg_id);
        self.dedup_sets[self.current_bucket].insert(msg_id)
    }

    pub(crate) fn contains_id(&self, msg_id: &MessageId) -> bool {
        self.dedup_sets.iter().any(|b| b.contains(msg_id))
    }

    /// Returns a value if the cache DID NOT contain the fast hash. 
    pub(crate) fn contains_fast(&self, data: &[u8]) -> Option<u64> {
        let mut hasher = FxHasher::default();
        data.hash(&mut hasher);
        let fh = hasher.finish();
        self.fast_sets.iter().any(|fs| fs.contains_key(&fh)).then_some(fh)
    }

    pub(crate) fn maybe_rotate(&mut self, now: Instant) {
        if self.last_rotation.elapsed() > ROTATION_INTERVAL {
            self.current_bucket = (self.current_bucket + 1) & (BUCKETS - 1);
            self.dedup_sets[self.current_bucket].clear();
            self.last_rotation = now;
        }
        if self.last_fast_rotation.elapsed() > FAST_ROTATION_INTERVAL {
            self.current_fast_bucket = (self.current_fast_bucket + 1) & (BUCKETS - 1);
            self.fast_sets[self.current_bucket].clear();
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
        }
    }
}

// MessageId = [u8; 20] → take first 8 bytes as u64 for the hash.
// A message id is already a hash, no need ot hash further. 
#[derive(Default)]
struct IdHasher(u64);                                                                                                                                                                                              
impl Hasher for IdHasher {
    fn write(&mut self, bytes: &[u8]) { 
        self.0 = u64::from_ne_bytes(bytes.try_into().unwrap());
    }                                                                                                             
    fn finish(&self) -> u64 { self.0 }                                                                                                                                                                             
}    
