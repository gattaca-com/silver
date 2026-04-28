use std::{
    collections::HashMap,
    hash::BuildHasherDefault,
    slice,
    time::{Duration, Instant},
};

use silver_common::{GossipTopic, MessageId, MessageIdHasher, TCacheRead, TRandomAccess};

/// Another rotating bucket cache. Each bucket optionally maps a message id to
/// TCacheRead. This cache maintains a tail of the TCache containing the cached
/// messages.
const ROTATION_INTERVAL: Duration = Duration::from_millis(700);
const BUCKETS: usize = 12;
const IHAVE_BUCKETS: usize = 3;
const MAX_IHAVES_PER_TOPIC: usize = 500;
const IHAVE_GENERATION_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone)]
struct Bucket {
    messages: HashMap<MessageId, TCacheRead, BuildHasherDefault<MessageIdHasher>>,
    ihaves: HashMap<GossipTopic, Vec<MessageId>>,
    tcache_min_seq: u64,
}

impl Default for Bucket {
    fn default() -> Self {
        Self { messages: Default::default(), ihaves: Default::default(), tcache_min_seq: u64::MAX }
    }
}

pub(crate) struct MessageCache {
    buckets: Box<[Bucket]>,
    cache_consumer: TRandomAccess,
    current_bucket: usize,
    last_rotation: Instant,
    last_ihaves: Instant,
}

impl MessageCache {
    pub(crate) fn new(cache_consumer: TRandomAccess) -> Self {
        Self {
            buckets: vec![Bucket::default(); BUCKETS].into_boxed_slice(),
            cache_consumer,
            current_bucket: 0,
            last_rotation: Instant::now(),
            last_ihaves: Instant::now(),
        }
    }

    pub(crate) fn insert(&mut self, id: MessageId, topic: GossipTopic, tcache: TCacheRead) {
        let bucket = &mut self.buckets[self.current_bucket];

        // TODO could have a preallocated ring of max ihaves per gossip topic.
        bucket.ihaves.entry(topic).and_modify(|v| v.push(id)).or_insert_with(|| vec![id]);
        bucket.tcache_min_seq = bucket.tcache_min_seq.min(tcache.seq());
        bucket.messages.insert(id, tcache);
    }

    pub(crate) fn has(&self, id: &MessageId) -> bool {
        self.buckets.iter().any(|b| b.messages.contains_key(id))
    }

    pub(crate) fn get(&self, id: &MessageId) -> Option<TCacheRead> {
        self.buckets.iter().find_map(|b| b.messages.get(id)).copied()
    }

    pub(crate) fn get_ihaves(
        &self,
        topic: &GossipTopic,
    ) -> impl ExactSizeIterator<Item = &MessageId> {
        IHaveIterator::new(*topic, self)
    }

    pub(crate) fn topics(&self) -> impl Iterator<Item = &GossipTopic> {
        self.buckets.iter().flat_map(|b| b.ihaves.keys())
    }

    pub(crate) fn generate_ihaves(&mut self, now: Instant) -> bool {
        if self.last_ihaves.elapsed() > IHAVE_GENERATION_INTERVAL {
            self.last_ihaves = now;
            true
        } else {
            false
        }
    }

    pub(crate) fn maybe_rotate(&mut self, now: Instant) {
        if self.last_rotation.elapsed() > ROTATION_INTERVAL {
            self.current_bucket = (self.current_bucket + 1) % BUCKETS;

            // oldest bucket has the min TCache seq
            let bucket = &mut self.buckets[self.current_bucket];
            self.cache_consumer.set_tail(bucket.tcache_min_seq);
            bucket.tcache_min_seq = u64::MAX;
            bucket.messages.clear();
            bucket.ihaves.clear();

            self.last_rotation = now;
        }
    }
}

struct IHaveIterator<'a> {
    topic: GossipTopic,
    count: usize,
    len: usize,
    bucket: usize,
    buckets_left: usize,
    mcache: &'a MessageCache,
    iter: Option<slice::Iter<'a, MessageId>>,
}

impl<'a> IHaveIterator<'a> {
    fn new(topic: GossipTopic, mcache: &'a MessageCache) -> Self {
        let mut len = 0;
        for i in 0..3 {
            let idx = (mcache.current_bucket + i) % BUCKETS;
            len += mcache.buckets[idx].ihaves.get(&topic).map(|v| v.len()).unwrap_or_default();
        }
        let iter = mcache.buckets[mcache.current_bucket].ihaves.get(&topic).map(|v| v.iter());
        Self {
            topic,
            count: 0,
            len: len.min(MAX_IHAVES_PER_TOPIC),
            bucket: mcache.current_bucket,
            buckets_left: IHAVE_BUCKETS - 1,
            iter,
            mcache,
        }
    }
}

impl<'a> Iterator for IHaveIterator<'a> {
    type Item = &'a MessageId;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.iter.as_mut().and_then(|i| i.next()) {
                Some(id) if self.count < MAX_IHAVES_PER_TOPIC => {
                    self.count += 1;
                    return Some(id)
                }
                Some(_) => return None,
                None if self.buckets_left == 0 => return None,
                None => {
                    self.buckets_left -= 1;
                    self.bucket = (self.bucket + 1) % BUCKETS;
                    self.iter =
                        self.mcache.buckets[self.bucket].ihaves.get(&self.topic).map(|v| v.iter());
                }
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len - self.count, Some(self.len - self.count))
    }
}

impl<'a> ExactSizeIterator for IHaveIterator<'a> {}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use silver_common::{MessageId, TCache};

    use super::*;

    fn mk_mcache() -> (MessageCache, silver_common::TProducer) {
        let producer = TCache::producer(1 << 14);
        let consumer = producer.cache_ref().random_access().unwrap();
        (MessageCache::new(consumer), producer)
    }

    fn mk_tcache_read(producer: &mut silver_common::TProducer) -> TCacheRead {
        let mut reservation = producer.reserve(64, true).unwrap();
        reservation.write_all(&[0u8; 64]).unwrap();
        reservation.read()
    }

    #[test]
    fn serve_iwant() {
        let (mut mcache, mut producer) = mk_mcache();
        let id = MessageId { id: [1u8; 20] };
        let tc = mk_tcache_read(&mut producer);
        mcache.insert(id, GossipTopic::BeaconBlock, tc);
        assert!(matches!(mcache.get(&id), Some(_)));
    }

    #[test]
    fn serve_iwant_unknown_for_missing_id() {
        let (mcache, _producer) = mk_mcache();
        let id = MessageId { id: [2u8; 20] };
        assert!(matches!(mcache.get(&id), None));
    }
}
