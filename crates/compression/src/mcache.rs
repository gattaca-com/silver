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
/// Gossipsub v1.1 `gossip_retransmission`: how many times we'll serve the
/// same msg_id to the same peer via IWANT before dropping further requests.
/// Matches rust-libp2p's default.
pub(crate) const GOSSIP_RETRANSMISSION: u16 = 3;

/// Outcome of an IWANT lookup in the mcache.
pub(crate) enum IwantServe {
    /// Message found and retransmission count is under cap — serve `tcache`.
    Serve(TCacheRead),
    /// Message found but the per-(peer, msg_id) cap is exhausted; caller
    /// should emit a `P2pGossipWantOverCap` rather than serving.
    OverCap,
    /// Message not in cache.
    Unknown,
}

#[derive(Clone)]
struct Bucket {
    messages: HashMap<MessageId, TCacheRead, BuildHasherDefault<MessageIdHasher>>,
    ihaves: HashMap<GossipTopic, Vec<MessageId>>,
    /// Per-(peer_conn, msg_id) IWANT serve count. Cleared when the bucket
    /// rotates out, so entries live at most `BUCKETS * ROTATION_INTERVAL`.
    retransmissions: HashMap<(usize, MessageId), u16>,
    tcache_min_seq: u64,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            messages: Default::default(),
            ihaves: Default::default(),
            retransmissions: Default::default(),
            tcache_min_seq: u64::MAX,
        }
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

    /// Attempt to serve an IWANT for `id` to `peer_conn`. Increments the
    /// per-(peer, id) retransmission counter in the bucket that owns the id
    /// and returns `IwantServe::Serve` when still under
    /// `GOSSIP_RETRANSMISSION`, `OverCap` once the cap is reached,
    /// `Unknown` if the id isn't cached.
    pub(crate) fn serve_iwant(&mut self, id: &MessageId, peer_conn: usize) -> IwantServe {
        for bucket in self.buckets.iter_mut() {
            let Some(tcache) = bucket.messages.get(id).copied() else {
                continue;
            };
            let count = bucket.retransmissions.entry((peer_conn, *id)).or_insert(0);
            if *count >= GOSSIP_RETRANSMISSION {
                return IwantServe::OverCap;
            }
            *count += 1;
            return IwantServe::Serve(tcache);
        }
        IwantServe::Unknown
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
            bucket.retransmissions.clear();

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
    fn serve_iwant_respects_retransmission_cap_per_peer() {
        let (mut mcache, mut producer) = mk_mcache();
        let id = MessageId { id: [1u8; 20] };
        let tc = mk_tcache_read(&mut producer);
        mcache.insert(id, GossipTopic::BeaconBlock, tc);

        // Peer 1: first GOSSIP_RETRANSMISSION serves hit; the (N+1)th is over cap.
        for _ in 0..GOSSIP_RETRANSMISSION {
            assert!(matches!(mcache.serve_iwant(&id, 1), IwantServe::Serve(_)));
        }
        assert!(matches!(mcache.serve_iwant(&id, 1), IwantServe::OverCap));

        // Peer 2 is tracked independently — still eligible.
        assert!(matches!(mcache.serve_iwant(&id, 2), IwantServe::Serve(_)));
    }

    #[test]
    fn serve_iwant_unknown_for_missing_id() {
        let (mut mcache, _producer) = mk_mcache();
        let id = MessageId { id: [2u8; 20] };
        assert!(matches!(mcache.serve_iwant(&id, 1), IwantServe::Unknown));
    }
}
