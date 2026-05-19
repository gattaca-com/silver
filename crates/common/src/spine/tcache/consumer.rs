use std::{ops::Deref, sync::atomic::Ordering};

use flux::timing::Nanos;

use crate::{GossipMsgOut, TCacheError, TCacheRef};

/// Reader for a TCache msg
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TCacheRead {
    pub(super) tcache: TCacheRef,
    pub(super) seq: u64,
}

impl TCacheRead {
    /// Returns the length the data buffer.
    #[inline]
    pub fn len(&self) -> Result<usize, TCacheError> {
        let (buffer, ..) = self.tcache.read(self.seq)?;
        Ok(buffer.len())
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len().map(|len| len == 0).unwrap_or(true)
    }

    #[inline]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    #[inline]
    pub fn cache_ref(&self) -> TCacheRef {
        self.tcache
    }

    #[inline]
    pub fn cache_ts(&self) -> Result<Nanos, TCacheError> {
        self.tcache.slot_ts(self.seq)
    }
}

impl From<GossipMsgOut> for TCacheRead {
    fn from(value: GossipMsgOut) -> Self {
        value.tcache
    }
}

/// Tailing consumer. Reads all messages in a TCache, in order.
#[derive(Debug)]
pub struct Consumer {
    pub(super) cache: TCacheRef,
    pub(super) index: usize,
    pub(super) seq: u64,
    pub(super) next_seq: u64,
}

impl Consumer {
    /// Read next data in the buffer with write timestamp.
    pub fn read(&mut self) -> Result<(&[u8], Nanos), TCacheError> {
        loop {
            let (data, ts) = self.cache.read(self.seq).map(|(data, inc, ts)| {
                self.next_seq = self.seq + inc;
                (data, ts)
            })?;

            if !data.is_empty() {
                return Ok((data, ts));
            }
            self.seq = self.next_seq;
        }
    }

    /// Release all data read so far. Should be called often, not necessarily
    /// after each read.
    pub fn free(&mut self) {
        //tracing::warn!("consumer free: {}", self.seq);
        self.seq = self.next_seq;
        self.cache.head.tails[self.index].store(self.seq, Ordering::Release);
    }
}

/// Consumer that supports random access to messages between its tail and buffer
/// head. Tail is tracked externally.  
pub struct RandomAccessConsumer {
    pub(super) cache: TCacheRef,
    pub(super) index: usize,
    // Mapping of active / enqueued sequence numbers and reader counts.
    pub(super) active: Buckets,
    // If set `free` is called on drop of every acquired read, ensuring the
    // consumer tail is published.
    pub(super) auto_free: bool,
}

impl RandomAccessConsumer {
    pub fn acquire(&mut self, read: TCacheRead) -> AcquiredRead {
        self.active.acquire(read.seq);
        AcquiredRead { consumer: self as *const Self, read }
    }

    /// Should be called periodically to publish the tail offset so it is
    /// visible to the Producer.
    pub fn free(&self) {
        let tail = self.active.tail_seq;
        self.cache.head.tails[self.index].store(tail, Ordering::Release);
    }

    fn release(&mut self, seq: u64) {
        self.active.release(seq);
    }
}

/// Automatically releases RandomConsumer seq on drop.
/// Can only be used within the same thread as the creating consumer.
///
/// SAFETY: `consumer` points into the owning tile, which keeps it alive
/// for the lifetime of every `AcquiredRead` it hands out — guaranteed by
/// drop-order discipline (see NetworkTile field ordering) - order containers
/// of reads before consumer.
#[derive(Clone, Debug)]
pub struct AcquiredRead {
    consumer: *const RandomAccessConsumer,
    pub read: TCacheRead,
}

impl AcquiredRead {
    pub fn buffer(&self) -> Result<(&[u8], Nanos), TCacheError> {
        let consumer = unsafe { &*self.consumer };
        if self.read.seq < consumer.active.tail_seq {
            return Err(TCacheError::StaleSeq {
                seq: self.read.seq,
                tail: consumer.active.tail_seq,
            });
        }
        consumer.cache.read(self.read.seq).map(|(data, _, ts)| (data, ts))
    }
}

impl Deref for AcquiredRead {
    type Target = TCacheRead;

    fn deref(&self) -> &Self::Target {
        &self.read
    }
}

unsafe impl Send for AcquiredRead {}

impl Drop for AcquiredRead {
    fn drop(&mut self) {
        // SAFETY: consumer outlives self by tile invariant.
        // SAFETY: the consumer lives in a single tile and access across self and
        // consumer is single threaded - so safe to coerce to mutable access.
        unsafe {
            let consumer = &mut *(self.consumer as *mut RandomAccessConsumer);
            consumer.release(self.read.seq());
            if consumer.auto_free {
                consumer.free();
            }
        }
    }
}

pub(super) struct Buckets {
    buckets: Box<[u16]>,
    tail_seq: u64,
    head_seq: u64,
    bucket_size: u64,
    bucket_shift: u64,
    // max difference between head and tail, before 'forced' eviction
    lag_threshold: u64,
}

impl Buckets {
    pub(super) fn new(bucket_size: u64, cache_capacity: u64) -> Self {
        // % of capacity occupancy that triggers evictions
        const LAG_PERCENT: f64 = 0.9;

        assert!(bucket_size.is_power_of_two());
        let mut number_of_buckets = cache_capacity / bucket_size;
        if !cache_capacity.is_multiple_of(bucket_size) || !number_of_buckets.is_power_of_two() {
            number_of_buckets = number_of_buckets.next_power_of_two();
        }
        Self {
            buckets: vec![0; number_of_buckets as usize].into_boxed_slice(),
            tail_seq: u64::MAX,
            head_seq: 0,
            bucket_size,
            bucket_shift: bucket_size.trailing_zeros() as u64,
            lag_threshold: (LAG_PERCENT * (cache_capacity as f64)) as u64,
        }
    }

    fn acquire(&mut self, seq: u64) {
        let bucket_idx = self.index(seq);
        self.buckets[bucket_idx] += 1;

        self.head_seq = self.head_seq.max(seq);

        if self.tail_seq == u64::MAX {
            self.tail_seq = seq & !(self.bucket_size - 1);
        }

        // check lagging
        if self.head_seq - self.tail_seq > self.lag_threshold {
            let mut tail_idx = self.index(self.tail_seq);
            self.buckets[tail_idx] = 0;

            while self.buckets[tail_idx] == 0 && (self.tail_seq + self.bucket_size) < self.head_seq
            {
                tail_idx = (tail_idx + 1) & (self.buckets.len() - 1);
                self.tail_seq += self.bucket_size;
            }
        }
    }

    fn release(&mut self, seq: u64) {
        if seq < self.tail_seq {
            return;
        }

        let mut bucket_idx = self.index(seq);
        self.buckets[bucket_idx] = self.buckets[bucket_idx].saturating_sub(1);

        let mut bucket_tail_seq = seq & !(self.bucket_size - 1);
        if bucket_tail_seq == self.tail_seq {
            while self.buckets[bucket_idx] == 0 &&
                (bucket_tail_seq + self.bucket_size) < self.head_seq
            {
                bucket_idx = (bucket_idx + 1) & (self.buckets.len() - 1);
                bucket_tail_seq += self.bucket_size;
            }
            self.tail_seq = bucket_tail_seq;
        }
    }

    fn index(&self, seq: u64) -> usize {
        ((seq >> self.bucket_shift) as usize) & (self.buckets.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        thread,
        time::{Duration, Instant},
    };

    use super::*;
    use crate::spine::tcache::{Producer, TCache, producer::TCacheProducer};

    // ---- Buckets algorithm ----

    #[test]
    fn buckets_acquire_initialises_tail_to_bucket_boundary() {
        let mut b = Buckets::new(64, 1024);
        b.acquire(100);
        // 100 lives in bucket 1 (64..128). Tail is bucket-aligned to 64.
        assert_eq!(b.tail_seq, 64);
        assert_eq!(b.head_seq, 100);
    }

    #[test]
    fn buckets_release_advances_tail_when_head_is_ahead() {
        let mut b = Buckets::new(64, 1024);
        b.acquire(0); // bucket 0, tail = 0
        b.acquire(200); // bucket 3, head = 200
        assert_eq!(b.tail_seq, 0);
        b.release(0); // bucket 0 empties; head far enough ahead to advance
        assert!(b.tail_seq > 0, "tail did not advance: {}", b.tail_seq);
        assert!(b.tail_seq <= 200);
    }

    #[test]
    fn buckets_out_of_order_release_keeps_holders_alive() {
        let mut b = Buckets::new(64, 1024);
        b.acquire(0); // bucket 0
        b.acquire(100); // bucket 1
        b.acquire(300); // bucket 4
        // Release the middle first — bucket 1 empties but tail is still at 0
        b.release(100);
        assert_eq!(b.tail_seq, 0, "tail moved while bucket 0 still held");
        // Release the head; tail jumps past bucket 0 and bucket 1 (both empty)
        b.release(0);
        assert!(b.tail_seq >= 128, "tail did not jump: {}", b.tail_seq);
    }

    #[test]
    fn buckets_lag_threshold_force_evicts_held_tail() {
        // threshold = 0.9 * 1024 = 921
        let mut b = Buckets::new(64, 1024);
        b.acquire(0); // hold bucket 0; never released
        let tail_before = b.tail_seq;
        // Bump head past lag threshold with a fresh acquire.
        b.acquire(1000);
        assert!(
            b.tail_seq > tail_before,
            "lag eviction did not advance tail (tail={})",
            b.tail_seq
        );
    }

    #[test]
    fn buckets_release_below_tail_is_noop() {
        let mut b = Buckets::new(64, 1024);
        b.acquire(0);
        b.acquire(1000); // forces tail past bucket 0
        let tail_after_eviction = b.tail_seq;
        b.release(0); // 0 is now below tail — must not corrupt state
        assert_eq!(b.tail_seq, tail_after_eviction);
    }

    // ---- RandomAccessConsumer integration ----

    fn write_marker(p: &mut Producer, len: usize, marker: u8) -> TCacheRead {
        let mut r = p.reserve(len, true).expect("reserve");
        let read = r.read();
        {
            let buf = r.buffer().expect("buffer");
            buf.fill(marker);
        }
        r.increment_offset(len);
        read
    }

    /// Produce → acquire → read → drop. Buffer is readable while held;
    /// the guard's Drop calls release without panicking.
    #[test]
    fn acquire_release_cycle_reads_buffer() {
        let mut producer = TCache::producer(1 << 16);
        let mut consumer = producer.cache_ref().random_access(false).unwrap();
        producer.publish_head();

        let reads: Vec<TCacheRead> =
            (0..4).map(|i| write_marker(&mut producer, 256, i as u8)).collect();

        let acquired: Vec<AcquiredRead> = reads.iter().map(|&r| consumer.acquire(r)).collect();
        for (i, a) in acquired.iter().enumerate() {
            let (buf, _) = a.buffer().expect("buffer while held");
            assert_eq!(buf.len(), 256);
            assert!(buf.iter().all(|&b| b == i as u8), "marker {i} corrupt");
        }
        // All guards drop here; release() should run for each without panic.
        drop(acquired);
        consumer.free();
    }

    /// A consumer that keeps acquiring without ever releasing must not
    /// stall the producer — the Buckets lag-threshold force-evicts the
    /// tail so the producer can reclaim space.
    #[test]
    fn lagging_consumer_does_not_block_producer() {
        const CACHE: usize = 1 << 20; // 1 MB
        const MSG_LEN: usize = 8 * 1024; // 8 KB
        // 1 MB / 8 KB ≈ 128 slots; lag threshold = 0.9 MB. Drive far more
        // than the cache capacity — without eviction the producer would
        // block at ~slot 128 forever.
        const TOTAL: usize = 1000;

        let mut producer = TCache::producer(CACHE);
        let mut consumer = producer.cache_ref().random_access(false).unwrap();
        producer.publish_head();

        let mut held: Vec<AcquiredRead> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut produced = 0;
        while produced < TOTAL {
            assert!(
                Instant::now() < deadline,
                "producer stalled at msg {produced}; lag eviction failed"
            );
            if let Some(mut r) = producer.reserve(MSG_LEN, true) {
                let read = r.read();
                r.buffer().unwrap().fill(0xab);
                r.increment_offset(MSG_LEN);
                // Consumer "lags": acquires but never drops the guard.
                held.push(consumer.acquire(read));
                // Publish updated tail so the producer can see eviction.
                consumer.free();
                produced += 1;
            } else {
                thread::yield_now();
            }
        }
        assert_eq!(produced, TOTAL);
    }

    /// Once the lag threshold has force-evicted past an acquired seq, that
    /// guard's `buffer()` must surface a `StaleSeq` error rather than
    /// hand out a slice into a slot that has since been reused.
    #[test]
    fn stale_acquired_read_returns_error() {
        const CACHE: usize = 1 << 20;
        const MSG_LEN: usize = 8 * 1024;

        let mut producer = TCache::producer(CACHE);
        let mut consumer = producer.cache_ref().random_access(false).unwrap();
        producer.publish_head();

        // The "victim" — held across heavy downstream production.
        let victim = {
            let read = write_marker(&mut producer, MSG_LEN, 0xee);
            consumer.acquire(read)
        };
        assert!(victim.buffer().is_ok(), "victim buffer should be readable before eviction");

        // Drive enough production + acquires to cross the lag threshold
        // and force the victim's seq out of the tail.
        for _ in 0..200 {
            let mut r = loop {
                if let Some(r) = producer.reserve(MSG_LEN, true) {
                    break r;
                }
                thread::yield_now();
            };
            let read = r.read();
            r.buffer().unwrap().fill(0x11);
            r.increment_offset(MSG_LEN);
            // Transient acquire — drop the guard immediately so only the
            // victim remains as a held seq.
            let _ = consumer.acquire(read);
            consumer.free();
        }

        match victim.buffer() {
            Err(TCacheError::StaleSeq { seq, tail }) => {
                assert!(seq < tail, "StaleSeq with seq {seq} not below tail {tail}");
            }
            other => panic!("expected StaleSeq, got {other:?}"),
        }
    }
}
