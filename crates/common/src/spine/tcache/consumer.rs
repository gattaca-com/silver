use std::{ops::Deref, sync::atomic::Ordering};

use flux::{Timer, timing::Nanos};

use crate::{
    GossipMsgOut, TCacheError, TCacheRef,
    spine::tcache::{IDLE_INTERVAL_NS, lag_threshold},
};

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
    /// Per-consumer flux Timer emitting `latency-tcache-{tcache}-{name}`
    /// — measures elapsed from `slot.reserve_ns` to first read.
    /// `None` if the TCache wasn't named or the Timer queue couldn't
    /// be opened.
    pub(super) timer: Option<Timer>,
    pub(super) last_read: Nanos,
    pub(super) last_head: u64,
    pub(super) lag_threshold: u64,
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
                if let Some(timer) = &mut self.timer {
                    timer.emit_latency_from_nanos(ts, Nanos::now());
                }
                return Ok((data, ts));
            }
            self.seq = self.next_seq;
        }
    }

    /// Release all data read so far. Should be called often, not necessarily
    /// after each read.
    pub fn free(&mut self) {
        self.seq = self.next_seq;

        let cache_head = self.cache.head();
        if self.last_read.elapsed() > IDLE_INTERVAL_NS {
            // check lagging
            let head = cache_head.seq.load(Ordering::Relaxed);
            if head.saturating_sub(self.seq) > self.lag_threshold {
                tracing::warn!(head, seq = self.seq, "force setting idle consumer tail");
                self.seq = if self.last_head > self.seq { self.last_head } else { head };
            }
            self.last_head = head;
            self.last_read = Nanos::now();
        }

        self.cache.head().tails[self.index].store(self.seq, Ordering::Release);
        self.cache.record_tail(self.index, self.seq);
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        self.cache.head().tails[self.index].store(u64::MAX, Ordering::Release);
        self.cache.record_tail(self.index, u64::MAX);
    }
}

/// Consumer that supports random access to messages between its tail and buffer
/// head. Tail is tracked externally.
pub struct RandomAccessConsumer {
    pub(super) cache: TCacheRef,
    pub(super) index: usize,
    pub(super) name: &'static str,
    // Mapping of active / enqueued sequence numbers and reader counts.
    pub(super) active: Buckets,
    // If set `free` is called on drop of every acquired read, ensuring the
    // consumer tail is published.
    pub(super) auto_free: bool,
    /// Per-consumer flux Timer emitting `latency-tcache-{tcache}-{name}`
    /// — measures elapsed from `slot.reserve_ns` at acquire time.
    pub(super) timer: Option<Timer>,
    pub(super) last_read: Nanos,
    pub(super) last_head: u64,
    pub(super) lag_threshold: u64,
}

impl RandomAccessConsumer {
    pub fn acquire(&mut self, read: TCacheRead) -> AcquiredRead {
        let now = Nanos::now();
        self.last_read = now;

        self.active.acquire(read.seq);
        if let Some(timer) = &mut self.timer {
            if let Ok(reserve_ns) = read.cache_ts() {
                timer.emit_latency_from_nanos(reserve_ns, now);
            }
        }
        AcquiredRead { consumer: self as *const Self, read }
    }

    /// Should be called periodically to publish the tail offset so it is
    /// visible to the Producer.
    pub fn free(&mut self) {
        let mut tail = self.active.tail_seq;
        if tail != u64::MAX {
            let cache_head = self.cache.head();
            if self.last_read.elapsed() > IDLE_INTERVAL_NS {
                // check lagging
                let head = cache_head.seq.load(Ordering::Relaxed);
                if head.saturating_sub(tail) > self.lag_threshold {
                    tracing::warn!(
                        head,
                        tail,
                        name = self.name,
                        "force setting idle consumer tail"
                    );
                    tail = if self.last_head > tail { self.last_head } else { head };
                    self.active.roll_to(tail);
                }
                self.last_head = head;
                self.last_read = Nanos::now();
            }

            cache_head.tails[self.index].store(tail, Ordering::Release);
            self.cache.record_tail(self.index, tail);
        }
    }

    fn release(&mut self, seq: u64) {
        self.active.release(seq, self.name);
    }
}

impl std::fmt::Debug for RandomAccessConsumer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RandomAccessConsumer")
            .field("index", &self.index)
            .field("name", &self.name)
            .field("head", &self.active.head_seq)
            .field("tail", &self.active.tail_seq)
            .finish()
    }
}

impl Drop for RandomAccessConsumer {
    fn drop(&mut self) {
        self.cache.head().tails[self.index].store(u64::MAX, Ordering::Release);
        self.cache.record_tail(self.index, u64::MAX);
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
            let e = TCacheError::StaleSeq {
                name: consumer.name,
                seq: self.read.seq,
                tail: consumer.active.tail_seq,
            };
            tracing::warn!("reading below current tail: {:?}", e);
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
    bucket_mask: u64,
    // max difference between head and tail, before 'forced' eviction
    lag_threshold: u64,
    // Out-of-order acquire lookback: the tail never advances within this
    // many seqs of the newest acquire's bucket, so late acquires up to
    // this far behind still land at or above the tail. 10% of capacity,
    // rounded up to a bucket.
    guard: u64,
}

impl Buckets {
    pub(super) fn new(bucket_size: u64, cache_capacity: u64, seq: u64) -> Self {
        assert!(bucket_size.is_power_of_two());
        let mut number_of_buckets = cache_capacity / bucket_size;
        if !cache_capacity.is_multiple_of(bucket_size) || !number_of_buckets.is_power_of_two() {
            number_of_buckets = number_of_buckets.next_power_of_two();
        }
        Self {
            buckets: vec![0; number_of_buckets as usize].into_boxed_slice(),
            tail_seq: seq,
            head_seq: 0,
            bucket_size,
            bucket_shift: bucket_size.trailing_zeros() as u64,
            bucket_mask: !(bucket_size - 1),
            lag_threshold: lag_threshold(cache_capacity as u32),
            guard: (cache_capacity / 10).next_multiple_of(bucket_size).max(bucket_size),
        }
    }

    fn acquire(&mut self, seq: u64) {
        // Out-of-order acquire beyond the guard window: the producer may
        // already be reclaiming this slot, and bucket_index aliases behind
        // the tail onto in-window buckets — counting it would corrupt a
        // live bucket (the matching release is dropped below tail). Skip;
        // the read surfaces as StaleSeq at buffer() time.
        if self.tail_seq != u64::MAX && seq < self.tail_seq {
            tracing::warn!(seq, tail = self.tail_seq, head = self.head_seq, "acquire below tail");
            return;
        }

        let bucket_idx = self.bucket_index(seq);
        self.buckets[bucket_idx] += 1;

        self.head_seq = self.head_seq.max(seq);

        if self.tail_seq == u64::MAX {
            self.tail_seq = self.bucket_start_seq(seq).saturating_sub(self.guard);
        }

        // Rollup tail for completed buckets — keep `guard` seqs of slack
        // below the newest acquire's bucket so bounded out-of-order
        // acquires never land behind the tail.
        let head_bucket_seq = self.bucket_start_seq(seq);
        while head_bucket_seq > (self.tail_seq + self.guard) {
            let tail_bucket = self.bucket_index(self.tail_seq);
            if self.head_seq - self.tail_seq > self.lag_threshold {
                tracing::warn!(
                    lagging = self.buckets[tail_bucket],
                    "unfreed lagging consumers dropped!"
                );
                self.buckets[tail_bucket] = 0;
            }
            if self.buckets[tail_bucket] != 0 {
                break;
            }
            self.tail_seq += self.bucket_size;
        }
    }

    fn release(&mut self, seq: u64, name: &str) {
        if seq < self.tail_seq {
            tracing::warn!(name, "tried to release: {seq} which is < {}", self.tail_seq);
            return;
        }

        let bucket_idx = self.bucket_index(seq);
        self.buckets[bucket_idx] = self.buckets[bucket_idx].saturating_sub(1);
    }

    #[inline]
    fn bucket_index(&self, seq: u64) -> usize {
        ((seq >> self.bucket_shift) as usize) & (self.buckets.len() - 1)
    }

    #[inline]
    fn bucket_start_seq(&self, seq: u64) -> u64 {
        seq & self.bucket_mask
    }

    fn roll_to(&mut self, seq: u64) {
        let head_bucket_seq = self.bucket_start_seq(seq);
        while head_bucket_seq > (self.tail_seq + self.bucket_size) {
            let tail_bucket = self.bucket_index(self.tail_seq);
            self.buckets[tail_bucket] = 0;
            self.tail_seq += self.bucket_size;
        }
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
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(100);
        // 100 lives in bucket 1 (64..128); tail starts `guard` (10% of
        // 1024 → 128) below its bucket start, saturating at 0.
        assert_eq!(b.tail_seq, 0);
        assert_eq!(b.head_seq, 100);
    }

    /// A late acquire within the guard window (10% of capacity behind the
    /// newest acquire) must land at or above the tail and be tracked.
    #[test]
    fn buckets_out_of_order_acquire_within_guard() {
        // guard = (1024/10).next_multiple_of(64) = 128.
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(0);
        b.release(0, "");
        b.acquire(300);
        // Tail rolled over the released bucket but held 128 back from
        // bucket_start(300) = 256.
        assert_eq!(b.tail_seq, 128);
        // Late low acquire inside the window: tracked, not dropped.
        b.acquire(200);
        assert!(b.tail_seq <= 200);
        b.release(200, "");
        b.release(300, "");
    }

    /// An acquire below the tail (out-of-order beyond the guard window)
    /// must not be counted: bucket_index aliases behind-tail seqs onto
    /// live buckets and the matching release is dropped, so counting
    /// would permanently stall the tail on a phantom holder.
    #[test]
    fn buckets_acquire_below_tail_dropped_without_corruption() {
        let mut b = Buckets::new(64, 1024, 0); // guard 128, lag threshold 921
        b.acquire(0);
        b.release(0, "");
        b.acquire(1000); // forces tail well past bucket 0 (tail = 832)
        let tail = b.tail_seq;
        assert!(tail >= 128);

        // Below-tail acquire: dropped (warn), tail untouched.
        b.acquire(1);
        assert_eq!(b.tail_seq, tail);
        // Its release is the existing below-tail no-op.
        b.release(1, "");

        // seq 1 aliases onto the same ring bucket as seqs 1024..1088; had
        // the acquire been counted, the tail would stall there forever
        // (head - tail stays under the lag threshold, so no force-evict).
        b.release(1000, "");
        b.acquire(1600);
        assert!(b.tail_seq > 1024, "tail stalled at {} on a phantom holder", b.tail_seq);
    }

    #[test]
    fn buckets_release_advances_tail_when_head_is_ahead() {
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(0); // bucket 0, tail = 0
        b.acquire(200); // bucket 3, head = 200
        assert_eq!(b.tail_seq, 0);
        b.release(0, ""); // bucket 0 empties; head far enough ahead to advance
        b.acquire(300);
        assert!(b.tail_seq > 0, "tail did not advance: {}", b.tail_seq);
        assert!(b.tail_seq <= 200);
    }

    #[test]
    fn buckets_out_of_order_release_keeps_holders_alive() {
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(0); // bucket 0
        b.acquire(100); // bucket 1
        b.acquire(300); // bucket 4
        // Release the middle first — bucket 1 empties but tail is still at 0
        b.release(100, "");
        assert_eq!(b.tail_seq, 0, "tail moved while bucket 0 still held");
        // Release the head; tail jumps past bucket 0 and bucket 1 (both empty)
        b.release(0, "");
        b.acquire(350);
        assert!(b.tail_seq >= 128, "tail did not jump: {}", b.tail_seq);
    }

    #[test]
    fn buckets_lag_threshold_force_evicts_held_tail() {
        // threshold = 0.9 * 1024 = 921
        let mut b = Buckets::new(64, 1024, 0);
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
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(0);
        b.acquire(1000); // forces tail past bucket 0
        let tail_after_eviction = b.tail_seq;
        b.release(0, ""); // 0 is now below tail — must not corrupt state
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
        let mut producer = TCache::producer("test_consumer", 1 << 16);
        let mut consumer = producer.cache_ref().random_access("test", false).unwrap();
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

        let mut producer = TCache::producer("test_consumer", CACHE);
        let mut consumer = producer.cache_ref().random_access("test", false).unwrap();
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
}
