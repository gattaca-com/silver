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
    pub(super) strict: bool,
}

impl RandomAccessConsumer {
    pub fn cache_ref(&self) -> TCacheRef {
        self.cache
    }

    pub fn is_strict(&self) -> bool {
        self.strict
    }

    pub fn is_retained(&self) -> bool {
        matches!(self.active.guard, TailGuard::Fixed(_))
    }

    pub(super) fn retain(&mut self) {
        assert!(self.strict);
        self.active.guard = TailGuard::Fixed(self.active.tail_seq);
    }

    /// The producer captures `seq` before reserving the next retained region.
    /// Live reads still stop rollup before this boundary.
    pub fn advance_retention(&mut self, seq: u64) {
        let TailGuard::Fixed(boundary) = &mut self.active.guard else {
            panic!("consumer has no fixed retention boundary");
        };
        if seq > *boundary {
            *boundary = seq;
            self.active.head_seq = self.active.head_seq.max(seq);
            self.active.rollup(self.active.head_seq);
            self.free();
        }
    }

    pub fn acquire(&mut self, read: TCacheRead) -> AcquiredRead {
        let now = Nanos::now();
        self.last_read = now;

        self.active.acquire(read.seq);
        if let Some(timer) = &mut self.timer {
            if let Ok(reserve_ns) = read.cache_ts() {
                timer.emit_latency_from_nanos(reserve_ns, now);
            }
        }
        AcquiredRead { consumer: self as *const Self, read, acquired: now }
    }

    pub fn acquire_strict(&mut self, read: TCacheRead) -> Option<AcquiredRead> {
        let now = Nanos::now();
        self.last_read = now;

        self.active
            .acquire(read.seq)
            .then(|| {
                if let Some(timer) = &mut self.timer {
                    if let Ok(reserve_ns) = read.cache_ts() {
                        timer.emit_latency_from_nanos(reserve_ns, now);
                    }
                }
                AcquiredRead { consumer: self as *const Self, read, acquired: now }
            })
            .and_then(|ar| {
                // check slot seq.
                self.cache.check_seq(read.seq).then_some(ar)
            })
    }

    /// Should be called periodically to publish the tail offset so it is
    /// visible to the Producer.
    pub fn free(&mut self) {
        let mut tail = self.active.tail_seq;
        if tail != u64::MAX {
            let cache_head = self.cache.head();
            if !self.strict && self.last_read.elapsed() > IDLE_INTERVAL_NS {
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
                    self.last_read = Nanos::now();
                }
                self.last_head = head;
            }

            cache_head.tails[self.index].store(tail, Ordering::Release);
            self.cache.record_tail(self.index, tail);
        }
    }

    fn release(&mut self, seq: u64) {
        self.active.release(seq, self.name);
    }

    #[cfg(test)]
    pub(super) fn active_count(&self) -> usize {
        self.active.buckets.iter().map(|count| usize::from(*count)).sum()
    }

    #[inline]
    fn warn_below_tail(&self, seq: u64) {
        if seq < self.active.tail_seq {
            let e = TCacheError::StaleSeq { name: self.name, seq, tail: self.active.tail_seq };
            tracing::warn!("reading below current tail: {:?}", e);
        }
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
#[derive(Debug)]
pub struct AcquiredRead {
    pub(super) consumer: *const RandomAccessConsumer,
    pub read: TCacheRead,
    pub acquired: Nanos,
}

impl AcquiredRead {
    pub fn is_strict(&self) -> bool {
        unsafe { &*self.consumer }.strict
    }

    pub fn buffer(&self) -> Result<(&[u8], Nanos), TCacheError> {
        let consumer = unsafe { &*self.consumer };
        consumer.warn_below_tail(self.read.seq);
        consumer.cache.read(self.read.seq).map(|(data, _, ts)| (data, ts))
    }

    #[inline]
    pub fn with_offset(&self, offset: usize) -> Option<AcquiredWithOffset> {
        let consumer = unsafe { &mut *(self.consumer as *mut RandomAccessConsumer) };
        let read = consumer.acquire_strict(self.read)?;
        let length = read.buffer().ok()?.0.len().checked_sub(offset)?;
        Some(AcquiredRange { read, offset, length })
    }

    #[inline]
    pub fn with_range(&self, offset: usize, length: usize) -> Option<AcquiredRange> {
        let mut range = self.with_offset(offset)?;
        if length > range.length {
            return None;
        }
        range.length = length;
        Some(range)
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

impl Clone for AcquiredRead {
    #[inline]
    fn clone(&self) -> Self {
        unsafe {
            let consumer = &mut *(self.consumer as *mut RandomAccessConsumer);
            consumer.active.acquire(self.read.seq);
        }
        Self { consumer: self.consumer, read: self.read, acquired: self.acquired }
    }
}

pub type AcquiredWithOffset = AcquiredRange;

#[derive(Clone, Debug)]
pub struct AcquiredRange {
    pub(super) read: AcquiredRead,
    pub(super) offset: usize,
    pub(super) length: usize,
}

impl AcquiredRange {
    #[inline]
    pub fn extend_contiguous(&mut self, next: &Self) -> bool {
        if self.read.consumer != next.read.consumer ||
            self.read.seq() != next.read.seq() ||
            self.offset + self.length != next.offset
        {
            return false;
        }
        self.length += next.length;
        true
    }

    pub fn slice(mut self, offset: usize, length: usize) -> Option<Self> {
        if offset.checked_add(length)? > self.length {
            return None;
        }
        self.offset += offset;
        self.length = length;
        Some(self)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.length
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
}

impl AsRef<[u8]> for AcquiredRange {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let consumer = unsafe { &*self.read.consumer };
        consumer.warn_below_tail(self.read.seq());
        consumer.cache.read_range(self.read.seq(), self.offset, self.length).unwrap_or(&[])
    }
}

enum TailGuard {
    Sliding(u64),
    Fixed(u64),
}

pub(super) struct Buckets {
    buckets: Box<[u16]>,
    tail_seq: u64,
    head_seq: u64,
    bucket_size: u64,
    bucket_shift: u64,
    bucket_mask: u64,
    // max difference between head and tail, before 'forced' eviction
    // for 'strict' consumers this is set to cache length so that it never
    // triggers
    lag_threshold: u64,
    // Sliding consumers keep 20% lookback. Retained consumers keep everything
    // from a fixed boundary, independent of acquire order.
    guard: TailGuard,
}

impl Buckets {
    pub(super) fn new(bucket_size: u64, cache_capacity: u64, seq: u64) -> Self {
        Self::create(bucket_size, cache_capacity, seq, false)
    }

    pub(super) fn strict(bucket_size: u64, cache_capacity: u64, seq: u64) -> Self {
        Self::create(bucket_size, cache_capacity, seq, true)
    }

    pub(super) fn create(bucket_size: u64, cache_capacity: u64, seq: u64, strict: bool) -> Self {
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
            lag_threshold: if strict {
                cache_capacity
            } else {
                lag_threshold(cache_capacity as u32)
            },
            guard: TailGuard::Sliding(
                (cache_capacity / 5).next_multiple_of(bucket_size).max(bucket_size),
            ),
        }
    }

    fn acquire(&mut self, seq: u64) -> bool {
        // Out-of-order acquire beyond the guard window: the producer may
        // already be reclaiming this slot, and bucket_index aliases behind
        // the tail onto in-window buckets — counting it would corrupt a
        // live bucket (the matching release is dropped below tail). Skip;
        // the read surfaces as StaleSeq at buffer() time.
        if self.tail_seq != u64::MAX && seq < self.tail_seq {
            tracing::warn!(seq, tail = self.tail_seq, head = self.head_seq, "acquire below tail");
            return false;
        }

        let bucket_idx = self.bucket_index(seq);
        self.buckets[bucket_idx] += 1;

        self.head_seq = self.head_seq.max(seq);

        if self.tail_seq == u64::MAX {
            self.tail_seq = self.rollup_limit(seq);
        }
        self.rollup(seq);
        true
    }

    fn release(&mut self, seq: u64, name: &str) {
        if seq < self.tail_seq {
            tracing::warn!(name, "tried to release: {seq} which is < {}", self.tail_seq);
            return;
        }

        let bucket_idx = self.bucket_index(seq);
        self.buckets[bucket_idx] = self.buckets[bucket_idx].saturating_sub(1);
        self.rollup(self.head_seq);
    }

    #[inline]
    fn rollup_limit(&self, seq: u64) -> u64 {
        match self.guard {
            TailGuard::Sliding(distance) => self.bucket_start_seq(seq).saturating_sub(distance),
            TailGuard::Fixed(boundary) => self.bucket_start_seq(boundary),
        }
    }

    fn rollup(&mut self, seq: u64) {
        let limit = self.rollup_limit(seq);
        while self.tail_seq < limit {
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
            self.advance_tail_to_next_bucket();
        }
    }

    fn advance_tail_to_next_bucket(&mut self) {
        self.tail_seq = self.bucket_start_seq(self.tail_seq).saturating_add(self.bucket_size);
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
        while head_bucket_seq > self.tail_seq.saturating_add(self.bucket_size) {
            let tail_bucket = self.bucket_index(self.tail_seq);
            self.buckets[tail_bucket] = 0;
            self.advance_tail_to_next_bucket();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        thread,
        time::{Duration, Instant},
    };

    use bytes::Bytes;

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
        // guard = (1024/5).next_multiple_of(64) = 256.
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(0);
        b.release(0, "");
        b.acquire(500);
        // Tail rolled over the released bucket but held 128 back from
        // bucket_start(500) = 448.
        assert_eq!(b.tail_seq, 192);
        // Late low acquire inside the window: tracked, not dropped.
        b.acquire(200);
        assert!(b.tail_seq <= 200);
        b.release(200, "");
        b.release(500, "");
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
        b.acquire(1000); // forces tail well past bucket 0 (tail = 704)
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
        b.acquire(500); // bucket 7, head = 500; held bucket 0 blocks rollup
        assert_eq!(b.tail_seq, 0);
        b.release(0, "");
        assert_eq!(b.tail_seq, 192, "release did not immediately advance tail");
    }

    #[test]
    fn buckets_rollup_does_not_advance_past_live_read_from_unaligned_tail() {
        let mut b = Buckets::new(64, 1024, 32);
        b.acquire(32); // hold the partial initial bucket
        b.acquire(64); // hold the next bucket
        b.acquire(500); // move head far enough for rollup
        assert_eq!(b.tail_seq, 32);

        b.release(32, "");
        assert_eq!(b.tail_seq, 64, "tail advanced past the live read at 64");
    }

    #[test]
    fn buckets_roll_to_aligns_an_unaligned_tail() {
        let mut b = Buckets::new(64, 1024, 32);
        b.roll_to(500);
        assert_eq!(b.tail_seq, 384);
    }

    #[test]
    fn buckets_out_of_order_release_keeps_holders_alive() {
        let mut b = Buckets::new(64, 1024, 0);
        b.acquire(0); // bucket 0
        b.acquire(100); // bucket 1
        b.acquire(500); // bucket 8
        // Release the middle first — bucket 1 empties but tail is still at 0
        b.release(100, "");
        assert_eq!(b.tail_seq, 0, "tail moved while bucket 0 still held");
        // Release the head; tail jumps past bucket 0 and bucket 1 and bucket 2 (all
        // empty)
        b.release(0, "");
        b.acquire(450);
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

    #[test]
    fn retention_advance_skips_unacquired_records_without_releasing_live_reads() {
        let mut producer = TCache::producer("", 1 << 18);
        let mut consumer = producer.cache_ref().retained_random_access("").unwrap();
        let read = write_marker(&mut producer, 32, 0xab);
        let pinned = consumer.acquire_strict(read).unwrap();
        for _ in 0..20 {
            write_marker(&mut producer, 8192, 0xcd);
        }
        let boundary = producer.next_seq();
        consumer.advance_retention(boundary);
        assert_eq!(consumer.active.tail_seq, 0);
        assert_eq!(pinned.buffer().unwrap().0, &[0xab; 32]);
        drop(pinned);
        assert_eq!(consumer.active.tail_seq, consumer.active.bucket_start_seq(boundary));
        assert!(consumer.acquire_strict(read).is_none());
    }

    #[test]
    fn fixed_retention_replaces_the_sliding_guard_on_acquire_and_drop() {
        let mut producer = TCache::producer("", 1 << 18);
        let mut consumer = producer.cache_ref().retained_random_access("").unwrap();
        let old = write_marker(&mut producer, 32, 0xab);
        for _ in 0..20 {
            let newer = write_marker(&mut producer, 8192, 0xcd);
            drop(consumer.acquire_strict(newer).unwrap());
            consumer.free();
        }
        assert_eq!(consumer.active.tail_seq, 0);
        assert_eq!(consumer.cache.head().tails[consumer.index].load(Ordering::Acquire), 0);
        assert_eq!(consumer.acquire_strict(old).unwrap().buffer().unwrap().0, &[0xab; 32]);

        let boundary = producer.next_seq();
        consumer.advance_retention(boundary);
        assert_eq!(consumer.active.tail_seq, consumer.active.bucket_start_seq(boundary));
        assert!(consumer.acquire_strict(old).is_none());
    }

    #[test]
    fn delayed_boundary_cannot_discard_next_region_or_move_backwards() {
        let mut producer = TCache::producer("", 1 << 18);
        let mut consumer = producer.cache_ref().retained_random_access("").unwrap();
        for _ in 0..10 {
            write_marker(&mut producer, 8192, 0xab);
        }
        let boundary = producer.next_seq();
        assert_ne!(boundary % consumer.active.bucket_size, 0);
        let next = write_marker(&mut producer, 32, 0xcd);
        for _ in 0..10 {
            let newer = write_marker(&mut producer, 8192, 0xef);
            drop(consumer.acquire_strict(newer).unwrap());
        }
        consumer.advance_retention(boundary);
        consumer.advance_retention(boundary - 8192);
        assert_eq!(consumer.active.tail_seq, consumer.active.bucket_start_seq(boundary));
        assert_eq!(consumer.acquire_strict(next).unwrap().buffer().unwrap().0, &[0xcd; 32]);
    }

    #[test]
    fn acquired_ranges_share_cell_and_proof_bytes() {
        let mut producer = TCache::producer("", 1 << 16);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let mut reservation = producer.reserve(2098, true).unwrap();
        let buffer = reservation.buffer().unwrap();
        buffer.fill(0xff);
        buffer[1..2049].fill(0x11);
        buffer[2049..2097].fill(0x22);
        reservation.increment_offset(2098);

        let acquired = consumer.acquire_strict(reservation.read()).unwrap();
        let cell = acquired.with_range(1, 2048).unwrap();
        let proof = acquired.with_range(2049, 48).unwrap();
        let buffer = acquired.buffer().unwrap().0;

        assert_eq!(cell.as_ref(), &[0x11; 2048]);
        assert_eq!(proof.as_ref(), &[0x22; 48]);
        assert_eq!(cell.as_ref().as_ptr(), buffer[1..].as_ptr());
        assert_eq!(proof.as_ref().as_ptr(), buffer[2049..].as_ptr());
        assert_eq!(cell.len(), 2048);
        assert_eq!(proof.len(), 48);
        assert!(!cell.is_empty());
        assert!(!proof.is_empty());
    }

    #[test]
    fn acquired_range_checks_bounds_without_leaking_pins() {
        let mut producer = TCache::producer("", 1 << 16);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let read = write_marker(&mut producer, 32, 0xab);
        let acquired = consumer.acquire_strict(read).unwrap();
        let bucket = consumer.active.bucket_index(read.seq());

        for (offset, length) in [(0, 0), (0, 32), (5, 7), (31, 1), (32, 0)] {
            let range = acquired.with_range(offset, length).unwrap();
            assert_eq!(range.as_ref(), &acquired.buffer().unwrap().0[offset..offset + length]);
            assert_eq!(range.len(), length);
            assert_eq!(range.is_empty(), length == 0);
            assert_eq!(consumer.active.buckets[bucket], 2);
            drop(range);
            assert_eq!(consumer.active.buckets[bucket], 1);
        }

        for (offset, length) in [
            (33, 0),
            (32, 1),
            (31, 2),
            (0, 33),
            (0, usize::MAX),
            (usize::MAX, 0),
            (usize::MAX, 1),
            (1, usize::MAX),
        ] {
            assert!(acquired.with_range(offset, length).is_none(), "{offset}, {length}");
            assert_eq!(consumer.active.buckets[bucket], 1);
        }
        drop(acquired);
        assert_eq!(consumer.active.buckets[bucket], 0);
    }

    #[test]
    fn acquired_offset_preserves_suffix_access() {
        let mut producer = TCache::producer("", 1 << 16);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let read = write_marker(&mut producer, 32, 0xab);
        let acquired = consumer.acquire_strict(read).unwrap();
        let bucket = consumer.active.bucket_index(read.seq());

        for offset in [0, 1, 31, 32] {
            let range: AcquiredWithOffset = acquired.with_offset(offset).unwrap();
            assert_eq!(range.as_ref(), &acquired.buffer().unwrap().0[offset..]);
            assert_eq!(range.len(), 32 - offset);
            assert_eq!(range.is_empty(), offset == 32);
        }
        for offset in [33, usize::MAX] {
            assert!(acquired.with_offset(offset).is_none());
            assert_eq!(consumer.active.buckets[bucket], 1);
        }
    }

    #[test]
    fn acquired_range_clones_release_exactly_once() {
        let mut producer = TCache::producer("", 1 << 18);
        let mut consumer = producer.cache_ref().strict_random_access("", false).unwrap();
        let read = write_marker(&mut producer, 2096, 0xab);
        let acquired = consumer.acquire_strict(read).unwrap();
        let cell = acquired.with_range(0, 2048).unwrap();
        let proof = acquired.with_range(2048, 48).unwrap();
        let cell_clone = cell.clone();
        let bucket = consumer.active.bucket_index(read.seq());
        assert_eq!(consumer.active.buckets[bucket], 4);

        write_marker(&mut producer, 3 * 32 * 1024, 0xcd);
        let newer = write_marker(&mut producer, 32, 0xef);
        drop(consumer.acquire_strict(newer).unwrap());

        drop(acquired);
        assert_eq!(consumer.active.buckets[bucket], 3);
        drop(cell);
        assert_eq!(consumer.active.buckets[bucket], 2);
        drop(proof);
        assert_eq!(consumer.active.buckets[bucket], 1);
        assert_eq!(cell_clone.as_ref(), &[0xab; 2048]);
        consumer.free();
        assert_eq!(consumer.cache.head().tails[consumer.index].load(Ordering::Acquire), 0);

        drop(cell_clone);
        assert_eq!(consumer.active.buckets[bucket], 0);
        consumer.free();
        assert!(consumer.cache.head().tails[consumer.index].load(Ordering::Acquire) > read.seq());
    }

    #[test]
    fn acquired_range_bytes_slices_share_one_pin() {
        let mut producer = TCache::producer("", 1 << 16);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let read = write_marker(&mut producer, 2096, 0xab);
        let acquired = consumer.acquire_strict(read).unwrap();
        let bytes = Bytes::from_owner(acquired.with_range(0, 2096).unwrap());
        let cell = bytes.slice(..2048);
        let proof = bytes.slice(2048..);
        let clone = cell.clone();
        let bucket = consumer.active.bucket_index(read.seq());
        assert_eq!(consumer.active.buckets[bucket], 2);

        drop(acquired);
        drop(bytes);
        drop(cell);
        drop(proof);
        assert_eq!(consumer.active.buckets[bucket], 1);
        assert_eq!(clone.as_ref(), &[0xab; 2048]);

        drop(clone);
        assert_eq!(consumer.active.buckets[bucket], 0);
    }

    #[test]
    fn strict_acquired_ranges_block_overwrite_until_last_drop() {
        const CAPACITY: usize = 1 << 18;
        const MESSAGE_LEN: usize = 8 * 1024;

        let mut producer = TCache::producer("", CAPACITY);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let read = write_marker(&mut producer, 2096, 0xab);
        let acquired = consumer.acquire_strict(read).unwrap();
        let cell = acquired.with_range(0, 2048).unwrap();
        let proof = acquired.with_range(2048, 48).unwrap();
        drop(acquired);

        let mut produced = 0;
        while let Some(mut reservation) = producer.reserve(MESSAGE_LEN, true) {
            reservation.buffer().unwrap().fill(0xcd);
            reservation.increment_offset(MESSAGE_LEN);
            drop(consumer.acquire_strict(reservation.read()).unwrap());
            produced += 1;
            assert!(produced <= CAPACITY / MESSAGE_LEN, "overwrote a pinned record");
        }

        assert!(produced > 0);
        assert_eq!(cell.as_ref(), &[0xab; 2048]);
        drop(cell);
        assert!(producer.reserve(MESSAGE_LEN, true).is_none());
        assert_eq!(proof.as_ref(), &[0xab; 48]);

        drop(proof);
        assert!(producer.reserve(MESSAGE_LEN, true).is_some());
        assert!(consumer.acquire_strict(read).is_none());
    }

    #[test]
    fn acquired_range_rejects_stale_reads_and_hides_overwritten_data() {
        const CAPACITY: usize = 1 << 18;

        let mut producer = TCache::producer("", CAPACITY);
        let mut consumer = producer.cache_ref().random_access("", true).unwrap();
        let read = write_marker(&mut producer, 32, 0xab);
        let acquired = consumer.acquire_strict(read).unwrap();
        let range = acquired.with_range(16, 16).unwrap();

        write_marker(&mut producer, CAPACITY - 16 * 1024, 0xcd);
        let newer = write_marker(&mut producer, 32, 0xef);
        let newer = consumer.acquire_strict(newer).unwrap();
        consumer.free();
        assert!(consumer.active.tail_seq > read.seq());
        assert!(consumer.cache.check_seq(read.seq()));
        assert!(acquired.with_range(0, 1).is_none());
        assert!(acquired.with_range(0, 0).is_none());
        assert!(acquired.with_offset(0).is_none());

        write_marker(&mut producer, 32 * 1024, 0x11);
        assert!(!consumer.cache.check_seq(read.seq()));
        assert!(range.as_ref().is_empty());
        let clone = range.clone();
        assert!(clone.as_ref().is_empty());
        drop(acquired);
        drop(range);
        drop(clone);
        assert_eq!(consumer.active.buckets.iter().sum::<u16>(), 1);
        assert_eq!(newer.buffer().unwrap().0, &[0xef; 32]);
        drop(newer);
        assert_eq!(consumer.active.buckets.iter().sum::<u16>(), 0);
    }

    #[test]
    fn acquired_range_rejects_uncommitted_reads_without_leaking_pins() {
        let mut producer = TCache::producer("", 1 << 16);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let mut reservation = producer.reserve(32, true).unwrap();
        let acquired = consumer.acquire(reservation.read());
        let bucket = consumer.active.bucket_index(reservation.seq());

        assert!(acquired.with_range(0, 1).is_none());
        assert!(acquired.with_offset(0).is_none());
        assert_eq!(consumer.active.buckets[bucket], 1);

        reservation.buffer().unwrap().fill(0xab);
        reservation.increment_offset(32);
        let range = acquired.with_range(0, 1).unwrap();
        assert_eq!(range.as_ref(), &[0xab]);
        drop(range);
        assert_eq!(consumer.active.buckets[bucket], 1);
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
