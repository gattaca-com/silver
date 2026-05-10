use std::sync::atomic::Ordering;

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
        self.cache.read(self.seq).map(|(data, inc, ts)| {
            self.next_seq = self.seq + inc;
            (data, ts)
        })
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
}

impl RandomAccessConsumer {
    /// Read buffer at specified offset.
    pub fn read_at(&self, seq: u64) -> Result<(&[u8], Nanos), TCacheError> {
        if seq < self.active.tail_seq {
            return Err(TCacheError::StaleSeq { seq, tail: self.active.tail_seq });
        }

        self.cache.read(seq).map(|(data, _, ts)| (data, ts))
    }

    pub fn acquire(&mut self, read: &TCacheRead) {
        self.active.acquire(read.seq());
    }

    pub fn release(&mut self, read: &TCacheRead) {
        self.active.release(read.seq());
    }

    /// Release all upto the specified seq . 
    pub fn release_to(&mut self, seq: u64) {
        self.active.release_all(seq);
    }

    /// Should be called periodically to publish the tail offset so it is
    /// visible to the Producer.
    pub fn free(&self) {
        let tail = self.active.tail_seq;
        self.cache.head.tails[self.index].store(tail, Ordering::Release);
    }
}

pub(super) struct Buckets {
    buckets: Box<[u16]>,
    tail_seq: u64,
    head_seq: u64,
    bucket_size: u64,
    bucket_shift: u64,
}

impl Buckets {
    pub(super) fn new(bucket_size: u64, cache_capacity: u64) -> Self {
        assert!(bucket_size.is_power_of_two());
        let mut number_of_buckets = cache_capacity / bucket_size;
        if cache_capacity % bucket_size != 0 || !number_of_buckets.is_power_of_two() {
            number_of_buckets = number_of_buckets.next_power_of_two();
        }
        Self {
            buckets: vec![0; number_of_buckets as usize].into_boxed_slice(),
            tail_seq: u64::MAX,
            head_seq: 0,
            bucket_size,
            bucket_shift: bucket_size.trailing_zeros() as u64,
        }
    }

    fn acquire(&mut self, seq: u64) {
        let bucket_idx = self.index(seq);
        self.buckets[bucket_idx] += 1;

        self.head_seq = self.head_seq.max(seq);

        if self.tail_seq == u64::MAX {
            self.tail_seq = seq & !(self.bucket_size - 1);
        }
    }

    fn release(&mut self, seq: u64) {
        let mut bucket_idx = self.index(seq);
        self.buckets[bucket_idx] = self.buckets[bucket_idx].saturating_sub(1);

        let mut bucket_tail_seq = seq & !(self.bucket_size - 1);
        if bucket_tail_seq == self.tail_seq {
            while self.buckets[bucket_idx] == 0 && (bucket_tail_seq + self.bucket_size) < self.head_seq {
                bucket_idx = (bucket_idx + 1) & (self.buckets.len() - 1);
                bucket_tail_seq += self.bucket_size;
            }
            self.tail_seq = bucket_tail_seq;
        }
    }

    fn release_all(&mut self, seq: u64) {
        if seq == u64::MAX {
            self.tail_seq = u64::MAX;
            self.buckets.fill(0);
            return;
        }
        let target_seq = (seq & !(self.bucket_size - 1)).min(self.head_seq);
        while self.tail_seq + self.bucket_size <= target_seq {
            let bucket_idx = self.index(self.tail_seq);
            self.buckets[bucket_idx] = 0;
            self.tail_seq += self.bucket_size;
        }
    }

    fn index(&self, seq: u64) -> usize {
        ((seq >> self.bucket_shift) as usize) & (self.buckets.len() - 1)
    }
}
