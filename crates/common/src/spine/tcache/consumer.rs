use std::sync::atomic::Ordering;

use flux::timing::Nanos;

use crate::{GossipMsgOut, RpcMsgOut, TCacheError, TCacheRef};

/// Reader for a TCache msg
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct TCacheRead {
    pub(super) tcache: TCacheRef,
    pub(super) seq: u64,
}

impl TCacheRead {
    #[inline]
    pub fn new(tcache: TCacheRef, seq: u64) -> Self {
        Self { tcache, seq }
    }

    /// Read the data buffer. Returns `(buffer, seq_increment)`.
    #[inline]
    pub fn read(&self) -> Result<(&[u8], u64, Nanos), TCacheError> {
        self.tcache.read(self.seq)
    }

    /// Read just the data buffer.
    #[inline]
    pub fn data(&self) -> Result<&[u8], TCacheError> {
        self.tcache.read(self.seq).map(|(buf, _, _)| buf)
    }

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

impl From<RpcMsgOut> for TCacheRead {
    fn from(value: RpcMsgOut) -> Self {
        value.data
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
        self.seq = self.next_seq;
        self.cache.head.tails[self.index].store(self.seq, Ordering::Release);
    }
}

/// Consumer that supports random access to messages between its tail and buffer
/// head. Tail is tracked externally.  
pub struct RandomAccessConsumer {
    pub(super) cache: TCacheRef,
    pub(super) index: usize,
    pub(super) tail: u64,
}

impl RandomAccessConsumer {
    /// Read buffer at specified offset.
    pub fn read_at(&self, seq: u64) -> Result<(&[u8], Nanos), TCacheError> {
        if seq < self.tail {
            return Err(TCacheError::StaleSeq { seq, tail: self.tail });
        }

        self.cache.read(seq).map(|(data, _, ts)| (data, ts))
    }

    /// Called to set the tail value of the consumer. User of the consumer is
    /// responsible for tracking the lowest in-use sequence and setting it
    /// via this method.
    pub fn set_tail(&mut self, seq: u64) {
        self.tail = seq;
    }

    /// Should be called periodically to publish the tail offset so it is
    /// visible to the Producer.
    pub fn free(&self) {
        self.cache.head.tails[self.index].store(self.tail, Ordering::Release);
    }
}
