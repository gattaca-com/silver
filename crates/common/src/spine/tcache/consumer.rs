use std::sync::atomic::Ordering;

use crate::{GossipMsgOut, RpcMsgOut, TCacheError, TCacheRef};

/// Reader for a TCache msg
#[derive(Clone, Debug)]
pub struct TCacheRead {
    tcache: TCacheRef,
    seq: u64,
}

impl TCacheRead {
    /// Returns the length the data buffer.
    #[inline]
    pub fn len(&self) -> Result<usize, TCacheError> {
        let (buffer, _) = self.tcache.read(self.seq)?;
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
}

impl From<GossipMsgOut> for TCacheRead {
    fn from(value: GossipMsgOut) -> Self {
        Self { tcache: value.cache_ref, seq: value.tcache_seq }
    }
}

impl From<RpcMsgOut> for TCacheRead {
    fn from(value: RpcMsgOut) -> Self {
        Self { tcache: value.cache_ref, seq: value.tcache_seq }
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
    /// Read next data in the buffer.
    pub fn read(&mut self) -> Result<&[u8], TCacheError> {
        self.cache.read(self.seq).map(|(data, inc)| {
            self.next_seq = self.seq + inc;
            data
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
    pub fn read_at(&self, seq: u64) -> Result<&[u8], TCacheError> {
        if seq < self.tail {
            return Err(TCacheError::StaleSeq { seq, tail: self.tail });
        }

        self.cache.read(seq).map(|(data, _)| data)
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
