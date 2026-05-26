use std::{io::Write, sync::Arc};

use flux::communication::Seqlock;

use super::*;

#[allow(private_bounds)]
pub trait TCacheProducer: SealedProducer {
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation>;

    /// Publish the head sequence for joining consumers.
    fn publish_head(&self) {
        let tcache = unsafe { &*self.tcache() };
        let seq = self.seq();
        tcache.head.seq.store(seq, Ordering::Release);
        tcache.record_head(seq);
    }

    fn cache_ref(&self) -> TCacheRef {
        TCacheRef { cache: self.tcache() as *const c_void }
    }

    #[allow(clippy::mut_from_ref)]
    fn reservation_buffer(&self, reservation: &mut Reservation) -> Result<&mut [u8], Error> {
        if reservation.cache.cache != (self.tcache() as *const c_void) {
            return Err(Error::UnexpectedCacheRef);
        }
        let tcache = unsafe { &*self.tcache() };
        let buffer = tcache.write(reservation.seq)?;
        Ok(&mut buffer[reservation.offset..])
    }
}

/// Private trait.
trait SealedProducer {
    fn tcache(&self) -> *const TCache;
    fn seq(&self) -> u64;
}

#[derive(Debug)]
pub struct Producer {
    pub(super) cache: *const TCache,
    pub(super) seq: u64,
    pub(super) space: u32,
}

unsafe impl Send for Producer {}
unsafe impl Sync for Producer {}

impl SealedProducer for Producer {
    fn tcache(&self) -> *const TCache {
        self.cache
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

impl TCacheProducer for Producer {
    /// Return requested buffer space, if available.
    /// If None is returned, caller should retry.
    /// if `auto_commit` the reservation will be commited as soon as it is
    /// filled. otherwise it must ber manually committed by calling `flush`.
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation> {
        let tcache = unsafe { &*self.cache };
        if tcache.reserve_len(self.seq, len) > self.space as usize {
            // try reclaim space.
            self.publish_head();
            self.space = tcache.space(self.seq);
        }
        tcache.reserve(self.seq, self.space, len as u32).map(|(seq, reservation_len)| {
            self.seq += reservation_len as u64;
            self.space -= reservation_len as u32;
            Reservation { cache: self.cache_ref(), seq, offset: 0, committed: false, auto_commit }
        })
    }
}

#[derive(Clone, Debug)]
pub struct MultiProducer {
    cache: *const TCache,
    state: Arc<Seqlock<MultiProducerState>>,
}

#[derive(Clone, Copy, Debug)]
struct MultiProducerState {
    seq: u64,
    space: u32,
}

unsafe impl Send for MultiProducer {}
unsafe impl Sync for MultiProducer {}

impl MultiProducer {
    pub(super) fn new(cache: *const TCache, len: u32) -> Self {
        let state = Arc::new(Seqlock::new(MultiProducerState { seq: 0, space: len }));
        Self { cache, state }
    }
}

impl SealedProducer for MultiProducer {
    fn tcache(&self) -> *const TCache {
        self.cache
    }

    fn seq(&self) -> u64 {
        self.state.read_copy().unwrap().0.seq
    }
}

impl TCacheProducer for MultiProducer {
    /// Return requested buffer space, if available.
    /// If None is returned, caller should retry.
    /// if `auto_commit` the reservation will be commited as soon as it is
    /// filled. otherwise it must ber manually committed by calling `flush`.
    fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation> {
        let tcache = unsafe { &*self.cache };

        loop {
            let (mut state, version) = self.state.read_copy().ok()?;
            let reservation_len = tcache.reserve_len(state.seq, len);
            if reservation_len as u32 > state.space {
                self.publish_head();
                state.space = tcache.space(state.seq);
                self.state.write_at_version(&state, version);
            }
            if reservation_len as u32 > state.space {
                // failed to reclaim enough space
                return None;
            }

            let alloc_seq = state.seq;
            state.seq += reservation_len as u64;
            state.space -= reservation_len as u32;

            if self.state.write_at_version(&state, version) {
                // We've claimed [alloc_seq, alloc_seq + reservation_len).
                return tcache.reserve(alloc_seq, reservation_len as u32, len as u32).map(
                    |(seq, res)| {
                        assert_eq!(reservation_len, res);
                        Reservation {
                            cache: self.cache_ref(),
                            seq,
                            offset: 0,
                            committed: false,
                            auto_commit,
                        }
                    },
                );
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct Reservation {
    pub(super) cache: TCacheRef,
    pub(super) seq: u64,
    offset: usize,
    committed: bool,
    auto_commit: bool,
}

unsafe impl Send for Reservation {}
unsafe impl Sync for Reservation {}

impl Reservation {
    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn remaining(&self) -> Result<usize, std::io::Error> {
        let buffer = self.cache.write(self.seq).map_err(std::io::Error::other)?;
        Ok(buffer.len() - self.offset)
    }

    pub fn increment_offset(&mut self, len: usize) {
        self.offset += len;
        if let Ok(len) = self.buffer().map(|b| b.len()) {
            if self.auto_commit && self.offset == len {
                tracing::trace!(seq = self.seq, len, "recv committed");
                self.cache.commit(self.seq, true);
                self.committed = true;
            }
        }
    }

    pub fn buffer(&self) -> Result<&mut [u8], std::io::Error> {
        self.cache.write(self.seq).map_err(std::io::Error::other)
    }

    /// Buffer slice from the current write offset to the end of the
    /// reservation. Use this when successive writes must not overwrite
    /// earlier bytes (e.g. a framed header followed by body chunks).
    pub fn remaining_buffer(&self) -> Result<&mut [u8], std::io::Error> {
        let buf = self.cache.write(self.seq).map_err(std::io::Error::other)?;
        Ok(&mut buf[self.offset..])
    }

    /// Returns a `TCacheRead` reference for this reservation.
    pub fn read(&self) -> TCacheRead {
        TCacheRead { tcache: self.cache, seq: self.seq }
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }
}

impl Write for Reservation {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buffer = self.cache.write(self.seq).map_err(std::io::Error::other)?;
        if buf.len() + self.offset > buffer.len() {
            return Err(std::io::ErrorKind::FileTooLarge.into());
        }
        buffer[self.offset..self.offset + buf.len()].copy_from_slice(buf);
        self.offset += buf.len();

        if self.auto_commit && self.offset == buffer.len() {
            self.cache.commit(self.seq, true);
            self.committed = true;
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.cache.commit(self.seq, true);
        self.committed = true;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.committed {
            self.cache.commit(self.seq, false);
        }
    }
}
