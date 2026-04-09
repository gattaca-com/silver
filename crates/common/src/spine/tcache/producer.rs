use std::io::Write;

use super::*;

#[derive(Debug)]
pub struct Producer {
    pub(super) cache: *const TCache,
    pub(super) seq: u64,
    pub(super) space: u32,
}

unsafe impl Send for Producer {}
unsafe impl Sync for Producer {}

impl Producer {
    /// Return requested buffer space, if available.
    /// If None is returned, caller should retry.
    /// if `auto_commit` the reservation will be commited as soon as it is
    /// filled. otherwise it must ber manually committed by calling `flush`.
    pub fn reserve(&mut self, len: usize, auto_commit: bool) -> Option<Reservation> {
        let tcache = unsafe { &*self.cache };
        match tcache.reserve(self, len as u32) {
            Some((seq, reservation_len)) => {
                self.seq += reservation_len as u64;
                self.space -= reservation_len as u32;
                Some(Reservation {
                    cache: self.cache_ref(),
                    seq,
                    offset: 0,
                    committed: false,
                    auto_commit,
                })
            }
            None => {
                // reset available space.
                // TODO kick out slow consumers
                self.space = tcache.space(self.seq);
                None
            }
        }
    }

    /// Publish the head sequence for joining consumers.
    pub fn publish_head(&self) {
        let tcache = unsafe { &*self.cache };
        tcache.head.seq.store(self.seq, Ordering::Release);
    }

    pub fn cache_ref(&self) -> TCacheRef {
        TCacheRef { cache: self.cache as *const c_void }
    }

    #[allow(clippy::mut_from_ref)]
    pub fn reservation_buffer(&self, reservation: &mut Reservation) -> Result<&mut [u8], Error> {
        if reservation.cache.cache != (self.cache as *const c_void) {
            return Err(Error::UnexpectedCacheRef);
        }
        let tcache = unsafe { &*self.cache };
        tcache.write(reservation.seq)
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
