use std::{io::Write, ops::Range, time::Instant};

use super::{
    AcquiredRange, AcquiredRead, Producer, SubReservationRef, TCacheId, TCacheProducer, TCacheRead,
    TCacheReader,
};
use crate::MAX_GOSSIP_FRAME_SIZE;

mod acquired;
pub use acquired::{AcquiredCacheFrame, AcquiredCacheSegment};

/// N.B. Sized for partial data columns gossip
pub const MAX_CACHE_SEGMENTS: usize = 2 * 128 + 8;
const HEADER_BYTES: usize = 16;
const SEGMENT_BYTES: usize = 40;
const MAGIC: [u8; 8] = *b"SGFRAME1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheFrameError {
    InvalidDescriptor,
    TooLarge,
    CacheFull,
    Expired,
    Stale,
}

#[derive(Clone, Copy, Debug)]
pub enum CacheSegment {
    Framing {
        offset: usize,
        length: usize,
    },
    Gossip {
        read: TCacheRead,
        offset: usize,
        length: usize,
    },
    DataColumns {
        read: TCacheRead,
        offset: usize,
        length: usize,
    },
    Shared {
        reservation: SubReservationRef,
        part: usize,
        second: bool,
        offset: usize,
        length: usize,
    },
}

// Only the builder constructs this handle. Encoded source identities originate
// from typed cache descriptors, never from network input.
// Pointer identities and trusted layout metadata make this an in-process
// format.
#[derive(Clone, Copy, Debug)]
pub struct CacheFrameRef {
    descriptor: TCacheRead,
    expires: Instant,
}

impl CacheFrameRef {
    pub fn write(
        producer: &mut Producer,
        expires: Instant,
        framing: &[u8],
        segments: impl ExactSizeIterator<Item = CacheSegment>,
    ) -> Result<Self, CacheFrameError> {
        let count = segments.len();
        if count == 0 || count > MAX_CACHE_SEGMENTS || framing.len() > MAX_GOSSIP_FRAME_SIZE {
            return Err(CacheFrameError::TooLarge);
        }
        let framing_start = HEADER_BYTES + count * SEGMENT_BYTES;
        let descriptor_len = framing_start + framing.len();
        let cache = producer.cache_ref();
        let mut reservation =
            producer.reserve(descriptor_len, false).ok_or(CacheFrameError::CacheFull)?;
        let buffer = reservation.buffer().map_err(|_| CacheFrameError::Stale)?;
        buffer[..8].copy_from_slice(&MAGIC);
        buffer[8..12].copy_from_slice(&(count as u32).to_le_bytes());
        buffer[framing_start..].copy_from_slice(framing);
        let mut total = 0usize;
        let mut written = 0;
        for (index, segment) in segments.enumerate() {
            if index >= count {
                return Err(CacheFrameError::InvalidDescriptor);
            }
            let (kind, read, metadata, offset, length) = match segment {
                CacheSegment::Framing { offset, length } => {
                    if offset.checked_add(length).is_none_or(|end| end > framing.len()) {
                        return Err(CacheFrameError::InvalidDescriptor);
                    }
                    (0u64, None, 0, offset, length)
                }
                CacheSegment::Gossip { read, offset, length } => {
                    if read.id != cache.id() {
                        return Err(CacheFrameError::InvalidDescriptor);
                    }
                    (1, Some(read), 0, offset, length)
                }
                CacheSegment::DataColumns { read, offset, length } => {
                    (2, Some(read), 0, offset, length)
                }
                CacheSegment::Shared { reservation, part, second, offset, length } => {
                    if part >= 128 {
                        return Err(CacheFrameError::InvalidDescriptor);
                    }
                    let metadata = ((reservation.header_bytes as u64) << 32) |
                        ((part as u64) << 1) |
                        u64::from(second);
                    (3, Some(reservation.read()), metadata, offset, length)
                }
            };
            if length == 0 || offset > u32::MAX as usize || length > u32::MAX as usize {
                return Err(CacheFrameError::InvalidDescriptor);
            }
            total = total.checked_add(length).ok_or(CacheFrameError::TooLarge)?;
            if total > MAX_GOSSIP_FRAME_SIZE {
                return Err(CacheFrameError::TooLarge);
            }
            let start = HEADER_BYTES + index * SEGMENT_BYTES;
            let entry = &mut buffer[start..start + SEGMENT_BYTES];
            entry[..8].copy_from_slice(&kind.to_le_bytes());
            entry[8..16].copy_from_slice(&read.map_or(0, |r| r.id as u64).to_le_bytes());
            entry[16..24].copy_from_slice(&read.map_or(0, |r| r.seq).to_le_bytes());
            entry[24..32].copy_from_slice(&metadata.to_le_bytes());
            entry[32..36].copy_from_slice(&(offset as u32).to_le_bytes());
            entry[36..40].copy_from_slice(&(length as u32).to_le_bytes());
            written += 1;
        }
        if written != count {
            return Err(CacheFrameError::InvalidDescriptor);
        }
        buffer[12..16].copy_from_slice(&(total as u32).to_le_bytes());
        reservation.flush().map_err(|_| CacheFrameError::Stale)?;
        Ok(Self { descriptor: reservation.read(), expires })
    }

    pub fn read(self) -> TCacheRead {
        self.descriptor
    }

    pub fn acquire(
        self,
        reader: &mut TCacheReader,
        now: Instant,
    ) -> Result<CacheFrameView, CacheFrameError> {
        if now >= self.expires {
            return Err(CacheFrameError::Expired);
        }
        let consumer = reader
            .get(self.descriptor.id)
            .filter(|consumer| consumer.is_strict())
            .ok_or(CacheFrameError::InvalidDescriptor)?;
        let read = consumer.acquire_strict(self.descriptor).ok_or(CacheFrameError::Stale)?;
        let buffer = read.buffer().map_err(|_| CacheFrameError::Stale)?.0;
        if buffer.len() < HEADER_BYTES || buffer[..8] != MAGIC {
            return Err(CacheFrameError::InvalidDescriptor);
        }
        let count = u32::from_le_bytes(buffer[8..12].try_into().unwrap()) as usize;
        let wire_len = u32::from_le_bytes(buffer[12..16].try_into().unwrap()) as usize;
        if count == 0 || count > MAX_CACHE_SEGMENTS {
            return Err(CacheFrameError::InvalidDescriptor);
        }
        let framing_start = HEADER_BYTES + count * SEGMENT_BYTES;
        if framing_start > buffer.len() || wire_len == 0 || wire_len > MAX_GOSSIP_FRAME_SIZE {
            return Err(CacheFrameError::InvalidDescriptor);
        }
        let descriptor_len = buffer.len();
        let view = CacheFrameView {
            read,
            expires: self.expires,
            count,
            wire_len,
            framing_start,
            descriptor_len,
        };
        let mut total = 0usize;
        for segment in view.segments() {
            if segment.length == 0 ||
                segment.kind > 3 ||
                (segment.kind == 0 &&
                    segment
                        .offset
                        .checked_add(segment.length)
                        .is_none_or(|end| end > view.descriptor_len() - framing_start))
            {
                return Err(CacheFrameError::InvalidDescriptor);
            }
            total = total.checked_add(segment.length).ok_or(CacheFrameError::TooLarge)?;
        }
        if total != wire_len {
            return Err(CacheFrameError::InvalidDescriptor);
        }
        Ok(view)
    }
}

#[derive(Debug)]
pub struct CacheFrameView {
    read: AcquiredRead,
    expires: Instant,
    count: usize,
    wire_len: usize,
    framing_start: usize,
    descriptor_len: usize,
}

impl CacheFrameView {
    pub fn reference(&self) -> CacheFrameRef {
        CacheFrameRef { descriptor: self.read.read, expires: self.expires }
    }

    pub fn wire_len(&self) -> usize {
        self.wire_len
    }

    pub fn segment_count(&self) -> usize {
        self.count
    }

    pub fn descriptor_len(&self) -> usize {
        self.descriptor_len
    }

    pub fn descriptor_range(&self) -> AcquiredRange {
        self.read.with_range(0, self.descriptor_len()).expect("acquired descriptor")
    }

    pub fn acquire_segments(self, reader: &mut TCacheReader) -> Option<AcquiredCacheFrame> {
        AcquiredCacheFrame::new(self, reader)
    }

    pub fn segments(&self) -> impl ExactSizeIterator<Item = CacheFrameSegment> + '_ {
        self.read.buffer().expect("acquired descriptor").0[HEADER_BYTES..self.framing_start]
            .chunks_exact(SEGMENT_BYTES)
            .map(|entry| CacheFrameSegment::decode(entry, self.framing_start))
    }

    fn segment(&self, index: usize) -> CacheFrameSegment {
        assert!(index < self.count);
        let start = HEADER_BYTES + index * SEGMENT_BYTES;
        let buffer = self.read.buffer().expect("acquired descriptor").0;
        CacheFrameSegment::decode(&buffer[start..start + SEGMENT_BYTES], self.framing_start)
    }
}

pub struct CacheFrameSegment {
    kind: u64,
    cache: u64,
    seq: u64,
    metadata: u64,
    offset: usize,
    length: usize,
    framing_start: usize,
}

impl CacheFrameSegment {
    fn decode(entry: &[u8], framing_start: usize) -> Self {
        Self {
            kind: u64::from_le_bytes(entry[..8].try_into().unwrap()),
            cache: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
            seq: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
            metadata: u64::from_le_bytes(entry[24..32].try_into().unwrap()),
            offset: u32::from_le_bytes(entry[32..36].try_into().unwrap()) as usize,
            length: u32::from_le_bytes(entry[36..40].try_into().unwrap()) as usize,
            framing_start,
        }
    }

    pub fn framing_range(&self) -> Option<Range<usize>> {
        (self.kind == 0).then(|| {
            self.framing_start + self.offset..self.framing_start + self.offset + self.length
        })
    }

    pub fn acquire(&self, reader: &mut TCacheReader) -> Option<AcquiredRange> {
        if !matches!(self.kind, 1..=3) || !self.seq.is_multiple_of(super::ALIGN as u64) {
            return None;
        }
        let consumer = reader.get(TCacheId::from_index(self.cache)?).filter(|c| c.is_strict())?;
        let read = TCacheRead { id: consumer.id(), seq: self.seq };
        if self.kind == 3 {
            let reference =
                SubReservationRef { read, header_bytes: (self.metadata >> 32) as usize };
            let acquired = reference.acquire(reader).ok()?;
            let [first, second] = acquired.ranges(((self.metadata as u32) >> 1) as usize)?;
            let range = if self.metadata & 1 == 0 { first } else { second };
            range.slice(self.offset, self.length)
        } else {
            consumer.acquire_strict(read)?.with_range(self.offset, self.length)
        }
    }
}

#[cfg(test)]
mod tests;
