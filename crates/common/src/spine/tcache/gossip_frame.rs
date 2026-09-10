use std::{io::Write, ops::Range, time::Instant};

use super::{
    AcquiredRange, AcquiredRead, Producer, RandomAccessConsumer, SubReservationRef, TCacheProducer,
    TCacheRead,
};
use crate::MAX_GOSSIP_FRAME_SIZE;

pub const MAX_GOSSIP_SEGMENTS: usize = 2 * 128 + 8;
const HEADER_BYTES: usize = 16;
const SEGMENT_BYTES: usize = 40;
const MAGIC: [u8; 8] = *b"SGFRAME1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GossipFrameError {
    InvalidDescriptor,
    TooLarge,
    CacheFull,
    Expired,
    Stale,
}

#[derive(Clone, Copy, Debug)]
pub enum GossipSegment {
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
#[derive(Clone, Copy, Debug)]
pub struct GossipFrameRef {
    descriptor: TCacheRead,
    expires: Instant,
}

impl GossipFrameRef {
    pub fn write(
        producer: &mut Producer,
        expires: Instant,
        framing: &[u8],
        segments: impl ExactSizeIterator<Item = GossipSegment>,
    ) -> Result<Self, GossipFrameError> {
        let count = segments.len();
        if count == 0 || count > MAX_GOSSIP_SEGMENTS || framing.len() > MAX_GOSSIP_FRAME_SIZE {
            return Err(GossipFrameError::TooLarge);
        }
        let framing_start = HEADER_BYTES + count * SEGMENT_BYTES;
        let descriptor_len = framing_start + framing.len();
        if descriptor_len >= producer.cache_ref().capacity() {
            return Err(GossipFrameError::CacheFull);
        }
        let cache = producer.cache_ref();
        let mut reservation =
            producer.reserve_scoped(descriptor_len).ok_or(GossipFrameError::CacheFull)?;
        let buffer = reservation.buffer().map_err(|_| GossipFrameError::Stale)?;
        buffer[..8].copy_from_slice(&MAGIC);
        buffer[8..12].copy_from_slice(&(count as u32).to_le_bytes());
        buffer[framing_start..].copy_from_slice(framing);
        let mut total = 0usize;
        let mut written = 0;
        for (index, segment) in segments.enumerate() {
            if index >= count {
                return Err(GossipFrameError::InvalidDescriptor);
            }
            let (kind, read, metadata, offset, length) = match segment {
                GossipSegment::Framing { offset, length } => {
                    if offset.checked_add(length).is_none_or(|end| end > framing.len()) {
                        return Err(GossipFrameError::InvalidDescriptor);
                    }
                    (0u64, None, 0, offset, length)
                }
                GossipSegment::Gossip { read, offset, length } => {
                    if read.tcache.cache != cache.cache {
                        return Err(GossipFrameError::InvalidDescriptor);
                    }
                    (1, Some(read), 0, offset, length)
                }
                GossipSegment::DataColumns { read, offset, length } => {
                    (2, Some(read), 0, offset, length)
                }
                GossipSegment::Shared { reservation, part, second, offset, length } => {
                    if part >= 128 {
                        return Err(GossipFrameError::InvalidDescriptor);
                    }
                    let metadata = ((reservation.header_bytes as u64) << 32) |
                        ((part as u64) << 1) |
                        u64::from(second);
                    (3, Some(reservation.read()), metadata, offset, length)
                }
            };
            if length == 0 || offset > u32::MAX as usize || length > u32::MAX as usize {
                return Err(GossipFrameError::InvalidDescriptor);
            }
            total = total.checked_add(length).ok_or(GossipFrameError::TooLarge)?;
            if total > MAX_GOSSIP_FRAME_SIZE {
                return Err(GossipFrameError::TooLarge);
            }
            let start = HEADER_BYTES + index * SEGMENT_BYTES;
            let entry = &mut buffer[start..start + SEGMENT_BYTES];
            entry[..8].copy_from_slice(&kind.to_le_bytes());
            entry[8..16]
                .copy_from_slice(&read.map_or(0, |r| r.tcache.cache as usize as u64).to_le_bytes());
            entry[16..24].copy_from_slice(&read.map_or(0, |r| r.seq).to_le_bytes());
            entry[24..32].copy_from_slice(&metadata.to_le_bytes());
            entry[32..36].copy_from_slice(&(offset as u32).to_le_bytes());
            entry[36..40].copy_from_slice(&(length as u32).to_le_bytes());
            written += 1;
        }
        if written != count {
            return Err(GossipFrameError::InvalidDescriptor);
        }
        buffer[12..16].copy_from_slice(&(total as u32).to_le_bytes());
        reservation.flush().map_err(|_| GossipFrameError::Stale)?;
        Ok(Self { descriptor: reservation.read(), expires })
    }

    pub fn read(self) -> TCacheRead {
        self.descriptor
    }

    pub fn acquire(
        self,
        consumer: &mut RandomAccessConsumer,
        now: Instant,
    ) -> Result<GossipFrameView, GossipFrameError> {
        if now >= self.expires {
            return Err(GossipFrameError::Expired);
        }
        if !consumer.is_strict() || consumer.cache.cache != self.descriptor.tcache.cache {
            return Err(GossipFrameError::InvalidDescriptor);
        }
        let read = consumer.acquire_strict(self.descriptor).ok_or(GossipFrameError::Stale)?;
        let buffer = read.buffer().map_err(|_| GossipFrameError::Stale)?.0;
        if buffer.len() < HEADER_BYTES || buffer[..8] != MAGIC {
            return Err(GossipFrameError::InvalidDescriptor);
        }
        let count = u32::from_le_bytes(buffer[8..12].try_into().unwrap()) as usize;
        let wire_len = u32::from_le_bytes(buffer[12..16].try_into().unwrap()) as usize;
        if count == 0 || count > MAX_GOSSIP_SEGMENTS {
            return Err(GossipFrameError::InvalidDescriptor);
        }
        let framing_start = HEADER_BYTES + count * SEGMENT_BYTES;
        if framing_start > buffer.len() || wire_len == 0 || wire_len > MAX_GOSSIP_FRAME_SIZE {
            return Err(GossipFrameError::InvalidDescriptor);
        }
        let descriptor_len = buffer.len();
        let view = GossipFrameView { read, count, wire_len, framing_start, descriptor_len };
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
                return Err(GossipFrameError::InvalidDescriptor);
            }
            total = total.checked_add(segment.length).ok_or(GossipFrameError::TooLarge)?;
        }
        if total != wire_len {
            return Err(GossipFrameError::InvalidDescriptor);
        }
        Ok(view)
    }
}

pub struct GossipFrameView {
    read: AcquiredRead,
    count: usize,
    wire_len: usize,
    framing_start: usize,
    descriptor_len: usize,
}

impl GossipFrameView {
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

    pub fn segments(&self) -> impl ExactSizeIterator<Item = GossipFrameSegment> + '_ {
        self.read.buffer().expect("acquired descriptor").0[HEADER_BYTES..self.framing_start]
            .chunks_exact(SEGMENT_BYTES)
            .map(|entry| GossipFrameSegment {
                kind: u64::from_le_bytes(entry[..8].try_into().unwrap()),
                cache: u64::from_le_bytes(entry[8..16].try_into().unwrap()),
                seq: u64::from_le_bytes(entry[16..24].try_into().unwrap()),
                metadata: u64::from_le_bytes(entry[24..32].try_into().unwrap()),
                offset: u32::from_le_bytes(entry[32..36].try_into().unwrap()) as usize,
                length: u32::from_le_bytes(entry[36..40].try_into().unwrap()) as usize,
                framing_start: self.framing_start,
            })
    }
}

pub struct GossipFrameSegment {
    kind: u64,
    cache: u64,
    seq: u64,
    metadata: u64,
    offset: usize,
    length: usize,
    framing_start: usize,
}

impl GossipFrameSegment {
    pub fn framing_range(&self) -> Option<Range<usize>> {
        (self.kind == 0).then(|| {
            self.framing_start + self.offset..self.framing_start + self.offset + self.length
        })
    }

    pub fn acquire(
        &self,
        gossip: &mut RandomAccessConsumer,
        columns: Option<&mut RandomAccessConsumer>,
    ) -> Option<AcquiredRange> {
        let consumer = match self.kind {
            1 => gossip,
            2 | 3 => columns?,
            _ => return None,
        };
        if !consumer.is_strict() ||
            consumer.cache.cache as usize as u64 != self.cache ||
            !self.seq.is_multiple_of(super::ALIGN as u64)
        {
            return None;
        }
        let read = TCacheRead { tcache: consumer.cache, seq: self.seq };
        if self.kind == 3 {
            let reference =
                SubReservationRef { read, header_bytes: (self.metadata >> 32) as usize };
            let acquired = reference.acquire(consumer).ok()?;
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
