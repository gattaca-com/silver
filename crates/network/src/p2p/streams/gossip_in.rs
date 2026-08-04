use std::io::Write;

use flux_profiler::timed;
use silver_common::{
    MAX_GOSSIP_FRAME_SIZE, P2pStreamId, TCacheProducer, TProducer, TReservation, decode_varint,
};

use crate::p2p::streams::{StreamError, StreamIo};

/// Read-side state for gossipsub: varint length prefix then body.
#[derive(Debug)]
pub(crate) enum GossipReadState {
    /// Reading varint length prefix (byte by byte).
    ReadingLength { buf: [u8; 10], read: usize },
    /// Have read length but buffer needs to be allocated.
    AllocBody { length: usize, buf: [u8; 10], buf_start: usize, buf_end: usize },
    /// Reading message body. `remaining` bytes left.
    ReadingBody { reservation: TReservation, remaining: usize },
    /// It is possible for the incoming half of the stream to be closed and
    /// stream still valid for an outbound gossip stream.
    Closed,
}

impl Default for GossipReadState {
    fn default() -> Self {
        Self::ReadingLength { buf: [0u8; 10], read: 0 }
    }
}

enum Spin {
    Ok(GossipReadState),
    Next(GossipReadState),
}

impl GossipReadState {
    #[timed]
    pub(crate) fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        tcache: &mut TProducer,
        p2p_id: &P2pStreamId,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, tcache, p2p_id)? {
                Spin::Ok(gossip_read_state) => return Ok(gossip_read_state),
                Spin::Next(gossip_read_state) => {
                    self = gossip_read_state;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(
        self,
        io: &mut S,
        tcache: &mut TProducer,
        p2p_id: &P2pStreamId,
    ) -> Result<Spin, StreamError> {
        match self {
            GossipReadState::ReadingLength { mut buf, mut read } => {
                match io.read_from_stream(p2p_id.stream_id(), &mut buf[read..]) {
                    Ok(len) => read += len,
                    Err(StreamError::StreamEOF) if read == 0 => {
                        return Ok(Spin::Ok(Self::Closed));
                    }
                    Err(e) => return Err(e),
                }

                for pos in 0..read {
                    if buf[pos] & 0x80 == 0 {
                        // last byte of varint.
                        let (length, offset) = decode_varint(&buf[..read], 0)?;
                        let length = checked_frame_length(length)?;
                        return Ok(Spin::Next(Self::AllocBody {
                            length,
                            buf,
                            buf_start: offset,
                            buf_end: read,
                        }));
                    }
                }

                if read == buf.len() {
                    return Err(StreamError::InvalidGossipFrame);
                }

                Ok(Spin::Ok(Self::ReadingLength { buf, read }))
            }
            GossipReadState::AllocBody { length, buf, buf_start, buf_end } => {
                let reservation_len = length
                    .checked_add(size_of::<P2pStreamId>())
                    .ok_or(StreamError::GossipFrameTooLarge)?;
                if let Some(mut reservation) = tcache.reserve(reservation_len, true) {
                    // write stream_id as header
                    let _ = reservation.write(p2p_id.as_ref())?;

                    // write any remainder bytes
                    let mut remaining = length;
                    if buf_end > buf_start {
                        remaining -= reservation.write(&buf[buf_start..buf_end])?;
                    }
                    return Ok(Spin::Next(Self::ReadingBody { reservation, remaining }));
                }
                Ok(Spin::Ok(Self::AllocBody { length, buf, buf_start, buf_end }))
            }
            GossipReadState::ReadingBody { mut reservation, mut remaining } => {
                let n = io.read_from_stream(p2p_id.stream_id(), reservation.remaining_buffer()?).inspect_err(|e| {
                    tracing::error!(?e, ?p2p_id, remaining, "reservation write failed");
                })?;
                reservation.increment_offset(n);
                remaining -= n;
                if remaining == 0 {
                    assert!(reservation.is_committed());
                    // Continue into the next frame.
                    return Ok(Spin::Next(Self::ReadingLength { buf: [0u8; 10], read: 0 }));
                }
                Ok(Spin::Ok(Self::ReadingBody { reservation, remaining }))
            }
            GossipReadState::Closed => Ok(Spin::Ok(Self::Closed)),
        }
    }
}

fn checked_frame_length(length: u64) -> Result<usize, StreamError> {
    if length > MAX_GOSSIP_FRAME_SIZE as u64 {
        return Err(StreamError::GossipFrameTooLarge);
    }
    usize::try_from(length).map_err(|_| StreamError::GossipFrameTooLarge)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_length_boundaries() {
        assert_eq!(
            checked_frame_length(MAX_GOSSIP_FRAME_SIZE as u64).unwrap(),
            MAX_GOSSIP_FRAME_SIZE
        );
        assert!(matches!(
            checked_frame_length(MAX_GOSSIP_FRAME_SIZE as u64 + 1),
            Err(StreamError::GossipFrameTooLarge)
        ));
        assert!(matches!(checked_frame_length(u64::MAX), Err(StreamError::GossipFrameTooLarge)));
    }
}
