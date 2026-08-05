use std::io::Write;

use flux_profiler::timed;
use silver_common::{
    MAX_GOSSIP_FRAME_SIZE, P2pStreamId, TCacheProducer, TProducer, TReservation, decode_varint,
};

use crate::p2p::streams::{StreamError, StreamIo};

/// Read-side state for gossipsub: varint length prefix then body.
#[derive(Debug)]
pub(crate) enum GossipReadState {
    /// Reading varint length prefix. The read is chunked, so `buf` may hold
    /// bytes past the varint — body bytes, and for frames shorter than the
    /// buffer even the next frame's start.
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

                    // The length read may have pulled bytes past this frame's
                    // body; the excess belongs to the next frame.
                    let take = (buf_end - buf_start).min(length);
                    let mut remaining = length;
                    if take > 0 {
                        remaining -= reservation.write(&buf[buf_start..buf_start + take])?;
                    }
                    if remaining == 0 {
                        assert!(reservation.is_committed());
                        tracing::warn!(
                            ?p2p_id,
                            length,
                            frame = %format_args!("{:02x?}", &buf[buf_start..buf_start + take]),
                            "tiny gossip frame"
                        );
                        let excess = buf_end - buf_start - take;
                        let mut next = [0u8; 10];
                        next[..excess].copy_from_slice(&buf[buf_start + take..buf_end]);
                        return Ok(Spin::Next(Self::ReadingLength { buf: next, read: excess }));
                    }
                    return Ok(Spin::Next(Self::ReadingBody { reservation, remaining }));
                }
                Ok(Spin::Ok(Self::AllocBody { length, buf, buf_start, buf_end }))
            }
            GossipReadState::ReadingBody { mut reservation, mut remaining } => {
                let n = io
                    .read_from_stream(p2p_id.stream_id(), reservation.remaining_buffer()?)
                    .inspect_err(|e| {
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
    use std::net::SocketAddr;

    use quinn_proto::StreamId;
    use silver_common::{StreamProtocol, TCache, TRead};

    use super::*;
    use crate::p2p::streams::AcquiredRpcOutbound;

    struct MockIo {
        data: Vec<u8>,
        pos: usize,
    }

    impl StreamIo for MockIo {
        fn write_to_stream(&mut self, _id: StreamId, _data: &[u8]) -> Result<usize, StreamError> {
            unreachable!("read-only test io")
        }

        fn read_from_stream(
            &mut self,
            _id: StreamId,
            buf: &mut [u8],
        ) -> Result<usize, StreamError> {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }

        fn close_write(&mut self, _id: StreamId) -> Result<(), StreamError> {
            Ok(())
        }

        fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
            None
        }

        fn gossip_next(&mut self) -> Option<TRead> {
            None
        }

        fn remote_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }
    }

    /// A frame shorter than the 10-byte length read, pipelined hard against
    /// the next frame: the length read grabs the whole frame plus the next
    /// frame's start. Regression: the remainder write overflowed the
    /// reservation (live: `FileTooLarge` teardown right after a meshsub
    /// 1.3.0→1.2.0 renegotiation, whose peers pipeline a 6-byte first frame).
    #[test]
    fn pipelined_small_frame_crosses_length_read() {
        let mut wire = vec![6u8];
        wire.extend_from_slice(b"aaaaaa");
        wire.push(12);
        wire.extend_from_slice(b"bbbbbbbbbbbb");

        let mut producer = TCache::producer("test_gossip_pipelined", 1 << 16);
        let mut consumer = producer.cache_ref().consumer("t").expect("consumer");
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::GossipSub, true);
        let mut io = MockIo { data: wire, pos: 0 };

        let state = GossipReadState::default()
            .spin(&mut io, &mut producer, &p2p_id)
            .expect("pipelined small frame must not error");
        assert!(matches!(state, GossipReadState::ReadingLength { read: 0, .. }));

        let header = size_of::<P2pStreamId>();
        let (frame, _) = consumer.read().expect("first frame");
        assert_eq!(&frame[header..], b"aaaaaa");
        consumer.free();
        let (frame, _) = consumer.read().expect("second frame");
        assert_eq!(&frame[header..], b"bbbbbbbbbbbb");
    }

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
