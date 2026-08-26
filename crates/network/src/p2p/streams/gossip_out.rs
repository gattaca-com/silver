use std::time::Instant;

use bytes::Bytes;
use silver_common::{MAX_GOSSIP_FRAME_SIZE, P2pStreamId, TRead};

use crate::{
    NetworkCounters,
    p2p::streams::{StreamError, StreamIo, gossip_in::GOSSIP_BODY_STALL_TIMEOUT},
};

/// Write-side state for gossipsub: idle → varint length → body.
#[derive(Debug)]
pub(crate) enum GossipWriteState {
    Idle,
    /// Writing varint length prefix. `last_write` is the last instant any
    /// bytes were accepted by the stream — the write-stall clock.
    WritingLength {
        buffer: [u8; 10],
        limit: usize,
        written: usize,
        tcache: TRead,
        last_write: Instant,
    },
    /// Writing body. `offset`/`length` track progress into the current
    /// message; the handler provides body bytes via `send_data`.
    Writing {
        offset: usize,
        length: usize,
        tcache: TRead,
        last_write: Instant,
    },
}

enum Spin {
    Ok(GossipWriteState),
    Next(GossipWriteState),
}

impl GossipWriteState {
    /// Instant the in-progress write times out if the peer grants no more
    /// credit; `None` when idle. Mirrors `GossipReadState`'s body stall.
    pub(crate) fn deadline(&self) -> Option<Instant> {
        match self {
            Self::WritingLength { last_write, .. } | Self::Writing { last_write, .. } => {
                Some(*last_write + GOSSIP_BODY_STALL_TIMEOUT)
            }
            Self::Idle => None,
        }
    }

    pub fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        p2p_id: &P2pStreamId,
        now: Instant,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id, now)? {
                Spin::Ok(gossip_write_state) => {
                    if let Some(last_write) = match &gossip_write_state {
                        Self::WritingLength { last_write, .. } |
                        Self::Writing { last_write, .. } => Some(*last_write),
                        Self::Idle => None,
                    } && now.saturating_duration_since(last_write) > GOSSIP_BODY_STALL_TIMEOUT
                    {
                        tracing::warn!(?p2p_id, "gossip body write stalled");
                        return Err(StreamError::GossipWriteStall);
                    }
                    return Ok(gossip_write_state);
                }
                Spin::Next(gossip_write_state) => {
                    self = gossip_write_state;
                }
            }
        }
    }
    fn spin_inner<S: StreamIo>(
        self,
        io: &mut S,
        p2p_id: &P2pStreamId,
        now: Instant,
    ) -> Result<Spin, StreamError> {
        match self {
            GossipWriteState::Idle => match io.gossip_next() {
                Some(tcache) => {
                    let mut buffer = [0u8; 10];
                    let len = tcache.len()?;
                    if len > MAX_GOSSIP_FRAME_SIZE {
                        return Err(StreamError::GossipFrameTooLarge);
                    }
                    let len = len as u64;
                    let limit =
                        silver_common::encode_varint(len, &mut buffer).inspect_err(|e| {
                            tracing::error!(?e, len, "network gossiip write failed");
                        })?;
                    Ok(Spin::Next(Self::WritingLength {
                        buffer,
                        limit,
                        written: 0,
                        tcache,
                        last_write: now,
                    }))
                }
                None => Ok(Spin::Ok(Self::Idle)),
            },
            GossipWriteState::WritingLength {
                buffer,
                limit,
                mut written,
                tcache,
                mut last_write,
            } => {
                let n = io.write_to_stream(p2p_id.stream_id(), &buffer[written..limit])?;
                written += n;
                if n > 0 {
                    last_write = now;
                }
                if written == limit {
                    return Ok(Spin::Next(Self::Writing {
                        offset: 0,
                        length: tcache.len()?,
                        tcache,
                        last_write,
                    }));
                }
                Ok(Spin::Ok(Self::WritingLength { buffer, limit, written, tcache, last_write }))
            }
            GossipWriteState::Writing { mut offset, length, tcache, mut last_write } => {
                let Some(r_offset) = tcache.with_offset(offset) else {
                    tracing::error!(?p2p_id, "stale tcache read @ {}, skipping", tcache.seq());
                    NetworkCounters::GossipMsgSkipped.inc();
                    return Ok(Spin::Next(Self::Idle));
                };

                let bytes = Bytes::from_owner(r_offset);
                let n = io.write_bytes_to_stream(p2p_id.stream_id(), bytes)?;
                offset += n;
                if n > 0 {
                    last_write = now;
                }
                if offset == length {
                    return Ok(Spin::Next(Self::Idle));
                }
                Ok(Spin::Ok(Self::Writing { offset, length, tcache, last_write }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, net::SocketAddr, time::Duration};

    use quinn_proto::StreamId;
    use silver_common::{StreamProtocol, TCache, TCacheProducer, TProducer, TRandomAccess};

    use super::*;
    use crate::p2p::streams::AcquiredRpcOutbound;

    /// Write-only io: hands out one queued gossip message, then accepts at
    /// most `budget` bytes per write call (0 = peer granting no credit).
    struct MockIo {
        pending: Option<TRead>,
        budget: usize,
    }

    impl StreamIo for MockIo {
        fn write_to_stream(&mut self, _id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
            Ok(data.len().min(self.budget))
        }

        fn write_bytes_to_stream(
            &mut self,
            _id: StreamId,
            data: Bytes,
        ) -> Result<usize, StreamError> {
            Ok(data.len().min(self.budget))
        }

        fn read_from_stream(&mut self, _id: StreamId, _b: &mut [u8]) -> Result<usize, StreamError> {
            unreachable!("write-only test io")
        }

        fn close_write(&mut self, _id: StreamId) -> Result<(), StreamError> {
            Ok(())
        }

        fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
            None
        }

        fn gossip_next(&mut self) -> Option<TRead> {
            self.pending.take()
        }

        fn remote_addr(&self) -> SocketAddr {
            "127.0.0.1:0".parse().unwrap()
        }
    }

    /// The read holds a raw pointer to its consumer, and the consumer one to
    /// the producer's cache: box the consumer so its address survives the
    /// return, and order the tuple so the consumer drops before the producer.
    fn queued_msg(name: &'static str) -> (Box<TRandomAccess>, TProducer, TRead) {
        let mut producer = TCache::producer(name, 1 << 16);
        let mut consumer = Box::new(producer.cache_ref().random_access(name, false).unwrap());
        let mut reservation = producer.reserve(100, true).unwrap();
        reservation.write_all(&[0xaa; 100]).unwrap();
        reservation.flush().unwrap();
        let read = consumer.acquire(reservation.read());
        (consumer, producer, read)
    }

    #[test]
    fn stalled_write_times_out() {
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::GossipSub, false);
        let (_consumer, _producer, msg) = queued_msg("test_gossip_wstall");
        let mut io = MockIo { pending: Some(msg), budget: 0 };

        let t0 = Instant::now();
        let state = GossipWriteState::Idle.spin(&mut io, &p2p_id, t0).expect("blocked write parks");
        assert!(matches!(state, GossipWriteState::WritingLength { written: 0, .. }));
        assert_eq!(state.deadline(), Some(t0 + GOSSIP_BODY_STALL_TIMEOUT));

        let state = state
            .spin(&mut io, &p2p_id, t0 + GOSSIP_BODY_STALL_TIMEOUT)
            .expect("at the deadline is not past it");
        let err = state
            .spin(&mut io, &p2p_id, t0 + GOSSIP_BODY_STALL_TIMEOUT + Duration::from_millis(1))
            .expect_err("stalled past deadline");
        assert!(matches!(err, StreamError::GossipWriteStall));
    }

    #[test]
    fn progressing_write_does_not_time_out() {
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::GossipSub, false);
        let (_consumer, _producer, msg) = queued_msg("test_gossip_wprogress");
        let mut io = MockIo { pending: Some(msg), budget: 0 };

        let t0 = Instant::now();
        let state = GossipWriteState::Idle.spin(&mut io, &p2p_id, t0).expect("blocked write parks");

        // Credit arrives late: the length prefix and part of the body drain,
        // and the stall clock restarts from this progress.
        io.budget = 10;
        let late = t0 + GOSSIP_BODY_STALL_TIMEOUT + Duration::from_millis(1);
        let state = state.spin(&mut io, &p2p_id, late).expect("progress refreshes the deadline");
        assert!(matches!(
            state,
            GossipWriteState::Writing { offset: 10, length: 100, last_write, .. } if last_write == late
        ));
        assert_eq!(state.deadline(), Some(late + GOSSIP_BODY_STALL_TIMEOUT));
    }
}
