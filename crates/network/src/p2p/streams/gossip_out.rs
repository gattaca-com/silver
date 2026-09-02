use silver_common::{MAX_GOSSIP_FRAME_SIZE, P2pStreamId, TRead};

use crate::{
    NetworkCounters,
    p2p::{
        quic::Leased,
        streams::{StreamError, StreamIo},
    },
};

/// Write-side state for gossipsub: idle → varint length → body.
#[derive(Debug)]
pub(crate) enum GossipWriteState {
    Idle,
    WritingLength {
        buffer: [u8; 10],
        limit: usize,
        written: usize,
        message: Leased<TRead>,
    },
    /// Writing body. `offset`/`length` track progress into the current
    /// message; the handler provides body bytes via `send_data`.
    Writing {
        offset: usize,
        length: usize,
        message: Leased<TRead>,
    },
}

enum Spin {
    Ok(GossipWriteState),
    Next(GossipWriteState),
}

impl GossipWriteState {
    pub fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        p2p_id: &P2pStreamId,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id)? {
                Spin::Ok(gossip_write_state) => return Ok(gossip_write_state),
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
    ) -> Result<Spin, StreamError> {
        match self {
            Self::Idle => match io.gossip_next() {
                Some(message) => {
                    let mut buffer = [0u8; 10];
                    let len = message.len()?;
                    if len > MAX_GOSSIP_FRAME_SIZE {
                        return Err(StreamError::GossipFrameTooLarge);
                    }
                    let len = len as u64;
                    let limit =
                        silver_common::encode_varint(len, &mut buffer).inspect_err(|e| {
                            tracing::error!(?e, len, "network gossiip write failed");
                        })?;
                    Ok(Spin::Next(Self::WritingLength { buffer, limit, written: 0, message }))
                }
                None => Ok(Spin::Ok(Self::Idle)),
            },
            Self::WritingLength { buffer, limit, mut written, message } => {
                let n = io.write_to_stream(p2p_id.stream_id(), &buffer[written..limit])?;
                written += n;
                if written == limit {
                    return Ok(Spin::Next(Self::Writing {
                        offset: 0,
                        length: message.len()?,
                        message,
                    }));
                }
                Ok(Spin::Ok(Self::WritingLength { buffer, limit, written, message }))
            }
            Self::Writing { mut offset, length, message } => {
                let Some(r_offset) = message.with_offset(offset) else {
                    tracing::error!(?p2p_id, "stale tcache read @ {}, skipping", message.seq());
                    NetworkCounters::GossipMsgSkipped.inc();
                    return Ok(Spin::Next(Self::Idle));
                };

                let n = io.write_gossip_to_stream(p2p_id.stream_id(), message.child(r_offset))?;
                offset += n;
                if offset == length {
                    return Ok(Spin::Next(Self::Idle));
                }
                Ok(Spin::Ok(Self::Writing { offset, length, message }))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Write as _, net::SocketAddr, time::Instant};

    use quinn_proto::StreamId;
    use silver_common::{StreamProtocol, TCache, TCacheProducer, TProducer, TRandomAccess};

    use super::*;
    use crate::p2p::{quic::OutboundLeaseWheel, streams::AcquiredRpcOutbound};

    /// Write-only io: hands out one queued gossip message, then accepts at
    /// most `budget` bytes per write call (0 = peer granting no credit).
    struct MockIo {
        pending: Option<Leased<TRead>>,
        retained: Vec<Leased<silver_common::AcquiredWithOffset>>,
        budget: usize,
    }

    impl StreamIo for MockIo {
        fn write_to_stream(&mut self, _id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
            Ok(data.len().min(self.budget))
        }

        fn write_gossip_to_stream(
            &mut self,
            _id: StreamId,
            data: Leased<silver_common::AcquiredWithOffset>,
        ) -> Result<usize, StreamError> {
            let n = data.as_ref().len().min(self.budget);
            if n != 0 {
                self.retained.push(data);
            }
            Ok(n)
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

        fn gossip_next(&mut self) -> Option<Leased<TRead>> {
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
    fn blocked_write_keeps_enqueue_lease() {
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::GossipSub, false);
        let (_consumer, _producer, msg) = queued_msg("test_gossip_wstall");
        let now = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(now));
        let mut io = MockIo { pending: Some(wheel.leased(msg, now)), retained: vec![], budget: 0 };

        let state = GossipWriteState::Idle.spin(&mut io, &p2p_id).expect("blocked write parks");
        assert!(matches!(state, GossipWriteState::WritingLength { written: 0, .. }));
        assert_eq!(wheel.active_count(), 1);
        drop(state);
        assert_eq!(wheel.active_count(), 0);
    }

    #[test]
    fn completed_write_keeps_lease_until_quinn_owner_drops() {
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::GossipSub, false);
        let (_consumer, _producer, msg) = queued_msg("test_gossip_wprogress");
        let now = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(now));
        let mut io =
            MockIo { pending: Some(wheel.leased(msg, now)), retained: vec![], budget: usize::MAX };

        let state = GossipWriteState::Idle.spin(&mut io, &p2p_id).expect("write completes");
        assert!(matches!(state, GossipWriteState::Idle));
        assert_eq!(wheel.active_count(), 1, "Quinn child must outlive the queue/write root");

        io.retained.clear();
        assert_eq!(wheel.active_count(), 0);
    }
}
