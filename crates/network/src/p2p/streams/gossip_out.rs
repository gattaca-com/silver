use silver_common::{MAX_GOSSIP_FRAME_SIZE, P2pStreamId, TRead};

use crate::{
    NetworkCounters,
    p2p::{
        quic::{Leased, OutboundGossip, SegmentedFrame},
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
        message: OutboundGossip,
    },
    /// Writing body. `offset`/`length` track progress into the current
    /// message; the handler provides body bytes via `send_data`.
    Writing {
        offset: usize,
        length: usize,
        message: Leased<TRead>,
    },
    WritingSegments(SegmentedFrame),
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
                    let len = match &message {
                        OutboundGossip::Contiguous(message) => message.len()?,
                        OutboundGossip::Segmented(frame) => frame.wire_len(),
                    };
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
                    return Ok(Spin::Next(match message {
                        OutboundGossip::Contiguous(message) => {
                            Self::Writing { offset: 0, length: message.len()?, message }
                        }
                        OutboundGossip::Segmented(frame) => Self::WritingSegments(frame),
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

                let n = io.write_leased_to_stream(p2p_id.stream_id(), message.child(r_offset))?;
                offset += n;
                if offset == length {
                    return Ok(Spin::Next(Self::Idle));
                }
                Ok(Spin::Ok(Self::Writing { offset, length, message }))
            }
            Self::WritingSegments(mut frame) => {
                let n = io.write_chunks(p2p_id.stream_id(), frame.chunks())?;
                if frame.written(n) {
                    Ok(Spin::Next(Self::Idle))
                } else {
                    Ok(Spin::Ok(Self::WritingSegments(frame)))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{array, io::Write as _, net::SocketAddr, time::Instant};

    use bytes::Bytes;
    use quinn_proto::StreamId;
    use silver_common::{
        AcquiredWithOffset, StreamProtocol, TCache, TCacheProducer, TProducer, TRandomAccess,
    };

    use super::*;
    use crate::p2p::{quic::OutboundLeaseWheel, streams::AcquiredRpcOutbound};

    /// Write-only io: hands out one queued gossip message, then accepts at
    /// most `budget` bytes per write call (0 = peer granting no credit).
    struct MockIo {
        pending: Option<Leased<TRead>>,
        retained: Vec<Bytes>,
        written: Vec<u8>,
        budget: usize,
    }

    impl StreamIo for MockIo {
        fn write_to_stream(&mut self, _id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
            let n = data.len().min(self.budget);
            self.written.extend_from_slice(&data[..n]);
            Ok(n)
        }

        fn write_leased_to_stream(
            &mut self,
            _id: StreamId,
            data: Leased<AcquiredWithOffset>,
        ) -> Result<usize, StreamError> {
            let mut data = Bytes::from_owner(data);
            let n = data.len().min(self.budget);
            if n != 0 {
                let accepted = data.split_to(n);
                self.written.extend_from_slice(&accepted);
                self.retained.push(accepted);
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

        fn gossip_next(&mut self) -> Option<OutboundGossip> {
            self.pending.take().map(OutboundGossip::Contiguous)
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
        let mut io = MockIo {
            pending: Some(wheel.leased(msg, now)),
            retained: vec![],
            written: vec![],
            budget: 0,
        };

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
        let mut io = MockIo {
            pending: Some(wheel.leased(msg, now)),
            retained: vec![],
            written: vec![],
            budget: usize::MAX,
        };

        let state = GossipWriteState::Idle.spin(&mut io, &p2p_id).expect("write completes");
        assert!(matches!(state, GossipWriteState::Idle));
        assert_eq!(wheel.active_count(), 1, "Quinn child must outlive the queue/write root");

        io.retained.clear();
        assert_eq!(wheel.active_count(), 0);
    }

    #[test]
    fn strict_partial_write_resumes_at_offset_and_pins_bytes_until_last_ack_owner_drops() {
        const CAPACITY: usize = 1 << 18;
        const CHURN_BYTES: usize = 8 * 1024;

        let mut producer = TCache::producer("", CAPACITY);
        let mut consumer = Box::new(producer.cache_ref().strict_random_access("", true).unwrap());
        let payload: [u8; 513] = array::from_fn(|i| i as u8);
        let mut reservation = producer.reserve(payload.len(), true).unwrap();
        reservation.write_all(&payload).unwrap();
        let read = reservation.read();
        let message = consumer.acquire_strict(read).unwrap();
        let payload_ptr = message.buffer().unwrap().0.as_ptr();
        let now = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(now));
        let mut io = MockIo {
            pending: Some(wheel.leased(message, now)),
            retained: vec![],
            written: vec![],
            budget: 17,
        };
        let p2p_id = P2pStreamId::new(0, 4, StreamProtocol::GossipSub, false);
        let mut state = GossipWriteState::Idle.spin(&mut io, &p2p_id).unwrap();
        assert!(matches!(state, GossipWriteState::Writing { offset: 17, .. }));
        assert_eq!(io.written[..2], [0x81, 0x04]);
        assert_eq!(&io.written[2..], &payload[..17]);
        assert_eq!(io.retained[0].as_ptr(), payload_ptr);
        assert_eq!(wheel.active_count(), 2);

        io.budget = 0;
        state = state.spin(&mut io, &p2p_id).unwrap();
        assert!(matches!(state, GossipWriteState::Writing { offset: 17, .. }));
        assert_eq!(io.written.len(), 2 + 17);
        assert_eq!(io.retained.len(), 1);
        assert_eq!(wheel.active_count(), 2, "blocked attempts must release their child owner");

        let mut produced = 0;
        while let Some(mut reservation) = producer.reserve(CHURN_BYTES, true) {
            reservation.buffer().unwrap().fill(0xee);
            reservation.increment_offset(CHURN_BYTES);
            drop(consumer.acquire_strict(reservation.read()).unwrap());
            produced += 1;
            assert!(produced <= CAPACITY / CHURN_BYTES, "overwrote a pinned send");
        }
        assert!(produced > 0);

        io.budget = 31;
        for _ in 0..payload.len().div_ceil(io.budget) {
            state = state.spin(&mut io, &p2p_id).unwrap();
            if matches!(state, GossipWriteState::Idle) {
                break;
            }
        }
        assert!(matches!(state, GossipWriteState::Idle));
        assert_eq!(&io.written[..2], &[0x81, 0x04]);
        assert_eq!(&io.written[2..], &payload);
        let mut offset = 0;
        for chunk in &io.retained {
            assert_eq!(chunk.as_ref(), &payload[offset..offset + chunk.len()]);
            assert_eq!(chunk.as_ptr(), payload_ptr.wrapping_add(offset));
            offset += chunk.len();
        }
        assert_eq!(offset, payload.len());
        assert_eq!(wheel.active_count(), io.retained.len() as u64);

        let ack_held = io.retained[0].slice(3..);
        let clone = ack_held.clone();
        io.retained.clear();
        assert_eq!(wheel.active_count(), 1);
        assert!(producer.reserve(CHURN_BYTES, true).is_none());
        drop(ack_held);
        assert_eq!(clone.as_ref(), &payload[3..17]);
        assert_eq!(wheel.active_count(), 1);
        assert!(producer.reserve(CHURN_BYTES, true).is_none());
        drop(clone);
        assert_eq!(wheel.active_count(), 0);
        assert!(producer.reserve(CHURN_BYTES, true).is_some());
    }
}
