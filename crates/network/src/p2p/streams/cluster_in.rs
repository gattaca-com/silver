use std::time::{Duration, Instant};

use silver_common::{P2pStreamId, TCacheProducer, TProducer, TReservation};

use crate::{
    NetEvent,
    p2p::streams::{StreamError, StreamIo},
};

pub(crate) const BODY_STALL_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub(crate) enum ClusterRead {
    /// Reading 2-byte length prefix.
    ReadingLength {
        raft_id: u64,
        buf: [u8; 2],
        read: usize,
    },
    /// Have read length but buffer needs to be allocated.
    AllocBody {
        raft_id: u64,
        length: usize,
        fail_count: usize,
    },
    /// Reading message body. `remaining` bytes left.
    ReadingBody {
        raft_id: u64,
        reservation: TReservation,
        remaining: usize,
        last_read: Instant,
    },
    Closed,
}

enum Spin {
    Ok(ClusterRead),
    Next(ClusterRead),
}

impl ClusterRead {
    pub(crate) fn new(raft_id: u64) -> Self {
        Self::ReadingLength { raft_id, buf: [0u8; 2], read: 0 }
    }

    pub(crate) fn spin<S, F>(
        mut self,
        io: &mut S,
        tcache: &mut silver_common::TProducer,
        id: &P2pStreamId,
        now: Instant,
        emit: &mut F,
    ) -> Result<Self, StreamError>
    where
        S: super::StreamIo,
        F: FnMut(crate::NetEvent),
    {
        loop {
            match self.spin_inner(io, tcache, id, now, emit)? {
                Spin::Ok(read_state) => {
                    if let Self::ReadingBody { last_read, remaining, .. } = &read_state &&
                        now.saturating_duration_since(*last_read) > BODY_STALL_TIMEOUT
                    {
                        tracing::warn!(?id, remaining, "cluster body read stalled");
                        return Err(StreamError::ReadStall);
                    }
                    return Ok(read_state);
                }
                Spin::Next(read_state) => {
                    self = read_state;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo, F>(
        self,
        io: &mut S,
        tcache: &mut TProducer,
        p2p_id: &P2pStreamId,
        now: Instant,
        emit: &mut F,
    ) -> Result<Spin, StreamError>
    where
        F: FnMut(NetEvent),
    {
        match self {
            ClusterRead::ReadingLength { raft_id, mut buf, mut read } => {
                match io.read_from_stream(p2p_id.stream_id(), &mut buf[read..]) {
                    Ok(len) => read += len,
                    Err(StreamError::StreamEOF) if read == 0 => {
                        return Ok(Spin::Ok(Self::Closed));
                    }
                    Err(e) => return Err(e),
                }

                if read == buf.len() {
                    let length = u16::from_le_bytes(buf) as usize;
                    if length == 0 {
                        return Err(StreamError::ClusterFrameZeroSize);
                    }
                    return Ok(Spin::Next(Self::AllocBody { raft_id, length, fail_count: 0 }));
                }

                Ok(Spin::Ok(Self::ReadingLength { raft_id, buf, read }))
            }
            ClusterRead::AllocBody { raft_id, length, fail_count } => {
                if let Some(reservation) = tcache.reserve(length, true) {
                    return Ok(Spin::Next(Self::ReadingBody {
                        raft_id,
                        reservation,
                        remaining: length,
                        last_read: now,
                    }));
                }
                if fail_count == 0 {
                    tracing::warn!(length, "failed to allocate incoming cluster");
                }
                Ok(Spin::Ok(Self::AllocBody { raft_id, length, fail_count: fail_count + 1 }))
            }
            ClusterRead::ReadingBody { raft_id, mut reservation, mut remaining, mut last_read } => {
                let n = io
                    .read_from_stream(p2p_id.stream_id(), reservation.remaining_buffer()?)
                    .inspect_err(|e| {
                        tracing::error!(?e, ?p2p_id, remaining, "reservation write failed");
                    })?;
                reservation.increment_offset(n);
                remaining -= n;
                if n > 0 {
                    last_read = now;
                }
                if remaining == 0 {
                    assert!(reservation.is_committed());
                    emit(NetEvent::Cluster { stream: *p2p_id, raft_id, msg: reservation.read() });
                    // Continue into the next frame.
                    return Ok(Spin::Next(Self::ReadingLength { raft_id, buf: [0u8; 2], read: 0 }));
                }
                Ok(Spin::Ok(Self::ReadingBody { raft_id, reservation, remaining, last_read }))
            }
            ClusterRead::Closed => Ok(Spin::Ok(Self::Closed)),
        }
    }
}
