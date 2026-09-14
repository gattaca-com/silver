use silver_common::{P2pStreamId, TRead};

use super::StreamIo;
use crate::p2p::{quic::Leased, streams::StreamError};

#[derive(Debug)]
pub enum ClusterWrite {
    Idle,
    WritingLength {
        buffer: [u8; 2],
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
    Ok(ClusterWrite),
    Next(ClusterWrite),
}

impl ClusterWrite {
    pub(crate) fn spin<S>(mut self, io: &mut S, id: &P2pStreamId) -> Result<Self, StreamError>
    where
        S: StreamIo,
    {
        loop {
            match self.spin_inner(io, id)? {
                Spin::Ok(write_state) => return Ok(write_state),
                Spin::Next(write_state) => {
                    self = write_state;
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
            Self::Idle => match io.cluster_next() {
                Some(message) => {
                    let len = message.len()?;
                    if len > u16::MAX as usize {
                        return Err(StreamError::ClusterFrameTooLarge);
                    }
                    let len = len as u16;
                    Ok(Spin::Next(Self::WritingLength {
                        buffer: len.to_le_bytes(),
                        written: 0,
                        message,
                    }))
                }
                None => Ok(Spin::Ok(Self::Idle)),
            },
            Self::WritingLength { buffer, mut written, message } => {
                let n = io.write_to_stream(p2p_id.stream_id(), &buffer[written..])?;
                written += n;
                if written == buffer.len() {
                    return Ok(Spin::Next(Self::Writing {
                        offset: 0,
                        length: message.len()?,
                        message,
                    }));
                }
                Ok(Spin::Ok(Self::WritingLength { buffer, written, message }))
            }
            Self::Writing { mut offset, length, message } => {
                let Some(r_offset) = message.with_offset(offset) else {
                    tracing::error!(?p2p_id, "stale tcache read @ {}, skipping", message.seq());
                    return Ok(Spin::Next(Self::Idle));
                };

                let n = io.write_leased_to_stream(p2p_id.stream_id(), message.child(r_offset))?;
                offset += n;
                if offset == length {
                    return Ok(Spin::Next(Self::Idle));
                }
                Ok(Spin::Ok(Self::Writing { offset, length, message }))
            }
        }
    }
}
