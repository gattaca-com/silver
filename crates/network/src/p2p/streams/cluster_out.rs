use std::slice;

use bytes::Bytes;
use silver_common::{MAX_CLUSTER_MESSAGE_BYTES, P2pStreamId, TRead};

use super::StreamIo;
use crate::p2p::{quic::Leased, streams::StreamError};

#[derive(Debug)]
pub enum ClusterWrite {
    Idle,
    WritingLength {
        buffer: [u8; 4],
        written: usize,
        message: Leased<TRead>,
    },
    /// Writing body.
    Writing {
        chunk: Bytes,
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
                    if len > MAX_CLUSTER_MESSAGE_BYTES {
                        return Err(StreamError::ClusterFrameTooLarge);
                    }
                    let len = len as u32;
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
                    let seq = message.seq();
                    let Some(r_offset) = message.into_offset(0) else {
                        silver_log::error!(?p2p_id, "stale tcache read @ {seq}, skipping");
                        return Ok(Spin::Next(Self::Idle));
                    };
                    return Ok(Spin::Next(Self::Writing { chunk: Bytes::from_owner(r_offset) }));
                }
                Ok(Spin::Ok(Self::WritingLength { buffer, written, message }))
            }
            Self::Writing { mut chunk } => {
                let _ = io.write_chunks(p2p_id.stream_id(), slice::from_mut(&mut chunk))?;
                if chunk.is_empty() {
                    return Ok(Spin::Next(Self::Idle));
                }
                Ok(Spin::Ok(Self::Writing { chunk }))
            }
        }
    }
}
