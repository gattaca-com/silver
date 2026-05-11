use silver_common::{P2pStreamId, TRead};

use crate::p2p::streams::{StreamError, StreamIo};

/// Write-side state for gossipsub: idle → varint length → body.
#[derive(Debug)]
pub(crate) enum GossipWriteState {
    Idle,
    /// Writing varint length prefix.
    WritingLength {
        buffer: [u8; 10],
        limit: usize,
        written: usize,
        tcache: TRead,
    },
    /// Writing body. `offset`/`length` track progress into the current
    /// message; the handler provides body bytes via `send_data`.
    Writing {
        offset: usize,
        length: usize,
        tcache: TRead,
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
            GossipWriteState::Idle => match io.gossip_next() {
                Some(tcache) => {
                    let mut buffer = [0u8; 10];
                    let limit = silver_common::encode_varint(tcache.len()? as u64, &mut buffer)?;
                    Ok(Spin::Next(Self::WritingLength { buffer, limit, written: 0, tcache }))
                }
                None => Ok(Spin::Ok(Self::Idle)),
            },
            GossipWriteState::WritingLength { buffer, limit, mut written, tcache } => {
                written += io.write_to_stream(p2p_id.stream_id(), &buffer[written..limit])?;
                if written == limit {
                    return Ok(Spin::Next(Self::Writing {
                        offset: 0,
                        length: tcache.len()?,
                        tcache,
                    }))
                }
                Ok(Spin::Ok(Self::WritingLength { buffer, limit, written, tcache }))
            }
            GossipWriteState::Writing { mut offset, length, tcache } => {
                let (buffer, _) = tcache.buffer()?;
                offset += io.write_to_stream(p2p_id.stream_id(), &buffer[offset..])?;
                if offset == length {
                    return Ok(Spin::Next(Self::Idle))
                }
                Ok(Spin::Ok(Self::Writing { offset, length, tcache }))
            }
        }
    }
}
