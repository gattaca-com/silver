use silver_common::{P2pStreamId, TCacheRead, TRandomAccess};

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
        tcache: TCacheRead,
    },
    /// Writing body. `offset`/`length` track progress into the current
    /// message; the handler provides body bytes via `send_data`.
    Writing {
        offset: usize,
        length: usize,
        tcache: TCacheRead,
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
        consumer: &mut TRandomAccess,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id, consumer)? {
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
        consumer: &mut TRandomAccess,
    ) -> Result<Spin, StreamError> {
        match self {
            GossipWriteState::Idle => match io.gossip_next() {
                Some(tcache) => {
                    let mut buffer = [0u8; 10];
                    let limit = silver_common::encode_varint(tcache.len()? as u64, &mut buffer).inspect_err(|_| {
                        consumer.release(&tcache); 
                    })?;
                    Ok(Spin::Next(Self::WritingLength { buffer, limit, written: 0, tcache }))
                }
                None => Ok(Spin::Ok(Self::Idle)),
            },
            GossipWriteState::WritingLength { buffer, limit, mut written, tcache } => {
                written += io.write_to_stream(p2p_id.stream_id(), &buffer[written..limit]).inspect_err(|_| {
                    consumer.release(&tcache); 
                })?;
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
                let (buffer, _) = consumer.read_at(tcache.seq())?;
                offset += io.write_to_stream(p2p_id.stream_id(), &buffer[offset..]).inspect_err(|_| {
                    consumer.release(&tcache); 
                })?;
                if offset == length {
                    consumer.release(&tcache); 
                    return Ok(Spin::Next(Self::Idle))
                }
                Ok(Spin::Ok(Self::Writing { offset, length, tcache }))
            }
        }
    }
}
