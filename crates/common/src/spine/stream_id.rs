use quinn_proto::{ConnectionHandle, StreamId, VarInt};

use crate::StreamProtocol;

/// P2p stream id.
#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub struct P2pStreamId {
    connection: usize,
    stream: u64,
    protocol: Option<StreamProtocol>,
}

impl P2pStreamId {
    pub fn new(connection: usize, stream: u64, protocol: Option<StreamProtocol>) -> Self {
        Self { connection, stream, protocol }
    }

    pub fn protocol(&self) -> Option<StreamProtocol> {
        self.protocol
    }
}

impl From<&P2pStreamId> for ConnectionHandle {
    fn from(value: &P2pStreamId) -> Self {
        ConnectionHandle(value.connection)
    }
}

impl From<&P2pStreamId> for StreamId {
    fn from(value: &P2pStreamId) -> Self {
        StreamId::from(unsafe { VarInt::from_u64_unchecked(value.stream) })
    }
}
