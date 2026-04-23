use std::{hash::Hash, ptr::addr_of, slice};

use quinn_proto::{ConnectionHandle, StreamId, VarInt};

use crate::StreamProtocol;

/// P2p stream id.
/// N.B. for PartialEq and Hash only connection and stream fields are used.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct P2pStreamId {
    connection: usize,
    stream: u64,
    protocol: StreamProtocol,
    _padding: [u8; 7],
}

impl P2pStreamId {
    pub fn new(connection: usize, stream: u64, protocol: StreamProtocol) -> Self {
        Self { connection, stream, protocol, _padding: [0u8; 7] }
    }

    pub fn protocol(&self) -> StreamProtocol {
        self.protocol
    }

    pub fn peer(&self) -> usize {
        self.connection
    }

    pub fn stream(&self) -> u64 {
        self.stream
    }

    pub fn set_protocol(&mut self, protocol: StreamProtocol) {
        self.protocol = protocol;
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

impl PartialEq for P2pStreamId {
    fn eq(&self, other: &Self) -> bool {
        self.connection == other.connection && self.stream == other.stream
    }
}

impl Eq for P2pStreamId {}

impl Hash for P2pStreamId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.connection.hash(state);
        self.stream.hash(state);
    }
}

impl AsRef<[u8]> for P2pStreamId {
    fn as_ref(&self) -> &[u8] {
        let ptr = addr_of!(*self) as *const u8;
        unsafe { slice::from_raw_parts(ptr, size_of::<P2pStreamId>()) }
    }
}

impl From<&[u8]> for &P2pStreamId {
    fn from(value: &[u8]) -> Self {
        let slot = value.as_ptr() as *const P2pStreamId;
        unsafe { &*slot }
    }
}
