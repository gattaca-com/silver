use std::io::Error;

use quinn_proto::StreamId;

use super::state::IncomingMultiStream;
use crate::p2p::stream::{
    StreamProtocol,
    state::{OutgoingMultiStream, StreamState},
};

pub(crate) struct Stream {
    stream_id: StreamId,
    state: StreamState,
}

impl Stream {
    pub(crate) fn new_incoming(id: StreamId) -> Self {
        Self {
            stream_id: id,
            state: StreamState::IncomingSetup(IncomingMultiStream::ReadingMultiStream {
                buffer: [0u8; 21],
                read: 0,
            }),
        }
    }

    pub(crate) fn new_outgoing(id: StreamId, protocol: StreamProtocol) -> Self {
        Self {
            stream_id: id,
            state: StreamState::OutgoingSetup(OutgoingMultiStream::WritingMultiStream {
                protocol,
                written: 0,
            }),
        }
    }

    pub(crate) fn read_bytes_wanted(&self) -> usize {
        self.state.read_bytes_max()
    }

    pub(crate) fn read(&mut self, bytes: &[u8]) -> Result<usize, Error> {
        Ok(0)
    }
}
