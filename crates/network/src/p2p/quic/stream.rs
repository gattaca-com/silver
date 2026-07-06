use std::io::{Error, Write};

use quinn_proto::{Connection, StreamId, WriteError};
use silver_metrics::timed;

use crate::p2p::{
    quic::peer::OutboundBuffer,
    streams::{AcquiredRpcOutbound, StreamError, StreamIo},
};

pub struct StreamIoImpl<'a> {
    pub connection: &'a mut Connection,
    pub outbound: &'a mut OutboundBuffer,
}

impl<'a> StreamIo for StreamIoImpl<'a> {
    #[timed]
    fn write_to_stream(&mut self, id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
        let mut stream = self.connection.send_stream(id);
        match stream.write(data) {
            Ok(wrote) => Ok(wrote),
            Err(WriteError::Blocked) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    #[timed]
    fn read_from_stream(&mut self, id: StreamId, data: &mut [u8]) -> Result<usize, StreamError> {
        let mut stream = self.connection.recv_stream(id);
        let mut chunks = stream.read(true)?;
        let mut offset = 0;
        while offset < data.len() {
            match chunks.next(data.len() - offset) {
                Ok(Some(chunk)) => {
                    let len = (data.len() - offset).min(chunk.bytes.len());
                    data[offset..offset + len].copy_from_slice(&chunk.bytes[..len]);
                    offset += len;
                }
                Ok(None) => {
                    // Stream finished. Bytes already copied were consumed
                    // from quinn's reassembly buffer — erroring here would
                    // drop them. Deliver them; EOF surfaces on the next
                    // call (offset == 0).
                    if offset == 0 {
                        let _ = chunks.finalize();
                        return Err(StreamError::StreamEOF);
                    }
                    break;
                }
                Err(quinn_proto::ReadError::Blocked) => break,
                Err(e) => {
                    let _ = chunks.finalize();
                    return Err(e.into());
                }
            }
        }
        let _ = chunks.finalize();
        Ok(offset)
    }

    fn close_write(&mut self, id: StreamId) -> Result<(), StreamError> {
        // Finish errors Stopped and Closed are no-ops.
        let _ = self.connection.send_stream(id).finish();
        Ok(())
    }

    fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
        match self.outbound {
            OutboundBuffer::Rpc(out_buffer) => out_buffer.pop(),
            _ => None,
        }
    }

    fn gossip_next(&mut self) -> Option<silver_common::TRead> {
        match self.outbound {
            OutboundBuffer::Gossip(out_buffer) => out_buffer.pop(),
            _ => None,
        }
    }
    fn remote_addr(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }
}

pub struct StreamWriter<'a, S: StreamIo>(pub StreamId, pub &'a mut S);

impl<'a, S: StreamIo> Write for StreamWriter<'a, S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.1.write_to_stream(self.0, buf).map_err(Error::other)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
