use silver_common::{P2pStreamId, encode_varint};

use crate::p2p::{
    quic::StreamWriter,
    streams::{StreamError, StreamIo, rpc::AcquiredRpcRequest, snappy::SnappyEncoder},
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcWriteRequest {
    WritingPrefix {
        app_id: u64,
        buf: [u8; 10],
        length: usize,
        written: usize,
        request: AcquiredRpcRequest,
    },
    WritingRequest {
        app_id: u64,
        request: AcquiredRpcRequest,
        written: usize,
    },
    Complete(u64),
}

impl RpcWriteRequest {
    pub fn new(app_id: u64, request: AcquiredRpcRequest) -> Result<Self, StreamError> {
        let len = request_length(&request)?;
        if len == 0 {
            Ok(Self::Complete(app_id))
        } else {
            let mut buf = [0u8; 10];
            let length = encode_varint(len as u64, &mut buf)?;
            Ok(Self::WritingPrefix { app_id, buf, length, written: 0, request })
        }
    }
}

enum Spin {
    Ok(RpcWriteRequest),
    Next(RpcWriteRequest),
}

impl RpcWriteRequest {
    pub fn spin<S: StreamIo>(
        mut self,
        id: &P2pStreamId,
        io: &mut S,
        encoder: &mut SnappyEncoder,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(id, io, encoder)? {
                Spin::Ok(rpc_write_request) => return Ok(rpc_write_request),
                Spin::Next(rpc_write_request) => {
                    self = rpc_write_request;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(
        self,
        id: &P2pStreamId,
        io: &mut S,
        encoder: &mut SnappyEncoder,
    ) -> Result<Spin, StreamError> {
        match self {
            RpcWriteRequest::WritingPrefix { app_id, buf, length, mut written, request } => {
                written += io.write_to_stream(id.stream_id(), &buf[written..length])?;
                if written == length {
                    encoder.reset();
                    Ok(Spin::Next(Self::WritingRequest { app_id, request, written: 0 }))
                } else {
                    Ok(Spin::Ok(Self::WritingPrefix { app_id, buf, length, written, request }))
                }
            }
            RpcWriteRequest::WritingRequest { app_id, request, mut written } => {
                // write bytes -> encoder -> stream.
                let buffer = request_buffer(&request, written)?;
                let buffer_len = buffer.len();

                let mut writer = StreamWriter(id.stream_id(), io);
                let (wrote, pending) = encoder.compress(buffer, &mut writer)?;
                written += wrote;

                if wrote == buffer_len && pending == 0 {
                    tracing::debug!(?id, "wrote rpc request");
                    Ok(Spin::Ok(Self::Complete(app_id)))
                } else {
                    Ok(Spin::Ok(Self::WritingRequest { app_id, request, written }))
                }
            }
            RpcWriteRequest::Complete(app_id) => Ok(Spin::Ok(Self::Complete(app_id))),
        }
    }
}

fn request_buffer(request: &AcquiredRpcRequest, offset: usize) -> Result<&[u8], StreamError> {
    let buf = match request {
        AcquiredRpcRequest::StatusV1(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcRequest::StatusV2(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcRequest::Ping(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcRequest::Goodbye(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcRequest::MetaData => &[],
        AcquiredRpcRequest::BlocksByRange(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcRequest::BlockByRoot(read) => {
            let (buf, _) = read.buffer()?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        AcquiredRpcRequest::DataColumnsByRange { ssz, len } => {
            if offset < *len {
                &ssz[offset..*len]
            } else {
                &[]
            }
        }
        AcquiredRpcRequest::DataColumnsByRoot(read) => {
            let (buf, _) = read.buffer()?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
    };
    Ok(buf)
}

fn request_length(request: &AcquiredRpcRequest) -> Result<usize, StreamError> {
    let len = match request {
        AcquiredRpcRequest::StatusV1(b) => b.len(),
        AcquiredRpcRequest::StatusV2(b) => b.len(),
        AcquiredRpcRequest::Ping(b) => b.len(),
        AcquiredRpcRequest::Goodbye(b) => b.len(),
        AcquiredRpcRequest::MetaData => 0,
        AcquiredRpcRequest::BlocksByRange(b) => b.len(),
        AcquiredRpcRequest::BlockByRoot(tcache_read) => tcache_read.len()?,
        AcquiredRpcRequest::DataColumnsByRange { ssz: _, len } => *len,
        AcquiredRpcRequest::DataColumnsByRoot(tcache_read) => tcache_read.len()?,
    };
    Ok(len)
}
