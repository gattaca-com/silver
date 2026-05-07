use silver_common::{P2pStreamId, RpcRequest, TRandomAccess, encode_varint};

use crate::p2p::{
    quic::StreamWriter,
    streams::{StreamError, StreamIo, snappy::SnappyEncoder},
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcWriteRequest {
    WritingPrefix { app_id: u64, buf: [u8; 10], length: usize, written: usize, request: RpcRequest },
    WritingRequest { app_id: u64, encoder: SnappyEncoder, request: RpcRequest, written: usize },
    Complete(u64),
}

impl RpcWriteRequest {
    pub fn new(app_id: u64, request: RpcRequest) -> Result<Self, StreamError> {
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
        consumer: &mut TRandomAccess,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(id, io, consumer)? {
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
        consumer: &mut TRandomAccess,
    ) -> Result<Spin, StreamError> {
        match self {
            RpcWriteRequest::WritingPrefix { app_id, buf, length, mut written, request } => {
                written += io.write_to_stream(id.stream_id(), &buf[written..length])?;
                if written == length {
                    let encoder = SnappyEncoder::new();
                    Ok(Spin::Next(Self::WritingRequest { app_id, encoder, request, written: 0 }))
                } else {
                    Ok(Spin::Ok(Self::WritingPrefix { app_id, buf, length, written, request }))
                }
            }
            RpcWriteRequest::WritingRequest { app_id, mut encoder, request, mut written } => {
                // write bytes -> encoder -> stream.
                let buffer = request_buffer(&request, written, consumer)?;

                let mut writer = StreamWriter(id.stream_id(), io);
                let (wrote, pending) = encoder.compress(buffer, &mut writer)?;
                written += wrote;

                if wrote == buffer.len() && pending == 0 {
                    Ok(Spin::Ok(Self::Complete(app_id)))
                } else {
                    Ok(Spin::Ok(Self::WritingRequest { app_id, encoder, request, written }))
                }
            }
            RpcWriteRequest::Complete(app_id) => Ok(Spin::Ok(Self::Complete(app_id))),
        }
    }
}

fn request_buffer<'a, 'b: 'a>(
    request: &'a RpcRequest,
    offset: usize,
    consumer: &'b mut TRandomAccess,
) -> Result<&'a [u8], StreamError> {
    let buf = match request {
        RpcRequest::StatusV1(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        RpcRequest::StatusV2(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        RpcRequest::Ping(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        RpcRequest::Goodbye(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        RpcRequest::MetaData => &[],
        RpcRequest::BlocksByRange(buffer) => {
            if offset < buffer.len() {
                &buffer[offset..]
            } else {
                &[]
            }
        }
        RpcRequest::BlockByRoot(tcache_read) => {
            let (buf, _) = consumer.read_at(tcache_read.seq())?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        RpcRequest::DataColumnsByRange { ssz, len } => {
            if offset < *len {
                &ssz[offset..*len]
            } else {
                &[]
            }
        }
        RpcRequest::DataColumnsByRoot(tcache_read) => {
            let (buf, _) = consumer.read_at(tcache_read.seq())?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
    };
    Ok(buf)
}

fn request_length(request: &RpcRequest) -> Result<usize, StreamError> {
    let len = match request {
        RpcRequest::StatusV1(b) => b.len(),
        RpcRequest::StatusV2(b) => b.len(),
        RpcRequest::Ping(b) => b.len(),
        RpcRequest::Goodbye(b) => b.len(),
        RpcRequest::MetaData => 0,
        RpcRequest::BlocksByRange(b) => b.len(),
        RpcRequest::BlockByRoot(tcache_read) => tcache_read.len()?,
        RpcRequest::DataColumnsByRange { ssz: _, len } => *len,
        RpcRequest::DataColumnsByRoot(tcache_read) => tcache_read.len()?,
    };
    Ok(len)
}
