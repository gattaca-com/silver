use silver_common::{P2pStreamId, encode_varint};

use crate::p2p::{
    quic::StreamWriter,
    streams::{
        StreamError, StreamIo,
        rpc::{AcquiredRpcOutbound, AcquiredRpcResponse},
        snappy::SnappyEncoder,
    },
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcWriteResponse {
    Idle,
    WritingPrefix { buf: [u8; 15], length: usize, written: usize, response: AcquiredRpcResponse },
    WritingResponse { response: AcquiredRpcResponse, written: usize },
}

impl RpcWriteResponse {
    pub fn new(response: AcquiredRpcResponse) -> Result<Self, StreamError> {
        let mut buf = [0u8; 15];
        let length = write_prefix(&response, &mut buf)?;
        if length == 0 {
            Ok(Self::Idle)
        } else {
            Ok(Self::WritingPrefix { buf, length, written: 0, response })
        }
    }
}

enum Spin {
    Ok(RpcWriteResponse),
    Next(RpcWriteResponse),
}

impl RpcWriteResponse {
    pub fn spin<S: StreamIo>(
        mut self,
        id: &P2pStreamId,
        io: &mut S,
        encoder: &mut SnappyEncoder,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(id, io, encoder)? {
                Spin::Ok(rpc_write_response) => return Ok(rpc_write_response),
                Spin::Next(rpc_write_response) => {
                    self = rpc_write_response;
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
            RpcWriteResponse::Idle => match io.rpc_next() {
                Some(AcquiredRpcOutbound::Response(rsp)) => match &rsp.response {
                    AcquiredRpcResponse::Complete => {
                        io.close_write(id.stream_id())?;
                        Ok(Spin::Ok(Self::Idle))
                    }
                    _ => Ok(Spin::Next(Self::new(rsp.response)?)),
                },
                Some(_) => Err(StreamError::InvalidRpc),
                None => Ok(Spin::Ok(Self::Idle)),
            },
            RpcWriteResponse::WritingPrefix { buf, length, mut written, response } => {
                written += io.write_to_stream(id.stream_id(), &buf[written..length])?;
                if written == length {
                    encoder.reset();
                    Ok(Spin::Next(Self::WritingResponse { response, written: 0 }))
                } else {
                    Ok(Spin::Ok(Self::WritingPrefix { buf, length, written, response }))
                }
            }
            RpcWriteResponse::WritingResponse { response, mut written } => {
                // write bytes -> encoder -> stream.
                let buffer = response_buffer(&response, written)?;
                let buffer_len = buffer.len();

                let mut writer = StreamWriter(id.stream_id(), io);
                let (wrote, pending) = encoder.compress(buffer, &mut writer)?;
                written += wrote;

                if wrote == buffer_len && pending == 0 {
                    // FIN the write side for any single-chunk response
                    // shape — receivers detect end-of-response from FIN,
                    // not from a sentinel chunk. Multi-chunk shapes
                    // (BeaconBlock / DataColumnSidecar) keep the stream
                    // open until the explicit `Complete` sentinel.
                    if !matches!(
                        response,
                        AcquiredRpcResponse::BeaconBlock { .. } |
                            AcquiredRpcResponse::DataColumnSidecar { .. }
                    ) {
                        io.close_write(id.stream_id())?;
                    }
                    Ok(Spin::Ok(Self::Idle))
                } else {
                    Ok(Spin::Ok(Self::WritingResponse { response, written }))
                }
            }
        }
    }
}

fn response_buffer(response: &AcquiredRpcResponse, offset: usize) -> Result<&[u8], StreamError> {
    let buf = match response {
        AcquiredRpcResponse::StatusV1(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcResponse::StatusV2(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcResponse::Ping(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcResponse::MetaData(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        AcquiredRpcResponse::BeaconBlock { fork_digest: _, ssz } => {
            let (buf, _) = ssz.buffer()?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        AcquiredRpcResponse::DataColumnSidecar { fork_digest: _, ssz } => {
            let (buf, _) = ssz.buffer()?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        AcquiredRpcResponse::ExecutionPayloadEnvelope { fork_digest: _, ssz } => {
            let (buf, _) = ssz.buffer()?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        AcquiredRpcResponse::Error { error: _, msg, len } => {
            if offset < *len {
                &msg[offset..*len]
            } else {
                &[]
            }
        }
        AcquiredRpcResponse::Complete => &[],
    };
    Ok(buf)
}

fn response_length(response: &AcquiredRpcResponse) -> Result<usize, StreamError> {
    let len = match response {
        AcquiredRpcResponse::StatusV1(b) => b.len(),
        AcquiredRpcResponse::StatusV2(b) => b.len(),
        AcquiredRpcResponse::Ping(b) => b.len(),
        AcquiredRpcResponse::MetaData(b) => b.len(),
        AcquiredRpcResponse::BeaconBlock { fork_digest: _, ssz } => ssz.len()?,
        AcquiredRpcResponse::DataColumnSidecar { fork_digest: _, ssz } => ssz.len()?,
        AcquiredRpcResponse::ExecutionPayloadEnvelope { fork_digest: _, ssz } => ssz.len()?,
        AcquiredRpcResponse::Error { error: _, msg: _, len } => *len,
        AcquiredRpcResponse::Complete => 0,
    };
    Ok(len)
}

fn write_prefix(
    response: &AcquiredRpcResponse,
    prefix: &mut [u8; 15],
) -> Result<usize, StreamError> {
    match response {
        AcquiredRpcResponse::BeaconBlock { fork_digest, ssz } => {
            prefix[0] = 0;
            prefix[1..5].copy_from_slice(fork_digest);
            let offset = encode_varint(ssz.len()? as u64, &mut prefix[5..])?;
            Ok(offset + 5)
        }
        AcquiredRpcResponse::DataColumnSidecar { fork_digest, ssz } => {
            prefix[0] = 0;
            prefix[1..5].copy_from_slice(fork_digest);
            let offset = encode_varint(ssz.len()? as u64, &mut prefix[5..])?;
            Ok(offset + 5)
        }
        AcquiredRpcResponse::ExecutionPayloadEnvelope { fork_digest, ssz } => {
            prefix[0] = 0;
            prefix[1..5].copy_from_slice(fork_digest);
            let offset = encode_varint(ssz.len()? as u64, &mut prefix[5..])?;
            Ok(offset + 5)
        }
        AcquiredRpcResponse::Error { error, msg: _, len } => {
            prefix[0] = *error;
            let offset = encode_varint(*len as u64, &mut prefix[1..])?;
            Ok(offset + 1)
        }
        AcquiredRpcResponse::Complete => Ok(0),
        other => {
            let length = response_length(other)?;
            prefix[0] = 0;
            let offset = encode_varint(length as u64, &mut prefix[1..])?;
            Ok(offset + 1)
        }
    }
}
