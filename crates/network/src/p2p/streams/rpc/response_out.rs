use silver_common::{P2pStreamId, RpcOutbound, RpcResponse, TRandomAccess, encode_varint};

use crate::p2p::{
    quic::StreamWriter,
    streams::{StreamError, StreamIo, snappy::SnappyEncoder},
};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcWriteResponse {
    Idle,
    WritingPrefix { buf: [u8; 15], length: usize, written: usize, response: RpcResponse },
    WritingResponse { encoder: SnappyEncoder, response: RpcResponse, written: usize },
}

impl RpcWriteResponse {
    pub fn new(response: RpcResponse) -> Result<Self, StreamError> {
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
        consumer: &mut TRandomAccess,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(id, io, consumer)? {
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
        consumer: &mut TRandomAccess,
    ) -> Result<Spin, StreamError> {
        match self {
            RpcWriteResponse::Idle => match io.rpc_next() {
                Some(RpcOutbound::Response(rsp)) => Ok(Spin::Next(Self::new(rsp.response)?)),
                Some(_) => Err(StreamError::InvalidRpc),
                None => Ok(Spin::Ok(Self::Idle)),
            },
            RpcWriteResponse::WritingPrefix { buf, length, mut written, response } => {
                written += io.write_to_stream(id.stream_id(), &buf[written..length])?;
                if written == length {
                    let encoder = SnappyEncoder::new();
                    Ok(Spin::Next(Self::WritingResponse { encoder, response, written: 0 }))
                } else {
                    Ok(Spin::Ok(Self::WritingPrefix { buf, length, written, response }))
                }
            }
            RpcWriteResponse::WritingResponse { mut encoder, response, mut written } => {
                // write bytes -> encoder -> stream.
                let buffer = response_buffer(&response, written, consumer)?;

                let mut writer = StreamWriter(id.stream_id(), io);
                let (wrote, pending) = encoder.compress(buffer, &mut writer)?;
                written += wrote;

                if wrote == buffer.len() && pending == 0 {
                    if matches!(response, RpcResponse::Error { .. }) {
                        io.close_write(id.stream_id())?;
                    }
                    Ok(Spin::Ok(Self::Idle))
                } else {
                    Ok(Spin::Ok(Self::WritingResponse { encoder, response, written }))
                }
            }
        }
    }
}

fn response_buffer<'a, 'b: 'a>(
    response: &'a RpcResponse,
    offset: usize,
    consumer: &'b mut TRandomAccess,
) -> Result<&'a [u8], StreamError> {
    let buf = match response {
        RpcResponse::StatusV1(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        RpcResponse::StatusV2(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        RpcResponse::Ping(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        RpcResponse::MetaData(buf) => {
            if offset < buf.len() {
                &buf[offset..]
            } else {
                &[]
            }
        }
        RpcResponse::BeaconBlock { fork_digest: _, ssz } => {
            let (buf, _) = consumer.read_at(ssz.seq())?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => {
            let (buf, _) = consumer.read_at(ssz.seq())?;
            if offset < buf.len() { &buf[offset..] } else { &[] }
        }
        RpcResponse::Error { error, msg, len } => {
            if offset < *len {
                &msg[offset..*len]
            } else {
                &[]
            }
        }
        RpcResponse::Complete => &[],
    };
    Ok(buf)
}

fn response_length(response: &RpcResponse) -> Result<usize, StreamError> {
    let len = match response {
        RpcResponse::StatusV1(b) => b.len(),
        RpcResponse::StatusV2(b) => b.len(),
        RpcResponse::Ping(b) => b.len(),
        RpcResponse::MetaData(b) => b.len(),
        RpcResponse::BeaconBlock { fork_digest: _, ssz } => ssz.len()?,
        RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => ssz.len()?,
        RpcResponse::Error { error: _, msg: _, len } => *len,
        RpcResponse::Complete => 0,
    };
    Ok(len)
}

fn write_prefix(response: &RpcResponse, prefix: &mut [u8; 15]) -> Result<usize, StreamError> {
    match response {
        RpcResponse::BeaconBlock { fork_digest, ssz } => {
            prefix[0] = 0;
            prefix[1..5].copy_from_slice(fork_digest);
            let offset = encode_varint(ssz.len()? as u64, &mut prefix[5..])?;
            Ok(offset + 5)
        }
        RpcResponse::DataColumnSidecar { fork_digest, ssz } => {
            prefix[0] = 0;
            prefix[1..5].copy_from_slice(fork_digest);
            let offset = encode_varint(ssz.len()? as u64, &mut prefix[5..])?;
            Ok(offset + 5)
        }
        RpcResponse::Error { error, msg, len } => {
            prefix[0] = *error;
            let offset = encode_varint(*len as u64, &mut prefix[1..])?;
            Ok(offset + 1)
        }
        RpcResponse::Complete => Ok(0),
        other => {
            let length = response_length(other)?;
            prefix[0] = 0;
            let offset = encode_varint(length as u64, &mut prefix[1..])?;
            Ok(offset + 1)
        }
    }
}
