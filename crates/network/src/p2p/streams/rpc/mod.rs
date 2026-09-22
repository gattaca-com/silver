mod pool;
mod request_in;
mod request_out;
mod reservation;
mod response_in;
mod response_out;

#[cfg(test)]
mod tests;

pub(crate) use pool::{RpcCodecDirection, RpcCodecPool};
pub use request_in::RpcReadRequest;
pub use request_out::RpcWriteRequest;
use reservation::{Rpc, RpcReservation, alloc_incoming_rpc};
pub use response_in::RpcReadResponse;
pub use response_out::RpcWriteResponse;
use silver_common::{
    P2pStreamId, RpcOutbound, RpcRequest, RpcRequestOutbound, RpcResponse, RpcResponseOutbound,
    StreamProtocol, TCacheReader, TRead,
    rpc_rate_limit::{RPC_ERR_RATE_LIMITED, RPC_RATE_LIMITED_MSG},
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, DC_BY_RANGE_REQ_MAX,
        EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE, GOODBYE_SIZE, METADATA_SIZE, PING_SIZE,
        STATUS_V1_SIZE, STATUS_V2_SIZE,
    },
};

use crate::p2p::streams::snappy::{SnappyDecoder, SnappyEncoder};

#[derive(Debug)]
pub struct RpcCodec {
    pub enc: SnappyEncoder,
    pub dec: SnappyDecoder,
}

impl RpcCodec {
    fn allocate() -> Box<Self> {
        Box::new(Self { enc: SnappyEncoder::new(), dec: SnappyDecoder::default() })
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcIn {
    ReadRequest(RpcReadRequest),
    WriteResponse(RpcWriteResponse),
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum RpcOut {
    WriteRequest(RpcWriteRequest),
    ReadResponse(RpcReadResponse),
}

// Consumer acquired wrapper for rpc outbound messages
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum AcquiredRpcOutbound {
    Request(AcquiredRpcRequestOutbound),
    Response(AcquiredRpcResponseOutbound),
}

impl AcquiredRpcOutbound {
    pub(crate) fn into_message(self, peer: usize) -> RpcOutbound {
        match self {
            Self::Request(req) => RpcOutbound::Request(RpcRequestOutbound {
                application_id: req.application_id,
                peer,
                request: req.request.into(),
            }),
            Self::Response(rsp) => RpcOutbound::Response(RpcResponseOutbound {
                stream_id: rsp.stream_id,
                response: rsp.response.into(),
            }),
        }
    }

    pub fn protocol(&self) -> StreamProtocol {
        match self {
            Self::Request(req) => req.request.protocol(),
            Self::Response(rsp) => rsp.stream_id.protocol(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AcquiredRpcRequestOutbound {
    pub(crate) application_id: u64,
    pub(crate) request: AcquiredRpcRequest,
}

#[derive(Clone, Debug)]
pub(crate) struct AcquiredRpcResponseOutbound {
    pub(crate) stream_id: P2pStreamId,
    pub(crate) response: AcquiredRpcResponse,
}

impl From<(RpcOutbound, &mut TCacheReader)> for AcquiredRpcOutbound {
    fn from((rpc, consumer): (RpcOutbound, &mut TCacheReader)) -> Self {
        match rpc {
            RpcOutbound::Request(req) => Self::Request(AcquiredRpcRequestOutbound {
                application_id: req.application_id,
                request: (req.request, consumer).into(),
            }),
            RpcOutbound::Response(rsp) => Self::Response(AcquiredRpcResponseOutbound {
                stream_id: rsp.stream_id,
                response: (rsp.response, consumer).into(),
            }),
        }
    }
}

// Same as `RpcResponse` but replaces `TCacheRead` with acquired `TRead`.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum AcquiredRpcResponse {
    StatusV1([u8; STATUS_V1_SIZE]),
    StatusV2([u8; STATUS_V2_SIZE]),
    Ping([u8; PING_SIZE]),
    MetaData([u8; METADATA_SIZE]),
    BeaconBlock { fork_digest: [u8; 4], ssz: TRead },
    DataColumnSidecar { fork_digest: [u8; 4], ssz: TRead },
    ExecutionPayloadEnvelope { fork_digest: [u8; 4], ssz: TRead },
    Error { error: u8, msg: [u8; 256], len: usize },
    Complete,
}

impl AcquiredRpcResponse {
    pub(crate) fn rate_limited() -> Self {
        let mut msg = [0u8; 256];
        msg[..RPC_RATE_LIMITED_MSG.len()].copy_from_slice(RPC_RATE_LIMITED_MSG);
        Self::Error { error: RPC_ERR_RATE_LIMITED, msg, len: RPC_RATE_LIMITED_MSG.len() }
    }
}

impl From<(RpcResponse, &mut TCacheReader)> for AcquiredRpcResponse {
    fn from((rsp, consumer): (RpcResponse, &mut TCacheReader)) -> Self {
        match rsp {
            RpcResponse::StatusV1(b) => Self::StatusV1(b),
            RpcResponse::StatusV2(b) => Self::StatusV2(b),
            RpcResponse::Ping(b) => Self::Ping(b),
            RpcResponse::MetaData(b) => Self::MetaData(b),
            RpcResponse::BeaconBlock { fork_digest, ssz } => {
                let acquired = consumer.acquire(ssz);
                Self::BeaconBlock { fork_digest, ssz: acquired }
            }
            RpcResponse::DataColumnSidecar { fork_digest, ssz } => {
                let acquired = consumer.acquire(ssz);
                Self::DataColumnSidecar { fork_digest, ssz: acquired }
            }
            RpcResponse::ExecutionPayloadEnvelope { fork_digest, ssz } => {
                let acquired = consumer.acquire(ssz);
                Self::ExecutionPayloadEnvelope { fork_digest, ssz: acquired }
            }
            RpcResponse::Error { error, msg, len } => Self::Error { error, msg, len },
            RpcResponse::Complete => Self::Complete,
        }
    }
}

impl From<AcquiredRpcResponse> for RpcResponse {
    fn from(rsp: AcquiredRpcResponse) -> Self {
        match rsp {
            AcquiredRpcResponse::StatusV1(b) => Self::StatusV1(b),
            AcquiredRpcResponse::StatusV2(b) => Self::StatusV2(b),
            AcquiredRpcResponse::Ping(b) => Self::Ping(b),
            AcquiredRpcResponse::MetaData(b) => Self::MetaData(b),
            AcquiredRpcResponse::BeaconBlock { fork_digest, ssz } => {
                Self::BeaconBlock { fork_digest, ssz: ssz.read }
            }
            AcquiredRpcResponse::DataColumnSidecar { fork_digest, ssz } => {
                Self::DataColumnSidecar { fork_digest, ssz: ssz.read }
            }
            AcquiredRpcResponse::ExecutionPayloadEnvelope { fork_digest, ssz } => {
                Self::ExecutionPayloadEnvelope { fork_digest, ssz: ssz.read }
            }
            AcquiredRpcResponse::Error { error, msg, len } => Self::Error { error, msg, len },
            AcquiredRpcResponse::Complete => Self::Complete,
        }
    }
}

#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum AcquiredRpcRequest {
    StatusV1([u8; STATUS_V1_SIZE]),
    StatusV2([u8; STATUS_V2_SIZE]),
    Ping([u8; PING_SIZE]),
    Goodbye([u8; GOODBYE_SIZE]),
    MetaData,
    BlocksByRange([u8; BLOCKS_BY_RANGE_REQ_SIZE]),
    BlockByRoot(TRead),
    DataColumnsByRange { ssz: [u8; DC_BY_RANGE_REQ_MAX], len: usize },
    DataColumnsByRoot(TRead),
    ExecutionPayloadEnvelopesByRange([u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE]),
    ExecutionPayloadEnvelopesByRoot(TRead),
}

impl AcquiredRpcRequest {
    pub fn protocol(&self) -> StreamProtocol {
        match self {
            AcquiredRpcRequest::StatusV1(_) => StreamProtocol::StatusV1,
            AcquiredRpcRequest::StatusV2(_) => StreamProtocol::StatusV2,
            AcquiredRpcRequest::Ping(_) => StreamProtocol::Ping,
            AcquiredRpcRequest::Goodbye(_) => StreamProtocol::Goodbye,
            AcquiredRpcRequest::MetaData => StreamProtocol::Metadata,
            AcquiredRpcRequest::BlocksByRange(_) => StreamProtocol::BeaconBlocksByRange,
            AcquiredRpcRequest::BlockByRoot { .. } => StreamProtocol::BeaconBlocksByRoot,
            AcquiredRpcRequest::DataColumnsByRange { .. } => {
                StreamProtocol::DataColumnSidecarsByRange
            }
            AcquiredRpcRequest::DataColumnsByRoot { .. } => {
                StreamProtocol::DataColumnSidecarsByRoot
            }
            AcquiredRpcRequest::ExecutionPayloadEnvelopesByRange(_) => {
                StreamProtocol::ExecutionPayloadEnvelopesByRange
            }
            AcquiredRpcRequest::ExecutionPayloadEnvelopesByRoot { .. } => {
                StreamProtocol::ExecutionPayloadEnvelopesByRoot
            }
        }
    }
}

impl From<(RpcRequest, &mut TCacheReader)> for AcquiredRpcRequest {
    fn from((req, consumer): (RpcRequest, &mut TCacheReader)) -> Self {
        match req {
            RpcRequest::StatusV1(b) => Self::StatusV1(b),
            RpcRequest::StatusV2(b) => Self::StatusV2(b),
            RpcRequest::Ping(b) => Self::Ping(b),
            RpcRequest::Goodbye(b) => Self::Goodbye(b),
            RpcRequest::MetaData => Self::MetaData,
            RpcRequest::BlocksByRange(b) => Self::BlocksByRange(b),
            RpcRequest::BlockByRoot(tcache_read) => {
                let acquired = consumer.acquire(tcache_read);
                Self::BlockByRoot(acquired)
            }
            RpcRequest::DataColumnsByRange { ssz, len } => Self::DataColumnsByRange { ssz, len },
            RpcRequest::DataColumnsByRoot(tcache_read) => {
                let acquired = consumer.acquire(tcache_read);
                Self::DataColumnsByRoot(acquired)
            }
            RpcRequest::ExecutionPayloadEnvelopesByRange(b) => {
                Self::ExecutionPayloadEnvelopesByRange(b)
            }
            RpcRequest::ExecutionPayloadEnvelopesByRoot(tcache_read) => {
                let acquired = consumer.acquire(tcache_read);
                Self::ExecutionPayloadEnvelopesByRoot(acquired)
            }
        }
    }
}

impl From<AcquiredRpcRequest> for RpcRequest {
    fn from(req: AcquiredRpcRequest) -> Self {
        match req {
            AcquiredRpcRequest::StatusV1(b) => Self::StatusV1(b),
            AcquiredRpcRequest::StatusV2(b) => Self::StatusV2(b),
            AcquiredRpcRequest::Ping(b) => Self::Ping(b),
            AcquiredRpcRequest::Goodbye(b) => Self::Goodbye(b),
            AcquiredRpcRequest::MetaData => Self::MetaData,
            AcquiredRpcRequest::BlocksByRange(b) => Self::BlocksByRange(b),
            AcquiredRpcRequest::BlockByRoot(read) => Self::BlockByRoot(read.read),
            AcquiredRpcRequest::DataColumnsByRange { ssz, len } => {
                Self::DataColumnsByRange { ssz, len }
            }
            AcquiredRpcRequest::DataColumnsByRoot(read) => Self::DataColumnsByRoot(read.read),
            AcquiredRpcRequest::ExecutionPayloadEnvelopesByRange(b) => {
                Self::ExecutionPayloadEnvelopesByRange(b)
            }
            AcquiredRpcRequest::ExecutionPayloadEnvelopesByRoot(read) => {
                Self::ExecutionPayloadEnvelopesByRoot(read.read)
            }
        }
    }
}
