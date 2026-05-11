mod request_in;
mod request_out;
mod reservation;
mod response_in;
mod response_out;

pub use request_in::RpcReadRequest;
pub use request_out::RpcWriteRequest;
use reservation::{Rpc, RpcReservation, alloc_incoming_rpc};
pub use response_in::RpcReadResponse;
pub use response_out::RpcWriteResponse;
use silver_common::{
    P2pStreamId, RpcOutbound, RpcRequest, RpcResponse, StreamProtocol, TRandomAccess, TRead,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, DC_BY_RANGE_REQ_MAX, GOODBYE_SIZE, METADATA_SIZE, PING_SIZE,
        STATUS_V1_SIZE, STATUS_V2_SIZE,
    },
};

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
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum AcquiredRpcOutbound {
    Request(AcquiredRpcRequestOutbound),
    Response(AcquiredRpcResponseOutbound),
}

#[derive(Clone)]
pub(crate) struct AcquiredRpcRequestOutbound {
    pub(crate) application_id: u64,
    pub(crate) request: AcquiredRpcRequest,
}

#[derive(Clone)]
pub(crate) struct AcquiredRpcResponseOutbound {
    pub(crate) stream_id: P2pStreamId,
    pub(crate) response: AcquiredRpcResponse,
}

impl From<(RpcOutbound, &mut TRandomAccess)> for AcquiredRpcOutbound {
    fn from((rpc, consumer): (RpcOutbound, &mut TRandomAccess)) -> Self {
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
    Error { error: u8, msg: [u8; 256], len: usize },
    Complete,
}

impl From<(RpcResponse, &mut TRandomAccess)> for AcquiredRpcResponse {
    fn from((rsp, consumer): (RpcResponse, &mut TRandomAccess)) -> Self {
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
            RpcResponse::Error { error, msg, len } => Self::Error { error, msg, len },
            RpcResponse::Complete => Self::Complete,
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
        }
    }
}

impl From<(RpcRequest, &mut TRandomAccess)> for AcquiredRpcRequest {
    fn from((req, consumer): (RpcRequest, &mut TRandomAccess)) -> Self {
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
        }
    }
}
