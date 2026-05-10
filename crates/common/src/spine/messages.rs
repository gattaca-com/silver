use std::net::{IpAddr, SocketAddr};

use flux::timing::Nanos;

use crate::{
    Enr, GossipTopic, Identify, MessageId, P2pStreamId, PeerId, StreamProtocol, TCacheRead,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView,
        BlobIdentifierView, DC_BY_RANGE_REQ_MAX, DataColumnSidecarView,
        DataColumnSidecarsByRangeRequestView, DataColumnsByRootIdentifierView, GOODBYE_SIZE,
        GoodbyeView, METADATA_SIZE, MetadataView, PING_SIZE, PingView, STATUS_V1_SIZE,
        STATUS_V2_SIZE, SignedBeaconBlockView, SszView, StatusView,
    },
};

/// Consumed by network tile. Gossip message indicated by `tcache` will be sent
/// to specified peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgOut {
    pub peer_id: usize,
    pub tcache: TCacheRead,
}

/// New inbound, decoded gossip message. Consumed by beacon state tile. The
/// `protobuf` message can be broadcast by producing `PeerEvent::SendGossip`
/// with details from this message.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct NewGossipMsg {
    pub stream_id: P2pStreamId,
    pub topic: GossipTopic,
    pub msg_hash: MessageId,
    pub recv_ts: Nanos,
    /// Decompressed message SSZ
    pub ssz: TCacheRead,
    /// Protobuf wrapped snappy compressed - as received.
    /// Use this cache ref in `PeerEvent::SendGossip` and `GossipMsgOut`.
    pub protobuf: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::large_enum_variant)]
#[repr(C)]
pub enum RpcRequest {
    StatusV1([u8; STATUS_V1_SIZE]),
    StatusV2([u8; STATUS_V2_SIZE]),
    Ping([u8; PING_SIZE]),
    Goodbye([u8; GOODBYE_SIZE]),
    MetaData,
    BlocksByRange([u8; BLOCKS_BY_RANGE_REQ_SIZE]),
    BlockByRoot(TCacheRead),
    DataColumnsByRange { ssz: [u8; DC_BY_RANGE_REQ_MAX], len: usize },
    DataColumnsByRoot(TCacheRead),
}

impl RpcRequest {
    pub fn protocol(&self) -> StreamProtocol {
        match self {
            RpcRequest::StatusV1(_) => StreamProtocol::StatusV1,
            RpcRequest::StatusV2(_) => StreamProtocol::StatusV2,
            RpcRequest::Ping(_) => StreamProtocol::Ping,
            RpcRequest::Goodbye(_) => StreamProtocol::Goodbye,
            RpcRequest::MetaData => StreamProtocol::Metadata,
            RpcRequest::BlocksByRange(_) => StreamProtocol::BeaconBlocksByRange,
            RpcRequest::BlockByRoot { .. } => StreamProtocol::BeaconBlocksByRoot,
            RpcRequest::DataColumnsByRange { .. } => StreamProtocol::DataColumnSidecarsByRange,
            RpcRequest::DataColumnsByRoot { .. } => StreamProtocol::DataColumnSidecarsByRoot,
        }
    }
}

/// An RPC request recevied from a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcRequestInbound {
    pub stream_id: P2pStreamId,
    pub request: RpcRequest,
}

/// An RPC request to be sent to a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcRequestOutbound {
    pub application_id: u64,
    pub peer: usize,
    pub request: RpcRequest,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum RpcResponse {
    StatusV1([u8; STATUS_V1_SIZE]),
    StatusV2([u8; STATUS_V2_SIZE]),
    Ping([u8; PING_SIZE]),
    MetaData([u8; METADATA_SIZE]),
    BeaconBlock {
        fork_digest: [u8; 4],
        ssz: TCacheRead,
    },
    DataColumnSidecar {
        fork_digest: [u8; 4],
        ssz: TCacheRead,
    },
    Error {
        error: u8,
        msg: [u8; 256],
        len: usize,
    },
    /// Indicates that a multi-part response is complete / stream is closed.
    /// Produced following `BeaconBlock`s or `DataColumnSidecar`s unless an
    /// `Error` is produced first.
    Complete,
}

/// RPC response received from a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcResponseInbound {
    pub application_id: u64,
    pub stream_id: P2pStreamId,
    pub response: RpcResponse,
}

/// RPC response to send to a peer.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcResponseOutbound {
    pub stream_id: P2pStreamId,
    pub response: RpcResponse,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[allow(clippy::large_enum_variant)]
pub enum RpcInbound {
    Request(RpcRequestInbound),
    Response(RpcResponseInbound),
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
#[allow(clippy::large_enum_variant)]
pub enum RpcOutbound {
    Request(RpcRequestOutbound),
    Response(RpcResponseOutbound),
}

impl RpcOutbound {
    pub fn peer_id(&self) -> usize {
        match self {
            RpcOutbound::Request(req) => req.peer,
            RpcOutbound::Response(rsp) => rsp.stream_id.peer(),
        }
    }

    pub fn protocol(&self) -> StreamProtocol {
        match self {
            RpcOutbound::Request(req) => req.request.protocol(),
            RpcOutbound::Response(rsp) => rsp.stream_id.protocol(),
        }
    }

    pub fn tcache_read(&self) -> Option<&TCacheRead> {
        match self {
            RpcOutbound::Request(req) => match &req.request {
                RpcRequest::BlockByRoot(tcache_read) => Some(tcache_read),
                RpcRequest::DataColumnsByRoot(tcache_read) => Some(tcache_read),
                _ => None,
            },
            RpcOutbound::Response(rsp) => match &rsp.response {
                RpcResponse::BeaconBlock { fork_digest: _, ssz } => Some(ssz),
                RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => Some(ssz),
                _ => None,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum PeerEvent {
    /// Peer_id_full contains the secp256k1 pubkey and can be used to derive
    /// discovery id
    P2pNewConnection {
        p2p_peer_id: usize,
        peer_id_full: PeerId,
        ip: IpBytes,
        port: u16,
        local_dial: bool,
    },
    P2pDisconnect {
        p2p_peer: usize,
    },
    P2pCannotCreateStream {
        p2p_peer: usize,
        protocol: StreamProtocol,
    },
    P2pOutboundMessageDropped {
        p2p_peer: usize,
        protocol: StreamProtocol,
    },
    P2pGossipTopicSubscribe {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipTopicUnsubscribe {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipTopicGraft {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipTopicPrune {
        p2p_peer: usize,
        topic: GossipTopic,
    },
    P2pGossipWant {
        p2p_peer: usize,
        hash: MessageId,
        tcache: TCacheRead,
    },
    P2pGossipDontWant {
        p2p_peer: usize,
        hash: MessageId,
    },
    P2pGossipHave {
        p2p_peer: usize,
        topic: GossipTopic,
        hash: MessageId,
        /// `true` if we already have this message in our dedup/mcache
        /// (no IWANT will be sent; counts toward IHAVE rate limits only).
        /// `false` if the id is new-to-us — an IWANT is implied.
        already_seen: bool,
    },
    P2pGossipInvalidMsg {
        p2p_peer: usize,
        topic: GossipTopic,
        hash: MessageId,
    },
    P2pGossipInvalidControl {
        p2p_peer: usize,
    },
    P2pGossipInvalidFrame {
        p2p_peer: usize,
    },
    DiscNodeFound {
        enr: Enr,
    },
    DiscExternalAddress {
        address: SocketAddr,
    },
    /// A fully-validated inbound gossip message arrived (post-dedup). Carries
    /// the sending peer, topic, msg id (for promise/score accounting) and a
    /// pre-encoded IDONTWANT protobuf frame the peer manager can fan out to
    /// mesh peers without re-encoding per target.
    NewGossip {
        p2p_peer: usize,
        topic: GossipTopic,
        msg_hash: MessageId,
        idontwant: TCacheRead,
    },
    /// Compression tile has prepared a batched IHAVE frame for `topic`.
    /// Peer manager fans it out to non-mesh subscribers with acceptable score.
    OutboundIHave {
        topic: GossipTopic,
        msg_count: usize,
        protobuf: TCacheRead,
    },
    OutboundIWant {
        p2p_peer: usize,
        iwant: TCacheRead,
    },
    /// Emitted in order to trigger sending of a gossip message.
    /// Peer manager will generate select peers to send to.
    SendGossip {
        originator_stream_id: P2pStreamId,
        topic: GossipTopic,
        msg_hash: MessageId,
        recv_ts: Nanos,
        protobuf: TCacheRead,
    },
    /// Misbehaviour observed on the RPC (req/resp) sub-protocol. The peer
    /// manager translates `severity` into a P5 application-score delta;
    /// `Fatal` is calibrated to push the peer below `graylist_threshold`
    /// outright so the next `tick` evicts them.
    RpcMisbehaviour {
        p2p_peer: usize,
        severity: RpcSeverity,
    },
    /// Peer status received over RPC
    P2pPeerStatus {
        p2p_peer: usize,
        status_ssz: PeerStatus,
    },
    /// Peer metadata recevied over RPC
    P2pPeerMetadata {
        p2p_peer: usize,
        metadata_ssz: [u8; METADATA_SIZE],
    },
    /// Goodbye received from peer
    P2pPeerGoodbye {
        p2p_peer: usize,
        status: u64,
    },
    /// Peer identity information.
    P2pPeerIdentity {
        p2p_peer: usize,
        /// Identify information.
        identify: Identify,
    },
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum PeerStatus {
    V1([u8; STATUS_V1_SIZE]),
    V2([u8; STATUS_V2_SIZE]),
}

/// Severity levels for RPC misbehaviour reports. Mirrors lighthouse's
/// `PeerAction` taxonomy. Mapping to score deltas lives in the peer manager.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum RpcSeverity {
    /// Cryptographic violation (bad signature on a chunk), fork-digest
    /// mismatch on Status, or response root mismatch with the request.
    Fatal,
    /// Invalid SSZ, malformed RPC chunk envelope, chunk-count overflow.
    LowTolerance,
    /// Stream timeout, slow response, missing-but-not-malicious chunks.
    MidTolerance,
    /// Soft signal — single dropped message, transient stream issue.
    HighTolerance,
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
#[allow(clippy::large_enum_variant)]
pub enum P2pSend {
    Gossip(GossipMsgOut),
    Identify(usize),
    Rpc(RpcOutbound),
}

impl P2pSend {
    pub fn peer_id(&self) -> usize {
        match self {
            P2pSend::Gossip(gossip_msg_out) => gossip_msg_out.peer_id,
            P2pSend::Identify(peer) => *peer,
            P2pSend::Rpc(rpc_outbound) => rpc_outbound.peer_id(),
        }
    }

    pub fn protocol(&self) -> StreamProtocol {
        match self {
            P2pSend::Gossip(_) => StreamProtocol::GossipSub,
            P2pSend::Identify(_) => StreamProtocol::Identity,
            P2pSend::Rpc(rpc_outbound) => rpc_outbound.protocol(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
// `P2pDial { enr }` carries the full ~200B `Enr` while most variants fit in
// ~60B. Boxing would break `Copy` (used widely in this enum's hot path) for
// the sake of one cold-path variant — the spine already pays the larger
// variant's footprint per slot, so we accept the disparity.
#[allow(clippy::large_enum_variant)]
pub enum PeerControl {
    Ban {
        p2p: PeerId,
        p2p_connection: usize,
    },
    BanIp {
        ip: IpAddr,
    },
    DiscoverNodes,
    P2pGossipSubscribe {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    P2pGossipUnsubscribe {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    P2pGossipGraft {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    P2pGossipPrune {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
    },
    /// Open a libp2p connection to the peer described by `enr`. Emitted by
    /// the peer manager on `DiscNodeFound` when capacity allows. The network
    /// tile dedupes against in-flight dials and existing connections.
    P2pDial {
        p2p: PeerId,
        enr: Enr,
    },
    P2pSend(P2pSend),
    /// Peer-level ban has timed out — counterpart to `Ban`. Network tile
    /// removes the peer from any deny-list / discv5 routing-table eviction
    /// state. Emitted from `tick` when the per-peer ban TTL expires.
    Unban {
        p2p: PeerId,
    },
    /// IP-level ban has timed out — counterpart to `BanIp`. Network tile
    /// removes the IP from its socket-level deny set. Emitted from `tick`
    /// when `banned_ip_ttl` elapses since the ban.
    UnbanIp {
        ip: IpAddr,
    },
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IpBytes {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl From<IpAddr> for IpBytes {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => IpBytes::V4(ipv4_addr.octets()),
            IpAddr::V6(ipv6_addr) => IpBytes::V6(ipv6_addr.octets()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum RpcMsg {
    // Status v2 and MetaData v3 are symmetric: same view for req and resp.
    Status(StatusView),
    /// `Ping` request and `Pong` response share wire shape (uint64 seq).
    Ping(PingView),
    /// `Goodbye` is request-only (uint64 reason).
    Goodbye(GoodbyeView),
    /// `MetaData` request body is empty; this carries the response only.
    MetaData(MetadataView),
    BlocksRangeReq(BeaconBlocksByRangeRequestView),
    BlocksRootReq(BeaconBlocksByRootRequestView),
    BlobId(BlobIdentifierView),
    DataColumnRangeReq(DataColumnSidecarsByRangeRequestView),
    DataColumnByRoot(DataColumnsByRootIdentifierView),
    // rpc response chunks (one per successful response_chunk)
    BlocksRangeResp(SignedBeaconBlockView),
    BlocksRootResp(SignedBeaconBlockView),
    DataColumnRangeResp(DataColumnSidecarView),
    DataColumnByRootResp(DataColumnSidecarView),
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PeerRpcIn {
    pub msg: RpcMsg,
    pub sender: P2pStreamId,
    pub tcache: TCacheRead,
    /// Request id this chunk belongs to. `0` = unsolicited (no matching
    /// outgoing request).
    pub request_id: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum BeaconStateEvent {
    Synced([u8; STATUS_V2_SIZE]),
    RequestBlocksByRange { request_id: u64, ssz: [u8; BLOCKS_BY_RANGE_REQ_SIZE] },
    Status([u8; STATUS_V2_SIZE]),
    PersistBlock(TCacheRead),
}

impl BeaconStateEvent {
    pub fn view(&self) -> SszView {
        match self {
            Self::Synced { .. } | Self::Status { .. } => SszView::Status(StatusView {}),
            Self::RequestBlocksByRange { .. } => {
                SszView::BeaconBlocksByRangeRequest(BeaconBlocksByRangeRequestView {})
            }
            Self::PersistBlock { .. } => SszView::SignedBeaconBlock(SignedBeaconBlockView {}),
        }
    }
}
