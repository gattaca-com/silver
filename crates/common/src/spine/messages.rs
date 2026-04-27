use std::net::{IpAddr, SocketAddr};

use flux::timing::Nanos;

use crate::{
    Enr, GossipTopic, MessageId, P2pStreamId, PeerId, StreamProtocol, TCacheRead,
    ssz_view::{
        BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView, BlobIdentifierView,
        DataColumnSidecarView, DataColumnSidecarsByRangeRequestView,
        DataColumnsByRootIdentifierView, SignedBeaconBlockView, StatusView,
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
/// `protobuf` message can be broadcast producing `PeerEvent::SendGossip` with
/// details from this message.
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
#[repr(C)]
pub enum RpcOutType {
    Request(usize, StreamProtocol), // peer id
    Response(P2pStreamId),          // response
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcMsgOut {
    pub msg_type: RpcOutType,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcMsgIn {
    pub stream_id: P2pStreamId,
    pub request_id: Option<usize>,
    pub tcache: TCacheRead,
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
    /// Peer manager with generate select peers to send to.
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
    /// Send a message
    P2pGossipSend {
        p2p: PeerId,
        p2p_connection: usize,
        tcache: TCacheRead,
    },
    /// Open a libp2p connection to the peer described by `enr`. Emitted by
    /// the peer manager on `DiscNodeFound` when capacity allows. The network
    /// tile dedupes against in-flight dials and existing connections.
    P2pDial {
        p2p: PeerId,
        enr: Enr,
    },
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

pub type Peer = u64;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum RpcMsg {
    // missing ping and goodbye
    // Status v2 and MetaData v3 are symmetric: same view for req and resp.
    Status(StatusView),
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
pub struct PeerGossipIn {
    pub topic: GossipTopic,
    pub sender: Peer,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PeerGossipOut {
    pub topic: GossipTopic,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PeerRpcIn {
    pub msg: RpcMsg,
    pub sender: Peer,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PeerRpcOut {
    pub msg: RpcMsg,
    pub recipient: Option<Peer>,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum Feedback {
    Valid,
    Invalid,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipFeedback {
    // TODO or tcache reference?
    pub sender: Peer,
    pub feedback: Feedback,
}
