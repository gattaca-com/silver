use std::net::{IpAddr, SocketAddr};

use flux::timing::Nanos;

use crate::{
    Enr, GossipTopic, MessageId, NodeId, P2pStreamId, PeerId, StreamProtocol, TCacheRead,
    ssz_view::{
        BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView, BlobIdentifierView,
        DataColumnSidecarView, DataColumnSidecarsByRangeRequestView,
        DataColumnsByRootIdentifierView, SignedBeaconBlockView, StatusView,
    },
};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgIn {
    pub stream_id: P2pStreamId,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgOut {
    pub peer_id: usize,
    pub tcache: TCacheRead,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum Gossip {
    NewInbound(NewGossipMsg),
    NewOutboundIHave(GossipIHaveOut),
}

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
    /// Use this cache ref in `GossipMsgOut`.
    pub protobuf: TCacheRead,
}

/// A new IHAVE message has been generated for a
/// topic that can be sent to peers.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipIHaveOut {
    pub topic: GossipTopic,
    pub msg_count: usize,
    /// Protobuf wrapped IHAVE control message.
    /// Use this cache ref in `GossipMsgOut` to send ot a peer.
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
    P2pGossipWantUnknown {
        p2p_peer: usize,
        hash: MessageId,
    },
    /// Peer kept asking for the same message beyond the mcache's per-(peer,
    /// msg_id) retransmission cap (`gossip_retransmission`, default 3 —
    /// matches rust-libp2p). Informational; no score impact by default.
    P2pGossipWantOverCap {
        p2p_peer: usize,
        hash: MessageId,
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
}

#[derive(Clone, Copy, Debug)]
#[repr(C, u8)]
pub enum PeerControl {
    Ban {
        p2p: PeerId,
        p2p_connection: usize,
        disc: NodeId,
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
    /// Serve an IWANT: forward the message referenced by `tcache` to the
    /// peer. Emitted after score-check passes for a `P2pGossipWant` event.
    P2pGossipForwardMsg {
        p2p: PeerId,
        p2p_connection: usize,
        tcache: TCacheRead,
    },
    /// Send a pre-encoded IHAVE control frame (the `tcache` bytes produced
    /// by the compression tile on `Gossip::NewOutboundIHave`) to a specific
    /// peer. One emission per target peer per outgoing IHAVE batch.
    P2pGossipSendIHave {
        p2p: PeerId,
        p2p_connection: usize,
        topic: GossipTopic,
        tcache: TCacheRead,
    },
    /// Send a pre-encoded IDONTWANT control frame (the `tcache` bytes
    /// produced by the compression tile on `PeerEvent::NewGossip`) to a
    /// specific mesh peer. Emitted by the manager after accepting a new
    /// inbound gossip message — mesh peers who haven't yet forwarded this
    /// id to us get told not to.
    P2pGossipSendDontWant {
        p2p: PeerId,
        p2p_connection: usize,
        tcache: TCacheRead,
    },
    /// Send a pre-encoded IWANT control frame (the `tcache` bytes produced
    /// by the compression tile on `PeerEvent::OutboundIWant`) to the peer
    /// whose IHAVE announced these ids. Gated on score ≥ `gossip_threshold`.
    P2pGossipSendIWant {
        p2p: PeerId,
        p2p_connection: usize,
        tcache: TCacheRead,
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
