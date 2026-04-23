use std::net::IpAddr;

use flux::timing::Nanos;

use crate::{GossipTopic, MessageId, P2pStreamId, PeerId, StreamProtocol, TCacheRead, TCacheRef};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgIn {
    pub stream_id: P2pStreamId,
    pub cache_ref: TCacheRef,
    pub tcache_seq: u64,
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
    pub cache_ref: TCacheRef,
    pub tcache_seq: u64,
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct RpcMsgIn {
    pub stream_id: P2pStreamId,
    pub request_id: Option<usize>,
    pub cache_ref: TCacheRef,
    pub tcache_seq: u64,
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
    P2pGossipDontWant {
        p2p_peer: usize,
        hash: MessageId,
    },
    P2pGossipHave {
        p2p_peer: usize,
        topic: GossipTopic,
        hash: MessageId,
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
