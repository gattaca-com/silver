use std::{net::IpAddr, ptr::addr_of, slice};

use crate::{GossipTopic, MessageId, P2pStreamId, StreamProtocol, TCacheRead, TCacheRef};

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
pub struct NewGossipMsg {
    pub stream_id: P2pStreamId,
    pub topic: GossipTopic,
    pub msg_hash: MessageId,
    /// Decompressed message SSZ
    pub ssz: TCacheRead,
    /// Protobuf wrapped snappy compressed - as received.
    /// Use this cache ref in `GossipMsgOut`.
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
    P2pNewConnection { p2p_peer: usize, ip: IpBytes, port: u16 },
    P2pDisconnect { p2p_peer: usize },
    P2pCannotCreateStream { p2p_peer: usize, protocol: StreamProtocol },
    P2pOutboundMessageDropped { p2p_peer: usize, protocol: StreamProtocol },
    P2pGossipTopicSubscribe { p2p_peer: usize, topic: GossipTopic },
    P2pGossipTopicUnsubscribe { p2p_peer: usize, topic: GossipTopic },
    P2pGossipTopicGraft { p2p_peer: usize, topic: GossipTopic },
    P2pGossipTopicPrune { p2p_peer: usize, topic: GossipTopic },
    P2pGossipWant { p2p_peer: usize, hash: MessageId, tcache: TCacheRead },
    P2pGossipWantUnknown { p2p_peer: usize, hash: MessageId },
    P2pGossipDontWant { p2p_peer: usize, hash: MessageId },
    P2pGossipHave { p2p_peer: usize, topic: GossipTopic, hash: MessageId },
    P2pGossipInvalidMsg { p2p_peer: usize, topic: GossipTopic, hash: MessageId },
    P2pGossipInvalidControl { p2p_peer: usize },
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
pub struct DecompressedGossipMsg {
    pub stream_id: P2pStreamId,
    pub msg_hash: [u8; 20],
    _padding: [u8; 4],
}

impl DecompressedGossipMsg {
    pub fn new(stream_id: P2pStreamId) -> Self {
        Self { stream_id, msg_hash: [0u8; 20], _padding: [0x6a, 0x77, 0xac, 0xca] }
    }
}

impl AsRef<[u8]> for DecompressedGossipMsg {
    fn as_ref(&self) -> &[u8] {
        let ptr = addr_of!(*self) as *const u8;
        unsafe { slice::from_raw_parts(ptr, size_of::<DecompressedGossipMsg>()) }
    }
}

impl From<&[u8]> for &DecompressedGossipMsg {
    fn from(value: &[u8]) -> Self {
        let slot = value.as_ptr() as *const DecompressedGossipMsg;
        unsafe { &*slot }
    }
}

impl From<&mut [u8]> for &mut DecompressedGossipMsg {
    fn from(value: &mut [u8]) -> Self {
        let slot = value.as_mut_ptr() as *mut DecompressedGossipMsg;
        unsafe { &mut *slot }
    }
}
