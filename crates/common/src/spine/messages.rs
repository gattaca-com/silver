use std::net::IpAddr;

use crate::{P2pStreamId, StreamProtocol, TCacheRef};

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct GossipMsgIn {
    pub stream_id: P2pStreamId,
    pub cache_ref: TCacheRef,
    pub tcache_seq: u64,
}

#[derive(Clone, Copy, Debug)]
#[allow(improper_ctypes)]
#[repr(C)]
pub struct GossipMsgOut {
    pub peer_id: usize,
    pub cache_ref: TCacheRef,
    pub tcache_seq: u64,
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
#[repr(C)]
pub enum PeerEvent {
    NewP2pConnection { p2p_peer: usize, ip: IpBytes, port: u16 },
    P2pDisconnect { p2p_peer: usize },
    CannotCreateStream { p2p_peer: usize, protocol: StreamProtocol },
    OutboundMessageDropped { p2p_peer: usize, protocol: StreamProtocol },
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub enum IpBytes {
    V4([u8;4]),
    V6([u8;16]),
}

impl From<IpAddr> for IpBytes {
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(ipv4_addr) => IpBytes::V4(ipv4_addr.octets()),
            IpAddr::V6(ipv6_addr) => IpBytes::V6(ipv6_addr.octets()),
        }
    }
}