use std::{net::SocketAddr, time::Instant};

use flux::utils::ArrayVec;
use silver_common::NodeId;

use crate::crypto::MAX_PACKET_SIZE;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DiscoveryEvent {
    SendMessage { to: SocketAddr, data: ArrayVec<u8, MAX_PACKET_SIZE> },
    NodeFound(NodeId),
    SessionEstablished { node_id: NodeId, addr: SocketAddr },
    ExternalAddrChanged(SocketAddr),
}

pub trait Discovery {
    fn local_id(&self) -> NodeId;

    fn add_node(
        &mut self,
        id: NodeId,
        addr: SocketAddr,
        enr_seq: u64,
        pubkey: [u8; 33],
        now: Instant,
    );

    fn find_node(&mut self, target: NodeId);

    // todo @ nina: ban / unban
}

pub trait DiscoveryNetworking {
    fn handle(&mut self, src_addr: SocketAddr, data: &[u8], now: Instant);

    fn poll<F: FnMut(DiscoveryEvent)>(&mut self, f: F);
}
