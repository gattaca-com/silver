use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use flux::utils::ArrayVec;
use silver_common::{Enr, NodeId};

use crate::crypto::MAX_PACKET_SIZE;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DiscoveryEvent {
    SendMessage { to: SocketAddr, data: ArrayVec<u8, MAX_PACKET_SIZE> },
    NodeFound(Enr),
    ExternalAddrChanged(SocketAddr),
}

pub trait Discovery {
    fn local_id(&self) -> NodeId;

    // todo @nina - change to enr?
    fn add_node(
        &mut self,
        id: NodeId,
        addr: SocketAddr,
        enr_seq: u64,
        pubkey: [u8; 33],
        now: Instant,
    );

    fn find_nodes(&mut self);

    fn ban_node(&mut self, id: NodeId, duration: Option<Duration>);

    fn ban_ip(&mut self, ip: IpAddr, duration: Option<Duration>);
}

pub trait DiscoveryNetworking {
    fn handle(&mut self, src_addr: SocketAddr, data: &[u8], now: Instant);

    fn poll<F: FnMut(DiscoveryEvent)>(&mut self, f: F);
}
