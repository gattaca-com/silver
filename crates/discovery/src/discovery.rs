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

// todo @nina - export these
#[derive(Debug, Default)]
pub struct DiscoveryMetrics {
    pub active_sessions: usize,
    pub pending_challenges: usize,
    pub routing_table_nodes: usize,
    pub nodes_discovered: usize,
    pub whoareyou_limit_hits: usize,
    pub failed_nodes: usize,
}

pub trait Discovery {
    fn local_id(&self) -> NodeId;

    fn add_enr(&mut self, enr: &Enr, now: Instant);

    fn find_nodes(&mut self);

    fn ban_node(&mut self, id: NodeId, duration: Option<Duration>);

    fn ban_ip(&mut self, ip: IpAddr, duration: Option<Duration>);
}

pub trait DiscoveryNetworking {
    fn handle(&mut self, src_addr: SocketAddr, data: &[u8], now: Instant);

    fn poll<F: FnMut(DiscoveryEvent)>(&mut self, f: F);
}
