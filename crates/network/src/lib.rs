mod p2p;
mod socket;
mod tile;

use std::net::SocketAddr;

pub use p2p::{Context, NetEvent, P2p, SendResult, create_endpoint, create_server_config};
use silver_common::PeerId;
pub use tile::{Event as NetworkTileEvent, NetworkTile, NetworkTileInner};

silver_common::declare_counters! {
    pub NetworkCounters => "network" {
        DiscBytesRecv,
        DiscBytesSent,
        P2pBytesRecv,
        P2pBytesSent,
        P2pConnections,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
    pub addr: SocketAddr,
}
