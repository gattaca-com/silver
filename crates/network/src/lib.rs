mod p2p;
mod socket;
mod tile;

pub use p2p::{P2p, PeerHandler, StreamHandler, create_endpoint, create_server_config};
use silver_common::PeerId;
pub use tile::NetworkTile;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
}
