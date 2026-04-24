#![allow(dead_code, unused_variables, unused_mut)]

mod p2p;
mod socket;
mod tile;

pub use p2p::{NetEvent, P2p, StreamData, TCacheStreamData, create_endpoint, create_server_config};
use silver_common::PeerId;
pub use tile::{Event as NetworkTileEvent, NetworkTile, NetworkTileInner};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
}
