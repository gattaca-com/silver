use std::net::SocketAddr;

use silver_common::PeerId;

use crate::RemotePeer;

pub trait PeerHandler: Send {
    /// Return a new peer to connect to (if any). This will be
    /// called in a loop by the Network tile until `None` is returned.
    fn poll_new_peer(&mut self) -> Option<(PeerId, SocketAddr)>;

    /// Callback when a new peer is connected
    fn new_peer(&mut self, remote_peer: RemotePeer, remote_addr: SocketAddr);
}
