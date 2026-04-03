mod p2p;
mod socket;
mod tile;

use std::net::SocketAddr;

pub use p2p::{P2p, StreamProtocol, create_endpoint, create_server_config};
use quinn_proto::StreamId;
use silver_common::PeerId;
pub use tile::NetworkTile;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
}

pub trait NetworkSend: Send {
    /// Return a new peer to connect to (if any). This will be
    /// called in a loop by the Network tile until `None` is returned.
    fn new_peer(&mut self) -> Option<(PeerId, SocketAddr)>;

    /// Return new stream to open with the given protocol. Multistream-select
    /// negotiation is handled internally by the peer.
    fn new_streams(&mut self) -> Option<(RemotePeer, StreamProtocol)>;

    /// Return data to send. Called in a loop by the network tile until
    /// `None` is returned.
    fn to_send(&mut self) -> Option<(usize, StreamId, &[u8])>;

    /// Send result callback.
    fn sent(&mut self, peer: &RemotePeer, stream: &StreamId, sent: usize);
}

pub trait NetworkRecv: Send {
    /// Callback when a new peer is connected
    fn new_connection(&mut self, remote_peer: RemotePeer, remote_addr: SocketAddr);

    /// Callback from network when a new stream is established
    /// TODO: return receive ring buffer?
    fn new_stream(&mut self, peer: &RemotePeer, stream_id: &StreamId);

    /// Callback from the network when a new data is received.
    /// TODO: write into returned ring buffer?
    fn recv(&mut self, peer: &RemotePeer, stream_id: &StreamId, data: &[u8]);
}
