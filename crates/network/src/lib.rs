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
        // Connection-lifecycle diagnostics.
        DialAttempts,
        DialHandshakeOk,
        // Outbound dial that died before the QUIC handshake completed
        // (the "zombie": peer never responded).
        DialTimeoutZombie,
        InboundAccepted,
        InboundRefused,
        InboundHandshakeOk,
        // Disconnect reason buckets (ConnectionError variants).
        DisconnectTimedOut,
        DisconnectReset,
        DisconnectAppClosed,
        DisconnectLocal,
        DisconnectOther,
        // A peer's read-timeout gave up on our response (their reset carried
        // the response-timeout code): direct we-are-slow signal.
        RemoteResponseTimeout,
        // Stale gossip skipped
        GossipMsgSkipped,
        // Gossip delivery or inbound read stalled — connection closed.
        GossipStallDisconnect,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
    pub addr: SocketAddr,
}
