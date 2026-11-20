mod p2p;
mod socket;
mod tile;

use std::net::SocketAddr;

pub use p2p::{
    ClusterNodes, Context, InboundLimits, NetEvent, P2p, SendResult, create_endpoint,
    create_server_config,
};
use silver_common::PeerId;
pub use tile::{Event as NetworkTileEvent, NetworkTile, NetworkTileInner};

silver_common::declare_counters! {
    pub NetworkCounters => "network" {
        DiscBytesRecv,
        DiscBytesSent,
        P2pBytesRecv,
        P2pBytesSent,
        // Stream payload after decryption; excludes QUIC/TLS overhead and
        // retransmits, so gossip + rpc < P2pBytes*.
        P2pGossipBytesRecv,
        P2pGossipBytesSent,
        P2pRpcBytesRecv,
        P2pRpcBytesSent,
        P2pConnections: gauge,
        // Connection-lifecycle diagnostics.
        DialAttempts,
        DialHandshakeOk,
        // Outbound dial that died before the QUIC handshake completed
        // (the "zombie": peer never responded).
        DialTimeoutZombie,
        InboundAccepted,
        InboundRefused,
        InboundRetried,
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
        // Outbound gossip delivery or an inbound cluster read stalled —
        // connection closed.
        GossipStallDisconnect,
        // Inbound gossip body behind its minimum rate — connection closed.
        GossipBodySlowDisconnect,
        // Inbound gossip body given up to free the ingress ring.
        GossipBodyEvicted,
        // Zero-length gossip frames, discarded without an event.
        GossipEmptyFrameDropped,
        // Inbound gossip over its byte quota — connection closed.
        GossipRateLimitDisconnect,
        InboundStreamRateLimited,
        // RPC codecs currently retained in the network-tile-wide free list.
        RpcCodecPoolIdle: gauge,
        CacheSegmentedAdmitted,
        CacheSegmentedRejected,
        CacheSegmentedCapacity,
        // Segmented frame refused: the peer holds its share of the budget.
        CacheSegmentedPeerCapacity,
        CacheSegmentedSegments,
        CacheSegmentedOwnerAllocations,
        CacheSegmentedFrames: gauge,
        // Reserved owner slots, including owners already held by Quinn.
        CacheSegmentedOwners: gauge,
        // Reserved ranges per recipient, including descriptors; not unique cache backing bytes.
        CacheSegmentedRetainedBytes: gauge,
        // Complete partial frames accepted by Quinn, not yet necessarily ACKed.
        PartialFramesWritten,
        PartialResponsesSent,
        PartialCellsServed,
        ClusterOutboundSendFailed,
        // The cluster stream queue was full and evicted its oldest message.
        ClusterOutboundOverwritten,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
    pub addr: SocketAddr,
}
