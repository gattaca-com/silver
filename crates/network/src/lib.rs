mod network_io;
mod p2p;
mod socket;
mod tile;

use std::net::SocketAddr;

#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub use network_io::{SocketId, uring_io::UringIo};
pub use p2p::{
    ClusterNodes, Context, NetEvent, P2p, SendResult, create_endpoint, create_server_config,
};
use silver_common::PeerId;
pub use silver_config::{NetworkConfig, UringConfig};
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
        // RPC codecs currently retained in the network-tile-wide free list.
        RpcCodecPoolIdle,
        CacheSegmentedAdmitted,
        CacheSegmentedRejected,
        CacheSegmentedCapacity,
        CacheSegmentedSegments,
        CacheSegmentedOwnerAllocations,
        CacheSegmentedFrames,
        // Reserved owner slots, including owners already held by Quinn.
        CacheSegmentedOwners,
        // Reserved ranges per recipient, including descriptors; not unique cache backing bytes.
        CacheSegmentedRetainedBytes,
        // Complete partial frames accepted by Quinn, not yet necessarily ACKed.
        PartialFramesWritten,
        PartialResponsesSent,
        PartialCellsServed,
        // Provided includes buffers whose receive CQE has not been processed.
        // InUse counts completed buffers awaiting recycling; HighWater tracks its peak per registration.
        // These four gauges are zero after unregistration or when using Mio.
        UringQuicRxBuffersCapacity,
        UringQuicRxBuffersProvided,
        UringQuicRxBuffersInUse,
        UringQuicRxBuffersHighWater,
        // Consumed counts selected buffers, including errors and discarded packets.
        // Recycled excludes initial provisioning and buffers discarded during shutdown.
        UringQuicRxBuffersConsumed,
        UringQuicRxBuffersRecycled,
        // Pinned buffers swapped for fresh allocations when the pool is exhausted.
        UringQuicRxBuffersReplaced,
        // ENOBUFS completions, not a count of dropped UDP datagrams.
        UringQuicRxNoBuffers,
        UringDiscoveryRxBuffersCapacity,
        UringDiscoveryRxBuffersProvided,
        UringDiscoveryRxBuffersInUse,
        UringDiscoveryRxBuffersHighWater,
        UringDiscoveryRxBuffersConsumed,
        UringDiscoveryRxBuffersRecycled,
        UringDiscoveryRxBuffersReplaced,
        UringDiscoveryRxNoBuffers,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct RemotePeer {
    pub peer_id: PeerId,
    pub connection: usize,
    pub addr: SocketAddr,
}
