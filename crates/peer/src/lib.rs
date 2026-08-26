mod counters;
mod database;
mod manager;
mod scoring;
mod state;

pub use manager::{PeerManager, RejectedRoots};
pub use silver_config::SyncingConfig;

silver_common::declare_counters! {
    pub PeerCounters => "peer" {
        // Live connected-peer count (set each tick).
        PeersConnected,
        // Local drops.
        PeersEvicted,
        PeersBanned,
        IpsBanned,
        // Peer-initiated / remote signals.
        GoodbyeReceived,
        RpcMisbehaviour,
        // Discovery candidates dropped before dial.
        DiscDroppedForkDigest,
        DiscDroppedBanned,
        DiscDroppedRemoteBan,
        // Gossip validation failures.
        GossipInvalidFrame,
        GossipInvalidControl,
        GossipInvalidMsg,
        // Mesh churn direction.
        MeshPrunedByRemote,
        MeshPrunedByUs,
        MeshGraftAcceptedByUs,
        MeshGraftRefusedByUs,
        // Re-GRAFT inside the backoff we advertised in our PRUNE.
        MeshGraftBackoffViolation,
        // Subnets still below `d` after a mesh sweep — peers covering these
        // dial past the ordinary caps.
        MeshSubnetDeficits,
        // Long-connected peer holding no mesh slot and no score, shed while
        // over the priority cap.
        IdlePeerGoodbye,
        // "cannot create stream" split by cause.
        StreamCreditExhausted,
        ResponseStreamGone,
    }
}
