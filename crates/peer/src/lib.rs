mod database;
mod manager;
mod scoring;
mod state;

pub use manager::PeerManager;
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
        // Gossip validation failures.
        GossipInvalidFrame,
        GossipInvalidControl,
        GossipInvalidMsg,
    }
}
