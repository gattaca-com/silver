/// Discriminant is the slot in `TCacheTable` / `TCacheReader`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCacheId {
    IncomingGossip,
    SszGossip,
    OutgoingGossip,
    IncomingRpc,
    IncomingEngineResp,
    ClusterInbound,
    ClusterOutbound,
    OutgoingRpc,
    ReplayBlocks,
    ElDataColumns,
    DataColumns,
    BeaconState,
}

impl TCacheId {
    pub const COUNT: usize = 12;
    pub const ALL: [Self; Self::COUNT] = [
        Self::IncomingGossip,
        Self::SszGossip,
        Self::OutgoingGossip,
        Self::IncomingRpc,
        Self::IncomingEngineResp,
        Self::ClusterInbound,
        Self::ClusterOutbound,
        Self::OutgoingRpc,
        Self::ReplayBlocks,
        Self::ElDataColumns,
        Self::DataColumns,
        Self::BeaconState,
    ];

    pub fn from_index(index: u64) -> Option<Self> {
        usize::try_from(index).ok().and_then(|index| Self::ALL.get(index)).copied()
    }

    /// Metrics label: `counters-tcache-{name}`, `tcache-write-{name}`.
    pub fn name(self) -> &'static str {
        match self {
            Self::IncomingGossip => "incoming_gossip",
            Self::SszGossip => "ssz_gossip",
            Self::OutgoingGossip => "outgoing_gossip",
            Self::IncomingRpc => "incoming_rpc",
            Self::IncomingEngineResp => "incoming_engine_resp",
            Self::ClusterInbound => "cluster_inbound",
            Self::ClusterOutbound => "cluster_outbound",
            Self::OutgoingRpc => "outgoing_rpc",
            Self::ReplayBlocks => "replay_blocks",
            Self::ElDataColumns => "el_data_columns",
            Self::DataColumns => "data_columns",
            Self::BeaconState => "beacon_state",
        }
    }
}

const _: () = assert!(TCacheId::BeaconState as usize + 1 == TCacheId::COUNT);
