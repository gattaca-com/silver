/// Discriminant is the slot in `TCacheTable` / `TCacheReader`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TCacheId {
    NetworkIngress,
    NetworkProcessing,
    ClusterInbound,
    ControlProcessing,
    ControlGossip,
    ControlRpc,
    ClusterOutbound,
    ControlSlot,
    StorageDelivery,
    BoundaryProcessing,
    ColumnsProcessing,
    BeaconStateHandoff,
}

impl TCacheId {
    pub const COUNT: usize = 12;
    pub const ALL: [Self; Self::COUNT] = [
        Self::NetworkIngress,
        Self::NetworkProcessing,
        Self::ClusterInbound,
        Self::ControlProcessing,
        Self::ControlGossip,
        Self::ControlRpc,
        Self::ClusterOutbound,
        Self::ControlSlot,
        Self::StorageDelivery,
        Self::BoundaryProcessing,
        Self::ColumnsProcessing,
        Self::BeaconStateHandoff,
    ];

    pub fn from_index(index: u64) -> Option<Self> {
        usize::try_from(index).ok().and_then(|index| Self::ALL.get(index)).copied()
    }

    /// Metrics label: `counters-tcache-{name}`, `tcache-write-{name}`.
    pub fn name(self) -> &'static str {
        match self {
            Self::NetworkIngress => "network_ingress",
            Self::NetworkProcessing => "network_processing",
            Self::ClusterInbound => "cluster_inbound",
            Self::ControlProcessing => "control_processing",
            Self::ControlGossip => "control_gossip",
            Self::ControlRpc => "control_rpc",
            Self::ClusterOutbound => "cluster_outbound",
            Self::ControlSlot => "control_slot",
            Self::StorageDelivery => "storage_delivery",
            Self::BoundaryProcessing => "boundary_processing",
            Self::ColumnsProcessing => "columns_processing",
            Self::BeaconStateHandoff => "beacon_state_handoff",
        }
    }
}

const _: () = assert!(TCacheId::BeaconStateHandoff as usize + 1 == TCacheId::COUNT);
