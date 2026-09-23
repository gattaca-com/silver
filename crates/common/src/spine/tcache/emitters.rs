use super::TCacheId;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TileId {
    Network,
    Control,
    BeaconState,
    Columns,
    Storage,
    ApplicationBoundary,
}

impl TileId {
    /// Name of the reader through which this tile forwards reads of `cache`.
    /// One per tile and cache: a tile's other readers on the cache are sinks.
    /// The forwarding graph is acyclic; a receiver declaring a tile that
    /// declares it back would freeze both at their open tails.
    pub fn emitter(self, cache: TCacheId) -> &'static str {
        match (self, cache) {
            (Self::BeaconState, TCacheId::ControlProcessing) => "bs_control_processing",
            (Self::BeaconState, TCacheId::NetworkProcessing) => "bs_network_processing",
            (Self::Columns, TCacheId::ControlProcessing) => "dc_control_processing",
            (Self::Columns, TCacheId::NetworkProcessing) => "dc_network_processing",
            (Self::Columns, TCacheId::ControlGossip) => "dc_control_gossip",
            (Self::Columns, TCacheId::ControlSlot) => "dc_control_slot",
            (Self::Control, TCacheId::ControlGossip) => "gossip_mcache",
            _ => panic!("{self:?} does not forward reads of {cache:?}"),
        }
    }
}
