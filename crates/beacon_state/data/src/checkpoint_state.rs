use crate::{B256, BeaconState, SpecConfig};

/// `Downloaded` came from untrusted providers, so its anchor block root must
/// equal the `block_root` they agreed on.
pub enum CheckpointState {
    Trusted(BeaconState),
    Downloaded { state: BeaconState, block_root: B256 },
}

impl CheckpointState {
    pub fn trusted(ssz: &[u8], spec: &SpecConfig, pubkeys: &[u8]) -> Self {
        Self::Trusted(Self::decompose(ssz, spec, pubkeys))
    }

    /// `latest_block_header.state_root` stays zero until the next slot fills
    /// it in. Zero means this is the block's own post-state, so the anchor
    /// root covers these bytes. A filled root covers an earlier state instead.
    pub fn downloaded(ssz: &[u8], spec: &SpecConfig, block_root: B256) -> Self {
        let state = Self::decompose(ssz, spec, &[]);
        let header = state.slot_states.finalized_view().state().latest_block_header;
        assert_eq!(header.state_root, [0; 32], "downloaded state is advanced past its block");
        Self::Downloaded { state, block_root }
    }

    pub fn state(&self) -> &BeaconState {
        match self {
            Self::Trusted(state) | Self::Downloaded { state, .. } => state,
        }
    }

    // A finalized checkpoint state is mandatory (no genesis or runtime sync):
    // an empty/absent blob errors here and crashes the boot rather than
    // running an inert node.
    fn decompose(ssz: &[u8], spec: &SpecConfig, pubkeys: &[u8]) -> BeaconState {
        BeaconState::from_checkpoint(ssz, spec, pubkeys)
            .unwrap_or_else(|e| panic!("bootstrap: decompose checkpoint failed: {e}"))
    }
}
