use crate::{
    merkle::{B256, hash_fixed_bytes, merkleize, uint64_chunk},
    ssz_view::{
        PROPOSER_PREFERENCES_SIZE, ProposerPreferencesView, SIGNED_PROPOSER_PREFERENCES_SIZE,
        SignedProposerPreferencesView,
    },
};

impl ProposerPreferencesView {
    /// Plain Container, not progressive.
    pub fn hash_tree_root(buf: &[u8; PROPOSER_PREFERENCES_SIZE]) -> B256 {
        let mut fee_recipient = [0u8; 32];
        fee_recipient[..20].copy_from_slice(Self::fee_recipient(buf));
        merkleize(&[
            *Self::dependent_root(buf),
            uint64_chunk(Self::proposal_slot(buf)),
            uint64_chunk(Self::validator_index(buf)),
            fee_recipient,
            uint64_chunk(Self::target_gas_limit(buf)),
        ])
    }
}

impl SignedProposerPreferencesView {
    pub fn hash_tree_root(buf: &[u8; SIGNED_PROPOSER_PREFERENCES_SIZE]) -> B256 {
        let message = ProposerPreferencesView::hash_tree_root(Self::message(buf));
        merkleize(&[message, hash_fixed_bytes(Self::signature(buf))])
    }
}
