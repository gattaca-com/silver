use flux_profiler::timed;

use crate::{
    merkle::{B256, FixedContainer, ZERO_HASH, hash_fixed_bytes, hash_variable_list},
    progressive::{ProgressiveContainer, ProgressiveHasher, packed_active_fields},
    ssz_hash::{hash_eth1_data_bytes, hash_sync_aggregate},
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        AttestationView, AttesterSlashingView, BeaconBlockBodyGloasView, DepositView,
        PayloadAttestationView, ProposerSlashingView, SignedBlsToExecutionChangeView,
        SignedExecutionPayloadBidView, SignedVoluntaryExitView,
    },
};

impl ProgressiveContainer for BeaconBlockBodyGloasView {
    const ACTIVE_FIELDS: B256 = packed_active_fields(13);
}

impl BeaconBlockBodyGloasView {
    #[timed]
    pub fn hash_tree_root(body: &[u8]) -> B256 {
        match Self::field_roots(body) {
            Some(roots) => Self::progressive_root(&roots),
            None => ZERO_HASH,
        }
    }

    // Body layout: `execution_payload` / `blob_kzg_commitments` /
    // `execution_requests` are replaced by `signed_execution_payload_bid` /
    // `payload_attestations` / `parent_execution_requests`, and
    // `bls_to_execution_changes` moves ahead of them; fields 0..9 are identical
    // to Fulu.
    fn field_roots(body: &[u8]) -> Option<[B256; 13]> {
        if body.len() < 396 {
            return None;
        }

        let randao = hash_fixed_bytes(Self::randao_reveal(body));
        let eth1 = hash_eth1_data_bytes(Self::eth1_data(body));
        let graffiti = *Self::graffiti(body);
        let sync_agg = hash_sync_aggregate(Self::sync_aggregate(body));

        let offsets = [
            Self::proposer_slashings_offset(body) as usize,
            Self::attester_slashings_offset(body) as usize,
            Self::attestations_offset(body) as usize,
            Self::deposits_offset(body) as usize,
            Self::voluntary_exits_offset(body) as usize,
            Self::bls_to_execution_changes_offset(body) as usize,
            Self::signed_execution_payload_bid_offset(body) as usize,
            Self::payload_attestations_offset(body) as usize,
            Self::parent_execution_requests_offset(body) as usize,
        ];
        let var_field = |idx: usize| -> &[u8] {
            let start = offsets[idx];
            let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { body.len() };
            if start <= end && end <= body.len() { &body[start..end] } else { &[] }
        };

        let proposer_slashings =
            ProposerSlashingView::hash_list(ProgressiveHasher::new(), var_field(0));
        let attester_slashings = hash_variable_list(
            ProgressiveHasher::new(),
            var_field(1),
            AttesterSlashingView::hash_tree_root_gloas,
        );
        let attestations = hash_variable_list(
            ProgressiveHasher::new(),
            var_field(2),
            AttestationView::hash_tree_root_gloas,
        );
        let deposits = DepositView::hash_list(ProgressiveHasher::new(), var_field(3));
        let voluntary_exits =
            SignedVoluntaryExitView::hash_list(ProgressiveHasher::new(), var_field(4));
        let bls_changes =
            SignedBlsToExecutionChangeView::hash_list(ProgressiveHasher::new(), var_field(5));
        let signed_bid = SignedExecutionPayloadBidView::hash_tree_root(var_field(6));
        let payload_attestations =
            PayloadAttestationView::hash_list(ProgressiveHasher::new(), var_field(7));
        let parent_requests = ExecutionRequestsView::hash_tree_root(var_field(8));

        Some([
            randao,
            eth1,
            graffiti,
            proposer_slashings,
            attester_slashings,
            attestations,
            deposits,
            voluntary_exits,
            sync_agg,
            bls_changes,
            signed_bid,
            payload_attestations,
            parent_requests,
        ])
    }
}
