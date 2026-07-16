use flux_profiler::timed;

use super::{
    hash_attestation, hash_attester_slashing, hash_execution_payload, hash_execution_requests_fulu,
};
use crate::{
    merkle::{
        B256, FixedContainer, MerkleStack, ZERO_HASH, hash_concat, hash_fixed_bytes, hash_list,
        hash_variable_list, merkleize, uint64_chunk,
    },
    ssz_view::{
        BeaconBlockBodyGloasView, DepositView, ProposerSlashingView,
        SignedBlsToExecutionChangeView, SignedVoluntaryExitView,
    },
};

#[timed]
pub fn hash_eth1_data_bytes(data: &[u8]) -> B256 {
    let deposit_root: B256 = data[0..32].try_into().unwrap();
    let deposit_count = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let block_hash: B256 = data[40..72].try_into().unwrap();
    let chunks = [deposit_root, uint64_chunk(deposit_count), block_hash];
    merkleize(&chunks)
}

#[timed]
pub fn hash_sync_aggregate(data: &[u8]) -> B256 {
    let bits_hash = hash_fixed_bytes(&data[0..64]);
    let sig_hash = hash_fixed_bytes(&data[64..160]);
    hash_concat(&bits_hash, &sig_hash)
}

pub fn hash_tree_root_body(body: &[u8], is_gloas: bool) -> B256 {
    if is_gloas {
        BeaconBlockBodyGloasView::hash_tree_root(body)
    } else {
        hash_tree_root_body_fulu(body)
    }
}

/// Compute hash_tree_root of a fulu BeaconBlockBody from raw SSZ bytes.
/// 13 fields → 16 leaves.
#[timed]
pub fn hash_tree_root_body_fulu(body: &[u8]) -> B256 {
    match field_roots(body) {
        Some(roots) => merkleize(&roots),
        None => ZERO_HASH,
    }
}

/// Generate the `kzg_commitments_inclusion_proof` carried by a
/// `DataColumnSidecar`: the 4-node Merkle branch proving the block's
/// `blob_kzg_commitments` list root (field 11 of the 13-field → 16-leaf
/// `BeaconBlockBody` tree) sits under `body_root`. Generator inverse of the
/// verifier in
/// `silver_storage::util::verify_data_column_sidecar_inclusion_proof`.
///
/// Returns all-zero bytes when `body` is below the fixed prefix size (mirrors
/// `hash_tree_root_body_fulu`'s fallback).
#[timed]
pub fn kzg_commitments_inclusion_proof(body: &[u8]) -> [u8; 128] {
    let Some(field_roots) = field_roots(body) else {
        return [0u8; 128];
    };

    // The 16 leaves of the body tree (13 fields + 3 zero-padding).
    let mut layer = [ZERO_HASH; 16];
    layer[..13].copy_from_slice(&field_roots);

    // Walk up the 4 levels, recording the sibling on leaf 11's path.
    let mut proof = [0u8; 128];
    let mut idx = 11usize;
    let mut width = 16usize;
    for level in 0..4 {
        proof[level * 32..level * 32 + 32].copy_from_slice(&layer[idx ^ 1]);
        let half = width / 2;
        for i in 0..half {
            layer[i] = hash_concat(&layer[2 * i], &layer[2 * i + 1]);
        }
        idx >>= 1;
        width = half;
    }
    proof
}

/// The 13 field roots of a fulu `BeaconBlockBody`, in field order (`None` below
/// the fixed prefix size). Shared by `hash_tree_root_body_fulu` (merkleized to
/// `body_root`) and `kzg_commitments_inclusion_proof` (Merkle branch from field
/// 11), so the layout is defined once.
fn field_roots(body: &[u8]) -> Option<[B256; 13]> {
    if body.len() < 396 {
        return None;
    }

    let randao = hash_fixed_bytes(&body[0..96]);
    let eth1 = hash_eth1_data_bytes(&body[96..168]);
    let graffiti: B256 = body[168..200].try_into().unwrap();
    let sync_agg = hash_sync_aggregate(&body[220..380]);

    let off = |pos: usize| -> usize {
        u32::from_le_bytes(body[pos..pos + 4].try_into().unwrap()) as usize
    };

    let offsets =
        [off(200), off(204), off(208), off(212), off(216), off(380), off(384), off(388), off(392)];

    let var_field = |idx: usize| -> &[u8] {
        let start = offsets[idx];
        let end = if idx + 1 < offsets.len() { offsets[idx + 1] } else { body.len() };
        if start <= end && end <= body.len() { &body[start..end] } else { &[] }
    };

    let proposer_slashings = ProposerSlashingView::hash_list(MerkleStack::new(16), var_field(0));
    let attester_slashings =
        hash_variable_list(MerkleStack::new(1), var_field(1), hash_attester_slashing);
    let attestations = hash_variable_list(MerkleStack::new(8), var_field(2), hash_attestation);
    let deposits = DepositView::hash_list(MerkleStack::new(16), var_field(3));
    let voluntary_exits = SignedVoluntaryExitView::hash_list(MerkleStack::new(16), var_field(4));
    let execution_payload = hash_execution_payload(var_field(5));
    let bls_changes = SignedBlsToExecutionChangeView::hash_list(MerkleStack::new(16), var_field(6));
    let blob_commitments =
        hash_list(MerkleStack::new(4096), var_field(7).chunks_exact(48).map(hash_fixed_bytes));
    let execution_requests = hash_execution_requests_fulu(var_field(8));

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
        execution_payload,
        bls_changes,
        blob_commitments,
        execution_requests,
    ])
}
