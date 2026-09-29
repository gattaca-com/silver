use flux_profiler::timed;

use super::{
    PayloadRoots, hash_attestation, hash_attester_slashing, hash_execution_payload_with_roots,
    hash_execution_requests_fulu,
};
use crate::{
    body_offsets::{BodyFork, BodyOffsets},
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
/// 13 fields → 16 leaves. Zero when a fixed prefix is missing.
pub fn hash_tree_root_body_fulu(body: &[u8]) -> B256 {
    BodyOffsets::new(body, BodyFork::Fulu)
        .map_or(ZERO_HASH, |offsets| hash_tree_root_body_fulu_with_roots(&offsets).0)
}

#[timed]
pub fn hash_tree_root_body_fulu_with_roots(offsets: &BodyOffsets<'_>) -> (B256, PayloadRoots) {
    let roots = field_roots(offsets);
    (merkleize(&roots.fields), roots.payload)
}

/// Generate the `kzg_commitments_inclusion_proof` carried by a
/// `DataColumnSidecar`: the 4-node Merkle branch proving the block's
/// `blob_kzg_commitments` list root (field 11 of the 13-field → 16-leaf
/// `BeaconBlockBody` tree) sits under `body_root`. Generates the inclusion
/// branch the data-column-sidecar verifier checks.
///
/// All-zero bytes when a fixed prefix is missing (mirrors
/// `hash_tree_root_body_fulu`'s fallback).
#[timed]
pub fn kzg_commitments_inclusion_proof(body: &[u8]) -> [u8; 128] {
    let Ok(offsets) = BodyOffsets::new(body, BodyFork::Fulu) else {
        return [0u8; 128];
    };
    let roots = field_roots(&offsets);

    // The 16 leaves of the body tree (13 fields + 3 zero-padding).
    let mut layer = [ZERO_HASH; 16];
    layer[..13].copy_from_slice(&roots.fields);

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
struct BodyFieldRoots {
    fields: [B256; 13],
    payload: PayloadRoots,
}

fn field_roots(body_offsets: &BodyOffsets<'_>) -> BodyFieldRoots {
    debug_assert_eq!(body_offsets.fork(), BodyFork::Fulu);
    let fixed = body_offsets.fixed();

    let randao = hash_fixed_bytes(&fixed[0..96]);
    let eth1 = hash_eth1_data_bytes(&fixed[96..168]);
    let graffiti: B256 = fixed[168..200].try_into().unwrap();
    let sync_agg = hash_sync_aggregate(body_offsets.sync_aggregate());

    fn or_empty(field: Option<&[u8]>) -> &[u8] {
        field.unwrap_or(&[])
    }
    let proposer_slashings = ProposerSlashingView::hash_list(
        MerkleStack::new(16),
        or_empty(body_offsets.proposer_slashings()),
    );
    let attester_slashings = hash_variable_list(
        MerkleStack::new(1),
        or_empty(body_offsets.attester_slashings()),
        hash_attester_slashing,
    );
    let attestations = hash_variable_list(
        MerkleStack::new(8),
        or_empty(body_offsets.attestations()),
        hash_attestation,
    );
    let deposits = DepositView::hash_list(MerkleStack::new(16), or_empty(body_offsets.deposits()));
    let voluntary_exits = SignedVoluntaryExitView::hash_list(
        MerkleStack::new(16),
        or_empty(body_offsets.voluntary_exits()),
    );
    let (execution_payload, payload) = hash_execution_payload_with_roots(body_offsets.payload());
    let bls_changes = SignedBlsToExecutionChangeView::hash_list(
        MerkleStack::new(16),
        or_empty(body_offsets.bls_changes()),
    );
    let blob_commitments = hash_list(
        MerkleStack::new(4096),
        body_offsets.blob_commitments_fulu().chunks_exact(48).map(hash_fixed_bytes),
    );
    let execution_requests = hash_execution_requests_fulu(body_offsets.execution_requests());

    let fields = [
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
    ];
    BodyFieldRoots { fields, payload }
}
