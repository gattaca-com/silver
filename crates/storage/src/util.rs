//! Utility helpers for data-column construction and verification.

use blst::{BLST_ERROR, min_pk::PublicKey};
use flux_profiler::timed;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    merkle::{
        B256, hash_concat, hash_list_fixed_elements, is_valid_merkle_branch, merkleize, sha256,
        uint64_chunk,
    },
    ssz_hash::{hash_tree_root_body_fulu, hash_tree_root_fork_data},
    ssz_hash_gloas::hash_tree_root_body_gloas,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DATA_COLUMN_SIDECAR_MIN,
        DataColumnSidecarFuluView, DataColumnSidecarGloasView, MAX_BLOB_COMMITMENTS_PER_BLOCK,
        NUMBER_OF_COLUMNS, SignedBeaconBlockView,
    },
};

/// EIP-4844 versioned-hash version byte (`VERSIONED_HASH_VERSION_KZG`).
const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;

/// Spec `compute_fork_digest` (EIP-7892) for the fork active at `slot`. Each
/// served RPC chunk must carry the context fork-digest for its own slot's
/// fork: a range/root request can span a
/// fork boundary, and post-fork the retention window still holds pre-fork
/// blocks/columns.
#[timed]
pub fn fork_digest_at(spec: &SpecConfig, slot: u64, genesis_validators_root: &B256) -> [u8; 4] {
    let epoch = slot / SLOTS_PER_EPOCH;
    let base = hash_tree_root_fork_data(spec.fork_version_at(epoch), genesis_validators_root);
    let bp = spec
        .blob_schedule
        .iter()
        .rev()
        .find(|e| epoch >= e.epoch)
        .copied()
        .unwrap_or_else(|| spec.default_blob_params());
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(&bp.epoch.to_le_bytes());
    input[8..].copy_from_slice(&bp.max_blobs_per_block.to_le_bytes());
    let mix = sha256(&input);
    [base[0] ^ mix[0], base[1] ^ mix[1], base[2] ^ mix[2], base[3] ^ mix[3]]
}

/// Depth of the Merkle branch attaching `kzg_commitments` to
/// `BeaconBlockBody.body_root`. Per Fulu spec: `floor(log2(gindex))`
/// where `gindex` is the generalised index of `blob_kzg_commitments`
/// inside `BeaconBlockBody`. With 13 body fields (next-pow-2 ⇒ 16
/// leaves, depth 4) and `blob_kzg_commitments` at field index 11,
/// gindex = 16 + 11 = 27, floor(log2(27)) = 4.
const KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH: u32 = 4;

/// Subtree-index of `blob_kzg_commitments` at depth
/// `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH`. Equals
/// `gindex % 2^depth = 27 % 16 = 11`.
const KZG_COMMITMENTS_SUBTREE_INDEX: u64 = 11;

/// SSZ `body_root` of a `BeaconBlockBody` given its raw SSZ bytes.
/// Returns `[0u8; 32]` if `body.len()` is below the post-Electra fixed
/// prefix size — mirrors the spec-compliant fallback in
/// `silver_common::ssz_hash::hash_tree_root_body_fulu`.
pub fn body_root(body: &[u8]) -> B256 {
    hash_tree_root_body_fulu(body)
}

/// SSZ `block_root` of a `BeaconBlockHeader` derived from a
/// `SignedBeaconBlock` buffer. Identical to `hash_tree_root` of the inner
/// `BeaconBlock`: both merkleize the same five leaves once the body is
/// replaced by `body_root`. This is the value used as
/// `DataColumnsByRootIdentifier.block_root` in DA RPC requests.
pub fn block_root_fulu(signed_block: &[u8]) -> B256 {
    block_root_from_body(
        signed_block,
        hash_tree_root_body_fulu(SignedBeaconBlockView::body(signed_block)),
    )
}

pub fn block_root_gloas(signed_block: &[u8]) -> B256 {
    block_root_from_body(
        signed_block,
        hash_tree_root_body_gloas(SignedBeaconBlockView::body(signed_block)),
    )
}

pub fn block_root(signed_block: &[u8], is_gloas: bool) -> B256 {
    if is_gloas { block_root_gloas(signed_block) } else { block_root_fulu(signed_block) }
}

fn block_root_from_body(signed_block: &[u8], body_root: B256) -> B256 {
    merkleize(&[
        uint64_chunk(SignedBeaconBlockView::slot(signed_block)),
        uint64_chunk(SignedBeaconBlockView::proposer_index(signed_block)),
        *SignedBeaconBlockView::parent_root(signed_block),
        *SignedBeaconBlockView::state_root(signed_block),
        body_root,
    ])
}

/// SSZ `block_root` reconstructed from a `DataColumnSidecar`'s embedded
/// `signed_block_header`. The sidecar carries `body_root` directly, so no
/// body hashing is required — just the 5-leaf merkleize.
pub fn block_root_from_sidecar(sidecar: &[u8]) -> B256 {
    merkleize(&[
        uint64_chunk(DataColumnSidecarFuluView::slot(sidecar)),
        uint64_chunk(DataColumnSidecarFuluView::proposer_index(sidecar)),
        *DataColumnSidecarFuluView::parent_root(sidecar),
        *DataColumnSidecarFuluView::state_root(sidecar),
        *DataColumnSidecarFuluView::body_root(sidecar),
    ])
}

fn check_sidecar_shape(column: &[u8], commits: &[u8], proofs: &[u8]) -> bool {
    if !column.len().is_multiple_of(BYTES_PER_CELL) ||
        !commits.len().is_multiple_of(BYTES_PER_KZG_COMMITMENT) ||
        !proofs.len().is_multiple_of(BYTES_PER_KZG_PROOF)
    {
        return false;
    }
    let n_cells = column.len() / BYTES_PER_CELL;
    let n_commits = commits.len() / BYTES_PER_KZG_COMMITMENT;
    let n_proofs = proofs.len() / BYTES_PER_KZG_PROOF;
    n_cells == n_commits && n_commits == n_proofs && n_commits <= MAX_BLOB_COMMITMENTS_PER_BLOCK
}

pub fn verify_data_column_sidecar_fulu(sidecar: &[u8]) -> bool {
    if !DataColumnSidecarFuluView::check_size(sidecar) {
        return false;
    }
    if DataColumnSidecarFuluView::index(sidecar) >= NUMBER_OF_COLUMNS as u64 {
        return false;
    }
    check_sidecar_shape(
        DataColumnSidecarFuluView::column(sidecar),
        DataColumnSidecarFuluView::kzg_commitments(sidecar),
        DataColumnSidecarFuluView::kzg_proofs(sidecar),
    )
}

pub fn verify_data_column_sidecar_gloas(sidecar: &[u8], commitments: &[u8]) -> bool {
    if !DataColumnSidecarGloasView::check_size(sidecar) {
        return false;
    }
    if DataColumnSidecarGloasView::index(sidecar) >= NUMBER_OF_COLUMNS as u64 {
        return false;
    }
    check_sidecar_shape(
        DataColumnSidecarGloasView::column(sidecar),
        commitments,
        DataColumnSidecarGloasView::kzg_proofs(sidecar),
    )
}

/// Spec `verify_data_column_sidecar_inclusion_proof` — re-roots the
/// sidecar's `kzg_commitments` list and verifies the
/// `kzg_commitments_inclusion_proof` Merkle branch lifts that root to
/// `signed_block_header.message.body_root`.
///
/// Caller MUST have already passed `verify_data_column_sidecar_fulu`
/// (relies on the size invariants for `kzg_commitments` and the
/// inclusion-proof bytes).
pub fn verify_data_column_sidecar_inclusion_proof(sidecar: &[u8]) -> bool {
    let commitments = DataColumnSidecarFuluView::kzg_commitments(sidecar);
    let leaf = hash_list_fixed_elements(
        commitments,
        BYTES_PER_KZG_COMMITMENT,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    );
    let branch = DataColumnSidecarFuluView::inclusion_proof(sidecar);
    let body_root = DataColumnSidecarFuluView::body_root(sidecar);
    is_valid_merkle_branch(
        &leaf,
        branch,
        KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH,
        KZG_COMMITMENTS_SUBTREE_INDEX,
        body_root,
    )
}

/// Spec `verify_data_column_sidecar_kzg_proofs` — KZG batch-verifies
/// every cell in the sidecar against its commitment + proof. All
/// cells in a single sidecar share the same column index (=
/// `sidecar.index`), so the batch's `cell_indices` is just that
/// index repeated `N` times.
///
/// Caller MUST have already passed `verify_data_column_sidecar_fulu` —
/// this function relies on the shape invariants (matching list
/// lengths, element-size multiples) and skips re-validation.
/// Empty-list sidecars (N = 0) trivially pass.
///
/// Uses the mainnet Ethereum trusted setup statically bundled by
/// c-kzg's `ethereum_kzg_settings` feature; no runtime initialisation
/// required. `precompute = 0` — verification doesn't benefit from the
/// precomputation table (only proof generation does).
#[timed]
pub fn verify_data_column_sidecar_kzg_proofs_fulu(sidecar: &[u8]) -> bool {
    kzg_verify_batch(
        DataColumnSidecarFuluView::column(sidecar),
        DataColumnSidecarFuluView::kzg_commitments(sidecar),
        DataColumnSidecarFuluView::kzg_proofs(sidecar),
        DataColumnSidecarFuluView::index(sidecar),
    )
}

pub fn verify_data_column_sidecar_kzg_proofs_gloas(sidecar: &[u8], commitments: &[u8]) -> bool {
    kzg_verify_batch(
        DataColumnSidecarGloasView::column(sidecar),
        commitments,
        DataColumnSidecarGloasView::kzg_proofs(sidecar),
        DataColumnSidecarGloasView::index(sidecar),
    )
}

/// KZG cell-proof batch verify shared by Fulu + Gloas. Every cell shares the
/// column `index`, so `cell_indices` is that index repeated `N` times. Uses the
/// statically-bundled mainnet trusted setup (`precompute = 0` — only proof
/// generation benefits). Empty (N = 0) trivially passes.
///
/// Preconditions (caller-verified via `verify_data_column_sidecar{,_gloas}`):
/// `column`/`commitments`/`proofs` carry the same element count and are clean
/// multiples of their element sizes — the raw-slice casts rely on it.
#[timed]
fn kzg_verify_batch(column: &[u8], commits: &[u8], proofs: &[u8], index: u64) -> bool {
    let n = column.len() / BYTES_PER_CELL;
    if n == 0 {
        return true;
    }

    let cells: &[c_kzg::Cell] =
        unsafe { std::slice::from_raw_parts(column.as_ptr() as *const c_kzg::Cell, n) };
    let commitments: &[c_kzg::Bytes48] =
        unsafe { std::slice::from_raw_parts(commits.as_ptr() as *const c_kzg::Bytes48, n) };
    let kzg_proofs: &[c_kzg::Bytes48] =
        unsafe { std::slice::from_raw_parts(proofs.as_ptr() as *const c_kzg::Bytes48, n) };

    // Stack-allocated indices array to avoid heap allocation on the hot path
    let mut stack_indices = [0u64; 128];
    let cell_indices: &[u64] = if n <= 128 {
        stack_indices[..n].fill(index);
        &stack_indices[..n]
    } else {
        &vec![index; n]
    };

    let settings = c_kzg::ethereum_kzg_settings(0);
    matches!(
        settings.verify_cell_kzg_proof_batch(commitments, cell_indices, cells, kzg_proofs),
        Ok(true)
    )
}

/// Spec `DOMAIN_BEACON_PROPOSER = bytes4(0x00000000)`.
const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0u8; 4];

/// BLS12-381 G2 hash-to-curve DST for proof-of-possession signatures
/// (eth2 ciphersuite: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`).
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Validation: sidecar's slot is strictly above the finalized slot.
/// `finalized_epoch` is `state.epoch.finalized_checkpoint.epoch`.
pub fn is_above_finalized(sidecar: &[u8], finalized_epoch: u64) -> bool {
    DataColumnSidecarFuluView::slot(sidecar) > finalized_epoch * SLOTS_PER_EPOCH
}

/// Validation: sidecar's `proposer_index` matches the expected proposer
/// for `sidecar.slot`. Caller resolves the expectation via
/// `state.epoch.proposer_lookahead` for the slot's epoch.
pub fn check_proposer_index(sidecar: &[u8], expected_proposer_index: u64) -> bool {
    DataColumnSidecarFuluView::proposer_index(sidecar) == expected_proposer_index
}

/// Validations 4 + 5: sidecar's `parent_root` has been seen AND validated.
///
/// Silver's design pushes a block root into the slot delta's
/// `block_roots` only after fork choice has validated the block, so
/// membership in the union of (finalized canonical block_roots) ∪
/// (post-finalization delta block_roots) is equivalent to "seen and
/// validated". `not present` means either not-yet-seen or invalid; the
/// caller resolves IGNORE vs REJECT severity from external context.
///
/// `finalized_block_roots` is the slot-indexed circular buffer (length
/// `SLOTS_PER_HISTORICAL_ROOT`). `delta_block_roots` is the appended
/// post-finalization set. Delta is checked first — virtually every live
/// sidecar's parent resolves there; the finalized scan is a defensive
/// fall-through.
pub fn parent_validated(
    sidecar: &[u8],
    finalized_block_roots: &[B256],
    delta_block_roots: &[B256],
    store_head_root: &B256,
) -> bool {
    let parent_root = DataColumnSidecarFuluView::parent_root(sidecar);
    parent_root == store_head_root ||
        delta_block_roots.iter().any(|r| r == parent_root) ||
        finalized_block_roots.iter().any(|r| r == parent_root)
}

/// Validation: BLS signature on the embedded `signed_block_header` is
/// valid under the proposer pubkey.
///
/// signing_root = sha256(hash_tree_root(BeaconBlockHeader) || domain)
/// domain       = DOMAIN_BEACON_PROPOSER || hash_tree_root(ForkData)[..28]
///
/// `fork_version` is the active version at `sidecar.slot`'s epoch; the
/// caller resolves it from the fork schedule. `proposer_pubkey` is the
/// already-decompressed registry entry (no extra subgroup check).
#[timed]
pub fn verify_proposer_signature(
    sidecar: &[u8],
    proposer_pubkey: &PublicKey,
    fork_version: [u8; 4],
    genesis_validators_root: &B256,
) -> bool {
    let fork_data_root = hash_tree_root_fork_data(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&DOMAIN_BEACON_PROPOSER);
    domain[4..].copy_from_slice(&fork_data_root[..28]);

    let header_root = block_root_from_sidecar(sidecar);
    let signing_root = hash_concat(&header_root, &domain);

    let sig_bytes = DataColumnSidecarFuluView::block_signature(sidecar);
    let Ok(signature) = blst::min_pk::Signature::from_bytes(sig_bytes) else {
        return false;
    };
    signature.verify(true, &signing_root, BLS_DST, &[], proposer_pubkey, false) ==
        BLST_ERROR::BLST_SUCCESS
}

/// EIP-4844 versioned hash of a 48-byte KZG commitment:
/// `sha256(commitment)` with the first byte replaced by the KZG version.
/// These are the `versionedHashes` passed to `engine_getBlobsV2`.
pub fn kzg_commitment_to_versioned_hash(commitment: &[u8]) -> [u8; 32] {
    let mut h = sha256(commitment);
    h[0] = VERSIONED_HASH_VERSION_KZG;
    h
}

/// SSZ-serialized size of a `DataColumnSidecar` whose three parallel lists
/// each hold `num_blobs` elements.
pub fn data_column_sidecar_len(num_blobs: usize) -> usize {
    DATA_COLUMN_SIDECAR_MIN +
        num_blobs * BYTES_PER_CELL +
        num_blobs * BYTES_PER_KZG_COMMITMENT +
        num_blobs * BYTES_PER_KZG_PROOF
}

/// Append the 356-byte fixed prefix of a `DataColumnSidecar` (index, the three
/// list offsets for `num_blobs` elements, the 208-byte `signed_block_header`,
/// and the 128-byte inclusion proof) to `out`
pub fn push_data_column_sidecar_prefix(
    out: &mut Vec<u8>,
    index: u64,
    num_blobs: usize,
    header: &[u8; 208],
    inclusion_proof: &[u8; 128],
) {
    let col_off = DATA_COLUMN_SIDECAR_MIN;
    let com_off = col_off + num_blobs * BYTES_PER_CELL;
    let proof_off = com_off + num_blobs * BYTES_PER_KZG_COMMITMENT;

    out.extend_from_slice(&index.to_le_bytes());
    out.extend_from_slice(&(col_off as u32).to_le_bytes());
    out.extend_from_slice(&(com_off as u32).to_le_bytes());
    out.extend_from_slice(&(proof_off as u32).to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(inclusion_proof);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_root_too_short_returns_zero_hash() {
        // Less than the 396-byte fixed prefix → zero root.
        assert_eq!(body_root(&[0u8; 100]), [0u8; 32]);
    }

    #[test]
    fn body_root_is_deterministic() {
        let body = [0u8; 396];
        assert_eq!(body_root(&body), body_root(&body));
    }

    /// Known-answer for the served context fork-digest: mainnet Fulu at epoch
    /// 419072 = `8c9f62fe` (same vector the beacon-state tile's
    /// `compute_fork_digest` is checked against — guards this crate's copy).
    #[test]
    fn fork_digest_at_matches_mainnet_fulu() {
        let mainnet_gvr: B256 = [
            0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f,
            0xdd, 0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f,
            0x51, 0x1b, 0xfe, 0x95,
        ];
        let spec = SpecConfig::mainnet();
        assert_eq!(fork_digest_at(&spec, 419072 * SLOTS_PER_EPOCH, &mainnet_gvr), [
            0x8c, 0x9f, 0x62, 0xfe
        ],);
    }

    /// A range/root request spanning the Gloas boundary must tag pre- and
    /// post-fork chunks with different context digests (the bug this fixes).
    #[test]
    fn fork_digest_at_differs_across_gloas_boundary() {
        let gvr = [7u8; 32];
        let mut spec = SpecConfig::mainnet();
        spec.gloas_fork_epoch = 10;
        let pre = fork_digest_at(&spec, 9 * SLOTS_PER_EPOCH, &gvr);
        let post = fork_digest_at(&spec, 10 * SLOTS_PER_EPOCH, &gvr);
        assert_ne!(pre, post, "fulu-era and gloas-era digests must differ");
    }

    /// Build a synthetic sidecar byte buffer with the given index and
    /// `n` parallel-list elements. Header + body_root + inclusion_proof
    /// are zero-filled; useful only for shape-check exercises.
    fn synth_sidecar(index: u64, n_cells: usize, n_commits: usize, n_proofs: usize) -> Vec<u8> {
        let col_len = n_cells * BYTES_PER_CELL;
        let com_len = n_commits * BYTES_PER_KZG_COMMITMENT;
        let proof_len = n_proofs * BYTES_PER_KZG_PROOF;
        let total = DATA_COLUMN_SIDECAR_MIN + col_len + com_len + proof_len;
        let mut buf = vec![0u8; total];
        buf[0..8].copy_from_slice(&index.to_le_bytes());
        let col_off = DATA_COLUMN_SIDECAR_MIN as u32;
        let com_off = col_off + col_len as u32;
        let proof_off = com_off + com_len as u32;
        buf[8..12].copy_from_slice(&col_off.to_le_bytes());
        buf[12..16].copy_from_slice(&com_off.to_le_bytes());
        buf[16..20].copy_from_slice(&proof_off.to_le_bytes());
        buf
    }

    #[test]
    fn verify_shape_accepts_synthetic_sidecar() {
        for n in [0usize, 1, 2, 6, 72] {
            let buf = synth_sidecar(0, n, n, n);
            assert!(verify_data_column_sidecar_fulu(&buf), "n={n}");
        }
    }

    #[test]
    fn verify_shape_rejects_out_of_range_index() {
        let mut buf = synth_sidecar(0, 1, 1, 1);
        buf[0..8].copy_from_slice(&(NUMBER_OF_COLUMNS as u64).to_le_bytes());
        assert!(!verify_data_column_sidecar_fulu(&buf));
    }

    #[test]
    fn verify_shape_rejects_length_mismatch() {
        // 2 cells but only 1 commitment + 1 proof — count mismatch.
        let buf = synth_sidecar(0, 2, 1, 1);
        assert!(!verify_data_column_sidecar_fulu(&buf));
    }

    #[test]
    fn verify_shape_rejects_truncated_buffer() {
        let mut buf = synth_sidecar(0, 1, 1, 1);
        buf.truncate(DATA_COLUMN_SIDECAR_MIN - 1);
        assert!(!verify_data_column_sidecar_fulu(&buf));
    }

    #[test]
    fn verify_inclusion_proof_rejects_zero_branch() {
        // All-zero inclusion_proof + zero body_root cannot match a
        // non-trivial commitments-list root (depth-4 zero branch
        // would lift the leaf to the zero subtree root at depth 4,
        // which is zh[4] != [0;32]).
        let buf = synth_sidecar(0, 1, 1, 1);
        assert!(!verify_data_column_sidecar_inclusion_proof(&buf));
    }

    #[test]
    fn verify_kzg_proofs_empty_sidecar_trivially_passes() {
        // N = 0 (no cells / commitments / proofs) → empty batch, KZG
        // verification is vacuously true. Also exercises the
        // static-init of the bundled mainnet trusted setup.
        let buf = synth_sidecar(0, 0, 0, 0);
        assert!(verify_data_column_sidecar_kzg_proofs_fulu(&buf));
    }

    /// Gloas sidecar: index(8), col_off(4), proof_off(4), slot(8),
    /// beacon_block_root(32), then column ‖ kzg_proofs.
    fn synth_gloas_sidecar(index: u64, n_cells: usize, n_proofs: usize) -> Vec<u8> {
        let col_len = n_cells * BYTES_PER_CELL;
        let proof_len = n_proofs * BYTES_PER_KZG_PROOF;
        let mut buf = vec![0u8; 56 + col_len + proof_len];
        buf[0..8].copy_from_slice(&index.to_le_bytes());
        buf[8..12].copy_from_slice(&56u32.to_le_bytes());
        buf[12..16].copy_from_slice(&(56 + col_len as u32).to_le_bytes());
        buf
    }

    #[test]
    fn gloas_sidecar_shape_checks() {
        let commits = |n: usize| vec![0u8; n * BYTES_PER_KZG_COMMITMENT];
        // 1 cell / 1 commit / 1 proof — well-formed.
        assert!(verify_data_column_sidecar_gloas(&synth_gloas_sidecar(0, 1, 1), &commits(1)));
        // empty.
        assert!(verify_data_column_sidecar_gloas(&synth_gloas_sidecar(0, 0, 0), &commits(0)));
        // index out of range.
        assert!(!verify_data_column_sidecar_gloas(
            &synth_gloas_sidecar(NUMBER_OF_COLUMNS as u64, 1, 1),
            &commits(1)
        ));
        // cell/proof count mismatch.
        assert!(!verify_data_column_sidecar_gloas(&synth_gloas_sidecar(0, 2, 1), &commits(2)));
        // commitment-count mismatch.
        assert!(!verify_data_column_sidecar_gloas(&synth_gloas_sidecar(0, 1, 1), &commits(2)));
    }

    /// End-to-end gloas: real cells + proofs through the gloas sidecar layout,
    /// commitments supplied externally (as they would come from the block bid),
    /// pass both the shape check and the shared KZG batch.
    #[test]
    fn gloas_built_sidecar_passes_kzg() {
        let settings = c_kzg::ethereum_kzg_settings(0);
        let n = 2usize;
        let blob = c_kzg::Blob::new([0u8; 131072]);

        let mut commitments = Vec::new();
        let mut cells = Vec::new();
        let mut proofs = Vec::new();
        for _ in 0..n {
            let c = settings.blob_to_kzg_commitment(&blob).unwrap();
            commitments.extend_from_slice(&c.to_bytes().into_inner());
            let (cs, ps) = settings.compute_cells_and_kzg_proofs(&blob).unwrap();
            cells.push(cs);
            proofs.push(ps);
        }

        for j in [0u64, 1, 63, 127] {
            let mut column = Vec::new();
            let mut col_proofs = Vec::new();
            for i in 0..n {
                column.extend_from_slice(&cells[i][j as usize].to_bytes());
                col_proofs.extend_from_slice(&proofs[i][j as usize].to_bytes().into_inner());
            }
            // index(8) col_off(4)=56 proof_off(4) slot(8) beacon_block_root(32).
            let mut buf = vec![0u8; 56];
            buf[0..8].copy_from_slice(&j.to_le_bytes());
            buf[8..12].copy_from_slice(&56u32.to_le_bytes());
            buf[12..16].copy_from_slice(&((56 + column.len()) as u32).to_le_bytes());
            buf.extend_from_slice(&column);
            buf.extend_from_slice(&col_proofs);

            assert!(verify_data_column_sidecar_gloas(&buf, &commitments), "shape j={j}");
            assert!(verify_data_column_sidecar_kzg_proofs_gloas(&buf, &commitments), "kzg j={j}");
        }
    }

    #[test]
    fn verify_kzg_proofs_rejects_zero_cells() {
        // A column of zero-cells with zero-commitments + zero-proofs
        // is NOT a valid KZG opening — the point-at-infinity
        // commitment (0xc000...) is reserved for "no blob" and zero
        // bytes are not a valid G1 encoding. c-kzg rejects with an
        // error; we map every non-Ok(true) result to false.
        let buf = synth_sidecar(0, 1, 1, 1);
        assert!(!verify_data_column_sidecar_kzg_proofs_fulu(&buf));
    }

    /// Build a minimal BeaconBlockBody whose only non-empty variable field is
    /// `blob_kzg_commitments`, so its body_root + inclusion proof are
    /// self-consistent for the encoded sidecar.
    fn synth_body_with_commitments(commitments: &[u8]) -> Vec<u8> {
        const FIXED: usize = 396;
        let mut body = vec![0u8; FIXED + commitments.len()];
        // All variable fields empty (offset = FIXED) except blob_kzg_commitments.
        for pos in [200usize, 204, 208, 212, 216, 380, 384, 388] {
            body[pos..pos + 4].copy_from_slice(&(FIXED as u32).to_le_bytes());
        }
        // execution_requests starts after the commitments list.
        body[392..396].copy_from_slice(&((FIXED + commitments.len()) as u32).to_le_bytes());
        body[FIXED..].copy_from_slice(commitments);
        body
    }

    /// End-to-end: reconstruct sidecars from blobs exactly as the EL-blob path
    /// does (commitments + cells + cell proofs from c-kzg, inclusion proof from
    /// the body) and assert they pass all three sidecar verifications.
    #[test]
    fn el_built_sidecars_pass_all_verifications() {
        use silver_common::ssz_hash::kzg_commitments_inclusion_proof;

        let settings = c_kzg::ethereum_kzg_settings(0);
        let n = 2usize;
        let blob = c_kzg::Blob::new([0u8; 131072]); // zero blob: valid field elements

        let mut commitments = Vec::new();
        let mut cells = Vec::new();
        let mut proofs = Vec::new();
        for _ in 0..n {
            let c = settings.blob_to_kzg_commitment(&blob).unwrap();
            commitments.extend_from_slice(&c.to_bytes().into_inner());
            let (cs, ps) = settings.compute_cells_and_kzg_proofs(&blob).unwrap();
            cells.push(cs);
            proofs.push(ps);
        }

        let body = synth_body_with_commitments(&commitments);
        let mut header = [0u8; 208];
        header[80..112].copy_from_slice(&hash_tree_root_body_fulu(&body));
        let inclusion_proof = kzg_commitments_inclusion_proof(&body);

        // A representative spread of column indices (full sweep is redundant).
        for j in [0u64, 1, 63, 127] {
            let mut column = Vec::new();
            let mut col_proofs = Vec::new();
            for i in 0..n {
                column.extend_from_slice(&cells[i][j as usize].to_bytes());
                col_proofs.extend_from_slice(&proofs[i][j as usize].to_bytes().into_inner());
            }
            let mut out = Vec::with_capacity(data_column_sidecar_len(n));
            push_data_column_sidecar_prefix(&mut out, j, n, &header, &inclusion_proof);
            out.extend_from_slice(&column);
            out.extend_from_slice(&commitments);
            out.extend_from_slice(&col_proofs);
            assert_eq!(out.len(), data_column_sidecar_len(n));

            assert!(verify_data_column_sidecar_fulu(&out), "shape, col {j}");
            assert_eq!(DataColumnSidecarFuluView::index(&out), j);
            assert!(verify_data_column_sidecar_kzg_proofs_fulu(&out), "kzg, col {j}");
            assert!(verify_data_column_sidecar_inclusion_proof(&out), "inclusion, col {j}");
        }
    }
}
