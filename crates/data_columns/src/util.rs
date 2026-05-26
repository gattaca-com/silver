//! Utility helpers for data-column construction and verification.

use blst::{BLST_ERROR, min_pk::PublicKey};
use silver_common::{
    SLOTS_PER_EPOCH,
    ssz_hash::{
        B256, hash_concat, hash_list_fixed_elements, hash_tree_root_body, hash_tree_root_fork_data,
        is_valid_merkle_branch, merkleize, uint64_chunk,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DataColumnSidecarView,
        MAX_BLOB_COMMITMENTS_PER_BLOCK, NUMBER_OF_COLUMNS, SignedBeaconBlockView,
    },
};

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
/// `silver_common::ssz_hash::hash_tree_root_body`.
pub fn body_root(body: &[u8]) -> B256 {
    hash_tree_root_body(body)
}

/// SSZ `block_root` of a `BeaconBlockHeader` derived from a
/// `SignedBeaconBlock` buffer. Identical to `hash_tree_root` of the inner
/// `BeaconBlock`: both merkleize the same five leaves once the body is
/// replaced by `body_root`. This is the value used as
/// `DataColumnsByRootIdentifier.block_root` in DA RPC requests.
pub fn block_root(signed_block: &[u8]) -> B256 {
    let body_root = hash_tree_root_body(SignedBeaconBlockView::body(signed_block));
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
        uint64_chunk(DataColumnSidecarView::slot(sidecar)),
        uint64_chunk(DataColumnSidecarView::proposer_index(sidecar)),
        *DataColumnSidecarView::parent_root(sidecar),
        *DataColumnSidecarView::state_root(sidecar),
        *DataColumnSidecarView::body_root(sidecar),
    ])
}

/// Spec `verify_data_column_sidecar` — pure shape/sanity checks against
/// a `DataColumnSidecar` byte buffer. Confirms:
/// - SSZ-level layout (offsets, total length within `[MIN, MAX]`).
/// - `index < NUMBER_OF_COLUMNS`.
/// - `column`, `kzg_commitments`, `kzg_proofs` are clean multiples of their
///   per-element sizes (2048 / 48 / 48) and all carry the same element count.
///
/// Does NOT verify KZG cell proofs (separate function pending a KZG
/// dep) or the proposer signature (needs proposer pubkey from state).
pub fn verify_data_column_sidecar(sidecar: &[u8]) -> bool {
    if !DataColumnSidecarView::check_size(sidecar) {
        return false;
    }
    if DataColumnSidecarView::index(sidecar) >= NUMBER_OF_COLUMNS as u64 {
        return false;
    }
    let column = DataColumnSidecarView::column(sidecar);
    let commits = DataColumnSidecarView::kzg_commitments(sidecar);
    let proofs = DataColumnSidecarView::kzg_proofs(sidecar);
    if !column.len().is_multiple_of(BYTES_PER_CELL) ||
        !commits.len().is_multiple_of(BYTES_PER_KZG_COMMITMENT) ||
        !proofs.len().is_multiple_of(BYTES_PER_KZG_PROOF)
    {
        return false;
    }
    let n_cells = column.len() / BYTES_PER_CELL;
    let n_commits = commits.len() / BYTES_PER_KZG_COMMITMENT;
    let n_proofs = proofs.len() / BYTES_PER_KZG_PROOF;
    if n_cells != n_commits || n_commits != n_proofs {
        return false;
    }
    if n_commits > MAX_BLOB_COMMITMENTS_PER_BLOCK {
        return false;
    }
    true
}

/// Spec `verify_data_column_sidecar_inclusion_proof` — re-roots the
/// sidecar's `kzg_commitments` list and verifies the
/// `kzg_commitments_inclusion_proof` Merkle branch lifts that root to
/// `signed_block_header.message.body_root`.
///
/// Caller MUST have already passed `verify_data_column_sidecar`
/// (relies on the size invariants for `kzg_commitments` and the
/// inclusion-proof bytes).
pub fn verify_data_column_sidecar_inclusion_proof(sidecar: &[u8]) -> bool {
    let commitments = DataColumnSidecarView::kzg_commitments(sidecar);
    let leaf = hash_list_fixed_elements(
        commitments,
        BYTES_PER_KZG_COMMITMENT,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
    );
    let branch = DataColumnSidecarView::inclusion_proof(sidecar);
    let body_root = DataColumnSidecarView::body_root(sidecar);
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
/// Caller MUST have already passed `verify_data_column_sidecar` —
/// this function relies on the shape invariants (matching list
/// lengths, element-size multiples) and skips re-validation.
/// Empty-list sidecars (N = 0) trivially pass.
///
/// Uses the mainnet Ethereum trusted setup statically bundled by
/// c-kzg's `ethereum_kzg_settings` feature; no runtime initialisation
/// required. `precompute = 0` — verification doesn't benefit from the
/// precomputation table (only proof generation does).
pub fn verify_data_column_sidecar_kzg_proofs(sidecar: &[u8]) -> bool {
    let column = DataColumnSidecarView::column(sidecar);
    let commits = DataColumnSidecarView::kzg_commitments(sidecar);
    let proofs = DataColumnSidecarView::kzg_proofs(sidecar);

    let n = column.len() / BYTES_PER_CELL;
    if n == 0 {
        return true;
    }

    // SAFETY: `Cell` is `#[repr(C)] { bytes: [u8; BYTES_PER_CELL] }` and
    // `Bytes48` is `#[repr(C)] { bytes: [u8; 48] }` — same layout as the
    // raw byte slices. The contiguous `&[u8]` we already validated as
    // an exact multiple of the per-element size in
    // `verify_data_column_sidecar` reinterprets as `&[Cell]` /
    // `&[Bytes48]` without alignment concerns (both repr-C wrappers
    // have alignment 1).
    let cells: &[c_kzg::Cell] =
        unsafe { std::slice::from_raw_parts(column.as_ptr() as *const c_kzg::Cell, n) };
    let commitments: &[c_kzg::Bytes48] =
        unsafe { std::slice::from_raw_parts(commits.as_ptr() as *const c_kzg::Bytes48, n) };
    let kzg_proofs: &[c_kzg::Bytes48] =
        unsafe { std::slice::from_raw_parts(proofs.as_ptr() as *const c_kzg::Bytes48, n) };

    let index = DataColumnSidecarView::index(sidecar);
    let cell_indices = vec![index; n];

    let settings = c_kzg::ethereum_kzg_settings(0);
    matches!(
        settings.verify_cell_kzg_proof_batch(commitments, &cell_indices, cells, kzg_proofs),
        Ok(true)
    )
}

/// Spec `DOMAIN_BEACON_PROPOSER = bytes4(0x00000000)`.
const DOMAIN_BEACON_PROPOSER: [u8; 4] = [0u8; 4];

/// BLS12-381 G2 hash-to-curve DST for proof-of-possession signatures
/// (eth2 ciphersuite: `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`).
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Validation: sidecar's slot is strictly above the finalised slot.
/// `finalized_epoch` is `state.epoch.finalized_checkpoint.epoch`.
pub fn is_above_finalized(sidecar: &[u8], finalized_epoch: u64) -> bool {
    DataColumnSidecarView::slot(sidecar) > finalized_epoch * SLOTS_PER_EPOCH
}

/// Validation: sidecar's `proposer_index` matches the expected proposer
/// for `sidecar.slot`. Caller resolves the expectation via
/// `state.epoch.proposer_lookahead` for the slot's epoch.
pub fn check_proposer_index(sidecar: &[u8], expected_proposer_index: u64) -> bool {
    DataColumnSidecarView::proposer_index(sidecar) == expected_proposer_index
}

/// Validations 4 + 5: sidecar's `parent_root` has been seen AND validated.
///
/// Silver's design pushes a block root into the slot delta's
/// `block_roots` only after fork choice has validated the block, so
/// membership in the union of (finalised canonical block_roots) ∪
/// (post-finalisation delta block_roots) is equivalent to "seen and
/// validated". `not present` means either not-yet-seen or invalid; the
/// caller resolves IGNORE vs REJECT severity from external context.
///
/// `finalised_block_roots` is the slot-indexed circular buffer (length
/// `SLOTS_PER_HISTORICAL_ROOT`). `delta_block_roots` is the appended
/// post-finalisation set. Delta is checked first — virtually every live
/// sidecar's parent resolves there; the finalised scan is a defensive
/// fall-through.
pub fn parent_validated(
    sidecar: &[u8],
    finalised_block_roots: &[B256],
    delta_block_roots: &[B256],
) -> bool {
    let parent_root = DataColumnSidecarView::parent_root(sidecar);
    delta_block_roots.iter().any(|r| r == parent_root) ||
        finalised_block_roots.iter().any(|r| r == parent_root)
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

    let sig_bytes = DataColumnSidecarView::block_signature(sidecar);
    let Ok(signature) = blst::min_pk::Signature::from_bytes(sig_bytes) else {
        return false;
    };
    signature.verify(true, &signing_root, BLS_DST, &[], proposer_pubkey, false) ==
        BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use silver_common::ssz_view::DATA_COLUMN_SIDECAR_MIN;

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
            assert!(verify_data_column_sidecar(&buf), "n={n}");
        }
    }

    #[test]
    fn verify_shape_rejects_out_of_range_index() {
        let mut buf = synth_sidecar(0, 1, 1, 1);
        buf[0..8].copy_from_slice(&(NUMBER_OF_COLUMNS as u64).to_le_bytes());
        assert!(!verify_data_column_sidecar(&buf));
    }

    #[test]
    fn verify_shape_rejects_length_mismatch() {
        // 2 cells but only 1 commitment + 1 proof — count mismatch.
        let buf = synth_sidecar(0, 2, 1, 1);
        assert!(!verify_data_column_sidecar(&buf));
    }

    #[test]
    fn verify_shape_rejects_truncated_buffer() {
        let mut buf = synth_sidecar(0, 1, 1, 1);
        buf.truncate(DATA_COLUMN_SIDECAR_MIN - 1);
        assert!(!verify_data_column_sidecar(&buf));
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
        assert!(verify_data_column_sidecar_kzg_proofs(&buf));
    }

    #[test]
    fn verify_kzg_proofs_rejects_zero_cells() {
        // A column of zero-cells with zero-commitments + zero-proofs
        // is NOT a valid KZG opening — the point-at-infinity
        // commitment (0xc000...) is reserved for "no blob" and zero
        // bytes are not a valid G1 encoding. c-kzg rejects with an
        // error; we map every non-Ok(true) result to false.
        let buf = synth_sidecar(0, 1, 1, 1);
        assert!(!verify_data_column_sidecar_kzg_proofs(&buf));
    }
}
