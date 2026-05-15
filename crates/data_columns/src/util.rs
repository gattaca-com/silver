//! Utility helpers for data-column construction and verification.

use std::sync::OnceLock;

use silver_common::{
    ssz_hash::{
        B256, ZERO_HASHES_LEN, compute_zero_hashes, hash_list_fixed_elements, hash_tree_root_body,
        is_valid_merkle_branch,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DataColumnSidecarView,
        MAX_BLOB_COMMITMENTS_PER_BLOCK, NUMBER_OF_COLUMNS,
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

/// Cached SSZ zero-hash table — built once and shared by every
/// `body_root` call. `compute_zero_hashes` is cheap (~48 sha256s) but
/// uncached calls would still dwarf the actual body-root work for small
/// blocks, so we cache once and re-use.
static ZERO_HASHES: OnceLock<[B256; ZERO_HASHES_LEN]> = OnceLock::new();

#[inline]
fn zero_hashes() -> &'static [B256; ZERO_HASHES_LEN] {
    ZERO_HASHES.get_or_init(compute_zero_hashes)
}

/// SSZ `body_root` of a `BeaconBlockBody` given its raw SSZ bytes.
/// Returns `[0u8; 32]` if `body.len()` is below the post-Electra fixed
/// prefix size — mirrors the spec-compliant fallback in
/// `silver_common::ssz_hash::hash_tree_root_body`.
pub fn body_root(body: &[u8]) -> B256 {
    hash_tree_root_body(body, zero_hashes())
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
    let zh = zero_hashes();
    let commitments = DataColumnSidecarView::kzg_commitments(sidecar);
    let leaf = hash_list_fixed_elements(
        commitments,
        BYTES_PER_KZG_COMMITMENT,
        MAX_BLOB_COMMITMENTS_PER_BLOCK,
        zh,
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
        // Same bytes → same root, across two calls (also verifies the
        // OnceLock-cached zero-hash table is reusable).
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
