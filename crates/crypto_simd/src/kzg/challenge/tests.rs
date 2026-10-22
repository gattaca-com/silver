use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::Preimage;
#[cfg(target_arch = "x86_64")]
use super::{challenge_in_parts, challenge_in_parts_portable};
#[cfg(target_arch = "x86_64")]
use crate::sha_kernel_runs;
use crate::{
    bls::COMPRESSED_LEN,
    kzg::{BYTES_PER_CELL, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, blst_ops},
};

/// The preimage of the spec's `compute_verify_cell_kzg_proof_batch_challenge`.
fn spec_preimage(
    commitments: &[[u8; COMPRESSED_LEN]],
    commitment_of_cell: &[usize],
    cell_indices: &[u64],
    cells: &[[u8; BYTES_PER_CELL]],
    proofs: &[[u8; COMPRESSED_LEN]],
) -> Vec<u8> {
    let mut bytes = b"RCKZGCBATCH__V1_".to_vec();
    let counts = [FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, commitments.len(), cells.len()];
    for count in counts {
        bytes.extend_from_slice(&(count as u64).to_be_bytes());
    }
    for commitment in commitments {
        bytes.extend_from_slice(commitment);
    }
    for k in 0..cells.len() {
        bytes.extend_from_slice(&(commitment_of_cell[k] as u64).to_be_bytes());
        bytes.extend_from_slice(&cell_indices[k].to_be_bytes());
        bytes.extend_from_slice(&cells[k]);
        bytes.extend_from_slice(&proofs[k]);
    }
    bytes
}

/// Both routes against blst's `hash_to_fr` of the spec's preimage, at the
/// verifier's shapes for 1 and 128 columns of 18 blobs, and small batches whose
/// preimages leave each of the four remainders modulo 64 that the layout
/// allows. One `Preimage` serves every batch, as in the verifier.
#[test]
fn challenge_matches_blst() {
    let mut rng = ChaCha8Rng::seed_from_u64(0xc4);
    let mut preimage = Preimage::new();
    for (unique, n) in [(0, 0), (1, 1), (2, 3), (3, 2), (4, 9), (18, 18), (18, 2304)] {
        let mut commitments = vec![[0u8; COMPRESSED_LEN]; unique];
        for commitment in &mut commitments {
            rng.fill(&mut commitment[..]);
        }
        let commitment_of_cell: Vec<_> = (0..n).map(|k| k % unique.max(1)).collect();
        let cell_indices: Vec<_> = (0..n).map(|_| rng.gen_range(0..128)).collect();
        let mut cells = vec![[0u8; BYTES_PER_CELL]; n];
        for cell in &mut cells {
            rng.fill(&mut cell[..]);
        }
        let mut proofs = vec![[0u8; COMPRESSED_LEN]; n];
        for proof in &mut proofs {
            rng.fill(&mut proof[..]);
        }
        let expected = blst_ops::hash_to_fr(&spec_preimage(
            &commitments,
            &commitment_of_cell,
            &cell_indices,
            &cells,
            &proofs,
        ));
        let got =
            preimage.challenge(&commitments, &commitment_of_cell, &cell_indices, &cells, &proofs);
        assert!(got == expected, "buffer, {unique} commitments, {n} cells");
        #[cfg(target_arch = "x86_64")]
        if sha_kernel_runs() {
            // SAFETY: `sha_kernel_runs` checked the SHA extensions and SSE4.1.
            let got = unsafe {
                challenge_in_parts(
                    &commitments,
                    &commitment_of_cell,
                    &cell_indices,
                    &cells,
                    &proofs,
                )
            };
            assert!(got == expected, "in parts, {unique} commitments, {n} cells");
        }
        #[cfg(target_arch = "x86_64")]
        {
            let got = challenge_in_parts_portable(
                &commitments,
                &commitment_of_cell,
                &cell_indices,
                &cells,
                &proofs,
            );
            assert!(got == expected, "portable, {unique} commitments, {n} cells");
        }
    }
}
