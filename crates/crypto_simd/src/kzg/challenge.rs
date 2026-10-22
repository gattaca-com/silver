//! The Fiat–Shamir challenge of `verifyCellKzgProofBatch`.

use blst::blst_fr;

use crate::{
    bls::COMPRESSED_LEN,
    kzg::{
        BYTES_PER_CELL, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, fr::fr_from_bytes_reduced,
    },
    sha256::Sha256,
};

/// A value rather than a reference: Aeneas rejects a loop that follows a read
/// of a reference constant, as a join of nested borrows.
const DOMAIN: [u8; 16] = *b"RCKZGCBATCH__V1_";

/// The preimage is hashed part by part, as the spec lays it out. Cells are
/// hashed as received: they were validated as field elements below r, so
/// their bytes are already the canonical encoding.
pub fn challenge(
    unique_commitments: &[[u8; COMPRESSED_LEN]],
    commitment_of_cell: &[usize],
    cell_indices: &[u64],
    cells: &[[u8; BYTES_PER_CELL]],
    proofs: &[[u8; COMPRESSED_LEN]],
) -> blst_fr {
    let mut hasher = Sha256::new();
    hasher.update(&DOMAIN);
    hasher.update(&(FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    hasher.update(&(FIELD_ELEMENTS_PER_CELL as u64).to_be_bytes());
    hasher.update(&(unique_commitments.len() as u64).to_be_bytes());
    hasher.update(&(cell_indices.len() as u64).to_be_bytes());
    let mut i = 0;
    while i < unique_commitments.len() {
        hasher.update(&unique_commitments[i]);
        i += 1;
    }
    let mut k = 0;
    while k < cell_indices.len() {
        hasher.update(&(commitment_of_cell[k] as u64).to_be_bytes());
        hasher.update(&cell_indices[k].to_be_bytes());
        hasher.update(&cells[k]);
        hasher.update(&proofs[k]);
        k += 1;
    }
    fr_from_bytes_reduced(&hasher.finish())
}

#[cfg(test)]
mod tests;
