//! The Fiat–Shamir challenge of `verifyCellKzgProofBatch`. Cells are hashed as
//! received: they were validated as field elements below r, so their bytes are
//! already the canonical encoding.

use blst::blst_fr;

#[cfg(any(test, not(target_arch = "x86_64")))]
use crate::kzg::blst_ops::hash_to_fr;
use crate::{
    bls::COMPRESSED_LEN,
    kzg::{BYTES_PER_CELL, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL},
};
#[cfg(target_arch = "x86_64")]
use crate::{
    kzg::fr::fr_from_bytes_reduced,
    sha256::{Sha256, portable::Sha256 as PortableSha256},
};

/// A value rather than a reference: Aeneas rejects a loop that follows a read
/// of a reference constant, as a join of nested borrows.
const DOMAIN: [u8; 16] = *b"RCKZGCBATCH__V1_";

/// The buffer for the spec's challenge preimage, reused between batches.
#[cfg(any(test, not(target_arch = "x86_64")))]
pub struct Preimage {
    bytes: Vec<u8>,
}

#[cfg(any(test, not(target_arch = "x86_64")))]
impl Preimage {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn challenge(
        &mut self,
        unique_commitments: &[[u8; COMPRESSED_LEN]],
        commitment_of_cell: &[usize],
        cell_indices: &[u64],
        cells: &[[u8; BYTES_PER_CELL]],
        proofs: &[[u8; COMPRESSED_LEN]],
    ) -> blst_fr {
        self.bytes.resize(0, 0);
        self.bytes.extend_from_slice(&DOMAIN);
        self.push_u64(FIELD_ELEMENTS_PER_BLOB as u64);
        self.push_u64(FIELD_ELEMENTS_PER_CELL as u64);
        self.push_u64(unique_commitments.len() as u64);
        self.push_u64(cell_indices.len() as u64);
        let mut i = 0;
        while i < unique_commitments.len() {
            self.bytes.extend_from_slice(&unique_commitments[i]);
            i += 1;
        }
        let mut k = 0;
        while k < cell_indices.len() {
            self.push_u64(commitment_of_cell[k] as u64);
            self.push_u64(cell_indices[k]);
            self.bytes.extend_from_slice(&cells[k]);
            self.bytes.extend_from_slice(&proofs[k]);
            k += 1;
        }
        hash_to_fr(&self.bytes)
    }

    fn push_u64(&mut self, value: u64) {
        let mut shift = 64;
        while shift > 0 {
            shift -= 8;
            self.bytes.push((value >> shift) as u8);
        }
    }
}

/// The challenge on the SHA extensions, each part of the preimage hashed as it
/// comes, without a buffer.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse4.1")]
pub fn challenge_in_parts(
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

/// `challenge_in_parts` in plain Rust, for CPUs without the SHA extensions.
#[cfg(target_arch = "x86_64")]
pub fn challenge_in_parts_portable(
    unique_commitments: &[[u8; COMPRESSED_LEN]],
    commitment_of_cell: &[usize],
    cell_indices: &[u64],
    cells: &[[u8; BYTES_PER_CELL]],
    proofs: &[[u8; COMPRESSED_LEN]],
) -> blst_fr {
    let mut hasher = PortableSha256::new();
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
