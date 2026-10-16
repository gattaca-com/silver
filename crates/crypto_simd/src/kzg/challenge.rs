//! The Fiat–Shamir challenge of `verifyCellKzgProofBatch`.

use blst::blst_fr;

use crate::{
    bls::COMPRESSED_LEN,
    kzg::{BYTES_PER_CELL, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, blst_ops::hash_to_fr},
};

/// A value rather than a reference: Aeneas rejects a loop that follows a read
/// of a reference constant, as a join of nested borrows.
const DOMAIN: [u8; 16] = *b"RCKZGCBATCH__V1_";

/// The buffer for the spec's challenge preimage, reused between batches.
pub struct Preimage {
    bytes: Vec<u8>,
}

impl Preimage {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Cells are hashed as received: they were validated as field elements
    /// below r, so their bytes are already the canonical encoding.
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
