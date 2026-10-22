//! `verify_cell_kzg_proof_batch` of EIP-7594, in the spec's phases: input
//! checks, commitment deduplication, decoding, the challenge, then the pairing
//! check. RLI uses c-kzg's per-column inverse FFT rather than the spec's
//! per-cell Lagrange interpolation. With IFMA, the cell checks and that
//! interpolation run on `Fr8` vectors, which read the cells' bytes directly,
//! and the four multi-scalar multiplications run on `Msm8`.

use blst::{blst_fr, blst_p1};

#[cfg(target_arch = "x86_64")]
use crate::{
    bls::msm8::Msm8,
    kzg::{fr8::Fr8, interpolation_kernel::InterpolationKernel},
    simd_available,
};
use crate::{
    bls::{COMPRESSED_LEN, blst_p1_affine, uncompress_in_g1},
    kzg::{
        BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL,
        blst_ops::{
            LincombScratch, fr_add, fr_from_bytes, fr_from_u64, fr_mul, g1_add, g1_lincomb, g1_neg,
            g1_to_affine, pairing_check,
        },
        challenge::Preimage,
        cosets::Cosets,
        domain::reverse_bits,
        fft::inverse_fft,
        setup::{G2_NEG_GENERATOR, G2_S_POW_CELL, Setup},
    },
};

const LOG_CELL: u32 = 6;

/// Verifies batches of cells against their commitments. Buffers are kept
/// between calls, so a verifier allocates only while its batches grow.
pub struct CellBatchVerifier {
    setup: Setup,
    cosets: Cosets,
    commitments: Deduplicated,
    decoded: Vec<Option<blst_p1_affine>>,
    commitment_points: Vec<blst_p1_affine>,
    proof_points: Vec<blst_p1_affine>,
    evaluations: Vec<blst_fr>,
    preimage: Preimage,
    r_powers: Vec<blst_fr>,
    scalars: Vec<blst_fr>,
    columns: Vec<blst_fr>,
    column_used: Vec<bool>,
    column: Vec<blst_fr>,
    coefficients: Vec<blst_fr>,
    interpolation: Vec<blst_fr>,
    lincomb: Lincomb,
    #[cfg(target_arch = "x86_64")]
    kernel: Option<InterpolationKernel>,
}

impl Default for CellBatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl CellBatchVerifier {
    pub fn new() -> Self {
        let setup = Setup::decode();
        let cosets = Cosets::new();
        #[cfg(target_arch = "x86_64")]
        let kernel = if simd_available() {
            // SAFETY: `simd_available` confirmed avx512f and avx512ifma on this CPU.
            Some(unsafe { InterpolationKernel::new(&cosets) })
        } else {
            None
        };
        Self {
            setup,
            cosets,
            commitments: Deduplicated::default(),
            decoded: Vec::new(),
            commitment_points: Vec::new(),
            proof_points: Vec::new(),
            evaluations: Vec::new(),
            preimage: Preimage::new(),
            r_powers: Vec::new(),
            scalars: Vec::new(),
            columns: Vec::new(),
            column_used: Vec::new(),
            column: Vec::new(),
            coefficients: Vec::new(),
            interpolation: Vec::new(),
            lincomb: Lincomb::new(),
            #[cfg(target_arch = "x86_64")]
            kernel,
        }
    }

    #[cfg(test)]
    pub(crate) fn without_kernel() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            kernel: None,
            #[cfg(target_arch = "x86_64")]
            lincomb: Lincomb { msm: None, ..Lincomb::new() },
            ..Self::new()
        }
    }

    /// True exactly when the spec's `verify_cell_kzg_proof_batch` returns true;
    /// every input the spec rejects with an error is false.
    pub fn verify(
        &mut self,
        commitments: &[[u8; COMPRESSED_LEN]],
        cell_indices: &[u64],
        cells: &[[u8; BYTES_PER_CELL]],
        proofs: &[[u8; COMPRESSED_LEN]],
    ) -> bool {
        let n = commitments.len();
        if cell_indices.len() != n || cells.len() != n || proofs.len() != n {
            return false;
        }
        let mut k = 0;
        while k < n && cell_indices[k] < CELLS_PER_EXT_BLOB as u64 {
            k += 1;
        }
        if k < n {
            return false;
        }
        self.commitments.fill(commitments);
        if !self.decode_commitments() || !self.decode_cells(cells) || !self.decode_proofs(proofs) {
            return false;
        }
        let r = self.preimage.challenge(
            &self.commitments.unique,
            &self.commitments.index_of_cell,
            cell_indices,
            cells,
            proofs,
        );
        self.pairing_holds(&r, cell_indices, cells)
    }

    fn decode_commitments(&mut self) -> bool {
        decode_points(&self.commitments.unique, &mut self.decoded, &mut self.commitment_points)
    }

    fn decode_proofs(&mut self, proofs: &[[u8; COMPRESSED_LEN]]) -> bool {
        decode_points(proofs, &mut self.decoded, &mut self.proof_points)
    }

    fn decode_cells(&mut self, cells: &[[u8; BYTES_PER_CELL]]) -> bool {
        #[cfg(target_arch = "x86_64")]
        if let Some(kernel) = &self.kernel {
            // SAFETY: `kernel` is built only where `simd_available` held.
            return unsafe { kernel.check(cells) };
        }
        self.evaluations.resize(0, fr_from_u64(0));
        let mut k = 0;
        while k < cells.len() && self.decode_cell(&cells[k]) {
            k += 1;
        }
        k == cells.len()
    }

    fn decode_cell(&mut self, cell: &[u8; BYTES_PER_CELL]) -> bool {
        let mut j = 0;
        while j < FIELD_ELEMENTS_PER_CELL {
            let mut bytes = [0u8; BYTES_PER_FIELD_ELEMENT];
            bytes.copy_from_slice(
                &cell[j * BYTES_PER_FIELD_ELEMENT..(j + 1) * BYTES_PER_FIELD_ELEMENT],
            );
            match fr_from_bytes(&bytes) {
                Some(value) => self.evaluations.push(value),
                None => break,
            }
            j += 1;
        }
        j == FIELD_ELEMENTS_PER_CELL
    }

    /// e(LL, [s^64])·e(RL, −[1]) = 1, with LL = Σ r^k·π_k and RL = RLC − RLI +
    /// RLP.
    fn pairing_holds(
        &mut self,
        r: &blst_fr,
        cell_indices: &[u64],
        cells: &[[u8; BYTES_PER_CELL]],
    ) -> bool {
        let n = cell_indices.len();
        let zero = fr_from_u64(0);
        self.r_powers.resize(0, zero);
        let mut power = fr_from_u64(1);
        for _ in 0..n {
            self.r_powers.push(power);
            power = fr_mul(&power, r);
        }
        let ll = self.lincomb.sum(&self.proof_points, &self.r_powers);

        self.scalars.resize(0, zero);
        self.scalars.resize(self.commitments.unique.len(), zero);
        for k in 0..n {
            let i = self.commitments.index_of_cell[k];
            self.scalars[i] = fr_add(&self.scalars[i], &self.r_powers[k]);
        }
        let rlc = self.lincomb.sum(&self.commitment_points, &self.scalars);

        let rli = self.interpolation_commitment(cell_indices, cells);

        self.scalars.resize(0, zero);
        for k in 0..n {
            let shift = &self.cosets.shift_pow_cell[cell_indices[k] as usize];
            self.scalars.push(fr_mul(&self.r_powers[k], shift));
        }
        let rlp = self.lincomb.sum(&self.proof_points, &self.scalars);

        let rl = g1_add(&g1_add(&rlc, &g1_neg(&rli)), &rlp);
        pairing_check(&g1_to_affine(&ll), &G2_S_POW_CELL, &g1_to_affine(&rl), &G2_NEG_GENERATOR)
    }

    /// RLI = [Σ_k r^k·I_k(s)]. The r^k-weighted cells of each column are
    /// summed, inverse-transformed, and shifted from the column's coset by
    /// h⁻¹. Without IFMA, each column is first put in natural order; the
    /// kernel's transform takes the cells' bit-reversed order as it is.
    fn interpolation_commitment(
        &mut self,
        cell_indices: &[u64],
        cells: &[[u8; BYTES_PER_CELL]],
    ) -> blst_p1 {
        let zero = fr_from_u64(0);
        #[cfg(target_arch = "x86_64")]
        if let Some(kernel) = &mut self.kernel {
            self.interpolation.resize(FIELD_ELEMENTS_PER_CELL, zero);
            // SAFETY: `kernel` is built only where `simd_available` held.
            unsafe {
                kernel.interpolate(cells, cell_indices, &self.r_powers, &mut self.interpolation)
            };
            return self.lincomb.sum(&self.setup.g1_monomial, &self.interpolation);
        }
        self.columns.resize(0, zero);
        self.columns.resize(CELLS_PER_EXT_BLOB * FIELD_ELEMENTS_PER_CELL, zero);
        self.column_used.resize(0, false);
        self.column_used.resize(CELLS_PER_EXT_BLOB, false);
        for k in 0..cell_indices.len() {
            let c = cell_indices[k] as usize;
            self.column_used[c] = true;
            for j in 0..FIELD_ELEMENTS_PER_CELL {
                let term =
                    fr_mul(&self.r_powers[k], &self.evaluations[k * FIELD_ELEMENTS_PER_CELL + j]);
                let at = c * FIELD_ELEMENTS_PER_CELL + j;
                self.columns[at] = fr_add(&self.columns[at], &term);
            }
        }

        self.interpolation.resize(0, zero);
        self.interpolation.resize(FIELD_ELEMENTS_PER_CELL, zero);
        self.column.resize(FIELD_ELEMENTS_PER_CELL, zero);
        self.coefficients.resize(FIELD_ELEMENTS_PER_CELL, zero);
        for c in 0..CELLS_PER_EXT_BLOB {
            if !self.column_used[c] {
                continue;
            }
            for j in 0..FIELD_ELEMENTS_PER_CELL {
                self.column[j] =
                    self.columns[c * FIELD_ELEMENTS_PER_CELL + reverse_bits(j, LOG_CELL)];
            }
            inverse_fft(
                &mut self.coefficients,
                &self.column,
                &self.cosets.inverse_roots,
                &self.cosets.inverse_size,
            );
            let mut factor = fr_from_u64(1);
            for i in 0..FIELD_ELEMENTS_PER_CELL {
                let term = fr_mul(&self.coefficients[i], &factor);
                self.interpolation[i] = fr_add(&self.interpolation[i], &term);
                factor = fr_mul(&factor, &self.cosets.shift_inverse[c]);
            }
        }
        self.lincomb.sum(&self.setup.g1_monomial, &self.interpolation)
    }
}

/// Σ scalars[i]·points[i], on `Msm8` where IFMA runs and by blst's Pippenger
/// elsewhere. Buffers are kept between calls.
struct Lincomb {
    scratch: LincombScratch,
    #[cfg(target_arch = "x86_64")]
    msm: Option<Msm8>,
    #[cfg(target_arch = "x86_64")]
    words: Vec<[u64; 4]>,
}

impl Lincomb {
    fn new() -> Self {
        Self {
            scratch: LincombScratch::new(),
            #[cfg(target_arch = "x86_64")]
            msm: if simd_available() { Some(Msm8::default()) } else { None },
            #[cfg(target_arch = "x86_64")]
            words: Vec::new(),
        }
    }

    fn sum(&mut self, points: &[blst_p1_affine], scalars: &[blst_fr]) -> blst_p1 {
        #[cfg(target_arch = "x86_64")]
        if let Some(msm) = &mut self.msm {
            // SAFETY: `msm` is built only where `simd_available` held.
            return unsafe {
                Fr8::plain_words(scalars, &mut self.words);
                msm.msm(points, &self.words)
            };
        }
        g1_lincomb(points, scalars, &mut self.scratch)
    }
}

/// Unique commitments in first-occurrence order, and each cell's index into
/// them, as the spec's linear scan builds them.
#[derive(Default)]
pub(crate) struct Deduplicated {
    pub unique: Vec<[u8; COMPRESSED_LEN]>,
    pub index_of_cell: Vec<usize>,
}

impl Deduplicated {
    pub fn fill(&mut self, commitments: &[[u8; COMPRESSED_LEN]]) {
        self.unique.resize(0, [0; COMPRESSED_LEN]);
        self.index_of_cell.resize(0, 0);
        for k in 0..commitments.len() {
            let mut found = self.unique.len();
            let mut i = 0;
            while i < self.unique.len() {
                if same_bytes(&self.unique[i], &commitments[k]) {
                    found = i;
                    break;
                }
                i += 1;
            }
            if found == self.unique.len() {
                self.unique.push(commitments[k]);
            }
            self.index_of_cell.push(found);
        }
    }
}

/// Decodes `encodings` into `points`; false if any is not a valid G1 point.
fn decode_points(
    encodings: &[[u8; COMPRESSED_LEN]],
    decoded: &mut Vec<Option<blst_p1_affine>>,
    points: &mut Vec<blst_p1_affine>,
) -> bool {
    decoded.resize(0, None);
    decoded.resize(encodings.len(), None);
    uncompress_in_g1(encodings, decoded);
    points.resize(0, blst_p1_affine::default());
    let mut i = 0;
    while i < encodings.len() {
        match decoded[i] {
            Some(point) => points.push(point),
            None => break,
        }
        i += 1;
    }
    i == encodings.len()
}

fn same_bytes(a: &[u8; COMPRESSED_LEN], b: &[u8; COMPRESSED_LEN]) -> bool {
    let mut i = 0;
    while i < COMPRESSED_LEN && a[i] == b[i] {
        i += 1;
    }
    i == COMPRESSED_LEN
}
