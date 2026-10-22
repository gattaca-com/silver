//! `verify_cell_kzg_proof_batch` of EIP-7594, in the spec's phases: input
//! checks, commitment deduplication, decoding, the challenge, then the pairing
//! check. RLI uses c-kzg's per-column inverse FFT rather than the spec's
//! per-cell Lagrange interpolation. With IFMA, the cell checks and that
//! interpolation run on `Fr8` vectors, which read the cells' bytes directly,
//! the four multi-scalar multiplications run on `Msm8`, and the pairing check
//! runs on `Fp12` lanes.

use blst::{blst_fr, blst_p1};

#[cfg(target_arch = "x86_64")]
use crate::{
    Route,
    bls::{
        fp8::{Fp8, LANES},
        g1x8::G1x8,
        msm8::Msm8,
    },
    ifma_available,
    kzg::{
        challenge::{challenge_in_parts, challenge_in_parts_portable},
        fr::fr_to_words,
        fr8::Fr8,
        interpolation_kernel::InterpolationKernel,
        pairing_lines::PAIRING_LINES,
    },
    portable::{g1::G1, msm::Msm, pairing::PairingLines},
    route, sha_extensions,
};
use crate::{
    bls::{COMPRESSED_LEN, blst_p1_affine, uncompress_in_g1},
    kzg::{
        BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL,
        FR_ONE, FR_ZERO,
        blst_ops::{LincombScratch, g1_add, g1_lincomb, g1_neg, g1_to_affine, pairing_check},
        challenge::Preimage,
        cosets::Cosets,
        domain::reverse_bits,
        fft::inverse_fft,
        fr::{fr_add, fr_from_bytes, fr_mul},
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
        let kernel = if ifma_available() {
            // SAFETY: `ifma_available` confirmed avx512f and avx512ifma on this CPU.
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
        let r = self.challenge(cell_indices, cells, proofs);
        self.pairing_holds(&r, cell_indices, cells)
    }

    /// On the SHA extensions where the kernel runs, and on the portable route
    /// where they run; in plain Rust elsewhere on the portable route; by blst
    /// elsewhere.
    fn challenge(
        &mut self,
        cell_indices: &[u64],
        cells: &[[u8; BYTES_PER_CELL]],
        proofs: &[[u8; COMPRESSED_LEN]],
    ) -> blst_fr {
        let unique = &self.commitments.unique;
        let index_of_cell = &self.commitments.index_of_cell;
        #[cfg(target_arch = "x86_64")]
        if self.kernel.is_some() || (self.lincomb.portable.is_some() && sha_extensions()) {
            // SAFETY: `kernel` is built only where `ifma_available` held, which
            // covers the SHA extensions; `sha_extensions` checks them itself.
            return unsafe {
                challenge_in_parts(unique, index_of_cell, cell_indices, cells, proofs)
            };
        }
        #[cfg(target_arch = "x86_64")]
        if self.lincomb.portable.is_some() {
            return challenge_in_parts_portable(unique, index_of_cell, cell_indices, cells, proofs);
        }
        self.preimage.challenge(unique, index_of_cell, cell_indices, cells, proofs)
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
            // SAFETY: `kernel` is built only where `ifma_available` held.
            return unsafe { kernel.check(cells) };
        }
        self.evaluations.resize(0, FR_ZERO);
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
        self.r_powers.resize(0, FR_ZERO);
        let mut power = FR_ONE;
        for _ in 0..n {
            self.r_powers.push(power);
            power = fr_mul(&power, r);
        }
        let ll = self.lincomb.sum(&self.proof_points, &self.r_powers);

        self.scalars.resize(0, FR_ZERO);
        self.scalars.resize(self.commitments.unique.len(), FR_ZERO);
        for k in 0..n {
            let i = self.commitments.index_of_cell[k];
            self.scalars[i] = fr_add(&self.scalars[i], &self.r_powers[k]);
        }
        let rlc = self.lincomb.sum(&self.commitment_points, &self.scalars);

        let rli = self.interpolation_commitment(cell_indices, cells);

        self.scalars.resize(0, FR_ZERO);
        for k in 0..n {
            let shift = &self.cosets.shift_pow_cell[cell_indices[k] as usize];
            self.scalars.push(fr_mul(&self.r_powers[k], shift));
        }
        let rlp = self.lincomb.sum(&self.proof_points, &self.scalars);

        self.lincomb.pairing_check(&ll, &rlc, &rli, &rlp)
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
        #[cfg(target_arch = "x86_64")]
        if let Some(kernel) = &mut self.kernel {
            self.interpolation.resize(FIELD_ELEMENTS_PER_CELL, FR_ZERO);
            // SAFETY: `kernel` is built only where `ifma_available` held.
            unsafe {
                kernel.interpolate(cells, cell_indices, &self.r_powers, &mut self.interpolation)
            };
            return self.lincomb.sum(&self.setup.g1_monomial, &self.interpolation);
        }
        self.columns.resize(0, FR_ZERO);
        self.columns.resize(CELLS_PER_EXT_BLOB * FIELD_ELEMENTS_PER_CELL, FR_ZERO);
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

        self.interpolation.resize(0, FR_ZERO);
        self.interpolation.resize(FIELD_ELEMENTS_PER_CELL, FR_ZERO);
        self.column.resize(FIELD_ELEMENTS_PER_CELL, FR_ZERO);
        self.coefficients.resize(FIELD_ELEMENTS_PER_CELL, FR_ZERO);
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
            let mut factor = FR_ONE;
            for i in 0..FIELD_ELEMENTS_PER_CELL {
                let term = fr_mul(&self.coefficients[i], &factor);
                self.interpolation[i] = fr_add(&self.interpolation[i], &term);
                factor = fr_mul(&factor, &self.cosets.shift_inverse[c]);
            }
        }
        self.lincomb.sum(&self.setup.g1_monomial, &self.interpolation)
    }
}

/// The verifier's curve work: sums Σ scalars[i]·points[i], and the pairing
/// check on two points from four of them. On `Msm8`, `Fp8` and `Fp12` lanes
/// where IFMA runs, on the scalar portable route where it is taken, by blst
/// elsewhere. Buffers are kept between calls.
struct Lincomb {
    scratch: LincombScratch,
    #[cfg(target_arch = "x86_64")]
    msm: Option<Msm8>,
    #[cfg(target_arch = "x86_64")]
    portable: Option<PortableCurve>,
    #[cfg(target_arch = "x86_64")]
    words: Vec<[u64; 4]>,
}

/// The portable route's MSM buffers and pairing lines.
#[cfg(target_arch = "x86_64")]
struct PortableCurve {
    msm: Msm,
    lines: Box<PairingLines>,
}

impl Lincomb {
    fn new() -> Self {
        Self {
            scratch: LincombScratch::new(),
            #[cfg(target_arch = "x86_64")]
            msm: if ifma_available() { Some(Msm8::default()) } else { None },
            #[cfg(target_arch = "x86_64")]
            portable: if route() == Route::Portable {
                let lines = Box::new(PairingLines::new(&PAIRING_LINES));
                Some(PortableCurve { msm: Msm::default(), lines })
            } else {
                None
            },
            #[cfg(target_arch = "x86_64")]
            words: Vec::new(),
        }
    }

    fn sum(&mut self, points: &[blst_p1_affine], scalars: &[blst_fr]) -> blst_p1 {
        #[cfg(target_arch = "x86_64")]
        if let Some(msm) = &mut self.msm {
            // SAFETY: `msm` is built only where `ifma_available` held.
            return unsafe {
                Fr8::plain_words(scalars, &mut self.words);
                msm.msm(points, &self.words)
            };
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(portable) = &mut self.portable {
            self.words.clear();
            let mut i = 0;
            while i < scalars.len() {
                self.words.push(fr_to_words(&scalars[i]));
                i += 1;
            }
            return portable.msm.msm(points, &self.words);
        }
        g1_lincomb(points, scalars, &mut self.scratch)
    }

    /// e(LL, [s^64])·e(RL, −[1]) = 1, with RL = RLC − RLI + RLP.
    fn pairing_check(&self, ll: &blst_p1, rlc: &blst_p1, rli: &blst_p1, rlp: &blst_p1) -> bool {
        #[cfg(target_arch = "x86_64")]
        if self.msm.is_some() {
            // SAFETY: `msm` is built only where `ifma_available` held.
            return unsafe {
                PAIRING_LINES.pairing_check(&pairing_points_in_lanes(ll, rlc, rli, rlp))
            };
        }
        #[cfg(target_arch = "x86_64")]
        if let Some(portable) = &self.portable {
            return portable.lines.pairing_check(&pairing_points(ll, rlc, rli, rlp));
        }
        let rl = g1_add(&g1_add(rlc, &g1_neg(rli)), rlp);
        pairing_check(&g1_to_affine(ll), &G2_S_POW_CELL, &g1_to_affine(&rl), &G2_NEG_GENERATOR)
    }
}

/// [LL, RL], gathered by complete additions on the scalar `G1`.
#[cfg(target_arch = "x86_64")]
fn pairing_points(ll: &blst_p1, rlc: &blst_p1, rli: &blst_p1, rlp: &blst_p1) -> [G1; 2] {
    let difference = G1::from_blst(rlc).add_complete(&G1::from_blst(rli).neg());
    [G1::from_blst(ll), difference.add_complete(&G1::from_blst(rlp))]
}

/// LL in lane 0 and RL in lane 1, Jacobian, gathered by complete additions.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
fn pairing_points_in_lanes(ll: &blst_p1, rlc: &blst_p1, rli: &blst_p1, rlp: &blst_p1) -> G1x8 {
    let infinity = blst_p1::default();
    let difference = two_lanes(ll, rlc).add_complete(&two_lanes(&infinity, rli).neg());
    difference.add_complete(&two_lanes(&infinity, rlp))
}

/// `first` in lane 0 and `second` in lane 1, from blst's Jacobian form; the
/// other lanes have z = 0, infinity.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
fn two_lanes(first: &blst_p1, second: &blst_p1) -> G1x8 {
    let mut x = [[0u64; 6]; LANES];
    let mut y = [[0u64; 6]; LANES];
    let mut z = [[0u64; 6]; LANES];
    x[0] = first.x.l;
    y[0] = first.y.l;
    z[0] = first.z.l;
    x[1] = second.x.l;
    y[1] = second.y.l;
    z[1] = second.z.l;
    G1x8 { x: Fp8::from_blst_limbs(&x), y: Fp8::from_blst_limbs(&y), z: Fp8::from_blst_limbs(&z) }
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

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
