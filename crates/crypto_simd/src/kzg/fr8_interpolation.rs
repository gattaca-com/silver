//! The 64 scalars of RLI = [Σ_k r^k·I_k(s)] on `Fr8`: the r^k-weighted cells of
//! each column are summed, inverse-transformed, scaled by h_c^(−i)/64 and
//! summed over the columns.
//!
//! Cell elements are plain and below r, powers are in R' form and below 2r, so
//! a product is plain and below 2r. Sums are kept below 2r. A column is reduced
//! below r before its length-64 inverse DIT FFT, which then leaves it below
//! 12r.

use crate::kzg::{
    BYTES_PER_CELL, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL,
    blst_ops::fr_mul,
    cosets::Cosets,
    fr8::{Fr8, Fr8Soa, LANES, R52, TWO_R52},
    fr8_bytes::BYTES_PER_VECTOR,
    fr8_fft::{
        BLOCK_VECTORS, FIRST_WIDE_STAGE, dit_first_stage, dit_stage, soa_of, transpose_blocks,
        twiddles,
    },
    fr8_scalars::CellScalars,
};

const LOG_CELL: usize = 6;
const _: () = assert!(FIELD_ELEMENTS_PER_CELL == BLOCK_VECTORS * LANES);
const _: () = assert!(1 << LOG_CELL == FIELD_ELEMENTS_PER_CELL);

pub struct Interpolation {
    inverse_twiddles: [Vec<Fr8Soa>; LOG_CELL],
    /// h_c^(−i)/64 in R' form, in layout S: column c, vector v, lane l is i =
    /// 8v+l.
    shift_factors: Vec<Fr8Soa>,
    /// Per column, its cells' weighted sums, plain and below 2r, in layout T:
    /// element j at vector j%8, lane j/8.
    columns: Vec<Fr8Soa>,
    used: [bool; CELLS_PER_EXT_BLOB],
    sums: [Fr8Soa; BLOCK_VECTORS],
    scalars: [[u8; 32]; FIELD_ELEMENTS_PER_CELL],
}

impl Interpolation {
    pub fn new(cosets: &Cosets) -> Self {
        let mut shift_factors = Vec::with_capacity(CELLS_PER_EXT_BLOB * BLOCK_VECTORS);
        for shift_inverse in &cosets.shift_inverse {
            let mut factor = cosets.inverse_size;
            let mut factors = Vec::with_capacity(FIELD_ELEMENTS_PER_CELL);
            for _ in 0..FIELD_ELEMENTS_PER_CELL {
                factors.push(factor);
                factor = fr_mul(&factor, shift_inverse);
            }
            for v in 0..BLOCK_VECTORS {
                shift_factors.push(soa_of(|lane| &factors[LANES * v + lane]));
            }
        }
        Self {
            inverse_twiddles: twiddles(&cosets.inverse_roots),
            shift_factors,
            columns: vec![Fr8Soa::ZERO; CELLS_PER_EXT_BLOB * BLOCK_VECTORS],
            used: [false; CELLS_PER_EXT_BLOB],
            sums: [Fr8Soa::ZERO; BLOCK_VECTORS],
            scalars: [[0; 32]; FIELD_ELEMENTS_PER_CELL],
        }
    }

    /// The 64 scalars, or None if some cell element is not below r.
    ///
    /// # Safety
    /// avx512f and avx512ifma must be available.
    #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
    pub unsafe fn scalars(
        &mut self,
        cells: &[[u8; BYTES_PER_CELL]],
        cell_indices: &[u64],
        powers: &CellScalars,
    ) -> Option<&[[u8; 32]; FIELD_ELEMENTS_PER_CELL]> {
        self.used.fill(false);
        for (k, cell) in cells.iter().enumerate() {
            let mut elements = [Fr8Soa::ZERO; BLOCK_VECTORS];
            if !decode_cell(cell, &mut elements) {
                return None;
            }
            let power = Fr8::splat(&powers.power_r260(k));
            let column = cell_indices[k] as usize;
            self.add_weighted(column, &elements, &power);
        }

        self.sums = [Fr8Soa::ZERO; BLOCK_VECTORS];
        for column in 0..CELLS_PER_EXT_BLOB {
            if self.used[column] {
                self.add_column_scaled(column);
            }
        }
        let r = Fr8::splat(&R52);
        for (v, sum) in self.sums.iter().enumerate() {
            let mut canonical = Fr8Soa::ZERO;
            Fr8::load(sum).cond_sub(&r).store(&mut canonical);
            for lane in 0..LANES {
                self.scalars[LANES * v + lane] = canonical.lane_le_bytes(lane);
            }
        }
        Some(&self.scalars)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add_weighted(&mut self, column: usize, elements: &[Fr8Soa; BLOCK_VECTORS], power: &Fr8) {
        let two_r = Fr8::splat(&TWO_R52);
        let first = !self.used[column];
        self.used[column] = true;
        let sums = &mut self.columns[column * BLOCK_VECTORS..(column + 1) * BLOCK_VECTORS];
        for (sum, element) in sums.iter_mut().zip(elements) {
            let product = Fr8::load(element).mul(power);
            let total = if first {
                product
            } else {
                Fr8::load(sum).add_raw(&product).normalise().cond_sub(&two_r)
            };
            total.store(sum);
        }
    }

    /// Adds the column's coefficients times h_c^(−i)/64 to `sums`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add_column_scaled(&mut self, column: usize) {
        let (r, two_r) = (Fr8::splat(&R52), Fr8::splat(&TWO_R52));
        let block = &mut self.columns[column * BLOCK_VECTORS..(column + 1) * BLOCK_VECTORS];
        for vector in block.iter_mut() {
            Fr8::load(vector).cond_sub(&r).store(vector);
        }
        dit_first_stage(block);
        for stage in 1..FIRST_WIDE_STAGE {
            dit_stage(block, &self.inverse_twiddles[stage], 1 << stage);
        }
        transpose_blocks(block);
        for stage in FIRST_WIDE_STAGE..LOG_CELL {
            dit_stage(block, &self.inverse_twiddles[stage], 1 << (stage - FIRST_WIDE_STAGE));
        }

        let factors = &self.shift_factors[column * BLOCK_VECTORS..(column + 1) * BLOCK_VECTORS];
        for ((sum, vector), factor) in self.sums.iter_mut().zip(block.iter()).zip(factors) {
            let scaled = Fr8::load(vector).normalise().mul(&Fr8::load(factor));
            Fr8::load(sum).add_raw(&scaled).normalise().cond_sub(&two_r).store(sum);
        }
    }
}

/// Into layout T, as limbs of the plain values; false if some element is not
/// below r.
#[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
fn decode_cell(cell: &[u8; BYTES_PER_CELL], elements: &mut [Fr8Soa; BLOCK_VECTORS]) -> bool {
    let mut below_r = true;
    for (vector, bytes) in elements.iter_mut().zip(cell.as_chunks::<BYTES_PER_VECTOR>().0) {
        below_r &= vector.set_from_be_bytes(bytes);
    }
    transpose_blocks(elements);
    below_r
}
