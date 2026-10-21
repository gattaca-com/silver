//! `CellBatchVerifier`'s interpolation on `Fr8` vectors: the coefficients of
//! Σ_k r^k·I_k, I_k the polynomial through cell k on its column's coset. The
//! weighted cells of each column are summed, inverse-transformed, scaled by
//! h_c^(−i)/64 and summed over the columns. A cell holds its evaluations in
//! bit-reversed order, the order `Fft8::dit` takes, so no step permutes.

use blst::blst_fr;

use crate::kzg::{
    BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL,
    blst_ops::{fr_from_bytes, fr_from_u64, fr_mul},
    cosets::Cosets,
    fft8::Fft8,
    fr8::{Fr8, LANES, multiplier},
};

const VECTORS_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL / LANES;
const BYTES_PER_VECTOR: usize = LANES * BYTES_PER_FIELD_ELEMENT;

pub struct InterpolationKernel {
    inverse: Fft8,
    /// Multipliers of h_c^(−i)/64 for column c, at c·8 + i/8, lane i % 8. Each
    /// is below r, so `mul` takes it with any normalised data.
    shift: Vec<Fr8>,
    /// Column c's weighted cells summed, reduced, laid out as `shift`, for the
    /// columns `used` marks.
    columns: Vec<Fr8>,
    used: Vec<bool>,
}

impl InterpolationKernel {
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn new(cosets: &Cosets) -> Self {
        let mut shift = Vec::with_capacity(CELLS_PER_EXT_BLOB * VECTORS_PER_CELL);
        let mut columns = Vec::with_capacity(CELLS_PER_EXT_BLOB * VECTORS_PER_CELL);
        let mut used = Vec::with_capacity(CELLS_PER_EXT_BLOB);
        let mut factors = [fr_from_u64(0); FIELD_ELEMENTS_PER_CELL];
        let mut c = 0;
        while c < CELLS_PER_EXT_BLOB {
            let mut factor = cosets.inverse_size;
            let mut i = 0;
            while i < FIELD_ELEMENTS_PER_CELL {
                factors[i] = multiplier(&factor);
                factor = fr_mul(&factor, &cosets.shift_inverse[c]);
                i += 1;
            }
            let mut v = 0;
            while v < VECTORS_PER_CELL {
                shift.push(Fr8::load(&factors, v * LANES));
                columns.push(Fr8::zero());
                v += 1;
            }
            used.push(false);
            c += 1;
        }
        Self {
            inverse: Fft8::new(&cosets.inverse_roots, FIELD_ELEMENTS_PER_CELL),
            shift,
            columns,
            used,
        }
    }

    /// True exactly when every element of `cells` is below r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn check(&self, cells: &[[u8; BYTES_PER_CELL]]) -> bool {
        let mut k = 0;
        while k < cells.len() && self.check_cell(&cells[k]) {
            k += 1;
        }
        k == cells.len()
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn check_cell(&self, cell: &[u8; BYTES_PER_CELL]) -> bool {
        let mut v = 0;
        while v < VECTORS_PER_CELL && Fr8::from_bytes(cell, v * BYTES_PER_VECTOR).1 == 0xff {
            v += 1;
        }
        v == VECTORS_PER_CELL
    }

    /// The coefficients of Σ_k powers[k]·I_k into `coefficients`, I_k the
    /// polynomial through cell k on the coset of column `cell_indices[k]`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn interpolate(
        &mut self,
        cells: &[[u8; BYTES_PER_CELL]],
        cell_indices: &[u64],
        powers: &[blst_fr],
        coefficients: &mut [blst_fr],
    ) {
        let mut c = 0;
        while c < CELLS_PER_EXT_BLOB {
            self.used[c] = false;
            c += 1;
        }
        let mut k = 0;
        while k < cells.len() {
            self.add_cell(&cells[k], cell_indices[k] as usize, &powers[k]);
            k += 1;
        }

        let mut sums = [Fr8::zero(); VECTORS_PER_CELL];
        c = 0;
        while c < CELLS_PER_EXT_BLOB {
            if self.used[c] {
                self.add_column(c, &mut sums);
            }
            c += 1;
        }
        store_canonical(&sums, coefficients);
    }

    /// Column `column`'s sum gains the cell's elements times `power`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add_cell(&mut self, cell: &[u8; BYTES_PER_CELL], column: usize, power: &blst_fr) {
        let weight = Fr8::splat(&multiplier(power));
        let first = !self.used[column];
        self.used[column] = true;
        let mut v = 0;
        while v < VECTORS_PER_CELL {
            let (element, _) = Fr8::from_bytes(cell, v * BYTES_PER_VECTOR);
            // lazy(2, 32): the element is normalised and the weight below r.
            let product = element.mul(&weight);
            let at = column * VECTORS_PER_CELL + v;
            self.columns[at] =
                if first { product.normalise() } else { self.columns[at].add(&product) };
            v += 1;
        }
    }

    /// `sums` gains column `column`'s coefficients times h_c^(−i)/64.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add_column(&mut self, column: usize, sums: &mut [Fr8; VECTORS_PER_CELL]) {
        let at = column * VECTORS_PER_CELL;
        // Reduced inputs give lazy(22, 172) outputs, below 2^260.
        self.inverse.dit(&mut self.columns[at..at + VECTORS_PER_CELL]);
        let mut v = 0;
        while v < VECTORS_PER_CELL {
            // lazy(2, 32): normalised below 22r times a multiplier below r.
            let scaled = self.columns[at + v].normalise().mul(&self.shift[at + v]);
            sums[v] = sums[v].add(&scaled);
            v += 1;
        }
    }
}

/// Every lane of the reduced `sums`, in order, as canonical blst elements.
#[target_feature(enable = "avx512f,avx512ifma")]
fn store_canonical(sums: &[Fr8; VECTORS_PER_CELL], out: &mut [blst_fr]) {
    let mut bytes = [0u8; BYTES_PER_CELL];
    let mut v = 0;
    while v < VECTORS_PER_CELL {
        sums[v].to_bytes(&mut bytes, v * BYTES_PER_VECTOR);
        v += 1;
    }
    let mut i = 0;
    while i < FIELD_ELEMENTS_PER_CELL {
        let mut element = [0u8; BYTES_PER_FIELD_ELEMENT];
        element.copy_from_slice(
            &bytes[i * BYTES_PER_FIELD_ELEMENT..(i + 1) * BYTES_PER_FIELD_ELEMENT],
        );
        out[i] = match fr_from_bytes(&element) {
            Some(value) => value,
            None => panic!("canonical elements decode"),
        };
        i += 1;
    }
}
