//! Per-cell constants. Cell k holds evaluations on the coset h_k·⟨ω64⟩, in
//! bit-reversed order of the powers of ω64, where h_k is entry 64·k of the
//! bit-reversed 8192nd roots of unity.

use blst::blst_fr;

use crate::kzg::{
    CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL, INVERSE_CELL_SIZE,
    domain::{inverse_roots, reverse_bits, roots_of_unity},
    fr::fr_mul,
};

const LOG_CELL: u32 = 6;
const LOG_EXT_BLOB: u32 = 13;
const _: () = assert!(1 << LOG_CELL == FIELD_ELEMENTS_PER_CELL);
const _: () = assert!(1 << LOG_EXT_BLOB == FIELD_ELEMENTS_PER_CELL * CELLS_PER_EXT_BLOB);

pub struct Cosets {
    /// Powers of ω64⁻¹, for the inverse FFT of one cell.
    pub inverse_roots: Vec<blst_fr>,
    /// 1/64.
    pub inverse_size: blst_fr,
    /// h_k⁻¹ for each cell index k.
    pub shift_inverse: Vec<blst_fr>,
    /// h_k^64 for each cell index k.
    pub shift_pow_cell: Vec<blst_fr>,
}

impl Cosets {
    pub fn new() -> Self {
        let ext_roots = roots_of_unity(LOG_EXT_BLOB);
        let inverse_ext_roots = inverse_roots(&ext_roots);
        let mut shift_inverse = Vec::with_capacity(CELLS_PER_EXT_BLOB);
        let mut shift_pow_cell = Vec::with_capacity(CELLS_PER_EXT_BLOB);
        for k in 0..CELLS_PER_EXT_BLOB {
            let exponent = reverse_bits(FIELD_ELEMENTS_PER_CELL * k, LOG_EXT_BLOB);
            shift_inverse.push(inverse_ext_roots[exponent]);
            let mut power = ext_roots[exponent];
            for _ in 0..LOG_CELL {
                power = fr_mul(&power, &power);
            }
            shift_pow_cell.push(power);
        }
        Self {
            inverse_roots: inverse_roots(&roots_of_unity(LOG_CELL)),
            inverse_size: INVERSE_CELL_SIZE,
            shift_inverse,
            shift_pow_cell,
        }
    }
}
