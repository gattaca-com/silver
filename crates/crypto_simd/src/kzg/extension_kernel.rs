//! `CellExtender`'s decoding, transforms and encoding on `Fr8` vectors. The
//! blob holds evaluations in bit-reversed order, the order the inverse
//! transform takes, and the forward transform leaves the extension's elements
//! in the order cells hold them, so no step permutes.

use blst::blst_fr;

use crate::kzg::{
    BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB,
    FIELD_ELEMENTS_PER_CELL, FR_ZERO,
    fft8::Fft8,
    fr::fr_mul,
    fr8::{Fr8, LANES, multiplier},
};

const VECTORS_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL / LANES;

pub struct ExtensionKernel {
    inverse: Fft8,
    forward: Fft8,
    /// Multipliers of `shift_powers[k]`/n. Each is below r, so `mul` takes it
    /// with any normalised data.
    shift: Vec<Fr8>,
    data: Vec<Fr8>,
}

impl ExtensionKernel {
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn new(
        roots: &[blst_fr],
        inverse_roots: &[blst_fr],
        shift_powers: &[blst_fr],
        inverse_size: &blst_fr,
    ) -> Self {
        let n = shift_powers.len();
        let mut shift = Vec::with_capacity(n / LANES);
        let mut data = Vec::with_capacity(n / LANES);
        let mut factors = [FR_ZERO; LANES];
        let mut v = 0;
        while v < n / LANES {
            let mut lane = 0;
            while lane < LANES {
                factors[lane] = multiplier(&fr_mul(&shift_powers[v * LANES + lane], inverse_size));
                lane += 1;
            }
            shift.push(Fr8::load(&factors, 0));
            data.push(Fr8::zero());
            v += 1;
        }
        Self { inverse: Fft8::new(inverse_roots, n), forward: Fft8::new(roots, n), shift, data }
    }

    /// False exactly when some element of `blob` is not below r.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn decode(&mut self, blob: &[u8; BYTES_PER_BLOB]) -> bool {
        assert!(BYTES_PER_BLOB == self.data.len() * LANES * BYTES_PER_FIELD_ELEMENT, "blob length");
        let mut valid = true;
        let mut v = 0;
        while v < self.data.len() {
            let (vector, below_r) = Fr8::from_bytes(blob, v * LANES * BYTES_PER_FIELD_ELEMENT);
            self.data[v] = vector;
            if below_r != 0xff {
                valid = false;
            }
            v += 1;
        }
        valid
    }

    /// The second half of the cells of the blob last decoded.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn extend(&mut self, cells: &mut [[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]) {
        self.inverse.dit(&mut self.data);
        let mut v = 0;
        while v < self.data.len() {
            self.data[v] = self.data[v].normalise().mul(&self.shift[v]);
            v += 1;
        }
        self.forward.dif(&mut self.data);
        v = 0;
        while v < self.data.len() {
            let cell = CELLS_PER_EXT_BLOB / 2 + v / VECTORS_PER_CELL;
            let at = v % VECTORS_PER_CELL * LANES * BYTES_PER_FIELD_ELEMENT;
            self.data[v].to_bytes(&mut cells[cell], at);
            v += 1;
        }
    }
}
