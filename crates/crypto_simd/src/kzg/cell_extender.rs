//! The cells of `computeCells`: the blob's polynomial evaluated on the 8192
//! bit-reversed roots of unity, 64 per cell. The first 4096 of those roots are
//! the blob's own domain in the same order, so cells 0–63 are the blob's bytes.
//! The rest is the coset ω·⟨ω²⟩ for ω of order 8192, in bit-reversed order:
//! an inverse FFT, coefficient k scaled by ω^k, then an FFT.

use blst::blst_fr;

use crate::kzg::{
    BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB,
    FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, FR_ZERO, INVERSE_BLOB_SIZE,
    blst_ops::{fr_from_bytes, fr_mul, fr_to_bytes},
    domain::{inverse_roots, reverse_bits, roots_of_unity},
    fft::{fft, inverse_fft},
};
#[cfg(target_arch = "x86_64")]
use crate::{kzg::extension_kernel::ExtensionKernel, simd_available};

const LOG_BLOB: u32 = 12;
const LOG_EXT_BLOB: u32 = 13;
const _: () = assert!(1 << LOG_BLOB == FIELD_ELEMENTS_PER_BLOB);
const _: () = assert!(1 << LOG_EXT_BLOB == FIELD_ELEMENTS_PER_CELL * CELLS_PER_EXT_BLOB);

pub struct CellExtender {
    roots: Vec<blst_fr>,
    inverse_roots: Vec<blst_fr>,
    inverse_size: blst_fr,
    /// ω^k for k < 4096, ω of order 8192.
    shift_powers: Vec<blst_fr>,
    evaluations: Vec<blst_fr>,
    coefficients: Vec<blst_fr>,
    #[cfg(target_arch = "x86_64")]
    kernel: Option<ExtensionKernel>,
}

impl Default for CellExtender {
    fn default() -> Self {
        Self::new()
    }
}

impl CellExtender {
    pub fn new() -> Self {
        let roots = roots_of_unity(LOG_BLOB);
        let mut shift_powers = roots_of_unity(LOG_EXT_BLOB);
        shift_powers.resize(FIELD_ELEMENTS_PER_BLOB, FR_ZERO);
        let mut evaluations = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
        evaluations.resize(FIELD_ELEMENTS_PER_BLOB, FR_ZERO);
        let mut coefficients = Vec::with_capacity(FIELD_ELEMENTS_PER_BLOB);
        coefficients.resize(FIELD_ELEMENTS_PER_BLOB, FR_ZERO);
        let inverse_roots = inverse_roots(&roots);
        #[cfg(target_arch = "x86_64")]
        let kernel = if simd_available() {
            // SAFETY: `simd_available` confirmed avx512f and avx512ifma on this CPU.
            Some(unsafe {
                ExtensionKernel::new(&roots, &inverse_roots, &shift_powers, &INVERSE_BLOB_SIZE)
            })
        } else {
            None
        };
        Self {
            roots,
            inverse_roots,
            inverse_size: INVERSE_BLOB_SIZE,
            shift_powers,
            evaluations,
            coefficients,
            #[cfg(target_arch = "x86_64")]
            kernel,
        }
    }

    #[cfg(test)]
    pub(crate) fn without_kernel() -> Self {
        Self {
            #[cfg(target_arch = "x86_64")]
            kernel: None,
            ..Self::new()
        }
    }

    /// False exactly when the spec's `computeCells` rejects `blob`: some
    /// element is not below r. `cells` is then unchanged.
    pub fn compute(
        &mut self,
        blob: &[u8; BYTES_PER_BLOB],
        cells: &mut [[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB],
    ) -> bool {
        #[cfg(target_arch = "x86_64")]
        if let Some(kernel) = &mut self.kernel {
            // SAFETY: `kernel` is built only where `simd_available` held.
            if !unsafe { kernel.decode(blob) } {
                return false;
            }
            copy_blob(blob, cells);
            // SAFETY: as above.
            unsafe { kernel.extend(cells) };
            return true;
        }

        if !self.decode_blob(blob) {
            return false;
        }
        copy_blob(blob, cells);
        inverse_fft(
            &mut self.coefficients,
            &self.evaluations,
            &self.inverse_roots,
            &self.inverse_size,
        );
        for k in 0..FIELD_ELEMENTS_PER_BLOB {
            self.coefficients[k] = fr_mul(&self.coefficients[k], &self.shift_powers[k]);
        }
        fft(&mut self.evaluations, &self.coefficients, &self.roots);
        self.write_extension(cells);
        true
    }

    /// Element i of the blob is the evaluation at root `reverse_bits(i)`;
    /// `evaluations` holds them in natural order.
    fn decode_blob(&mut self, blob: &[u8; BYTES_PER_BLOB]) -> bool {
        let mut i = 0;
        while i < FIELD_ELEMENTS_PER_BLOB {
            let mut bytes = [0u8; BYTES_PER_FIELD_ELEMENT];
            bytes.copy_from_slice(
                &blob[i * BYTES_PER_FIELD_ELEMENT..(i + 1) * BYTES_PER_FIELD_ELEMENT],
            );
            match fr_from_bytes(&bytes) {
                Some(value) => self.evaluations[reverse_bits(i, LOG_BLOB)] = value,
                None => break,
            }
            i += 1;
        }
        i == FIELD_ELEMENTS_PER_BLOB
    }

    fn write_extension(&self, cells: &mut [[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]) {
        for j in 0..FIELD_ELEMENTS_PER_BLOB {
            let bytes = fr_to_bytes(&self.evaluations[reverse_bits(j, LOG_BLOB)]);
            let cell = CELLS_PER_EXT_BLOB / 2 + j / FIELD_ELEMENTS_PER_CELL;
            let at = j % FIELD_ELEMENTS_PER_CELL * BYTES_PER_FIELD_ELEMENT;
            cells[cell][at..at + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&bytes);
        }
    }
}

/// The first half of the cells are the blob's bytes.
fn copy_blob(blob: &[u8; BYTES_PER_BLOB], cells: &mut [[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]) {
    for k in 0..CELLS_PER_EXT_BLOB / 2 {
        cells[k].copy_from_slice(&blob[k * BYTES_PER_CELL..(k + 1) * BYTES_PER_CELL]);
    }
}
