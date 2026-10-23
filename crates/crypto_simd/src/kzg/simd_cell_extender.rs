//! `CellExtender` on `Fr8`: the same bytes from an iterative inverse FFT, the
//! shift-and-scale by ω^k/4096, and a forward FFT, eight elements per vector.
//!
//! The blob's elements are the evaluations in bit-reversed order, so the
//! decimation-in-time inverse FFT reads them as they are and the
//! decimation-in-frequency forward FFT leaves its output bit-reversed, as the
//! cells want it: no permutation. Stages of length 2 to 8 pair elements within
//! a block of eight vectors, so they run on a transposed layout. The blob is
//! decoded in layout S and transposed before the first stage; the result is
//! transposed back before it is written.
//!
//! Layout S: element i at vector i/8, lane i%8. Layout T: element i at vector
//! (i/64)·8 + i%8, lane (i/8)%8. A block transpose switches between them.

#[cfg(target_arch = "x86_64")]
pub use x86::SimdCellExtender;

#[cfg(not(target_arch = "x86_64"))]
pub struct SimdCellExtender;

#[cfg(not(target_arch = "x86_64"))]
impl SimdCellExtender {
    pub fn new() -> Option<Self> {
        None
    }

    pub fn compute(
        &mut self,
        _blob: &[u8; crate::kzg::BYTES_PER_BLOB],
        _cells: &mut [[u8; crate::kzg::BYTES_PER_CELL]; crate::kzg::CELLS_PER_EXT_BLOB],
    ) -> bool {
        unreachable!("`new` is None without x86_64")
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use crate::{
        bls::simd_available,
        kzg::{
            BYTES_PER_BLOB, BYTES_PER_CELL, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_BLOB,
            blst_ops::{fr_from_u64, fr_inverse, fr_mul},
            domain::{inverse_roots, roots_of_unity},
            fr8::{Fr8Soa, LANES, LIMBS},
            fr8_bytes::BYTES_PER_VECTOR,
            fr8_fft::{
                BLOCK_VECTORS, FIRST_WIDE_STAGE, Stage, dif_last_stage_canonical,
                pointwise_multiply, soa_of, transpose_blocks, transpose_blocks_dit_first_stage,
                twiddles,
            },
        },
    };

    const LOG_BLOB: usize = 12;
    const VECTORS: usize = FIELD_ELEMENTS_PER_BLOB / LANES;

    pub struct SimdCellExtender {
        /// Inverse roots.
        dit: [Vec<Fr8Soa>; LOG_BLOB],
        dif: [Vec<Fr8Soa>; LOG_BLOB],
        /// ω^k / 4096 for ω of order 8192, k < 4096, in layout S.
        pointwise: Vec<Fr8Soa>,
        buf: Vec<Fr8Soa>,
    }

    impl SimdCellExtender {
        /// None without AVX-512 IFMA and BW.
        pub fn new() -> Option<Self> {
            if !simd_available() || !is_x86_feature_detected!("avx512bw") {
                return None;
            }
            let roots = roots_of_unity(LOG_BLOB as u32);
            let inverse_size = fr_inverse(&fr_from_u64(FIELD_ELEMENTS_PER_BLOB as u64));
            let shifts = roots_of_unity(LOG_BLOB as u32 + 1);
            let scaled: Vec<_> = shifts[..FIELD_ELEMENTS_PER_BLOB]
                .iter()
                .map(|shift| fr_mul(shift, &inverse_size))
                .collect();
            Some(Self {
                dit: twiddles(&inverse_roots(&roots)),
                dif: twiddles(&roots),
                pointwise: (0..VECTORS).map(|v| soa_of(|lane| &scaled[LANES * v + lane])).collect(),
                buf: vec![Fr8Soa([[0; LANES]; LIMBS]); VECTORS],
            })
        }

        /// False exactly when `CellExtender::compute` is: some element is not
        /// below r. `cells` is then unchanged.
        pub fn compute(
            &mut self,
            blob: &[u8; BYTES_PER_BLOB],
            cells: &mut [[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB],
        ) -> bool {
            // SAFETY: `new` checked avx512f, avx512ifma and avx512bw.
            if !unsafe { self.decode_blob(blob) } {
                return false;
            }
            for (k, cell) in cells[..CELLS_PER_EXT_BLOB / 2].iter_mut().enumerate() {
                cell.copy_from_slice(&blob[k * BYTES_PER_CELL..(k + 1) * BYTES_PER_CELL]);
            }
            // SAFETY: as above.
            unsafe {
                self.transform();
                self.write_extension(cells);
            }
            true
        }

        /// Into layout S, as limbs of the plain value: the first multiplication
        /// by a twiddle in R' form brings it into Montgomery form.
        #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
        unsafe fn decode_blob(&mut self, blob: &[u8; BYTES_PER_BLOB]) -> bool {
            let vectors = blob.as_chunks::<BYTES_PER_VECTOR>().0;
            self.buf.iter_mut().zip(vectors).all(|(vector, bytes)| vector.set_from_be_bytes(bytes))
        }

        #[target_feature(enable = "avx512f,avx512ifma,avx512bw")]
        unsafe fn write_extension(&self, cells: &mut [[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]) {
            let extension = cells[CELLS_PER_EXT_BLOB / 2..].as_flattened_mut();
            let vectors = extension.as_chunks_mut::<BYTES_PER_VECTOR>().0;
            for (vector, bytes) in self.buf.iter().zip(vectors) {
                vector.write_be_bytes(bytes);
            }
        }

        #[target_feature(enable = "avx512f,avx512ifma")]
        unsafe fn transform(&mut self) {
            let Self { dit, dif, pointwise, buf } = self;

            transpose_blocks_dit_first_stage(buf);
            for stage in 1..FIRST_WIDE_STAGE {
                Stage::new(1 << stage, BLOCK_VECTORS).dit(buf, &dit[stage]);
            }
            transpose_blocks(buf);
            for stage in FIRST_WIDE_STAGE..LOG_BLOB {
                Stage::new(1 << (stage - FIRST_WIDE_STAGE), VECTORS).dit(buf, &dit[stage]);
            }

            pointwise_multiply(buf, pointwise);

            for stage in (FIRST_WIDE_STAGE..LOG_BLOB).rev() {
                Stage::new(1 << (stage - FIRST_WIDE_STAGE), VECTORS).dif(buf, &dif[stage]);
            }
            transpose_blocks(buf);
            for stage in (1..FIRST_WIDE_STAGE).rev() {
                Stage::new(1 << stage, BLOCK_VECTORS).dif(buf, &dif[stage]);
            }
            for block in buf.chunks_exact_mut(BLOCK_VECTORS) {
                dif_last_stage_canonical(block);
            }
            transpose_blocks(buf);
        }
    }
}
