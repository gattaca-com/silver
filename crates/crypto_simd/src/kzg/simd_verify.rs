//! `CellBatchVerifier` on AVX-512 IFMA: the same verdicts, with the scalar
//! side and the multi-scalar multiplications on vectors.

#[cfg(target_arch = "x86_64")]
pub use x86::SimdCellBatchVerifier;

#[cfg(not(target_arch = "x86_64"))]
pub struct SimdCellBatchVerifier;

#[cfg(not(target_arch = "x86_64"))]
impl SimdCellBatchVerifier {
    pub fn new() -> Option<Self> {
        None
    }

    pub fn verify(
        &mut self,
        _commitments: &[[u8; crate::bls::COMPRESSED_LEN]],
        _cell_indices: &[u64],
        _cells: &[[u8; crate::kzg::BYTES_PER_CELL]],
        _proofs: &[[u8; crate::bls::COMPRESSED_LEN]],
    ) -> bool {
        unreachable!("`new` is None without x86_64")
    }
}

#[cfg(target_arch = "x86_64")]
mod x86 {
    use blst::blst_fr;

    use crate::{
        bls::{COMPRESSED_LEN, blst_p1_affine, simd_available, uncompress_in_g1},
        kzg::{
            BYTES_PER_CELL, CELLS_PER_EXT_BLOB,
            blst_ops::{g1_add, g1_neg, g1_to_affine},
            challenge::Preimage,
            column_sums::ColumnSums,
            commitment_cache::CommitmentCache,
            cosets::Cosets,
            fr8_interpolation::Interpolation,
            fr8_scalars::CellScalars,
            msm8::{FixedBase8, Msm8},
            pairing_lines::PairingLines,
            setup::Setup,
            verify::Deduplicated,
        },
    };

    pub struct SimdCellBatchVerifier {
        fixed_base: FixedBase8,
        pairing_lines: PairingLines,
        commitments: Deduplicated,
        commitment_cache: CommitmentCache,
        decoded: Vec<Option<blst_p1_affine>>,
        commitment_points: Vec<blst_p1_affine>,
        proof_points: Vec<blst_p1_affine>,
        preimage: Preimage,
        cell_scalars: CellScalars,
        interpolation: Interpolation,
        column_sums: ColumnSums,
        msm: Msm8,
    }

    impl SimdCellBatchVerifier {
        /// None without AVX-512 IFMA and BW.
        pub fn new() -> Option<Self> {
            if !simd_available() || !is_x86_feature_detected!("avx512bw") {
                return None;
            }
            let setup = Setup::decode();
            let cosets = Cosets::new();
            Some(Self {
                fixed_base: FixedBase8::new(setup.g1_monomial.as_slice().try_into().unwrap()),
                pairing_lines: PairingLines::new(&setup.g2_s_pow_cell, &setup.g2_neg_generator),
                commitments: Deduplicated::default(),
                commitment_cache: CommitmentCache::default(),
                decoded: Vec::new(),
                commitment_points: Vec::new(),
                proof_points: Vec::new(),
                preimage: Preimage::new(),
                cell_scalars: CellScalars::new(&cosets),
                interpolation: Interpolation::new(&cosets),
                column_sums: ColumnSums::new(&cosets),
                msm: Msm8::new()?,
            })
        }

        /// True exactly when `CellBatchVerifier::verify` is.
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
            if cell_indices.iter().any(|&index| index >= CELLS_PER_EXT_BLOB as u64) {
                return false;
            }
            self.commitments.fill(commitments);
            if !self.commitment_cache.decode(&self.commitments.unique, &mut self.commitment_points) ||
                !decode_points(proofs, &mut self.decoded, &mut self.proof_points)
            {
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

        /// e(LL, [s^64])·e(RL, −[1]) = 1, with LL = Σ r^k·π_k and RL = RLC −
        /// RLI + RLP.
        fn pairing_holds(
            &mut self,
            r: &blst_fr,
            cell_indices: &[u64],
            cells: &[[u8; BYTES_PER_CELL]],
        ) -> bool {
            // SAFETY: `new` checked avx512f, avx512ifma and avx512bw.
            let rli_scalars = unsafe {
                self.cell_scalars.fill(
                    r,
                    cell_indices,
                    &self.commitments.index_of_cell,
                    self.commitments.unique.len(),
                );
                self.interpolation.scalars(cells, cell_indices, &self.cell_scalars)
            };
            let Some(rli_scalars) = rli_scalars else { return false };
            // SAFETY: `new` checked avx512f, avx512ifma and avx512bw.
            let rli = unsafe { self.fixed_base.mult(rli_scalars) };

            let grouped = self.column_sums.ll_and_rlp(
                &mut self.msm,
                cell_indices,
                &self.proof_points,
                self.cell_scalars.ll(),
            );
            let (ll, rlp) = grouped.unwrap_or_else(|| {
                (
                    self.msm.lincomb(&self.proof_points, self.cell_scalars.ll()),
                    self.msm.lincomb(&self.proof_points, self.cell_scalars.rlp()),
                )
            });
            let rlc = self.msm.lincomb(&self.commitment_points, self.cell_scalars.rlc());
            let rl = g1_add(&g1_add(&rlc, &g1_neg(&rli)), &rlp);
            self.pairing_lines.check(&g1_to_affine(&ll), &g1_to_affine(&rl))
        }
    }

    /// Decodes `encodings` into `points`; false if any is not a valid G1 point.
    fn decode_points(
        encodings: &[[u8; COMPRESSED_LEN]],
        decoded: &mut Vec<Option<blst_p1_affine>>,
        points: &mut Vec<blst_p1_affine>,
    ) -> bool {
        decoded.clear();
        decoded.resize(encodings.len(), None);
        uncompress_in_g1(encodings, decoded);
        points.clear();
        for point in decoded.iter() {
            match point {
                Some(point) => points.push(*point),
                None => return false,
            }
        }
        true
    }
}
