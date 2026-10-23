//! LL and RLP of a batch that spans few columns, from one sum per column:
//! S_c = Σ_(k in column c) r^k·π_k, LL = Σ_c S_c and RLP = Σ_c h_c^64·S_c. Two
//! multi-scalar multiplications over all cells become one, and one
//! multiplication by a 255-bit scalar per column.

use blst::blst_p1;

use crate::{
    bls::blst_p1_affine,
    kzg::{
        CELLS_PER_EXT_BLOB,
        blst_msm::{g1_mult, scalar_bytes},
        blst_ops::g1_add,
        cosets::Cosets,
        msm8::Msm8,
    },
};

/// Past this many columns the multiplications by h_c^64 cost more than the
/// second multi-scalar multiplication.
const MAX_COLUMNS: u32 = 4;

pub struct ColumnSums {
    shift_pow_cell: Vec<[u8; 32]>,
    points: Vec<blst_p1_affine>,
    scalars: Vec<[u8; 32]>,
}

impl ColumnSums {
    pub fn new(cosets: &Cosets) -> Self {
        Self {
            shift_pow_cell: cosets.shift_pow_cell.iter().map(scalar_bytes).collect(),
            points: Vec::new(),
            scalars: Vec::new(),
        }
    }

    /// (LL, RLP) for cell k with proof `proofs[k]`, power r^k as `powers[k]`,
    /// in column `cell_indices[k]`; None when the cells span more than
    /// `MAX_COLUMNS` columns.
    pub fn ll_and_rlp(
        &mut self,
        msm: &mut Msm8,
        cell_indices: &[u64],
        proofs: &[blst_p1_affine],
        powers: &[[u8; 32]],
    ) -> Option<(blst_p1, blst_p1)> {
        const _: () = assert!(CELLS_PER_EXT_BLOB <= u128::BITS as usize);
        let columns = cell_indices.iter().fold(0u128, |columns, &c| columns | 1 << c);
        if columns.count_ones() > MAX_COLUMNS {
            return None;
        }

        let (mut ll, mut rlp) = (blst_p1::default(), blst_p1::default());
        for column in (0..CELLS_PER_EXT_BLOB).filter(|&c| columns >> c & 1 == 1) {
            let sum = if columns.count_ones() == 1 {
                msm.lincomb(proofs, powers)
            } else {
                self.points.clear();
                self.scalars.clear();
                for k in (0..cell_indices.len()).filter(|&k| cell_indices[k] as usize == column) {
                    self.points.push(proofs[k]);
                    self.scalars.push(powers[k]);
                }
                msm.lincomb(&self.points, &self.scalars)
            };
            ll = g1_add(&ll, &sum);
            rlp = g1_add(&rlp, &g1_mult(&sum, &self.shift_pow_cell[column]));
        }
        Some((ll, rlp))
    }
}

#[cfg(test)]
mod tests {
    use blst::{blst_fr, blst_p1_affine_generator, blst_p1_from_affine};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::kzg::blst_ops::{fr_from_bytes, fr_mul, g1_to_affine};

    fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
        loop {
            let mut bytes: [u8; 32] = rng.r#gen();
            bytes[0] &= 0x7f;
            if let Some(fr) = fr_from_bytes(&bytes) {
                return fr;
            }
        }
    }

    fn random_points(rng: &mut ChaCha8Rng, count: usize) -> Vec<blst_p1_affine> {
        (0..count)
            .map(|_| {
                let mut base = blst_p1::default();
                // SAFETY: blst returns a pointer to its static generator.
                unsafe { blst_p1_from_affine(&mut base, blst_p1_affine_generator()) };
                g1_to_affine(&g1_mult(&base, &scalar_bytes(&random_fr(rng))))
            })
            .collect()
    }

    #[test]
    fn sums_match_the_full_multiplications() {
        let Some(mut msm) = Msm8::new() else { return };
        let cosets = Cosets::new();
        let mut sums = ColumnSums::new(&cosets);
        let mut rng = ChaCha8Rng::seed_from_u64(0xc01_5005);
        for (cells, columns) in [(1, 1), (18, 1), (40, 2), (60, 3), (144, 4), (70, 5), (100, 20)] {
            let proofs = random_points(&mut rng, cells);
            let frs: Vec<_> = (0..cells).map(|_| random_fr(&mut rng)).collect();
            let chosen: Vec<u64> = (0..columns).map(|_| rng.gen_range(0..128)).collect();
            let cell_indices: Vec<u64> = (0..cells).map(|k| chosen[k % chosen.len()]).collect();
            let powers: Vec<_> = frs.iter().map(scalar_bytes).collect();
            let shifted: Vec<_> = (0..cells)
                .map(|k| {
                    scalar_bytes(&fr_mul(&frs[k], &cosets.shift_pow_cell[cell_indices[k] as usize]))
                })
                .collect();

            let got = sums.ll_and_rlp(&mut msm, &cell_indices, &proofs, &powers);
            let distinct = {
                let mut columns = cell_indices.clone();
                columns.sort();
                columns.dedup();
                columns.len()
            };
            if distinct > MAX_COLUMNS as usize {
                assert!(got.is_none(), "{distinct} columns");
                continue;
            }
            let (ll, rlp) = got.expect("few columns");
            assert!(g1_to_affine(&ll) == g1_to_affine(&msm.lincomb(&proofs, &powers)));
            assert!(g1_to_affine(&rlp) == g1_to_affine(&msm.lincomb(&proofs, &shifted)));
        }
    }
}
