//! The Miller loop of two pairs whose G2 points are fixed, from their
//! precomputed lines and the G1 points in lanes 0 and 1 of a `G1x8`.

use std::arch::x86_64::__mmask8;

use crate::bls::{
    constants::Z_BITS,
    fp2x8::Fp2x8,
    fp8::{Fp8, LANES, Limbs},
    fp12::Fp12,
    g1x8::{G1x8, is_lower_z_bit},
};

/// A doubling per bit of |z| below the top one, 63, and an addition per
/// lower set bit, 5.
pub const LINE_COUNT: usize = 68;

/// Pair k's line (Z³, l1·XZ, l2·Y) in lanes 0 to 2: c0 takes Z³ from lane k
/// of the cubes, then the products' c0 lanes; c1 takes 0, then their c1
/// lanes.
const LINE_C0: [[i64; LANES]; 2] = [[0, 8, 10, 0, 0, 0, 0, 0], [1, 12, 14, 1, 1, 1, 1, 1]];
const LINE_C1: [[i64; LANES]; 2] = [[0, 9, 11, 0, 0, 0, 0, 0], [0, 13, 15, 0, 0, 0, 0, 0]];

/// The Miller loop's lines for two G2 points, a step per doubling or
/// addition in the loop's order. Lanes 0 to 3 hold l1.c0, l1.c1, l2.c0 and
/// l2.c1 for the first point, lanes 4 to 7 for the second, in Fp8's
/// Montgomery form, below p. At P = (x, y) a step's line is
/// (1, l1·x, 0) + (0, l2·y, 0)·w: the spec's line, times a factor in Fp4
/// that the final exponentiation removes.
pub struct MillerLines(pub [[Limbs; LANES]; LINE_COUNT]);

impl MillerLines {
    /// The product of both pairs' Miller values, conjugated since z < 0,
    /// for the G1 points in lanes 0 and 1; a pair whose point is infinity
    /// is left out. At Jacobian (X, Y, Z), each line is scaled by Z³:
    /// (Z³, l1·XZ, 0) + (0, l2·Y, 0)·w.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn miller_loop(&self, points: &G1x8) -> Fp12 {
        let present = !points.z.is_zero_mask();
        // [XZ, XZ, Y, Y] for each pair, against l1's and l2's components.
        let factors = points.x.mul(&points.z).permute2(&points.y, &[0, 0, 8, 8, 1, 1, 9, 9]);
        let z_cubed = points.z.square().mul(&points.z);
        let mut f = Fp12::one();
        let mut step = 0;
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            if step > 0 {
                f = f.square();
            }
            f = self.times_lines(&f, step, &factors, &z_cubed, present);
            step += 1;
            if is_lower_z_bit(bit) {
                f = self.times_lines(&f, step, &factors, &z_cubed, present);
                step += 1;
            }
        }
        f.conjugate()
    }

    /// `f` times step `step`'s line at each present point.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn times_lines(
        &self,
        f: &Fp12,
        step: usize,
        factors: &Fp8,
        z_cubed: &Fp8,
        present: __mmask8,
    ) -> Fp12 {
        let products = Fp8::load(&self.0[step]).mul(factors);
        let mut f = *f;
        if present & 1 != 0 {
            f = f.mul_by_line(&line(&products, z_cubed, 0));
        }
        if present & 2 != 0 {
            f = f.mul_by_line(&line(&products, z_cubed, 1));
        }
        f
    }
}

/// Pair `pair`'s line in lanes 0 to 2, from both pairs' products
/// [l1·XZ, l2·Y] and cubes Z³.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn line(products: &Fp8, z_cubed: &Fp8, pair: usize) -> Fp2x8 {
    Fp2x8 {
        c0: z_cubed.permute2(products, &LINE_C0[pair]),
        c1: Fp8::zero().permute2(products, &LINE_C1[pair]),
    }
}

#[cfg(test)]
mod tests;
