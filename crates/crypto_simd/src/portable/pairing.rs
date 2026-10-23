//! The pairing check of two pairs whose G2 points are fixed, from their
//! precomputed lines, on the scalar `Fp12`.

use crate::{
    bls::{
        constants::{Z_BITS, is_lower_z_bit},
        limbs::pack64,
        miller_lines::{LINE_COUNT, MillerLines},
    },
    portable::{fp::Fp, fp2::Fp2, fp12::Fp12, g1::G1},
};

/// `MillerLines` in blst's form: per step, per pair, l1 and l2. At P = (x, y)
/// a step's line is (1, l1·x, 0) + (0, l2·y, 0)·w.
pub struct PairingLines([[[Fp2; 2]; 2]; LINE_COUNT]);

impl PairingLines {
    /// From Fp8's form, R' = 2^416: the Montgomery product with 2^352 takes
    /// a·R' to a·R.
    pub fn new(lines: &MillerLines) -> Self {
        let r_prime_to_r = Fp([0, 0, 0, 0, 0, 1 << 32]);
        let mut out = [[[Fp2::ZERO; 2]; 2]; LINE_COUNT];
        let mut step = 0;
        while step < LINE_COUNT {
            let mut pair = 0;
            while pair < 2 {
                let mut l = 0;
                while l < 2 {
                    let lane = 4 * pair + 2 * l;
                    out[step][pair][l] = Fp2::new(
                        Fp(pack64(&lines.0[step][lane])).mul(&r_prime_to_r),
                        Fp(pack64(&lines.0[step][lane + 1])).mul(&r_prime_to_r),
                    );
                    l += 1;
                }
                pair += 1;
            }
            step += 1;
        }
        Self(out)
    }

    /// The spec's `pairingCheck` of the two pairs: whether
    /// e(P0, Q0)·e(P1, Q1) = 1.
    pub fn pairing_check(&self, points: &[G1; 2]) -> bool {
        self.miller_loop(points).final_exponentiation().is_one()
    }

    /// The product of both pairs' Miller values, conjugated since z < 0; a
    /// pair whose point is infinity is left out. At Jacobian (X, Y, Z), each
    /// line is scaled by Z³: (Z³, l1·XZ, 0) + (0, l2·Y, 0)·w.
    pub fn miller_loop(&self, points: &[G1; 2]) -> Fp12 {
        let mut factors = [[Fp::ZERO; 3]; 2];
        let mut k = 0;
        while k < 2 {
            let p = &points[k];
            factors[k] = [p.z.square().mul(&p.z), p.x.mul(&p.z), p.y];
            k += 1;
        }
        let present = [!points[0].is_infinity(), !points[1].is_infinity()];
        let mut f = Fp12::ONE;
        let mut step = 0;
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            if step > 0 {
                f = f.square();
            }
            f = self.times_lines(&f, step, &factors, &present);
            step += 1;
            if is_lower_z_bit(bit) {
                f = self.times_lines(&f, step, &factors, &present);
                step += 1;
            }
        }
        f.conjugate()
    }

    /// `f` times step `step`'s line at each present point, whose factors are
    /// [Z³, XZ, Y].
    #[inline]
    fn times_lines(
        &self,
        f: &Fp12,
        step: usize,
        factors: &[[Fp; 3]; 2],
        present: &[bool; 2],
    ) -> Fp12 {
        let mut f = *f;
        let mut k = 0;
        while k < 2 {
            if present[k] {
                let lines = &self.0[step][k];
                let x = Fp2 { c0: factors[k][0], c1: Fp::ZERO };
                f = f.mul_by_line(
                    &x,
                    &lines[0].mul_by_fp(&factors[k][1]),
                    &lines[1].mul_by_fp(&factors[k][2]),
                );
            }
            k += 1;
        }
        f
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests;
