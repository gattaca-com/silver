// The functions marked below follow the same formulas as Supranational's
// blst (Apache-2.0). This file is silver's own implementation.

//! Fp12 = Fp6[w]/(w² − v) over the scalar [`Fp`], blst's `blst_fp12`:
//! c0 + c1·w. The Fp2 coefficient k of half h, `c[h].c[k]`, is the
//! coefficient of w^(2k + h).

use crate::{
    bls::constants::{Z_BITS, is_lower_z_bit},
    portable::{
        constants::{FROBENIUS, ONE},
        fp::Fp,
        fp2::Fp2,
        fp6::Fp6,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp12 {
    pub c0: Fp6,
    pub c1: Fp6,
}

impl Fp12 {
    pub const ONE: Fp12 = Fp12 {
        c0: Fp6 { c0: Fp2 { c0: ONE, c1: Fp::ZERO }, c1: Fp2::ZERO, c2: Fp2::ZERO },
        c1: Fp6::ZERO,
    };

    /// Karatsuba over the halves: three Fp6 products.
    // Follows blst 0.3.16 fp12_tower.c `mul_fp12`.
    pub fn mul(&self, rhs: &Self) -> Self {
        let t0 = self.c0.mul(&rhs.c0);
        let t1 = self.c1.mul(&rhs.c1);
        let c1 = self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1)).sub(&t0).sub(&t1);
        Self { c0: t0.add(&t1.mul_by_v()), c1 }
    }

    /// (a + b·w)² = (a + b)(a + v·b) − t − v·t + 2t·w, t = a·b: two Fp6
    /// products.
    // Follows blst 0.3.16 fp12_tower.c `sqr_fp12`.
    pub fn square(&self) -> Self {
        let t = self.c0.mul(&self.c1);
        let c0 =
            self.c0.add(&self.c1).mul(&self.c0.add(&self.c1.mul_by_v())).sub(&t).sub(&t.mul_by_v());
        Self { c0, c1: t.double() }
    }

    /// Times the line (x + y·v) + z·v·w, blst's `mul_by_xy00z0`: 13 Fp2
    /// products.
    // Follows blst 0.3.16 fp12_tower.c `mul_by_xy00z0_fp12`.
    pub fn mul_by_line(&self, x: &Fp2, y: &Fp2, z: &Fp2) -> Self {
        let t0 = self.c0.mul_by_xy(x, y);
        let t1 = self.c1.mul_by_y(z);
        let c1 = self.c0.add(&self.c1).mul_by_xy(x, &y.add(z)).sub(&t0).sub(&t1);
        Self { c0: t0.add(&t1.mul_by_v()), c1 }
    }

    /// Granger–Scott, on the cyclotomic subgroup: nine Fp2 squarings, as
    /// blst's `cyclotomic_sqr_fp12`. Off the subgroup it computes the same
    /// formula.
    // Follows blst 0.3.16 fp12_tower.c `cyclotomic_sqr_fp12`.
    pub fn cyclotomic_square(&self) -> Self {
        let (t00, t01) = fp4_square(&self.c0.c0, &self.c1.c1);
        let (t10, t11) = fp4_square(&self.c1.c0, &self.c0.c2);
        let (t20, t21) = fp4_square(&self.c0.c1, &self.c1.c2);
        Self {
            c0: Fp6 {
                c0: thrice_less_twice(&t00, &self.c0.c0),
                c1: thrice_less_twice(&t10, &self.c0.c1),
                c2: thrice_less_twice(&t20, &self.c0.c2),
            },
            c1: Fp6 {
                c0: thrice_plus_twice(&t21.mul_by_xi(), &self.c1.c0),
                c1: thrice_plus_twice(&t01, &self.c1.c1),
                c2: thrice_plus_twice(&t11, &self.c1.c2),
            },
        }
    }

    pub fn conjugate(&self) -> Self {
        Self { c0: self.c0, c1: self.c1.neg() }
    }

    /// The p-power Frobenius map: the coefficient of w^j conjugated, times
    /// ξ^(j(p − 1)/6).
    pub fn frobenius(&self) -> Self {
        Self {
            c0: Fp6 {
                c0: frobenius_coefficient(&self.c0.c0, 0),
                c1: frobenius_coefficient(&self.c0.c1, 2),
                c2: frobenius_coefficient(&self.c0.c2, 4),
            },
            c1: Fp6 {
                c0: frobenius_coefficient(&self.c1.c0, 1),
                c1: frobenius_coefficient(&self.c1.c1, 3),
                c2: frobenius_coefficient(&self.c1.c2, 5),
            },
        }
    }

    /// (a − b·w) / (a² − v·b²).
    // Follows blst 0.3.16 fp12_tower.c `inverse_fp12`.
    pub fn inverse(&self) -> Self {
        let norm = self.c0.mul(&self.c0).sub(&self.c1.mul(&self.c1).mul_by_v());
        let inverse = norm.inverse();
        Self { c0: self.c0.mul(&inverse), c1: self.c1.mul(&inverse).neg() }
    }

    /// f^(3·(p¹² − 1)/r), the chain of `bls::fp12::Fp12::final_exponentiation`.
    pub fn final_exponentiation(&self) -> Self {
        let t0 = self.conjugate();
        let t1 = self.inverse();
        let t2 = t0.mul(&t1);
        let t1 = t2;
        let t2 = t2.frobenius().frobenius().mul(&t1);

        let t1 = t2.cyclotomic_square().conjugate();
        let t3 = t2.cyclotomic_exp();
        let t4 = t3.cyclotomic_square();
        let t5 = t1.mul(&t3);
        let t1 = t5.cyclotomic_exp();
        let t0 = t1.cyclotomic_exp();
        let t6 = t0.cyclotomic_exp().mul(&t4);
        let t4 = t6.cyclotomic_exp();
        let t5 = t5.conjugate();
        let t4 = t4.mul(&t5.mul(&t2));
        let t5 = t2.conjugate();
        let t1 = t1.mul(&t2).frobenius().frobenius().frobenius();
        let t6 = t6.mul(&t5).frobenius();
        let t3 = t3.mul(&t0).frobenius().frobenius();
        t3.mul(&t1).mul(&t6).mul(&t4)
    }

    /// f^z on the cyclotomic subgroup, where the inverse is the conjugate.
    fn cyclotomic_exp(&self) -> Self {
        let mut r = *self;
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            r = r.cyclotomic_square();
            if is_lower_z_bit(bit) {
                r = r.mul(self);
            }
        }
        r.conjugate()
    }

    pub fn is_one(&self) -> bool {
        *self == Self::ONE
    }
}

/// (a0 + a1·w')² in Fp4 = Fp2[w']/(w'² − ξ): (a0² + ξ·a1², 2·a0·a1).
// Follows blst 0.3.16 fp12_tower.c `sqr_fp4`.
#[inline]
fn fp4_square(a0: &Fp2, a1: &Fp2) -> (Fp2, Fp2) {
    let s0 = a0.square();
    let s1 = a1.square();
    let cross = a0.add(a1).square().sub(&s0).sub(&s1);
    (s0.add(&s1.mul_by_xi()), cross)
}

/// 3t − 2a.
// Follows blst 0.3.16 fp12_tower.c `cyclotomic_sqr_fp12`.
#[inline(always)]
fn thrice_less_twice(t: &Fp2, a: &Fp2) -> Fp2 {
    t.sub(a).double().add(t)
}

/// 3t + 2a.
// Follows blst 0.3.16 fp12_tower.c `cyclotomic_sqr_fp12`.
#[inline(always)]
fn thrice_plus_twice(t: &Fp2, a: &Fp2) -> Fp2 {
    t.add(a).double().add(t)
}

#[inline]
fn frobenius_coefficient(c: &Fp2, power: usize) -> Fp2 {
    let gamma = Fp2 { c0: FROBENIUS[power][0], c1: FROBENIUS[power][1] };
    c.conjugate().mul(&gamma)
}

#[cfg(all(test, target_arch = "x86_64"))]
pub(crate) mod tests;
