//! Fp2 = Fp[i]/(i² + 1) over the scalar [`Fp`], blst's `blst_fp2`: c0 + c1·i.

use crate::portable::fp::Fp;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ZERO };

    /// Karatsuba: three products.
    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        let t0 = self.c0.mul(&rhs.c0);
        let t1 = self.c1.mul(&rhs.c1);
        let t2 = self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1));
        Self { c0: t0.sub(&t1), c1: t2.sub(&t0).sub(&t1) }
    }

    /// (c0 + c1)(c0 − c1) + 2·c0·c1·i: two products.
    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    pub fn square(&self) -> Self {
        let c0 = self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1));
        let c1 = self.c0.mul(&self.c1).double();
        Self { c0, c1 }
    }

    #[target_feature(enable = "bmi2,adx")]
    #[inline]
    pub fn mul_by_fp(&self, rhs: &Fp) -> Self {
        Self { c0: self.c0.mul(rhs), c1: self.c1.mul(rhs) }
    }

    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.add(&rhs.c0), c1: self.c1.add(&rhs.c1) }
    }

    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.sub(&rhs.c0), c1: self.c1.sub(&rhs.c1) }
    }

    #[inline(always)]
    pub fn double(&self) -> Self {
        Self { c0: self.c0.double(), c1: self.c1.double() }
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        Self { c0: self.c0.neg(), c1: self.c1.neg() }
    }

    #[inline(always)]
    pub fn conjugate(&self) -> Self {
        Self { c0: self.c0, c1: self.c1.neg() }
    }

    /// Times ξ = 1 + i: (c0 − c1) + (c0 + c1)·i.
    #[inline(always)]
    pub fn mul_by_xi(&self) -> Self {
        Self { c0: self.c0.sub(&self.c1), c1: self.c0.add(&self.c1) }
    }

    pub fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    /// conj / (c0² + c1²); 0 for 0.
    #[target_feature(enable = "bmi2,adx")]
    pub fn inverse(&self) -> Self {
        let norm_inverse = self.c0.square().add(&self.c1.square()).inverse();
        Self { c0: self.c0.mul(&norm_inverse), c1: self.c1.neg().mul(&norm_inverse) }
    }
}
