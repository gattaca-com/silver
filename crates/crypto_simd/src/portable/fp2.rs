//! Fp2 = Fp[i]/(i² + 1) over the scalar [`Fp`], blst's `blst_fp2`: c0 + c1·i.

#[cfg(target_arch = "x86_64")]
use crate::bmi2_available;
use crate::portable::fp::{Fp, Wide};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp2 {
    pub c0: Fp,
    pub c1: Fp,
}

impl Fp2 {
    pub const ZERO: Fp2 = Fp2 { c0: Fp::ZERO, c1: Fp::ZERO };

    // Aeneas mistranslates an Fp2 struct literal written into a nested array slot.
    pub const fn new(c0: Fp, c1: Fp) -> Self {
        Self { c0, c1 }
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        if bmi2_available() {
            // SAFETY: `bmi2_available` checked BMI2 on this CPU.
            return unsafe { self.mul_on_bmi2(rhs) };
        }
        self.mul_on_baseline(rhs)
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    pub fn mul(&self, rhs: &Self) -> Self {
        self.product(rhs)
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "bmi2")]
    fn mul_on_bmi2(&self, rhs: &Self) -> Self {
        self.product(rhs)
    }

    /// Out of line, so that `mul`'s callers do not inline this copy.
    #[cfg(target_arch = "x86_64")]
    #[inline(never)]
    fn mul_on_baseline(&self, rhs: &Self) -> Self {
        self.product(rhs)
    }

    /// Karatsuba on unreduced products, blst's `mul_mont_384x`: three
    /// products, two reductions. On unreduced sums, (a0 + a1)(b0 + b1) − a0·b0
    /// − a1·b1 is a0·b1 + a1·b0 exactly, below 2p².
    #[inline(always)]
    fn product(&self, rhs: &Self) -> Self {
        let t0 = Wide::product(&self.c0.0, &rhs.c0.0);
        let t1 = Wide::product(&self.c1.0, &rhs.c1.0);
        let t2 = Wide::product(&self.c0.unreduced_add(&self.c1), &rhs.c0.unreduced_add(&rhs.c1));
        Self { c0: t0.minus_mod(&t1).reduce(), c1: t2.minus(&t0).minus(&t1).reduce() }
    }

    /// (c0 + c1)(c0 − c1) + 2·c0·c1·i: two products.
    #[inline]
    pub fn square(&self) -> Self {
        let c0 = self.c0.add(&self.c1).mul(&self.c0.sub(&self.c1));
        let c1 = self.c0.mul(&self.c1).double();
        Self { c0, c1 }
    }

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

    /// conj / (c0² + c1²); 0 for 0.
    pub fn inverse(&self) -> Self {
        let norm_inverse = self.c0.square().add(&self.c1.square()).inverse();
        Self { c0: self.c0.mul(&norm_inverse), c1: self.c1.neg().mul(&norm_inverse) }
    }
}

#[cfg(test)]
mod tests;
