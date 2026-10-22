//! Fp6 = Fp2[v]/(v³ − ξ), ξ = 1 + i, blst's `blst_fp6`: c0 + c1·v + c2·v².

use crate::portable::fp2::Fp2;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp6 {
    pub c0: Fp2,
    pub c1: Fp2,
    pub c2: Fp2,
}

impl Fp6 {
    pub const ZERO: Fp6 = Fp6 { c0: Fp2::ZERO, c1: Fp2::ZERO, c2: Fp2::ZERO };

    /// Karatsuba over the three coefficients: six Fp2 products.
    #[target_feature(enable = "bmi2,adx")]
    pub fn mul(&self, rhs: &Self) -> Self {
        let t0 = self.c0.mul(&rhs.c0);
        let t1 = self.c1.mul(&rhs.c1);
        let t2 = self.c2.mul(&rhs.c2);
        let c0 =
            self.c1.add(&self.c2).mul(&rhs.c1.add(&rhs.c2)).sub(&t1).sub(&t2).mul_by_xi().add(&t0);
        let c1 =
            self.c0.add(&self.c1).mul(&rhs.c0.add(&rhs.c1)).sub(&t0).sub(&t1).add(&t2.mul_by_xi());
        let c2 = self.c0.add(&self.c2).mul(&rhs.c0.add(&rhs.c2)).sub(&t0).sub(&t2).add(&t1);
        Self { c0, c1, c2 }
    }

    /// Times x + y·v, blst's `mul_by_xy0`: five Fp2 products.
    #[target_feature(enable = "bmi2,adx")]
    pub fn mul_by_xy(&self, x: &Fp2, y: &Fp2) -> Self {
        let t0 = self.c0.mul(x);
        let t1 = self.c1.mul(y);
        let c0 = self.c2.mul(y).mul_by_xi().add(&t0);
        let c1 = self.c0.add(&self.c1).mul(&x.add(y)).sub(&t0).sub(&t1);
        let c2 = self.c2.mul(x).add(&t1);
        Self { c0, c1, c2 }
    }

    /// Times y·v, blst's `mul_by_0y0`: three Fp2 products.
    #[target_feature(enable = "bmi2,adx")]
    pub fn mul_by_y(&self, y: &Fp2) -> Self {
        Self { c0: self.c2.mul(y).mul_by_xi(), c1: self.c0.mul(y), c2: self.c1.mul(y) }
    }

    /// Times v: ξ·c2 + c0·v + c1·v².
    #[inline(always)]
    pub fn mul_by_v(&self) -> Self {
        Self { c0: self.c2.mul_by_xi(), c1: self.c0, c2: self.c1 }
    }

    #[inline(always)]
    pub fn add(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.add(&rhs.c0), c1: self.c1.add(&rhs.c1), c2: self.c2.add(&rhs.c2) }
    }

    #[inline(always)]
    pub fn sub(&self, rhs: &Self) -> Self {
        Self { c0: self.c0.sub(&rhs.c0), c1: self.c1.sub(&rhs.c1), c2: self.c2.sub(&rhs.c2) }
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        Self { c0: self.c0.neg(), c1: self.c1.neg(), c2: self.c2.neg() }
    }

    #[inline(always)]
    pub fn double(&self) -> Self {
        Self { c0: self.c0.double(), c1: self.c1.double(), c2: self.c2.double() }
    }

    /// From the norm to Fp2: t = (c0² − ξc1c2, ξc2² − c0c1, c1² − c0c2) and
    /// self⁻¹ = t / (c0·t0 + ξ(c2·t1 + c1·t2)).
    #[target_feature(enable = "bmi2,adx")]
    pub fn inverse(&self) -> Self {
        let t0 = self.c0.square().sub(&self.c1.mul(&self.c2).mul_by_xi());
        let t1 = self.c2.square().mul_by_xi().sub(&self.c0.mul(&self.c1));
        let t2 = self.c1.square().sub(&self.c0.mul(&self.c2));
        let determinant =
            self.c0.mul(&t0).add(&self.c2.mul(&t1).add(&self.c1.mul(&t2)).mul_by_xi());
        let inverse = determinant.inverse();
        Self { c0: t0.mul(&inverse), c1: t1.mul(&inverse), c2: t2.mul(&inverse) }
    }
}
