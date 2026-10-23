// The functions marked below follow the same formulas as Supranational's
// blst (Apache-2.0). This file is silver's own implementation.

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

    /// Karatsuba multiplication (Devegili et al., eprint 2006/471, §4): six
    /// Fp2 products.
    // Follows blst 0.3.16 fp12_tower.c `mul_fp6`.
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

    /// Karatsuba multiplication by x + y·v: five Fp2 products. A variant of
    /// Beuchat et al., eprint 2010/354, Algorithm 15, with c2·y in place of
    /// its (c1 + c2)·y − c1·y.
    // Follows blst 0.3.16 fp12_tower.c `mul_by_xy0_fp6`.
    pub fn mul_by_xy(&self, x: &Fp2, y: &Fp2) -> Self {
        let t0 = self.c0.mul(x);
        let t1 = self.c1.mul(y);
        let c0 = self.c2.mul(y).mul_by_xi().add(&t0);
        let c1 = self.c0.add(&self.c1).mul(&x.add(y)).sub(&t0).sub(&t1);
        let c2 = self.c2.mul(x).add(&t1);
        Self { c0, c1, c2 }
    }

    /// Times the monomial y·v: a scaling by y, then multiplication by v.
    /// Three Fp2 products.
    /// As Beuchat et al., eprint 2010/354, Algorithms 14 then 12.
    // Follows blst 0.3.16 fp12_tower.c `mul_by_0y0_fp6`.
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

    /// Inversion through the norm to Fp2: self⁻¹ = adj(self) / N(self).
    /// Three Fp2 squarings, nine products and one Fp2 inversion.
    /// Beuchat et al., eprint 2010/354, Algorithm 17, misprints steps 6 and 9.
    // Follows blst 0.3.16 fp12_tower.c `inverse_fp6`.
    pub fn inverse(&self) -> Self {
        let t0 = self.c0.square().sub(&self.c1.mul(&self.c2).mul_by_xi());
        let t1 = self.c2.square().mul_by_xi().sub(&self.c0.mul(&self.c1));
        let t2 = self.c1.square().sub(&self.c0.mul(&self.c2));
        let norm = self.c0.mul(&t0).add(&self.c2.mul(&t1).add(&self.c1.mul(&t2)).mul_by_xi());
        let inverse = norm.inverse();
        Self { c0: t0.mul(&inverse), c1: t1.mul(&inverse), c2: t2.mul(&inverse) }
    }
}
