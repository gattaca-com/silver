//! G1 points in Jacobian coordinates over the scalar [`Fp`], z = 0 at
//! infinity.
//!
//! The formulas are the a = 0 ones from the EFD: dbl-2009-l, madd-2007-bl and
//! add-2007-bl. Doubling is complete as it is: y = 0 or z = 0 gives z = 0.
//! The additions assume distinct, finite summands; their `_complete` forms
//! branch to the spec's `G1.add` for every input.

use blst::{blst_fp, blst_p1};

use crate::{
    bls::{constants::Z_BITS, g1x8::is_lower_z_bit},
    portable::{
        constants::{BETA, ONE},
        fp::Fp,
    },
};

#[derive(Clone, Copy, Debug)]
pub struct G1 {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

impl G1 {
    pub const INFINITY: G1 = G1 { x: ONE, y: ONE, z: Fp::ZERO };

    pub fn from_affine(x: &Fp, y: &Fp) -> Self {
        Self { x: *x, y: *y, z: ONE }
    }

    /// blst's Jacobian coordinates are these, z = 0 at infinity too.
    pub fn from_blst(p: &blst_p1) -> Self {
        Self { x: Fp(p.x.l), y: Fp(p.y.l), z: Fp(p.z.l) }
    }

    pub fn to_blst(&self) -> blst_p1 {
        blst_p1 {
            x: blst_fp { l: self.x.0 },
            y: blst_fp { l: self.y.0 },
            z: blst_fp { l: self.z.0 },
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// dbl-2009-l.
    #[target_feature(enable = "bmi2,adx")]
    pub fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.add(&b).square().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let x3 = e.square().sub(&d.double());
        let y3 = e.mul(&d.sub(&x3)).sub(&c.double().double().double());
        let z3 = self.y.mul(&self.z).double();
        Self { x: x3, y: y3, z: z3 }
    }

    /// madd-2007-bl, for a finite self and x ≠ qx.
    #[target_feature(enable = "bmi2,adx")]
    pub fn add_affine(&self, qx: &Fp, qy: &Fp) -> Self {
        MixedTerms::new(self, qx, qy).sum(self)
    }

    /// add-2007-bl, for finite summands with distinct x.
    #[target_feature(enable = "bmi2,adx")]
    pub fn add(&self, q: &Self) -> Self {
        Terms::new(self, q).sum(self, q)
    }

    /// The spec's `G1.add` of self and the affine point (qx, qy).
    #[target_feature(enable = "bmi2,adx")]
    pub fn add_affine_complete(&self, qx: &Fp, qy: &Fp) -> Self {
        if self.is_infinity() {
            return Self::from_affine(qx, qy);
        }
        let terms = MixedTerms::new(self, qx, qy);
        if !terms.h.is_zero() {
            terms.sum(self)
        } else if terms.r.is_zero() {
            self.double()
        } else {
            Self::INFINITY
        }
    }

    /// The spec's `G1.add`.
    #[target_feature(enable = "bmi2,adx")]
    pub fn add_complete(&self, q: &Self) -> Self {
        if self.is_infinity() {
            return *q;
        }
        if q.is_infinity() {
            return *self;
        }
        let terms = Terms::new(self, q);
        if !terms.h.is_zero() {
            terms.sum(self, q)
        } else if terms.r.is_zero() {
            self.double()
        } else {
            Self::INFINITY
        }
    }

    pub fn neg(&self) -> Self {
        Self { x: self.x, y: self.y.neg(), z: self.z }
    }

    /// Affine x and y; (0, 0) at infinity, as blst encodes it.
    #[target_feature(enable = "bmi2,adx")]
    pub fn to_affine(&self) -> (Fp, Fp) {
        if self.is_infinity() {
            return (Fp::ZERO, Fp::ZERO);
        }
        let z_inverse = self.z.inverse();
        let z_inverse_squared = z_inverse.square();
        (self.x.mul(&z_inverse_squared), self.y.mul(&z_inverse_squared.mul(&z_inverse)))
    }

    /// Whether both represent the same point.
    #[target_feature(enable = "bmi2,adx")]
    pub fn equals(&self, q: &Self) -> bool {
        if self.is_infinity() || q.is_infinity() {
            return self.is_infinity() && q.is_infinity();
        }
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        self.x.mul(&z2z2) == q.x.mul(&z1z1) &&
            self.y.mul(&q.z).mul(&z2z2) == q.y.mul(&self.z).mul(&z1z1)
    }

    /// `[|z|] P` for an affine P, by double-and-add over the set bits of |z|.
    #[target_feature(enable = "bmi2,adx")]
    fn times_z_affine(px: &Fp, py: &Fp) -> Self {
        let mut r = Self::from_affine(px, py);
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            r = r.double();
            if is_lower_z_bit(bit) {
                r = r.add_affine_complete(px, py);
            }
        }
        r
    }

    /// `[|z|] self`, by the same chain as `times_z_affine`.
    #[target_feature(enable = "bmi2,adx")]
    fn times_z(&self) -> Self {
        let mut r = *self;
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            r = r.double();
            if is_lower_z_bit(bit) {
                r = r.add_complete(self);
            }
        }
        r
    }

    /// Scott's test: a finite affine curve point is in G1 iff `[-z^2] P ==
    /// sigma^2(P)`, where sigma scales x by a cube root of unity.
    #[target_feature(enable = "bmi2,adx")]
    pub fn in_g1(px: &Fp, py: &Fp) -> bool {
        Self::times_z_affine(px, py).times_z().is_minus_sigma_squared(px, py)
    }

    /// Whether self is −σ²(P) for the finite affine P = (px, py).
    #[target_feature(enable = "bmi2,adx")]
    pub fn is_minus_sigma_squared(&self, px: &Fp, py: &Fp) -> bool {
        if self.is_infinity() {
            return false;
        }
        let zz = self.z.square();
        self.x == px.mul(&BETA).mul(&BETA).mul(&zz) && self.y.neg() == py.mul(&zz.mul(&self.z))
    }
}

/// madd-2007-bl's terms up to h = qx·z1² − x1 and r = 2·(qy·z1³ − y1):
/// p and (qx, qy) share x when h = 0, and are equal when r = 0 too.
struct MixedTerms {
    z1z1: Fp,
    h: Fp,
    r: Fp,
}

impl MixedTerms {
    #[target_feature(enable = "bmi2,adx")]
    fn new(p: &G1, qx: &Fp, qy: &Fp) -> Self {
        let z1z1 = p.z.square();
        let h = qx.mul(&z1z1).sub(&p.x);
        let r = qy.mul(&p.z).mul(&z1z1).sub(&p.y).double();
        Self { z1z1, h, r }
    }

    #[target_feature(enable = "bmi2,adx")]
    fn sum(&self, p: &G1) -> G1 {
        let hh = self.h.square();
        let i = hh.double().double();
        let j = self.h.mul(&i);
        let v = p.x.mul(&i);
        let x3 = self.r.square().sub(&j).sub(&v.double());
        let y3 = self.r.mul(&v.sub(&x3)).sub(&p.y.mul(&j).double());
        let z3 = p.z.add(&self.h).square().sub(&self.z1z1).sub(&hh);
        G1 { x: x3, y: y3, z: z3 }
    }
}

/// add-2007-bl's terms up to h = u2 − u1 and r = 2·(s2 − s1), as in
/// `MixedTerms`.
struct Terms {
    z1z1: Fp,
    z2z2: Fp,
    u1: Fp,
    s1: Fp,
    h: Fp,
    r: Fp,
}

impl Terms {
    #[target_feature(enable = "bmi2,adx")]
    fn new(p: &G1, q: &G1) -> Self {
        let z1z1 = p.z.square();
        let z2z2 = q.z.square();
        let u1 = p.x.mul(&z2z2);
        let s1 = p.y.mul(&q.z).mul(&z2z2);
        let h = q.x.mul(&z1z1).sub(&u1);
        let r = q.y.mul(&p.z).mul(&z1z1).sub(&s1).double();
        Self { z1z1, z2z2, u1, s1, h, r }
    }

    #[target_feature(enable = "bmi2,adx")]
    fn sum(&self, p: &G1, q: &G1) -> G1 {
        let i = self.h.double().square();
        let j = self.h.mul(&i);
        let v = self.u1.mul(&i);
        let x3 = self.r.square().sub(&j).sub(&v.double());
        let y3 = self.r.mul(&v.sub(&x3)).sub(&self.s1.mul(&j).double());
        let z3 = p.z.add(&q.z).square().sub(&self.z1z1).sub(&self.z2z2).mul(&self.h);
        G1 { x: x3, y: y3, z: z3 }
    }
}

#[cfg(test)]
mod tests;
