//! Eight G1 points in Jacobian coordinates, one per lane, over [`Fp8`].
//!
//! The formulas are the a = 0 ones from the EFD (dbl-2009-l, madd-2007-bl,
//! add-2007-bl) with no exceptional-case handling: a lane that hits one —
//! doubling a point with y = 0, adding P to ±P, or any point at infinity —
//! is reported as undecided instead, and the caller falls back to blst for
//! it. Honest points of prime order never do; only non-members can.

use std::arch::x86_64::__mmask8;

use crate::{
    Membership,
    constants::{BETA_MONT, Z_BITS},
    fp8::Fp8,
};

pub struct G1x8 {
    pub x: Fp8,
    pub y: Fp8,
    pub z: Fp8,
}

impl G1x8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn from_affine(x: &Fp8, y: &Fp8) -> Self {
        Self { x: *x, y: *y, z: Fp8::one() }
    }

    /// dbl-2009-l. Undecided when y = 0 or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn double(&self) -> (Self, __mmask8) {
        let a = self.x.square();
        let b = self.y.square();
        let c = b.square();
        let d = self.x.add(&b).square().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let f = e.square();
        let x3 = f.sub(&d.double());
        let y3 = e.mul(&d.sub(&x3)).sub(&c.double().double().double());
        let z3 = self.y.mul(&self.z).double();
        let undecided = self.y.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    /// madd-2007-bl with Z2 = 1. Undecided when the points coincide or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add_affine(&self, qx: &Fp8, qy: &Fp8) -> (Self, __mmask8) {
        let z1z1 = self.z.square();
        let u2 = qx.mul(&z1z1);
        let s2 = qy.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.double().double();
        let j = h.mul(&i);
        let r = s2.sub(&self.y).double();
        let v = self.x.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&j).double());
        let z3 = self.z.add(&h).square().sub(&z1z1).sub(&hh);
        let undecided = h.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    /// add-2007-bl. Undecided when the points coincide or either z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add(&self, q: &Self) -> (Self, __mmask8) {
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = self.y.mul(&q.z).mul(&z2z2);
        let s2 = q.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let i = h.double().square();
        let j = h.mul(&i);
        let r = s2.sub(&s1).double();
        let v = u1.mul(&i);
        let x3 = r.square().sub(&j).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).double());
        let z3 = self.z.add(&q.z).square().sub(&z1z1).sub(&z2z2).mul(&h);
        let undecided = h.is_zero_mask() | self.z.is_zero_mask() | q.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    /// `[|z|] P` for an affine P, by double-and-add over the six set bits of
    /// |z|.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn times_z_affine(px: &Fp8, py: &Fp8) -> (Self, __mmask8) {
        let mut undecided = 0;
        let mut r = Self::from_affine(px, py);
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            let (d, u) = r.double();
            r = d;
            undecided |= u;
            if is_lower_z_bit(bit) {
                let (a, u) = r.add_affine(px, py);
                r = a;
                undecided |= u;
            }
        }
        (r, undecided)
    }

    /// `[|z|] Q` for a Jacobian Q, by the same chain as `times_z_affine`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn times_z(&self) -> (Self, __mmask8) {
        let mut undecided = 0;
        let mut r = Self { x: self.x, y: self.y, z: self.z };
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            let (d, u) = r.double();
            r = d;
            undecided |= u;
            if is_lower_z_bit(bit) {
                let (a, u) = r.add(self);
                r = a;
                undecided |= u;
            }
        }
        (r, undecided)
    }

    /// Scott's test: an affine curve point is in G1 iff `[-z^2] P ==
    /// sigma^2(P)`, where sigma scales x by a cube root of unity.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn scott_membership(px: &Fp8, py: &Fp8) -> Membership {
        let (zp, u1) = Self::times_z_affine(px, py);
        let (zzp, u2) = zp.times_z();
        let undecided = u1 | u2 | zzp.z.is_zero_mask();

        let beta = Fp8::splat_limbs(&BETA_MONT);
        let sigma2_x = px.mul(&beta).mul(&beta);
        let zz = zzp.z.square();
        let zzz = zz.mul(&zzp.z);
        let x_matches = zzp.x.eq_mask(&sigma2_x.mul(&zz));
        let y_matches = zzp.y.neg().eq_mask(&py.mul(&zzz));
        Membership { members: x_matches & y_matches & !undecided, undecided }
    }
}

/// A set bit of |z| below the top one, where both chains start.
fn is_lower_z_bit(bit: u32) -> bool {
    bit == Z_BITS[1] || bit == Z_BITS[2] || bit == Z_BITS[3] || bit == Z_BITS[4] || bit == Z_BITS[5]
}
