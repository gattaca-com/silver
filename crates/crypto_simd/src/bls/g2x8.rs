//! Eight G2 points in Jacobian coordinates, one per lane, over [`Fp2x8`].
//!
//! The formulas are the a = 0 ones from the EFD (dbl-2009-l, madd-2007-bl)
//! with no exceptional-case handling: a lane that hits one — doubling a point
//! with y = 0, adding P to ±P, or any point at infinity — is reported as
//! undecided instead, and the caller falls back to blst for it. Honest points
//! of prime order never do; only non-members can.
//!
//! Coordinates in and out are reduced. Inside a formula, sums and
//! differences stay lazy, offset by multiples of p to stay positive, and are
//! carried only where a product or the output needs it. The comments bound
//! each lazy value and each product's operands; `Fp2x8::mul` and
//! `Fp2x8::square` admit them all. Adjacent products do not depend on each
//! other, so the out-of-order core overlaps them.

use std::arch::x86_64::__mmask8;

use crate::bls::{
    Membership,
    constants::{PSI_X_MONT, PSI_Y_MONT, Z_BITS},
    fp2x8::Fp2x8,
    fp8::Fp8,
};

pub struct G2x8 {
    pub x: Fp2x8,
    pub y: Fp2x8,
    pub z: Fp2x8,
}

/// The multiples of p the lazy differences are offset by.
struct Offsets {
    two_p: Fp8,
    four_p: Fp8,
    eight_p: Fp8,
}

impl Offsets {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn new() -> Self {
        Self {
            two_p: Fp8::multiple_of_p(2),
            four_p: Fp8::multiple_of_p(4),
            eight_p: Fp8::multiple_of_p(8),
        }
    }

    /// A lazy value below 4p, reduced.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn reduced_from_4p(&self, v: &Fp2x8) -> Fp2x8 {
        v.normalise().cond_sub(&self.two_p)
    }

    /// A lazy value below 8p, reduced.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn reduced_from_8p(&self, v: &Fp2x8) -> Fp2x8 {
        v.normalise().cond_sub(&self.four_p).cond_sub(&self.two_p)
    }
}

impl G2x8 {
    /// dbl-2009-l. Undecided when y = 0 or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn double(&self) -> (Self, __mmask8) {
        let o = Offsets::new();
        let a = self.x.square();
        let b = self.y.square();
        let e = a.add_raw(&a).add_raw(&a).normalise(); // < 6p
        let f = e.square(); // 6p · 6p
        let c = b.square();
        let xb = self.x.add_raw(&b).normalise(); // < 4p
        let xb_squared = xb.square(); // 4p · 4p
        let yz = self.y.mul(&self.z);
        let d = o.reduced_from_8p(&xb_squared.sub_raw(&a, &o.two_p).sub_raw(&c, &o.two_p));
        let d = o.reduced_from_4p(&d.add_raw(&d));
        let x3 = f.sub_raw(&d.add_raw(&d), &o.four_p).normalise(); // < 6p
        let dx = d.sub_raw(&x3, &o.eight_p).normalise(); // < 10p
        let c8 = o.reduced_from_8p(&c.add_raw(&c).add_raw(&c).add_raw(&c));
        let y3 = o.reduced_from_8p(&e.mul(&dx).sub_raw(&c8.add_raw(&c8), &o.four_p)); // 6p · 10p
        let z3 = o.reduced_from_4p(&yz.add_raw(&yz));
        let undecided = self.y.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3.cond_sub(&o.four_p).cond_sub(&o.two_p), y: y3, z: z3 }, undecided)
    }

    /// madd-2007-bl with Z2 = 1. Undecided when the points coincide or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn add_affine(&self, qx: &Fp2x8, qy: &Fp2x8) -> (Self, __mmask8) {
        let o = Offsets::new();
        let z1z1 = self.z.square();
        let qy_z = qy.mul(&self.z);
        let u2 = qx.mul(&z1z1);
        let s2 = qy_z.mul(&z1z1);
        let h = u2.sub(&self.x);
        let hh = h.square();
        let zh = self.z.add_raw(&h).normalise(); // < 4p
        let zh_squared = zh.square(); // 4p · 4p
        let i = hh.add_raw(&hh).add_raw(&hh).add_raw(&hh).normalise(); // < 8p
        let j = h.mul(&i); // 2p · 8p
        let v = self.x.mul(&i); // 2p · 8p
        let r = s2.sub_raw(&self.y, &o.two_p);
        let r = r.add_raw(&r).normalise(); // < 8p
        let rr = r.square(); // 8p · 8p
        let yj = self.y.mul(&j);
        let x3 = o.reduced_from_8p(&rr.sub_raw(&j, &o.two_p).sub_raw(&v.add_raw(&v), &o.four_p));
        let vx = v.sub_raw(&x3, &o.two_p).normalise(); // < 4p
        let y3 = o.reduced_from_8p(&r.mul(&vx).sub_raw(&yj.add_raw(&yj), &o.four_p)); // 8p · 4p
        let z3 = o.reduced_from_8p(&zh_squared.sub_raw(&z1z1, &o.two_p).sub_raw(&hh, &o.two_p));
        let undecided = h.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    /// `[-z] P = [|z|] P` for an affine P, by double-and-add over the six set
    /// bits of |z|.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn times_minus_z(px: &Fp2x8, py: &Fp2x8) -> (Self, __mmask8) {
        let mut undecided = 0;
        let mut r = Self { x: *px, y: *py, z: Fp2x8::one() };
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            let (d, u) = r.double();
            r = d;
            undecided |= u;
            if bit == Z_BITS[1] ||
                bit == Z_BITS[2] ||
                bit == Z_BITS[3] ||
                bit == Z_BITS[4] ||
                bit == Z_BITS[5]
            {
                let (a, u) = r.add_affine(px, py);
                r = a;
                undecided |= u;
            }
        }
        (r, undecided)
    }

    /// Scott's test (eprint 2021/1130): a curve point is in G2 iff
    /// `psi(P) == [z] P`, which is `[-z] P` negated.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn scott_membership(px: &Fp2x8, py: &Fp2x8) -> Membership {
        let (mzp, chain_undecided) = Self::times_minus_z(px, py);
        let undecided = chain_undecided | mzp.z.is_zero_mask();

        let psi_scale = Fp8::splat_limbs(&PSI_X_MONT);
        let psi_x = Fp2x8 { c0: px.c1.mul(&psi_scale), c1: px.c0.mul(&psi_scale) };
        let psi_y = py.conjugate().mul(&Fp2x8::splat(&PSI_Y_MONT));
        let zz = mzp.z.square();
        let zzz = zz.mul(&mzp.z);
        let x_matches = mzp.x.eq_mask(&psi_x.mul(&zz));
        let y_matches = mzp.y.neg().eq_mask(&psi_y.mul(&zzz));
        Membership { members: x_matches & y_matches & !undecided, undecided }
    }
}

#[cfg(test)]
mod tests;
