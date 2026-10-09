//! Eight G2 points in Jacobian coordinates, one per lane, over [`Fp2x8`].
//!
//! The formulas are the a = 0 ones from the EFD (dbl-2009-l, madd-2007-bl)
//! with no exceptional-case handling: a lane that hits one — doubling a point
//! with y = 0, adding P to ±P, or any point at infinity — is reported as
//! undecided instead, and the caller falls back to blst for it. Honest points
//! of prime order never do; only non-members can.

use std::arch::x86_64::__mmask8;

use crate::{
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

impl G2x8 {
    /// dbl-2009-l. Undecided when y = 0 or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
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
    #[inline]
    pub fn add_affine(&self, qx: &Fp2x8, qy: &Fp2x8) -> (Self, __mmask8) {
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
