//! Eight G1 points in Jacobian coordinates, one per lane, over [`Fp8`].
//!
//! The formulas are the a = 0 ones from the EFD (dbl-2009-l, madd-2007-bl,
//! add-2007-bl) with no exceptional-case handling: a lane that hits one —
//! doubling a point with y = 0, adding P to ±P, or any point at infinity —
//! is reported as undecided instead, and the caller falls back to blst for
//! it. Honest points of prime order never do; only non-members can.

use std::arch::x86_64::__mmask8;

use crate::bls::{
    Membership,
    constants::{BETA_MONT, Z_BITS},
    fp8::Fp8,
    g1x8_lazy::Offsets,
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
        let c = Offsets::new();
        let undecided = self.y.is_zero_mask() | self.z.is_zero_mask();
        (self.double_loose(&c).tighten(&c), undecided)
    }

    /// madd-2007-bl with Z2 = 1. Undecided when the points coincide or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add_affine(&self, qx: &Fp8, qy: &Fp8) -> (Self, __mmask8) {
        let c = Offsets::new();
        let z1z1 = self.z.square();
        let u2 = qx.mul(&z1z1);
        let s2 = qy.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&self.x);
        let hh = h.square();
        let i = hh.add_raw(&hh).add_raw(&hh).add_raw(&hh).normalise(); // < 8p
        let j = h.mul(&i); // 2p · 8p
        let r = s2.sub_raw(&self.y, &c.two_p);
        let r = r.add_raw(&r).normalise(); // < 8p
        let v = self.x.mul(&i); // 2p · 8p
        let rr = r.square(); // 8p · 8p
        let x3 = c.below_2p_from_8p(&rr.sub_raw(&j, &c.two_p).sub_raw(&v.add_raw(&v), &c.four_p));
        let vx = v.sub_raw(&x3, &c.two_p).normalise(); // < 4p
        let yj = self.y.mul(&j);
        let y3 = c.below_2p_from_8p(&r.mul(&vx).sub_raw(&yj.add_raw(&yj), &c.four_p)); // 8p · 4p
        let zh = self.z.add_raw(&h).normalise(); // < 4p
        let z3 = c.below_2p_from_8p(&zh.square().sub_raw(&z1z1, &c.two_p).sub_raw(&hh, &c.two_p));
        let undecided = h.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    /// add-2007-bl. Undecided when the points coincide or either z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add(&self, q: &Self) -> (Self, __mmask8) {
        let c = Offsets::new();
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = self.y.mul(&q.z).mul(&z2z2);
        let s2 = q.y.mul(&self.z).mul(&z1z1);
        let h = u2.sub(&u1);
        let i = h.add_raw(&h).normalise().square(); // 4p · 4p
        let j = h.mul(&i);
        let r = s2.sub_raw(&s1, &c.two_p);
        let r = r.add_raw(&r).normalise(); // < 8p
        let v = u1.mul(&i);
        let rr = r.square(); // 8p · 8p
        let x3 = c.below_2p_from_8p(&rr.sub_raw(&j, &c.two_p).sub_raw(&v.add_raw(&v), &c.four_p));
        let vx = v.sub_raw(&x3, &c.two_p).normalise(); // < 4p
        let sj = s1.mul(&j);
        let y3 = c.below_2p_from_8p(&r.mul(&vx).sub_raw(&sj.add_raw(&sj), &c.four_p)); // 8p · 4p
        let zz = self.z.add_raw(&q.z).normalise(); // < 4p
        let zz = zz.square().sub_raw(&z1z1, &c.two_p).sub_raw(&z2z2, &c.two_p).normalise(); // < 6p
        let z3 = zz.mul(&h); // 6p · 2p
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

#[cfg(test)]
mod reference {
    use std::arch::x86_64::__mmask8;

    use crate::bls::{fp8::Fp8, g1x8::G1x8};

    impl G1x8 {
        #[target_feature(enable = "avx512f,avx512ifma")]
        pub(crate) fn double_reference(&self) -> (Self, __mmask8) {
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

        #[target_feature(enable = "avx512f,avx512ifma")]
        pub(crate) fn add_affine_reference(&self, qx: &Fp8, qy: &Fp8) -> (Self, __mmask8) {
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

        #[target_feature(enable = "avx512f,avx512ifma")]
        pub(crate) fn add_reference(&self, q: &Self) -> (Self, __mmask8) {
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::{
        constants::{P, R_MOD_P},
        fp8::{LANES, Limbs},
        fp8_lazy::TWO_P,
        g1x8_lazy::Offsets,
        g1x8_test_util::{below, plain, random_below_p, rng, splat_value},
        simd_available,
    };

    fn lane_values(first: Limbs, second: Limbs, lane_bits: u32) -> [Limbs; LANES] {
        std::array::from_fn(|lane| if (lane >> lane_bits) & 1 == 0 { first } else { second })
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn assert_formulas_match_reference(p: &G1x8, q: &G1x8, case: &str) {
        let (want, wu) = p.double_reference();
        let (got, gu) = p.double();
        assert!(plain(&want) == plain(&got) && wu == gu, "double, {case}");

        let (want, wu) = p.add_affine_reference(&q.x, &q.y);
        let (got, gu) = p.add_affine(&q.x, &q.y);
        assert!(plain(&want) == plain(&got) && wu == gu, "add_affine, {case}");

        let (want, wu) = p.add_reference(q);
        let (got, gu) = p.add(q);
        assert!(plain(&want) == plain(&got) && wu == gu, "add, {case}");

        let c = Offsets::new();
        let (mut loose, mut tight) =
            (G1x8 { x: p.x, y: p.y, z: p.z }, G1x8 { x: p.x, y: p.y, z: p.z });
        for _ in 0..5 {
            loose = loose.double_loose(&c);
            tight = tight.double_reference().0;
        }
        assert!(plain(&tight) == plain(&loose.tighten(&c)), "double_loose chain, {case}");
    }

    /// Random field elements make the formulas' arithmetic identical whether
    /// or not the lanes are curve points.
    #[test]
    fn formulas_match_the_reference_on_random_lanes() {
        if !simd_available() {
            return;
        }
        let mut rng = rng(0x61);
        for _ in 0..8 {
            let v: [[Limbs; LANES]; 5] =
                std::array::from_fn(|_| std::array::from_fn(|_| random_below_p(&mut rng)));
            // SAFETY: checked above.
            unsafe {
                let f = v.map(|limbs| Fp8::from_plain(&limbs));
                let p = G1x8 { x: f[0], y: f[1], z: f[2] };
                let q = G1x8 { x: f[3], y: f[4], z: f[2].add(&f[0]) };
                assert_formulas_match_reference(&p, &q, "random lanes");
            }
        }
    }

    #[test]
    fn formulas_match_the_reference_at_the_input_bounds() {
        if !simd_available() {
            return;
        }
        let (two_p_minus_one, p_minus_one) = (below(TWO_P), below(P));
        let one = R_MOD_P;
        // SAFETY: checked above.
        unsafe {
            let coordinates = |bit_of_x: u32, bit_of_y: u32, bit_of_z: u32| G1x8 {
                x: Fp8::load(&lane_values(two_p_minus_one, p_minus_one, bit_of_x)),
                y: Fp8::load(&lane_values(two_p_minus_one, p_minus_one, bit_of_y)),
                z: Fp8::load(&lane_values(one, two_p_minus_one, bit_of_z)),
            };
            let p = coordinates(0, 1, 2);
            let q = coordinates(1, 2, 0);
            assert_formulas_match_reference(&p, &q, "mixed bounds");
            assert_formulas_match_reference(&q, &p, "mixed bounds swapped");

            let all_two_p = G1x8 {
                x: splat_value(two_p_minus_one),
                y: splat_value(two_p_minus_one),
                z: splat_value(two_p_minus_one),
            };
            let all_p = G1x8 {
                x: splat_value(p_minus_one),
                y: splat_value(p_minus_one),
                z: splat_value(p_minus_one),
            };
            assert_formulas_match_reference(&all_two_p, &all_p, "2p - 1 against p - 1");
            assert_formulas_match_reference(&all_p, &all_two_p, "p - 1 against 2p - 1");

            let affine_one = G1x8 { x: p.x, y: p.y, z: Fp8::one() };
            assert_formulas_match_reference(&affine_one, &q, "z = one");
        }
    }
}
