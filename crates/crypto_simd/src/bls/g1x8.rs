//! Eight G1 points in Jacobian coordinates, one per lane, over [`Fp8`].
//!
//! The formulas are the a = 0 ones from the EFD (dbl-2009-l, madd-2007-bl,
//! add-2007-bl) with no exceptional-case handling: a lane that hits one —
//! doubling a point with y = 0, adding P to ±P, or any point at infinity —
//! is reported as undecided instead, and the caller falls back to blst for
//! it. Honest points of prime order never do; only non-members can. The
//! `_complete` forms decide every lane as the spec's `G1.add` and
//! `G1.double` do, with z = 0 at infinity.
//!
//! Coordinates in and out are reduced. Inside a formula, sums and
//! differences stay lazy, offset by multiples of p to stay positive, and are
//! carried only where a product or the output needs it. The comments bound
//! each lazy value and each product's operands; `Fp8::mul` admits them all.
//! Adjacent products do not depend on each other, so the out-of-order core
//! overlaps them.

use std::arch::x86_64::__mmask8;

use crate::bls::{
    Membership,
    constants::{BETA_MONT, Z_BITS},
    fp8::{Fp8, LANES},
};

pub struct G1x8 {
    pub x: Fp8,
    pub y: Fp8,
    pub z: Fp8,
}

/// The multiples of p the lazy differences are offset by.
pub(crate) struct Offsets {
    pub(crate) two_p: Fp8,
    four_p: Fp8,
    eight_p: Fp8,
}

impl Offsets {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            two_p: Fp8::multiple_of_p(2),
            four_p: Fp8::multiple_of_p(4),
            eight_p: Fp8::multiple_of_p(8),
        }
    }

    /// A lazy value below 4p, reduced.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(crate) fn reduced_from_4p(&self, v: &Fp8) -> Fp8 {
        v.normalise().cond_sub(&self.two_p)
    }

    /// A lazy value below 8p, reduced.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub(crate) fn reduced_from_8p(&self, v: &Fp8) -> Fp8 {
        v.normalise().cond_sub(&self.four_p).cond_sub(&self.two_p)
    }
}

impl G1x8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn from_affine(x: &Fp8, y: &Fp8) -> Self {
        Self { x: *x, y: *y, z: Fp8::one() }
    }

    /// dbl-2009-l. Undecided when y = 0 or z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
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
    pub fn add_affine(&self, qx: &Fp8, qy: &Fp8) -> (Self, __mmask8) {
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

    /// add-2007-bl. Undecided when the points coincide or either z = 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add(&self, q: &Self) -> (Self, __mmask8) {
        let o = Offsets::new();
        let z1z1 = self.z.square();
        let z2z2 = q.z.square();
        let y1_z2 = self.y.mul(&q.z);
        let y2_z1 = q.y.mul(&self.z);
        let z_sum = self.z.add_raw(&q.z).normalise(); // < 4p
        let z_sum_squared = z_sum.square(); // 4p · 4p
        let u1 = self.x.mul(&z2z2);
        let u2 = q.x.mul(&z1z1);
        let s1 = y1_z2.mul(&z2z2);
        let s2 = y2_z1.mul(&z1z1);
        let h = u2.sub(&u1);
        let i = h.add_raw(&h).normalise().square(); // 4p · 4p
        let two_z1_z2 = z_sum_squared.sub_raw(&z1z1, &o.two_p).sub_raw(&z2z2, &o.two_p).normalise(); // < 6p
        let z3 = two_z1_z2.mul(&h); // 6p · 2p
        let j = h.mul(&i);
        let v = u1.mul(&i);
        let r = s2.sub_raw(&s1, &o.two_p);
        let r = r.add_raw(&r).normalise(); // < 8p
        let rr = r.square(); // 8p · 8p
        let s1_j = s1.mul(&j);
        let x3 = o.reduced_from_8p(&rr.sub_raw(&j, &o.two_p).sub_raw(&v.add_raw(&v), &o.four_p));
        let vx = v.sub_raw(&x3, &o.two_p).normalise(); // < 4p
        let y3 = o.reduced_from_8p(&r.mul(&vx).sub_raw(&s1_j.add_raw(&s1_j), &o.four_p)); // 8p · 4p
        let undecided = h.is_zero_mask() | self.z.is_zero_mask() | q.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    /// The spec's `G1.zero` in every lane.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn infinity() -> Self {
        Self { x: Fp8::one(), y: Fp8::one(), z: Fp8::zero() }
    }

    /// Lanes of `k` take `b`, the rest `a`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn select(k: __mmask8, a: &Self, b: &Self) -> Self {
        Self {
            x: Fp8::select(k, &a.x, &b.x),
            y: Fp8::select(k, &a.y, &b.y),
            z: Fp8::select(k, &a.z, &b.z),
        }
    }

    /// Lane l takes lane `from[l]`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn permute(&self, from: &[i64; LANES]) -> Self {
        Self { x: self.x.permute(from), y: self.y.permute(from), z: self.z.permute(from) }
    }

    /// The spec's `G1.double`, lane by lane.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn double_complete(&self) -> Self {
        Self::select(self.z.is_zero_mask(), &self.double().0, self)
    }

    /// The spec's `G1.add` of each lane and the affine point (qx, qy).
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add_affine_complete(&self, qx: &Fp8, qy: &Fp8) -> Self {
        let (sum, undecided) = self.add_affine(qx, qy);
        if undecided == 0 {
            return sum;
        }
        let infinite = self.z.is_zero_mask();
        let same_x = undecided & !infinite;
        let decided = if same_x == 0 {
            sum
        } else {
            let s2 = qy.mul(&self.z).mul(&self.z.square());
            self.coincident(&sum, same_x, s2.eq_mask(&self.y))
        };
        Self::select(infinite, &decided, &Self::from_affine(qx, qy))
    }

    /// The spec's `G1.add`, lane by lane.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn add_complete(&self, q: &Self) -> Self {
        let (sum, undecided) = self.add(q);
        if undecided == 0 {
            return sum;
        }
        let infinite = self.z.is_zero_mask();
        let q_infinite = q.z.is_zero_mask();
        let same_x = undecided & !(infinite | q_infinite);
        let decided = if same_x == 0 {
            sum
        } else {
            let s1 = self.y.mul(&q.z).mul(&q.z.square());
            let s2 = q.y.mul(&self.z).mul(&self.z.square());
            self.coincident(&sum, same_x, s1.eq_mask(&s2))
        };
        Self::select(infinite, &Self::select(q_infinite, &decided, self), q)
    }

    /// The spec's `G1.neg`, lane by lane.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn neg(&self) -> Self {
        Self { x: self.x, y: self.y.neg(), z: self.z }
    }

    /// Each lane's affine x and y, reduced, from one inversion for all eight
    /// lanes; (0, 0) at infinity, as blst encodes it.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn to_affine(&self) -> (Fp8, Fp8) {
        let z_inverse = self.z.inverse();
        let z_inverse_squared = z_inverse.square();
        (self.x.mul(&z_inverse_squared), self.y.mul(&z_inverse_squared.mul(&z_inverse)))
    }

    /// `[2^k]` of each lane, by complete doublings.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn times_two_pow(&self, k: usize) -> Self {
        let mut r = Self { x: self.x, y: self.y, z: self.z };
        let mut i = 0;
        while i < k {
            r = r.double_complete();
            i += 1;
        }
        r
    }

    /// Σ_l `[2^(bits·l)]` lane l, in lane 0: lanes join pairwise, then
    /// pairs of pairs, the upper of each scaled to its place.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn sum_lanes_shifted(&self, bits: usize) -> Self {
        let mut r = Self { x: self.x, y: self.y, z: self.z };
        let mut distance = 1;
        while distance < LANES {
            let upper = r.times_two_pow(distance * bits).permute(&lanes_above(distance));
            r = r.add_complete(&upper);
            distance *= 2;
        }
        r
    }

    /// `sum`, but in the lanes of `same_x`, where the summands share x, the
    /// double of `self` where their y agree too and infinity where not.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn coincident(&self, sum: &Self, same_x: __mmask8, same_y: __mmask8) -> Self {
        let cancelled = Self::select(same_x & !same_y, sum, &Self::infinity());
        Self::select(same_x & same_y, &cancelled, &self.double().0)
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

/// Lane l takes lane l + `distance`, wrapping around.
fn lanes_above(distance: usize) -> [i64; LANES] {
    let mut from = [0i64; LANES];
    let mut lane = 0;
    while lane < LANES {
        from[lane] = ((lane + distance) % LANES) as i64;
        lane += 1;
    }
    from
}

/// A set bit of |z| below the top one, where both chains start.
fn is_lower_z_bit(bit: u32) -> bool {
    bit == Z_BITS[1] || bit == Z_BITS[2] || bit == Z_BITS[3] || bit == Z_BITS[4] || bit == Z_BITS[5]
}

#[cfg(test)]
mod tests;
