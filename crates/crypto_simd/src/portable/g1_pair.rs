//! Two G1 points in lockstep, over pairs of [`Fp`]: every product runs as
//! `Fp::mul_pair`, so the core overlaps the two points' chains. The formulas
//! are `G1`'s without the exceptional cases; a lane that meets one is
//! reported, and the caller recomputes it with `G1`.

use crate::{
    bls::{constants::Z_BITS, g1x8::is_lower_z_bit},
    portable::{constants::ONE, fp::Fp, g1::G1},
};

pub struct G1Pair {
    pub x: [Fp; 2],
    pub y: [Fp; 2],
    pub z: [Fp; 2],
}

#[inline]
fn mul(a: &[Fp; 2], b: &[Fp; 2]) -> [Fp; 2] {
    Fp::mul_pair(a, b)
}

#[inline]
fn square(a: &[Fp; 2]) -> [Fp; 2] {
    Fp::mul_pair(a, a)
}

#[inline(always)]
fn add(a: &[Fp; 2], b: &[Fp; 2]) -> [Fp; 2] {
    [a[0].add(&b[0]), a[1].add(&b[1])]
}

#[inline(always)]
fn sub(a: &[Fp; 2], b: &[Fp; 2]) -> [Fp; 2] {
    [a[0].sub(&b[0]), a[1].sub(&b[1])]
}

#[inline(always)]
fn double(a: &[Fp; 2]) -> [Fp; 2] {
    [a[0].double(), a[1].double()]
}

impl G1Pair {
    pub fn from_affine(x: &[Fp; 2], y: &[Fp; 2]) -> Self {
        Self { x: *x, y: *y, z: [ONE; 2] }
    }

    pub fn lane(&self, k: usize) -> G1 {
        G1 { x: self.x[k], y: self.y[k], z: self.z[k] }
    }

    /// `G1::double` in both lanes.
    pub fn double(&self) -> Self {
        let a = square(&self.x);
        let b = square(&self.y);
        let c = square(&b);
        let d = double(&sub(&sub(&square(&add(&self.x, &b)), &a), &c));
        let e = add(&double(&a), &a);
        let x3 = sub(&square(&e), &double(&d));
        let y3 = sub(&mul(&e, &sub(&d, &x3)), &double(&double(&double(&c))));
        let z3 = double(&mul(&self.y, &self.z));
        Self { x: x3, y: y3, z: z3 }
    }

    /// `G1::add_affine` in both lanes, and the lanes where it does not hold:
    /// self at infinity, or x = qx.
    pub fn add_affine(&self, qx: &[Fp; 2], qy: &[Fp; 2]) -> (Self, [bool; 2]) {
        let z1z1 = square(&self.z);
        let u2 = mul(qx, &z1z1);
        let s2 = mul(&mul(qy, &self.z), &z1z1);
        let h = sub(&u2, &self.x);
        let hh = square(&h);
        let i = double(&double(&hh));
        let j = mul(&h, &i);
        let r = double(&sub(&s2, &self.y));
        let v = mul(&self.x, &i);
        let x3 = sub(&sub(&square(&r), &j), &double(&v));
        let y3 = sub(&mul(&r, &sub(&v, &x3)), &double(&mul(&self.y, &j)));
        let z3 = sub(&sub(&square(&add(&self.z, &h)), &z1z1), &hh);
        let exceptional =
            [h[0].is_zero() || self.z[0].is_zero(), h[1].is_zero() || self.z[1].is_zero()];
        (Self { x: x3, y: y3, z: z3 }, exceptional)
    }

    /// `G1::add` in both lanes, and the lanes where it does not hold: either
    /// summand at infinity, or equal x.
    pub fn add(&self, q: &Self) -> (Self, [bool; 2]) {
        let z1z1 = square(&self.z);
        let z2z2 = square(&q.z);
        let u1 = mul(&self.x, &z2z2);
        let u2 = mul(&q.x, &z1z1);
        let s1 = mul(&mul(&self.y, &q.z), &z2z2);
        let s2 = mul(&mul(&q.y, &self.z), &z1z1);
        let h = sub(&u2, &u1);
        let i = square(&double(&h));
        let j = mul(&h, &i);
        let r = double(&sub(&s2, &s1));
        let v = mul(&u1, &i);
        let x3 = sub(&sub(&square(&r), &j), &double(&v));
        let y3 = sub(&mul(&r, &sub(&v, &x3)), &double(&mul(&s1, &j)));
        let z3 = mul(&sub(&sub(&square(&add(&self.z, &q.z)), &z1z1), &z2z2), &h);
        let mut exceptional = [false; 2];
        let mut k = 0;
        while k < 2 {
            exceptional[k] = h[k].is_zero() || self.z[k].is_zero() || q.z[k].is_zero();
            k += 1;
        }
        (Self { x: x3, y: y3, z: z3 }, exceptional)
    }

    /// `G1::in_g1` of two finite affine curve points in lockstep; a lane whose
    /// chain meets an exceptional case is decided by `G1::in_g1` alone.
    pub fn in_g1(px: &[Fp; 2], py: &[Fp; 2]) -> [bool; 2] {
        let mut exceptional = [false; 2];
        let mut r = Self::from_affine(px, py);
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            r = r.double();
            if is_lower_z_bit(bit) {
                let (sum, e) = r.add_affine(px, py);
                r = sum;
                exceptional = [exceptional[0] || e[0], exceptional[1] || e[1]];
            }
        }
        let zp = Self { x: r.x, y: r.y, z: r.z };
        bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            r = r.double();
            if is_lower_z_bit(bit) {
                let (sum, e) = r.add(&zp);
                r = sum;
                exceptional = [exceptional[0] || e[0], exceptional[1] || e[1]];
            }
        }
        let mut members = [false; 2];
        let mut k = 0;
        while k < 2 {
            members[k] = if exceptional[k] {
                G1::in_g1(&px[k], &py[k])
            } else {
                r.lane(k).is_minus_sigma_squared(&px[k], &py[k])
            };
            k += 1;
        }
        members
    }
}
