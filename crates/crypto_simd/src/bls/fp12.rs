//! One Fp12 = Fp6[w]/(w² − v) across the lanes of an `Fp2x8`, with Fp6 =
//! Fp2[v]/(v³ − ξ) and ξ = 1 + i, the tower blst and the spec use. Lane
//! 3h + k holds the Fp2 coefficient k of half h, blst's fp6[h].fp2[k], the
//! coefficient of w^(2k + h). Lanes 6 and 7 carry no value.
//!
//! Each operation gathers its independent Fp products into lanes, multiplies
//! them with `Fp8::mul`, and recombines them with lane permutations and
//! `Fp8`'s lazy steps. A product's three Karatsuba levels sit on two axes:
//! - Fp2 (c0, c1, c0 + c1) and Fp12 over Fp6 (a0, a1, a0 + a1) across vectors,
//!   where they combine lane by lane, ξ included;
//! - Fp6 over Fp2 (x0, x1, x2, x0 + x1, x0 + x2, x1 + x2) across lanes 0 to 5,
//!   where they recombine through permutations.
//!
//! Nine such vectors hold a product's 54 Fp products; the last two ride in
//! lanes 6 and 7 of six others, so seven `Fp8::mul` calls do them all.
//!
//! Every operation takes normalised components below `BOUND`·p, lazy, and
//! returns normalised components below `BOUND`·p, so operations chain
//! without reduction. The bound beside each step is for operands below
//! K·p, K = `BOUND`. Products land below 2p whatever the operands; the
//! largest operand pair, below 10K·p and 8K·p, is far below R·p = 2^416·p.

use crate::bls::{
    constants::{FROBENIUS_MONT, LIMBS, R_MOD_P, Z_BITS},
    fp2x8::Fp2x8,
    fp8::{Fp8, LANES, Limbs},
    g1x8::is_lower_z_bit,
};

pub const BOUND: u64 = 256;

/// A lane index that reads 0 from the second operand of `permute2`, where
/// that operand is zero.
const Z: i64 = 8;

/// Lane l holds the coefficient of w^j, j = `POWER_OF_LANE[l]`.
const POWER_OF_LANE: [usize; 6] = [0, 2, 4, 1, 3, 5];

#[derive(Clone, Copy)]
pub struct Fp12(pub Fp2x8);

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn zero2() -> Fp2x8 {
    Fp2x8 { c0: Fp8::zero(), c1: Fp8::zero() }
}

/// The Fp2 product from its Karatsuba products m0 = a0·b0, m1 = a1·b1 and
/// m2 = (a0 + a1)(b0 + b1), each below k·p: c0 below 2k·p, c1 below 3k·p.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn fp2_from_products(m0: &Fp8, m1: &Fp8, m2: &Fp8, k: u64) -> Fp2x8 {
    Fp2x8 {
        c0: m0.sub_raw(m1, &Fp8::multiple_of_p(k)),
        c1: m2.sub_raw(&m0.add_raw(m1), &Fp8::multiple_of_p(2 * k)),
    }
}

/// Lane-wise Fp2 products of normalised operands below 2K·p: normalised,
/// below 6p.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn fp2_products(a: &Fp2x8, b: &Fp2x8) -> Fp2x8 {
    let m0 = a.c0.mul(&b.c0);
    let m1 = a.c1.mul(&b.c1);
    let m2 = a.c0.add_raw(&a.c1).normalise().mul(&b.c0.add_raw(&b.c1).normalise());
    fp2_from_products(&m0, &m1, &m2, 2).normalise()
}

/// Lanes 6 and 7 set to 0, so recombination can read zeros there.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn clear_free_lanes(x: &Fp2x8) -> Fp2x8 {
    Fp2x8::select(0xc0, x, &zero2())
}

/// [x0, x1, x2, x0 + x1, x0 + x2, x1 + x2] for the Fp6 at lanes `base` to
/// `base + 2`, 0 in lanes 6 and 7: below 2K·p.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn karatsuba_lanes(a: &Fp2x8, base: i64) -> Fp2x8 {
    let zero = zero2();
    let b = base;
    let first = a.permute2(&zero, &[b, b + 1, b + 2, b, b, b + 1, Z, Z]);
    let second = a.permute2(&zero, &[Z, Z, Z, b + 1, b + 2, b + 2, Z, Z]);
    first.add_raw(&second)
}

/// The three Fp2 Karatsuba vectors of `x`: c0, c1 and c0 + c1.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn fp2_operands(x: &Fp2x8) -> [Fp8; 3] {
    [x.c0, x.c1, x.c0.add_raw(&x.c1)]
}

/// Nine six-lane vectors into seven: vectors 7 and 8 move into lanes 6 and 7
/// of vectors 0 to 2 and 3 to 5. Normalised for `Fp8::mul`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn pack_nine(l: &[Fp8; 9]) -> [Fp8; 7] {
    [
        l[0].permute2(&l[7], &[0, 1, 2, 3, 4, 5, 8, 9]).normalise(),
        l[1].permute2(&l[7], &[0, 1, 2, 3, 4, 5, 10, 11]).normalise(),
        l[2].permute2(&l[7], &[0, 1, 2, 3, 4, 5, 12, 13]).normalise(),
        l[3].permute2(&l[8], &[0, 1, 2, 3, 4, 5, 8, 9]).normalise(),
        l[4].permute2(&l[8], &[0, 1, 2, 3, 4, 5, 10, 11]).normalise(),
        l[5].permute2(&l[8], &[0, 1, 2, 3, 4, 5, 12, 13]).normalise(),
        l[6].normalise(),
    ]
}

/// The inverse of `pack_nine` on lanes 0 to 5.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn unpack_nine(q: &[Fp8; 7]) -> [Fp8; 9] {
    let low7 = q[0].permute2(&q[1], &[6, 7, 14, 15, 6, 7, 14, 15]);
    let low8 = q[3].permute2(&q[4], &[6, 7, 14, 15, 6, 7, 14, 15]);
    [
        q[0],
        q[1],
        q[2],
        q[3],
        q[4],
        q[5],
        q[6],
        low7.permute2(&q[2], &[0, 1, 2, 3, 14, 15, 14, 15]),
        low8.permute2(&q[5], &[0, 1, 2, 3, 14, 15, 14, 15]),
    ]
}

/// Six six-lane vectors into five: vector 5 moves into lanes 6 and 7 of
/// vectors 0 to 2. Normalised for `Fp8::mul`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn pack_six(l: &[Fp8; 6]) -> [Fp8; 5] {
    [
        l[0].permute2(&l[5], &[0, 1, 2, 3, 4, 5, 8, 9]).normalise(),
        l[1].permute2(&l[5], &[0, 1, 2, 3, 4, 5, 10, 11]).normalise(),
        l[2].permute2(&l[5], &[0, 1, 2, 3, 4, 5, 12, 13]).normalise(),
        l[3].normalise(),
        l[4].normalise(),
    ]
}

#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn unpack_six(q: &[Fp8; 5]) -> [Fp8; 6] {
    let low5 = q[0].permute2(&q[1], &[6, 7, 14, 15, 6, 7, 14, 15]);
    [q[0], q[1], q[2], q[3], q[4], low5.permute2(&q[2], &[0, 1, 2, 3, 14, 15, 14, 15])]
}

/// Adds two permutations of the pair (`e`, `xi_e`) to `acc`; index 6 must
/// read 0.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn add_slices(acc: &Fp2x8, e: &Fp2x8, xi_e: &Fp2x8, slices: &[[i64; 8]; 2]) -> Fp2x8 {
    acc.add_raw(&e.permute2(xi_e, &slices[0])).add_raw(&e.permute2(xi_e, &slices[1]))
}

// The Fp6 recombination z(E) = (e0 + ξ(e12 − e1 − e2), e01 − e0 − e1 + ξe2,
// e02 − e0 − e2 + e1) from E = [e0, e1, e2, e01, e02, e12] and ξE (lanes 8
// up), as positive and negative slices, where lane 6 of E reads 0. The `V_`
// slices give v·z(E) = (ξz2, z0, z1). The digit is the first output lane.
const Z0_POS: [[i64; 8]; 2] = [[0, 3, 4, 6, 6, 6, 6, 6], [13, 10, 1, 6, 6, 6, 6, 6]];
const Z0_NEG: [[i64; 8]; 2] = [[9, 0, 0, 6, 6, 6, 6, 6], [10, 1, 2, 6, 6, 6, 6, 6]];
const Z3_POS: [[i64; 8]; 2] = [[6, 6, 6, 0, 3, 4, 6, 6], [6, 6, 6, 13, 10, 1, 6, 6]];
const Z3_NEG: [[i64; 8]; 2] = [[6, 6, 6, 9, 0, 0, 6, 6], [6, 6, 6, 10, 1, 2, 6, 6]];
const V_Z0_POS: [[i64; 8]; 2] = [[12, 0, 3, 6, 6, 6, 6, 6], [9, 13, 10, 6, 6, 6, 6, 6]];
const V_Z0_NEG: [[i64; 8]; 2] = [[8, 9, 0, 6, 6, 6, 6, 6], [10, 10, 1, 6, 6, 6, 6, 6]];

impl Fp12 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    pub fn one() -> Self {
        let zero = Fp8::zero();
        Self(Fp2x8 { c0: zero.permute2(&Fp8::one(), &[8, 0, 0, 0, 0, 0, 0, 0]), c1: zero })
    }

    /// Karatsuba on all three levels, 54 Fp products in seven `Fp8::mul`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn mul(&self, rhs: &Self) -> Self {
        let left = product_operands(&self.0);
        let right = product_operands(&rhs.0);
        let mut q = [Fp8::zero(); 7];
        let mut i = 0;
        while i < 7 {
            q[i] = left[i].mul(&right[i]);
            i += 1;
        }
        Self::from_product_lanes(&q)
    }

    /// The product from its packed Fp products, each below 2p: below 108p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn from_product_lanes(q: &[Fp8; 7]) -> Self {
        let m = unpack_nine(q);

        // A0·B0 and A1·B1, then the Fp12 cross term (A0 + A1)(B0 + B1) − both.
        let p4 = Fp8::multiple_of_p(4);
        let cross = [
            m[6].sub_raw(&m[0].add_raw(&m[3]), &p4),
            m[7].sub_raw(&m[1].add_raw(&m[4]), &p4),
            m[8].sub_raw(&m[2].add_raw(&m[5]), &p4),
        ]; // below 6p
        let r0 = clear_free_lanes(&fp2_from_products(&m[0], &m[1], &m[2], 2)); // below 6p
        let r1 = clear_free_lanes(&fp2_from_products(&m[3], &m[4], &m[5], 2));
        let d = clear_free_lanes(&fp2_from_products(&cross[0], &cross[1], &cross[2], 6)); // 18p
        let xi_r0 = r0.mul_by_xi_raw(&Fp8::multiple_of_p(6)); // below 10p
        let xi_r1 = r1.mul_by_xi_raw(&Fp8::multiple_of_p(6));
        let xi_d = d.mul_by_xi_raw(&Fp8::multiple_of_p(18)); // below 30p

        // c0 = z(R0) + v·z(R1) in lanes 0 to 2, c1 = z(D) in lanes 3 to 5.
        let zero = zero2();
        let pos = add_slices(&zero, &r0, &xi_r0, &Z0_POS);
        let pos = add_slices(&pos, &r1, &xi_r1, &V_Z0_POS);
        let pos = add_slices(&pos, &d, &xi_d, &Z3_POS); // below 48p
        let neg = add_slices(&zero, &r0, &xi_r0, &Z0_NEG);
        let neg = add_slices(&neg, &r1, &xi_r1, &V_Z0_NEG);
        let neg = add_slices(&neg, &d, &xi_d, &Z3_NEG); // below 60p
        Self(pos.sub_raw(&neg, &Fp8::multiple_of_p(60)).normalise())
    }

    /// The complex method: a0·a1 and (a0 + a1)(a0 + v·a1), 36 Fp products in
    /// five `Fp8::mul`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn square(&self) -> Self {
        let a = &self.0;
        let zero = zero2();
        let xi_a = a.mul_by_xi_raw(&Fp8::multiple_of_p(BOUND)); // below 2K·p
        let k0 = karatsuba_lanes(a, 0);
        let k1 = karatsuba_lanes(a, 3);
        // The Karatsuba lanes of v·a1 = (ξa5, a3, a4): below 3K·p.
        let kv1 = a
            .permute2(&xi_a, &[13, 3, 4, 13, 13, 3, 6, 6])
            .add_raw(&a.permute2(&zero, &[Z, Z, Z, 3, 4, 4, Z, Z]));
        let left_sum = k0.add_raw(&k1); // below 4K·p
        let right_sum = k0.add_raw(&kv1); // below 5K·p
        let lt = fp2_operands(&k0);
        let ls = fp2_operands(&left_sum);
        let rt = fp2_operands(&k1);
        let rs = fp2_operands(&right_sum);
        let left = pack_six(&[lt[0], lt[1], lt[2], ls[0], ls[1], ls[2]]);
        let right = pack_six(&[rt[0], rt[1], rt[2], rs[0], rs[1], rs[2]]);
        let mut q = [Fp8::zero(); 5];
        let mut i = 0;
        while i < 5 {
            q[i] = left[i].mul(&right[i]);
            i += 1;
        }
        Self::from_square_lanes(&q)
    }

    /// The square from its packed Fp products, each below 2p: below 112p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn from_square_lanes(q: &[Fp8; 5]) -> Self {
        let m = unpack_six(q);
        let t = fp2_from_products(&m[0], &m[1], &m[2], 2); // c0 below 4p, c1 6p
        let s = fp2_from_products(&m[3], &m[4], &m[5], 2);
        let u = clear_free_lanes(&Fp2x8 {
            c0: s.c0.sub_raw(&t.c0, &Fp8::multiple_of_p(4)),
            c1: s.c1.sub_raw(&t.c1, &Fp8::multiple_of_p(6)),
        }); // below 12p
        let t = clear_free_lanes(&t);
        let xi_t = t.mul_by_xi_raw(&Fp8::multiple_of_p(6)); // below 10p
        let xi_u = u.mul_by_xi_raw(&Fp8::multiple_of_p(12)); // below 20p

        // c0 = z(s − t) − v·z(t) in lanes 0 to 2, c1 = 2·z(t) in lanes 3 to 5.
        let zero = zero2();
        let pos = add_slices(&zero, &u, &xi_u, &Z0_POS);
        let pos = add_slices(&pos, &t, &xi_t, &V_Z0_NEG);
        let twice_pos = add_slices(&zero, &t, &xi_t, &Z3_POS);
        let pos = pos.add_raw(&twice_pos).add_raw(&twice_pos); // below 52p
        let neg = add_slices(&zero, &u, &xi_u, &Z0_NEG);
        let neg = add_slices(&neg, &t, &xi_t, &V_Z0_POS);
        let twice_neg = add_slices(&zero, &t, &xi_t, &Z3_NEG);
        let neg = neg.add_raw(&twice_neg).add_raw(&twice_neg); // below 60p
        Self(pos.sub_raw(&neg, &Fp8::multiple_of_p(60)).normalise())
    }

    /// Times the line (x, y, 0) + (0, z, 0)·w, blst's `mul_by_xy00z0`, with x,
    /// y and z in lanes 0 to 2 of `line`: 39 Fp products in five `Fp8::mul`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn mul_by_line(&self, line: &Fp2x8) -> Self {
        let a = &self.0;
        let zero = zero2();
        // Eight Fp2 products: a0·(x, y, 0)'s five, then a1·(0, z, 0)'s three:
        // [a0·x, a1·y, (a0 + a1)(x + y), (a0 + a2)·x, (a1 + a2)·y, a5·z, a3·z,
        // a4·z], with ai the Fp2 at lane i.
        let left_a = a
            .permute2(&zero, &[0, 1, 0, 0, 1, 5, 3, 4])
            .add_raw(&a.permute2(&zero, &[Z, Z, 1, 2, 2, Z, Z, Z])); // below 2K·p
        let right_a = line
            .permute2(&zero, &[0, 1, 0, 0, 1, 2, 2, 2])
            .add_raw(&line.permute2(&zero, &[Z, Z, 1, Z, Z, Z, Z, Z]));
        // Five: (a0 + a1)·(x, y + z, 0)'s, in lanes 0 to 4.
        let sum = a.add_raw(&a.permute2(&zero, &[3, 4, 5, Z, Z, Z, Z, Z]));
        let left_b = sum
            .permute2(&zero, &[0, 1, 0, 0, 1, Z, Z, Z])
            .add_raw(&sum.permute2(&zero, &[Z, Z, 1, 2, 2, Z, Z, Z])); // below 4K·p
        let line_sum = line.add_raw(&line.permute2(&zero, &[Z, 2, Z, Z, Z, Z, Z, Z]));
        let right_b = line_sum
            .permute2(&zero, &[0, 1, 0, 0, 1, Z, Z, Z])
            .add_raw(&line_sum.permute2(&zero, &[Z, Z, 1, Z, Z, Z, Z, Z]));
        let left = line_operands(&left_a, &left_b);
        let right = line_operands(&right_a, &right_b);
        let mut q = [Fp8::zero(); 5];
        let mut i = 0;
        while i < 5 {
            q[i] = left[i].mul(&right[i]);
            i += 1;
        }
        Self::from_line_lanes(&q)
    }

    /// The line product from its packed Fp products, each below 2p: below
    /// 120p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn from_line_lanes(q: &[Fp8; 5]) -> Self {
        // ra = [e0, e1, e01, e02, e12, g0, g1, g2]; db = t2's five minus t0's.
        let zero = zero2();
        let ra = fp2_from_products(&q[0], &q[1], &q[2], 2); // c0 below 4p, c1 6p
        let b2 = q[3].permute2(&q[4], &[5, 6, 7, 13, 14, 15, 15, 15]);
        let rb = fp2_from_products(&q[3], &q[4], &b2, 2);
        let db = Fp2x8::select(
            0xe0,
            &Fp2x8 {
                c0: rb.c0.sub_raw(&ra.c0, &Fp8::multiple_of_p(4)),
                c1: rb.c1.sub_raw(&ra.c1, &Fp8::multiple_of_p(6)),
            },
            &zero,
        ); // below 12p, 0 in lanes 5 to 7

        // c = n + ξ·m over (ra, db), with lane 13 reading 0:
        // c0 = (e0 + ξ(e12 − e1 + g2), e01 − e0 − e1 + ξg0, e02 − e0 + e1 + g1),
        // c1 = (d0 + ξ(d12 − d1 − g0), d01 − d0 − d1 − g1, d02 − d0 + d1 − g2).
        let n_pos = ra
            .permute2(&db, &[0, 2, 3, 8, 10, 11, 13, 13])
            .add_raw(&ra.permute2(&db, &[13, 13, 1, 13, 13, 9, 13, 13]))
            .add_raw(&ra.permute2(&db, &[13, 13, 6, 13, 13, 13, 13, 13])); // 24p
        let n_neg = ra
            .permute2(&db, &[13, 0, 0, 13, 8, 8, 13, 13])
            .add_raw(&ra.permute2(&db, &[13, 1, 13, 13, 9, 7, 13, 13]))
            .add_raw(&ra.permute2(&db, &[13, 13, 13, 13, 6, 13, 13, 13])); // 30p
        let m_pos = ra
            .permute2(&db, &[4, 5, 13, 12, 13, 13, 13, 13])
            .add_raw(&ra.permute2(&db, &[7, 13, 13, 13, 13, 13, 13, 13])); // 12p
        let m_neg = ra
            .permute2(&db, &[1, 13, 13, 9, 13, 13, 13, 13])
            .add_raw(&ra.permute2(&db, &[13, 13, 13, 5, 13, 13, 13, 13])); // 18p
        let c0_pos = n_pos.c0.add_raw(&m_pos.c0).add_raw(&m_neg.c1); // below 54p
        let c0_neg = n_neg.c0.add_raw(&m_neg.c0).add_raw(&m_pos.c1); // below 60p
        let c1_pos = n_pos.c1.add_raw(&m_pos.c0).add_raw(&m_pos.c1); // below 48p
        let c1_neg = n_neg.c1.add_raw(&m_neg.c0).add_raw(&m_neg.c1); // below 66p
        let offset = Fp8::multiple_of_p(66);
        Self(Fp2x8 {
            c0: c0_pos.sub_raw(&c0_neg, &offset).normalise(),
            c1: c1_pos.sub_raw(&c1_neg, &offset).normalise(),
        })
    }

    /// Granger–Scott, on the cyclotomic subgroup: nine Fp2 squarings, 18 Fp
    /// products in three `Fp8::mul`. Off the subgroup it computes the same
    /// formula, as blst's `cyclotomic_sqr_fp12` does.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn cyclotomic_square(&self) -> Self {
        let a = &self.0;
        let zero = zero2();
        // Fp4 pairs (x, y): (a0, a4), (a3, a2), (a1, a5). Squared in lanes:
        // [x0, x1, x2, y0, y1, y2, x0 + y0, 0], then x1 + y1 and x2 + y2.
        let u = a
            .permute2(&zero, &[0, 3, 1, 4, 2, 5, 0, Z])
            .add_raw(&a.permute2(&zero, &[Z, Z, Z, Z, Z, Z, 4, Z])); // below 2K·p
        let sums = a
            .permute2(&zero, &[3, 1, Z, Z, Z, Z, Z, Z])
            .add_raw(&a.permute2(&zero, &[2, 5, Z, Z, Z, Z, Z, Z]));
        let offset = Fp8::multiple_of_p(2 * BOUND);
        let q = Fp2x8 {
            c0: u.c0.add_raw(&u.c1).normalise().mul(&u.c0.sub_raw(&u.c1, &offset).normalise()),
            c1: u.c0.normalise().mul(&u.c1.add_raw(&u.c1).normalise()),
        }; // q lanes 0 to 6 squared, 0 in lane 7
        let sum = sums.c0.add_raw(&sums.c1);
        let difference = sums.c0.sub_raw(&sums.c1, &offset);
        let twice = sums.c1.add_raw(&sums.c1);
        let left = sum.permute2(&sums.c0, &[0, 8, 1, 9, 7, 7, 7, 7]).normalise();
        let right = difference.permute2(&twice, &[0, 8, 1, 9, 7, 7, 7, 7]).normalise();
        // 3t ± 2a depends on a's range, so two conditional subtractions bring
        // it from below 572p back under K·p.
        let r = Self::cyclotomic_sum(&q, &left.mul(&right), a);
        let r = r.cond_sub(&Fp8::multiple_of_p(2 * BOUND));
        Self(r.cond_sub(&Fp8::multiple_of_p(BOUND)))
    }

    /// 3t ± 2a, normalised, below 572p, from `q`, the squares of lanes 0 to 6
    /// with 0 in lane 7, `m`, the two others' components with 0 above lane
    /// 3, and the input `a`.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn cyclotomic_sum(q: &Fp2x8, m: &Fp8, a: &Fp2x8) -> Fp2x8 {
        let zero = zero2();
        let squared_sums = Fp2x8 {
            c0: m.permute2(&zero.c0, &[7, 7, 7, 2, 7, 0, 7, 7]),
            c1: m.permute2(&zero.c0, &[7, 7, 7, 3, 7, 1, 7, 7]),
        }; // (x2 + y2)² in lane 3, (x1 + y1)² in lane 5

        // t = n + ξ·m' = [t0.0, t1.0, t2.0, ξ·t2.1, t0.1, t1.1], lane 7 reading 0:
        // n = [x0², x1², x2², 0, s0² − x0² − y0², s1² − x1² − y1²],
        // m' = [y0², y1², y2², s2² − x2² − y2², 0, 0].
        let n_pos = q.permute2(&squared_sums, &[0, 1, 2, 7, 6, 13, 7, 7]); // 2p
        let n_neg = q
            .permute2(&squared_sums, &[7, 7, 7, 7, 0, 1, 7, 7])
            .add_raw(&q.permute2(&squared_sums, &[7, 7, 7, 7, 3, 4, 7, 7])); // 4p
        let m_pos = q.permute2(&squared_sums, &[3, 4, 5, 11, 7, 7, 7, 7]); // 2p
        let m_neg = q
            .permute2(&squared_sums, &[7, 7, 7, 2, 7, 7, 7, 7])
            .add_raw(&q.permute2(&squared_sums, &[7, 7, 7, 5, 7, 7, 7, 7])); // 4p
        let p12 = Fp8::multiple_of_p(12);
        let t = Fp2x8 {
            c0: n_pos
                .c0
                .add_raw(&m_pos.c0)
                .add_raw(&m_neg.c1)
                .sub_raw(&n_neg.c0.add_raw(&m_neg.c0).add_raw(&m_pos.c1), &p12),
            c1: n_pos
                .c1
                .add_raw(&m_pos.c0)
                .add_raw(&m_pos.c1)
                .sub_raw(&n_neg.c1.add_raw(&m_neg.c0).add_raw(&m_neg.c1), &p12),
        }; // below 20p

        // 3t − 2a in lanes 0 to 2, 3t + 2a in lanes 3 to 5.
        let twice_a = a.add_raw(a);
        let offset = Fp8::multiple_of_p(2 * BOUND);
        let signed = Fp2x8::select(0x38, &zero.sub_raw(&twice_a, &offset), &twice_a);
        t.add_raw(&t).add_raw(&t).add_raw(&signed).normalise()
    }

    /// c0 − c1·w: lanes 3 to 5 negated, K·p − a, and K·p itself taken to 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn conjugate(&self) -> Self {
        let bound = Fp8::multiple_of_p(BOUND);
        let negated = zero2().sub_raw(&self.0, &bound).normalise().cond_sub(&bound);
        Self(Fp2x8::select(0x38, &self.0, &negated))
    }

    /// The p-power Frobenius map; p² and p³ are its repeats.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn frobenius(&self) -> Self {
        self.conjugate_coefficients().times_coefficients(&FROBENIUS_MONT)
    }

    /// Every Fp2 coefficient conjugated: c1 negated in every lane.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn conjugate_coefficients(&self) -> Self {
        let c1 = Fp8::zero().sub_raw(&self.0.c1, &Fp8::multiple_of_p(BOUND)).normalise();
        Self(Fp2x8 { c0: self.0.c0, c1 })
    }

    /// The coefficient of w^j times `gamma[j]`: below 6p.
    #[target_feature(enable = "avx512f,avx512ifma")]
    #[inline]
    fn times_coefficients(&self, gamma: &[[Limbs; 2]; 6]) -> Self {
        let mut c0 = [[0u64; LIMBS]; LANES];
        let mut c1 = [[0u64; LIMBS]; LANES];
        let mut lane = 0;
        while lane < 6 {
            c0[lane] = gamma[POWER_OF_LANE[lane]][0];
            c1[lane] = gamma[POWER_OF_LANE[lane]][1];
            lane += 1;
        }
        let constants = Fp2x8 { c0: Fp8::load(&c0), c1: Fp8::load(&c1) };
        Self(fp2_products(&self.0, &constants))
    }

    /// The inverse, through the norms down to one `Fp8::inverse`: self·conj
    /// is the Fp6 norm n, and n's inverse comes from its own norm in Fp2.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn inverse(&self) -> Self {
        let conjugate = self.conjugate();
        let n = self.mul(&conjugate).0; // lanes 0 to 2, below 108p

        // t = (n0² − ξn1n2, ξn2² − n0n1, n1² − n0n2).
        let xi_n = n.mul_by_xi_raw(&Fp8::multiple_of_p(BOUND)).normalise();
        let left = n.permute2(&xi_n, &[0, 10, 1, 1, 0, 0, 0, 0]);
        let right = n.permute(&[0, 2, 1, 2, 1, 2, 0, 0]);
        let products = fp2_products(&left, &right); // [n0², ξn2², n1², n1n2, n0n1, n0n2]
        let xi_products = products.mul_by_xi_raw(&Fp8::multiple_of_p(6)).normalise();
        let subtrahend = products.permute2(&xi_products, &[11, 4, 5, 0, 0, 0, 0, 0]);
        let t = products.sub_raw(&subtrahend, &Fp8::multiple_of_p(12)).normalise(); // 18p

        // det = n0·t0 + ξ(n2·t1 + n1·t2), in lane 0.
        let d = fp2_products(&n.permute(&[0, 2, 1, 0, 0, 0, 0, 0]), &t);
        let xi_d = d.mul_by_xi_raw(&Fp8::multiple_of_p(6)).normalise();
        let det = d
            .add_raw(&xi_d.permute(&[1, 1, 1, 1, 1, 1, 1, 1]))
            .add_raw(&xi_d.permute(&[2, 2, 2, 2, 2, 2, 2, 2]))
            .normalise(); // below 30p

        // det⁻¹ = conj(det) / (det.c0² + det.c1²), in every lane.
        let components = det.c0.permute2(&det.c1, &[0, 8, 0, 8, 0, 8, 0, 8]);
        let squares = components.mul(&components);
        let norm = squares.add_raw(&squares.permute(&[1, 0, 1, 0, 1, 0, 1, 0])).normalise();
        let inverse_norm = norm.inverse().permute(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let det_inverse = Fp2x8 {
            c0: det.c0.permute(&[0, 0, 0, 0, 0, 0, 0, 0]).mul(&inverse_norm),
            c1: Fp8::zero()
                .sub_raw(&det.c1, &Fp8::multiple_of_p(30))
                .normalise()
                .permute(&[0, 0, 0, 0, 0, 0, 0, 0])
                .mul(&inverse_norm),
        };

        // n⁻¹ = t·det⁻¹ in lanes 0 to 2, then self⁻¹ = conj·n⁻¹.
        let n_inverse =
            fp2_products(&t, &det_inverse).permute2(&zero2(), &[0, 1, 2, Z, Z, Z, Z, Z]);
        conjugate.mul(&Self(n_inverse))
    }

    /// f^(3·(p¹² − 1)/r): the spec's final exponentiation, cubed, which
    /// leaves `is_one` unchanged as 3 is prime to r. This is zkcrypto's
    /// chain. The easy part, f^((p⁶ − 1)(p² + 1)), lands in the cyclotomic
    /// subgroup. The hard part takes that to 3·Φ12(p)/r through five
    /// exponentiations by z.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn final_exponentiation(&self) -> Self {
        let t0 = self.conjugate();
        let t1 = self.inverse();
        let t2 = t0.mul(&t1);
        let t1 = t2;
        let t2 = t2.frobenius().frobenius().mul(&t1);

        let t1 = t2.cyclotomic_square().conjugate();
        let t3 = t2.cyclotomic_exp();
        let t4 = t3.cyclotomic_square();
        let t5 = t1.mul(&t3);
        let t1 = t5.cyclotomic_exp();
        let t0 = t1.cyclotomic_exp();
        let t6 = t0.cyclotomic_exp().mul(&t4);
        let t4 = t6.cyclotomic_exp();
        let t5 = t5.conjugate();
        let t4 = t4.mul(&t5.mul(&t2));
        let t5 = t2.conjugate();
        let t1 = t1.mul(&t2).frobenius().frobenius().frobenius();
        let t6 = t6.mul(&t5).frobenius();
        let t3 = t3.mul(&t0).frobenius().frobenius();
        t3.mul(&t1).mul(&t6).mul(&t4)
    }

    /// f^z on the cyclotomic subgroup, where the inverse is the conjugate:
    /// f^|z| over the bits of |z|, conjugated as z < 0.
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn cyclotomic_exp(&self) -> Self {
        let mut r = *self;
        let mut bit = Z_BITS[0];
        while bit > 0 {
            bit -= 1;
            r = r.cyclotomic_square();
            if is_lower_z_bit(bit) {
                r = r.mul(self);
            }
        }
        r.conjugate()
    }

    /// Whether the value is 1.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn is_one(&self) -> bool {
        let one = Fp8::splat_limbs(&R_MOD_P);
        let expected = Self::one().0;
        let c0 = self.0.c0.mul(&one).eq_mask(&expected.c0);
        let c1 = self.0.c1.mul(&one).eq_mask(&expected.c1);
        (c0 & c1 & 0x3f) == 0x3f
    }
}

/// The seven `Fp8::mul` operands of a product's 54 Fp products.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn product_operands(a: &Fp2x8) -> [Fp8; 7] {
    let k0 = karatsuba_lanes(a, 0);
    let k1 = karatsuba_lanes(a, 3);
    let k01 = k0.add_raw(&k1); // below 4K·p
    let l0 = fp2_operands(&k0);
    let l1 = fp2_operands(&k1);
    let l2 = fp2_operands(&k01); // below 8K·p
    pack_nine(&[l0[0], l0[1], l0[2], l1[0], l1[1], l1[2], l2[0], l2[1], l2[2]])
}

/// Group A's three Fp2 Karatsuba vectors, full, then group B's 15 lanes in
/// two vectors. Normalised for `Fp8::mul`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn line_operands(group_a: &Fp2x8, group_b: &Fp2x8) -> [Fp8; 5] {
    let a = fp2_operands(group_a);
    let b = fp2_operands(group_b);
    [
        a[0].normalise(),
        a[1].normalise(),
        a[2].normalise(),
        b[0].permute2(&b[2], &[0, 1, 2, 3, 4, 8, 9, 10]).normalise(),
        b[1].permute2(&b[2], &[0, 1, 2, 3, 4, 11, 12, 13]).normalise(),
    ]
}

#[cfg(test)]
pub(crate) mod tests;
