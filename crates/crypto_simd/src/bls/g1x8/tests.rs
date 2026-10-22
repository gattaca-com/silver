//! The point formulas against the exact ones they rearrange, on reduced
//! inputs at their bounds and at random: the same values modulo p and the
//! same undecided lanes, with reduced coordinates out. The complete forms
//! against blst's complete ones, on curve points.

use std::arch::x86_64::__mmask8;

use blst::{
    blst_fp, blst_fp_from_uint64, blst_fp_mul, blst_fp_sqr, blst_p1, blst_p1_add_or_double,
    blst_p1_add_or_double_affine, blst_p1_cneg, blst_p1_double, blst_p1_generator,
    blst_p1_is_equal, blst_p1_is_inf, blst_p1_mult, blst_p1_to_affine, blst_uint64_from_fp,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::G1x8;
use crate::{
    bls::{
        blst_p1_affine,
        constants::{LIMBS, MASK52, R_MOD_P},
        fp8::{
            Fp8,
            tests::{below, near_multiple_of_p},
        },
        limbs::{LANES, Limbs, unpack52},
    },
    kernels_run,
};

impl G1x8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn double_reference(&self) -> (Self, __mmask8) {
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
    fn add_affine_reference(&self, qx: &Fp8, qy: &Fp8) -> (Self, __mmask8) {
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
    fn add_reference(&self, q: &Self) -> (Self, __mmask8) {
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

#[target_feature(enable = "avx512f,avx512ifma")]
fn assert_same_points(got: &(G1x8, __mmask8), want: &(G1x8, __mmask8), formula: &str) {
    assert!(got.1 == want.1, "{formula}: undecided lanes");
    let two_p = near_multiple_of_p(2, 0);
    for (g, w) in [(&got.0.x, &want.0.x), (&got.0.y, &want.0.y), (&got.0.z, &want.0.z)] {
        for limbs in g.store() {
            let normalised = limbs.iter().all(|&limb| limb <= MASK52);
            let below_two_p = limbs.iter().rev().lt(two_p.iter().rev());
            assert!(normalised && below_two_p, "{formula}: {limbs:x?} not reduced");
        }
        assert!(g.canonical().store() == w.canonical().store(), "{formula}: values");
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn assert_formulas_match(coordinates: &[[Limbs; LANES]; 6], case: &str) {
    let [x1, y1, z1, x2, y2, z2] = coordinates.map(|c| Fp8::load(&c));
    let p = G1x8 { x: x1, y: y1, z: z1 };
    let q = G1x8 { x: x2, y: y2, z: z2 };
    assert_same_points(&p.double(), &p.double_reference(), &format!("double, {case}"));
    assert_same_points(
        &p.add_affine(&q.x, &q.y),
        &p.add_affine_reference(&q.x, &q.y),
        &format!("add_affine, {case}"),
    );
    assert_same_points(&p.add(&q), &p.add_reference(&q), &format!("add, {case}"));
}

/// Every combination of 0, one, p − 1, p and 2p − 1 for the six coordinates
/// of two points, eight combinations to a vector.
#[test]
fn formulas_match_the_reference_at_the_input_bounds() {
    if !kernels_run() {
        return;
    }
    let edges = [(0, 0), (1, -1), (1, 0), (2, -1)].map(|(k, d)| near_multiple_of_p(k, d));
    let edges = [edges[0], R_MOD_P, edges[1], edges[2], edges[3]];
    let combinations = edges.len().pow(6);
    for first in (0..combinations).step_by(LANES) {
        let mut coordinates = [[[0u64; LIMBS]; LANES]; 6];
        for lane in 0..LANES {
            let mut n = (first + lane) % combinations;
            for coordinate in &mut coordinates {
                coordinate[lane] = edges[n % edges.len()];
                n /= edges.len();
            }
        }
        // SAFETY: `kernels_run` checked `ifma_available`.
        unsafe { assert_formulas_match(&coordinates, &format!("combinations from {first}")) };
    }
}

/// Random values below 2p: the arithmetic does not need curve points.
#[test]
fn formulas_match_the_reference_on_random_lanes() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x61);
    let two_p = near_multiple_of_p(2, 0);
    for case in 0..256 {
        let coordinates = std::array::from_fn(|_| std::array::from_fn(|_| below(&mut rng, &two_p)));
        // SAFETY: `kernels_run` checked `ifma_available`.
        unsafe { assert_formulas_match(&coordinates, &format!("case {case}")) };
    }
}

/// Multiples of the generator by random 255-bit scalars, whose z is not 1.
pub(crate) fn random_points(rng: &mut ChaCha8Rng, n: usize) -> Vec<blst_p1> {
    (0..n)
        .map(|_| {
            let mut scalar: [u8; 32] = rng.r#gen();
            scalar[31] &= 0x7f;
            let mut point = blst_p1::default();
            // SAFETY: blst returns a pointer to its static generator; a valid
            // pointer to a single value, and blst reads 255 bits of the scalar.
            unsafe { blst_p1_mult(&mut point, blst_p1_generator(), scalar.as_ptr(), 255) };
            point
        })
        .collect()
}

/// The same point at another Jacobian scale: (λ²x, λ³y, λz).
pub(crate) fn rescaled(point: &blst_p1, lambda: u64) -> blst_p1 {
    let (mut l, mut l2, mut l3) = (blst_fp::default(), blst_fp::default(), blst_fp::default());
    let mut out = blst_p1::default();
    // SAFETY: valid pointers to single values; blst reads six words.
    unsafe {
        blst_fp_from_uint64(&mut l, [lambda, 0, 0, 0, 0, 0].as_ptr());
        blst_fp_sqr(&mut l2, &l);
        blst_fp_mul(&mut l3, &l2, &l);
        blst_fp_mul(&mut out.x, &point.x, &l2);
        blst_fp_mul(&mut out.y, &point.y, &l3);
        blst_fp_mul(&mut out.z, &point.z, &l);
    }
    out
}

pub(crate) fn negated(point: &blst_p1) -> blst_p1 {
    let mut out = *point;
    // SAFETY: a valid pointer to a single value.
    unsafe { blst_p1_cneg(&mut out, true) };
    out
}

pub(crate) fn affine(point: &blst_p1) -> blst_p1_affine {
    let mut out = blst_p1_affine::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_to_affine(&mut out, point) };
    out
}

fn plain(fp: &blst_fp) -> Limbs {
    let mut words = [0u64; 6];
    // SAFETY: blst writes six words for one value.
    unsafe { blst_uint64_from_fp(words.as_mut_ptr(), fp) };
    unpack52(&words)
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn coordinate(values: &[blst_fp; LANES]) -> Fp8 {
    Fp8::from_plain(&values.each_ref().map(plain))
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) fn in_lanes(points: &[blst_p1; LANES]) -> G1x8 {
    G1x8 {
        x: coordinate(&points.map(|p| p.x)),
        y: coordinate(&points.map(|p| p.y)),
        z: coordinate(&points.map(|p| p.z)),
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn of_lanes(point: &G1x8) -> [blst_p1; LANES] {
    let (x, y, z) = (point.x.to_blst_limbs(), point.y.to_blst_limbs(), point.z.to_blst_limbs());
    std::array::from_fn(|l| blst_p1 {
        x: blst_fp { l: x[l] },
        y: blst_fp { l: y[l] },
        z: blst_fp { l: z[l] },
    })
}

/// The same point, z = 0 exactly when it is infinity.
fn assert_same_point(got: &blst_p1, want: &blst_p1, case: &str) {
    // SAFETY: valid pointers to single values.
    let (got_infinite, want_infinite, equal) =
        unsafe { (blst_p1_is_inf(got), blst_p1_is_inf(want), blst_p1_is_equal(got, want)) };
    assert!(got_infinite == want_infinite && equal, "{case}");
}

/// Per lane: P + Q, P + P and P − P at other scales, infinity on either side
/// or both, and P + 2P.
#[test]
fn complete_additions_match_blst() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x62);
    let infinity = blst_p1::default();
    let mut odd_infinity = blst_p1::default();
    odd_infinity.x.l[0] = 5;
    odd_infinity.y.l[0] = 7;
    for round in 0..16 {
        let points = random_points(&mut rng, 4);
        let (p, q, r) = (points[0], points[1], points[2]);
        let mut twice = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_double(&mut twice, &p) };
        let left = [p, p, p, infinity, q, odd_infinity, p, rescaled(&r, 7)];
        let right =
            [q, rescaled(&p, 3), rescaled(&negated(&p), 5), q, infinity, infinity, twice, r];
        // SAFETY: `kernels_run` checked `ifma_available`.
        let (sums, doubles, shifted) = unsafe {
            let (a, b) = (in_lanes(&left), in_lanes(&right));
            (
                of_lanes(&a.add_complete(&b)),
                of_lanes(&a.double_complete()),
                of_lanes(&a.times_two_pow(5)),
            )
        };
        for lane in 0..LANES {
            let (mut sum, mut double, mut times_32) =
                (blst_p1::default(), blst_p1::default(), left[lane]);
            // SAFETY: valid pointers to single values.
            unsafe {
                blst_p1_add_or_double(&mut sum, &left[lane], &right[lane]);
                blst_p1_double(&mut double, &left[lane]);
                for _ in 0..5 {
                    let before = times_32;
                    blst_p1_double(&mut times_32, &before);
                }
            }
            assert_same_point(&sums[lane], &sum, &format!("add, round {round}, lane {lane}"));
            assert_same_point(
                &doubles[lane],
                &double,
                &format!("double, round {round}, lane {lane}"),
            );
            assert_same_point(
                &shifted[lane],
                &times_32,
                &format!("[32], round {round}, lane {lane}"),
            );
        }
    }
}

/// Per lane: P + Q, P + P and P − P with P at another scale, infinity plus Q,
/// and P + 2P.
#[test]
fn complete_affine_additions_match_blst() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x63);
    let infinity = blst_p1::default();
    let mut odd_infinity = blst_p1::default();
    odd_infinity.x.l[0] = 5;
    odd_infinity.y.l[0] = 7;
    for round in 0..16 {
        let points = random_points(&mut rng, 4);
        let (p, q, r) = (points[0], points[1], points[2]);
        let mut twice = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_double(&mut twice, &p) };
        let left = [p, rescaled(&p, 3), rescaled(&p, 5), infinity, odd_infinity, p, r, q];
        let right = [q, p, negated(&p), q, r, twice, r, q].map(|point| affine(&point));
        // SAFETY: `kernels_run` checked `ifma_available`.
        let sums = unsafe {
            let a = in_lanes(&left);
            let x = coordinate(&right.map(|point| point.x));
            let y = coordinate(&right.map(|point| point.y));
            of_lanes(&a.add_affine_complete(&x, &y))
        };
        for lane in 0..LANES {
            let mut sum = blst_p1::default();
            // SAFETY: valid pointers to single values.
            unsafe { blst_p1_add_or_double_affine(&mut sum, &left[lane], &right[lane]) };
            assert_same_point(&sums[lane], &sum, &format!("round {round}, lane {lane}"));
        }
    }
}

/// Σ_l [2^(bits·l)] P_l in lane 0, with some lanes at infinity.
#[test]
fn shifted_lane_sums_match_blst() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x64);
    for bits in [1, 4, 6, 8] {
        let mut lanes: [blst_p1; LANES] = random_points(&mut rng, LANES).try_into().unwrap();
        lanes[3] = blst_p1::default();
        lanes[6] = blst_p1::default();
        // SAFETY: `kernels_run` checked `ifma_available`.
        let got = unsafe { of_lanes(&in_lanes(&lanes).sum_lanes_shifted(bits))[0] };
        let mut want = blst_p1::default();
        for lane in (0..LANES).rev() {
            // SAFETY: valid pointers to single values.
            unsafe {
                for _ in 0..bits {
                    let before = want;
                    blst_p1_double(&mut want, &before);
                }
                let before = want;
                blst_p1_add_or_double(&mut want, &before, &lanes[lane]);
            }
        }
        assert_same_point(&got, &want, &format!("{bits} bits"));
    }
}
