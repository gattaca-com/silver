//! The point formulas against the exact ones they rearrange, on reduced
//! inputs at their bounds and at random: the same values modulo p and the
//! same undecided lanes, with reduced coordinates out.

use std::arch::x86_64::__mmask8;

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use super::G1x8;
use crate::{
    bls::{
        constants::{LIMBS, MASK52, R_MOD_P},
        fp8::{
            Fp8, LANES, Limbs, lanes,
            tests::{below, near_multiple_of_p},
        },
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

/// Lane l's limbs, as they are.
fn lane_limbs(v: &Fp8) -> [Limbs; LANES] {
    let mut out = [[0u64; LIMBS]; LANES];
    for j in 0..LIMBS {
        let l = lanes(v.0[j]);
        for lane in 0..LANES {
            out[lane][j] = l[lane];
        }
    }
    out
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn assert_same_points(got: &(G1x8, __mmask8), want: &(G1x8, __mmask8), formula: &str) {
    assert!(got.1 == want.1, "{formula}: undecided lanes");
    let two_p = near_multiple_of_p(2, 0);
    for (g, w) in [(&got.0.x, &want.0.x), (&got.0.y, &want.0.y), (&got.0.z, &want.0.z)] {
        for limbs in lane_limbs(g) {
            let normalised = limbs.iter().all(|&limb| limb <= MASK52);
            let below_two_p = limbs.iter().rev().lt(two_p.iter().rev());
            assert!(normalised && below_two_p, "{formula}: {limbs:x?} not reduced");
        }
        assert!(lane_limbs(&g.canonical()) == lane_limbs(&w.canonical()), "{formula}: values");
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
        // SAFETY: `kernels_run` checked `simd_available`.
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
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe { assert_formulas_match(&coordinates, &format!("case {case}")) };
    }
}
