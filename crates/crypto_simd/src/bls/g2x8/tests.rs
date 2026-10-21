//! The G2 point formulas against the exact ones they rearrange, on reduced
//! inputs at their bounds and at random: the same values modulo p and the
//! same undecided lanes, with reduced coordinates out.

use std::arch::x86_64::__mmask8;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::G2x8;
use crate::{
    bls::{
        constants::{LIMBS, R_MOD_P},
        fp2x8::{
            Fp2x8,
            tests::{assert_reduced, assert_same_value},
        },
        fp8::{
            Fp8, LANES, Limbs,
            tests::{below, near_multiple_of_p},
        },
    },
    kernels_run,
};

impl G2x8 {
    #[target_feature(enable = "avx512f,avx512ifma")]
    fn double_reference(&self) -> (Self, __mmask8) {
        let a = self.x.square_reference();
        let b = self.y.square_reference();
        let c = b.square_reference();
        let d = self.x.add(&b).square_reference().sub(&a).sub(&c).double();
        let e = a.double().add(&a);
        let f = e.square_reference();
        let x3 = f.sub(&d.double());
        let y3 = e.mul_reference(&d.sub(&x3)).sub(&c.double().double().double());
        let z3 = self.y.mul_reference(&self.z).double();
        let undecided = self.y.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }

    #[target_feature(enable = "avx512f,avx512ifma")]
    fn add_affine_reference(&self, qx: &Fp2x8, qy: &Fp2x8) -> (Self, __mmask8) {
        let z1z1 = self.z.square_reference();
        let u2 = qx.mul_reference(&z1z1);
        let s2 = qy.mul_reference(&self.z).mul_reference(&z1z1);
        let h = u2.sub(&self.x);
        let hh = h.square_reference();
        let i = hh.double().double();
        let j = h.mul_reference(&i);
        let r = s2.sub(&self.y).double();
        let v = self.x.mul_reference(&i);
        let x3 = r.square_reference().sub(&j).sub(&v.double());
        let y3 = r.mul_reference(&v.sub(&x3)).sub(&self.y.mul_reference(&j).double());
        let z3 = self.z.add(&h).square_reference().sub(&z1z1).sub(&hh);
        let undecided = h.is_zero_mask() | self.z.is_zero_mask();
        (Self { x: x3, y: y3, z: z3 }, undecided)
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn assert_same_points(got: &(G2x8, __mmask8), want: &(G2x8, __mmask8), formula: &str) {
    assert!(got.1 == want.1, "{formula}: undecided lanes");
    for (g, w, coordinate) in
        [(&got.0.x, &want.0.x, "x"), (&got.0.y, &want.0.y, "y"), (&got.0.z, &want.0.z, "z")]
    {
        let what = format!("{formula}, {coordinate}");
        assert_reduced(g, &what);
        assert_same_value(g, w, &what);
    }
}

/// x, y, z, qx and qy, two components each.
type Coordinates = [[Limbs; LANES]; 10];

#[target_feature(enable = "avx512f,avx512ifma")]
fn assert_formulas_match(coordinates: &Coordinates, case: &str) {
    let f = coordinates.map(|c| Fp8::load(&c));
    let fp2 = |k: usize| Fp2x8 { c0: f[2 * k], c1: f[2 * k + 1] };
    let p = G2x8 { x: fp2(0), y: fp2(1), z: fp2(2) };
    let (qx, qy) = (fp2(3), fp2(4));
    assert_same_points(&p.double(), &p.double_reference(), &format!("double, {case}"));
    assert_same_points(
        &p.add_affine(&qx, &qy),
        &p.add_affine_reference(&qx, &qy),
        &format!("add_affine, {case}"),
    );
}

/// 0, one, p − 1, p and 2p − 1.
fn edges() -> [Limbs; 5] {
    let [zero, p_minus_one, p, two_p_minus_one] =
        [(0, 0), (1, -1), (1, 0), (2, -1)].map(|(k, d)| near_multiple_of_p(k, d));
    [zero, R_MOD_P, p_minus_one, p, two_p_minus_one]
}

/// Every combination of the edges for the five coordinates, both components
/// of a coordinate alike, eight combinations to a vector.
#[test]
fn formulas_match_the_reference_at_the_input_bounds() {
    if !kernels_run() {
        return;
    }
    let edges = edges();
    let combinations = edges.len().pow(5);
    for first in (0..combinations).step_by(LANES) {
        let mut coordinates = [[[0u64; LIMBS]; LANES]; 10];
        for lane in 0..LANES {
            let mut n = (first + lane) % combinations;
            for k in 0..5 {
                let edge = edges[n % edges.len()];
                coordinates[2 * k][lane] = edge;
                coordinates[2 * k + 1][lane] = edge;
                n /= edges.len();
            }
        }
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe { assert_formulas_match(&coordinates, &format!("combinations from {first}")) };
    }
}

/// Every component an edge drawn at random, so the two components of a
/// coordinate differ.
#[test]
fn formulas_match_the_reference_on_random_edges() {
    if !kernels_run() {
        return;
    }
    let edges = edges();
    let mut rng = ChaCha8Rng::seed_from_u64(0xe2);
    for case in 0..512 {
        let coordinates =
            std::array::from_fn(|_| std::array::from_fn(|_| edges[rng.gen_range(0..edges.len())]));
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe { assert_formulas_match(&coordinates, &format!("case {case}")) };
    }
}

/// Random values below 2p: the arithmetic does not need curve points.
#[test]
fn formulas_match_the_reference_on_random_lanes() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x62);
    let two_p = near_multiple_of_p(2, 0);
    for case in 0..256 {
        let coordinates = std::array::from_fn(|_| std::array::from_fn(|_| below(&mut rng, &two_p)));
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe { assert_formulas_match(&coordinates, &format!("case {case}")) };
    }
}
