//! The Miller loop and the pairing check against the spec's and blst's. The
//! Miller values compare after blst's final exponentiation, which removes
//! the factors each line form leaves.

use blst::{
    blst_final_exp, blst_fp, blst_fp2, blst_fp12, blst_fp12_is_one, blst_miller_loop, blst_p1,
    blst_p1_affine, blst_p1_affine_generator, blst_p1_affine_is_inf, blst_p1_from_affine,
    blst_p1_mult, blst_p2, blst_p2_affine, blst_p2_affine_generator, blst_p2_from_affine,
    blst_p2_mult, blst_p2_to_affine,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{LINE_COUNT, MillerLines};
use crate::{
    bls::{
        constants::LIMBS,
        fp8::{Fp8, LANES},
        fp12::tests::blst_of_lanes,
        g1x8::{
            G1x8,
            tests::{affine, in_lanes, negated, random_points, rescaled},
        },
        spec_pairing::{self, fp, inverse, miller_lines, mul, of_g1, of_g2, pairing_product, zero},
    },
    kernels_run,
};

/// A random 255-bit scalar, little-endian.
pub(crate) fn random_scalar(rng: &mut ChaCha8Rng) -> [u8; 32] {
    let mut scalar: [u8; 32] = rng.r#gen();
    scalar[31] &= 0x7f;
    scalar
}

pub(crate) fn g1_times(p: &blst_p1, scalar: &[u8; 32]) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: valid pointers to single values; blst reads 255 bits.
    unsafe { blst_p1_mult(&mut out, p, scalar.as_ptr(), 255) };
    out
}

pub(crate) fn g2_times(q: &blst_p2_affine, scalar: &[u8; 32]) -> blst_p2_affine {
    let (mut point, mut product, mut out) =
        (blst_p2::default(), blst_p2::default(), blst_p2_affine::default());
    // SAFETY: valid pointers to single values; blst reads 255 bits.
    unsafe {
        blst_p2_from_affine(&mut point, q);
        blst_p2_mult(&mut product, &point, scalar.as_ptr(), 255);
        blst_p2_to_affine(&mut out, &product);
    }
    out
}

/// A multiple of the G2 generator by a random 255-bit scalar.
pub(crate) fn random_g2(rng: &mut ChaCha8Rng) -> blst_p2_affine {
    // SAFETY: blst returns a pointer to its static generator.
    g2_times(unsafe { &*blst_p2_affine_generator() }, &random_scalar(rng))
}

pub(crate) fn jacobian(p: &blst_p1_affine) -> blst_p1 {
    let mut out = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_from_affine(&mut out, p) };
    out
}

pub(crate) fn final_exp(f: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_final_exp(&mut out, f) };
    out
}

fn blst_miller(q: &blst_p2_affine, p: &blst_p1_affine) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_miller_loop(&mut out, q, p) };
    out
}

fn embedded(a: &blst_fp2) -> blst_fp12 {
    let mut f = zero();
    f.fp6[0].fp2[0] = *a;
    f
}

fn embedded_fp(a: &blst_fp) -> blst_fp12 {
    let mut fp2 = blst_fp2::default();
    fp2.fp[0] = *a;
    embedded(&fp2)
}

/// The lines of two G2 points in blst's form, lanes as in `MillerLines`, from
/// the spec's lines at the G1 generator (x, y): w³ times a spec line is
/// c·((1, l1·x, 0) + (0, l2·y, 0)·w), with c in Fp2.
pub(crate) fn line_values(points: &[blst_p2_affine; 2]) -> [[[u64; 6]; LANES]; LINE_COUNT] {
    // SAFETY: blst returns a pointer to a static point.
    let g = unsafe { *blst_p1_affine_generator() };
    let (x_inverse, y_inverse) = (inverse(&embedded_fp(&g.x)), inverse(&embedded_fp(&g.y)));
    let mut w_cubed = zero();
    w_cubed.fp6[1].fp2[1].fp[0] = fp(1);
    let mut values = [[[0u64; 6]; LANES]; LINE_COUNT];
    for (pair, q) in points.iter().enumerate() {
        for (step, line) in miller_lines(&of_g2(q), &of_g1(&g)).iter().enumerate() {
            let scaled = mul(line, &w_cubed);
            let c_inverse = inverse(&embedded(&scaled.fp6[0].fp2[0]));
            let l1 = mul(&mul(&embedded(&scaled.fp6[0].fp2[1]), &c_inverse), &x_inverse);
            let l2 = mul(&mul(&embedded(&scaled.fp6[1].fp2[1]), &c_inverse), &y_inverse);
            let (l1, l2) = (l1.fp6[0].fp2[0], l2.fp6[0].fp2[0]);
            let lanes = &mut values[step][4 * pair..4 * pair + 4];
            lanes.copy_from_slice(&[l1.fp[0].l, l1.fp[1].l, l2.fp[0].l, l2.fp[1].l]);
        }
    }
    values
}

/// The `MillerLines` of two G2 points, from `line_values`.
#[target_feature(enable = "avx512f,avx512ifma")]
fn lines_of(points: &[blst_p2_affine; 2]) -> MillerLines {
    let values = line_values(points);
    let mut lines = [[[0u64; LIMBS]; LANES]; LINE_COUNT];
    for step in 0..LINE_COUNT {
        lines[step] = Fp8::from_blst_limbs(&values[step]).canonical().store();
    }
    MillerLines(lines)
}

/// Lanes 0 and 1 hold `points`; the other lanes repeat lane 0.
#[target_feature(enable = "avx512f,avx512ifma")]
fn pair_lanes(points: &[blst_p1; 2]) -> G1x8 {
    let mut lanes = [points[0]; LANES];
    lanes[1] = points[1];
    in_lanes(&lanes)
}

/// The Miller loop on lanes, the spec's `pairingCheck` accumulator and
/// blst's Miller loop agree after the final exponentiation. The G1 points
/// come with z ≠ 1, with z = 1, and rescaled.
#[test]
fn miller_loop_matches_the_spec_after_the_final_exponentiation() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x4d11);
    for _ in 0..4 {
        let p = random_points(&mut rng, 2);
        let p = [p[0], p[1]];
        let q = [random_g2(&mut rng), random_g2(&mut rng)];
        let a = [affine(&p[0]), affine(&p[1])];
        let want = final_exp(&pairing_product(&[(a[0], q[0]), (a[1], q[1])]));
        let blst = mul(&blst_miller(&q[0], &a[0]), &blst_miller(&q[1], &a[1]));
        assert!(final_exp(&blst) == want, "blst's Miller values are the spec's");
        let scales =
            [p, [jacobian(&a[0]), jacobian(&a[1])], [rescaled(&p[0], 3), rescaled(&p[1], 5)]];
        // SAFETY: `kernels_run` held.
        unsafe {
            let lines = lines_of(&q);
            for (case, points) in scales.iter().enumerate() {
                let got = blst_of_lanes(&lines.miller_loop(&pair_lanes(points)));
                assert!(final_exp(&got) == want, "scale {case}");
            }
        }
    }
}

/// A pair whose G1 point is infinity is left out, as `pairingCheck` leaves
/// it out. z = p is infinity too, since `G1x8` coordinates are only
/// reduced.
#[test]
fn miller_loop_leaves_out_points_at_infinity() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x1f);
    let p = random_points(&mut rng, 2);
    let q = [random_g2(&mut rng), random_g2(&mut rng)];
    let infinity = blst_p1 { z: blst_fp::default(), ..p[0] };
    let alone = |pair: usize| final_exp(&pairing_product(&[(affine(&p[pair]), q[pair])]));
    // SAFETY: `kernels_run` held.
    unsafe {
        let lines = lines_of(&q);
        let got = |points: &[blst_p1; 2]| {
            final_exp(&blst_of_lanes(&lines.miller_loop(&pair_lanes(points))))
        };
        assert!(got(&[infinity, p[1]]) == alone(1), "first at infinity");
        assert!(got(&[p[0], infinity]) == alone(0), "second at infinity");
        assert!(lines.miller_loop(&pair_lanes(&[infinity, infinity])).is_one(), "both");
        let mut lazy = pair_lanes(&[p[0], p[1]]);
        lazy.z = Fp8::multiple_of_p(1);
        assert!(lines.miller_loop(&lazy).is_one(), "z = p");
    }
}

/// blst's verdict, leaving out each pair with its G1 point at infinity.
pub(crate) fn blst_pairing_check(pairs: &[(blst_p1_affine, blst_p2_affine)]) -> bool {
    let mut product = spec_pairing::one();
    for (p, q) in pairs {
        // SAFETY: a valid pointer to a single value.
        if !unsafe { blst_p1_affine_is_inf(p) } {
            product = mul(&product, &blst_miller(q, p));
        }
    }
    // SAFETY: a valid pointer to a single value.
    unsafe { blst_fp12_is_one(&final_exp(&product)) }
}

/// The pairing check against the spec's `pairingCheck` and blst's: on a
/// balanced product, the same with a wrong sign, unrelated points, and
/// points at infinity.
#[test]
fn pairing_check_matches_the_spec() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x9c);
    let p = random_points(&mut rng, 3);
    let q = [random_g2(&mut rng), random_g2(&mut rng)];
    let a = random_scalar(&mut rng);
    let (ap, aq) = (g1_times(&p[0], &a), g2_times(&q[0], &a));
    let infinity = blst_p1 { z: blst_fp::default(), ..p[0] };
    let cases = [
        ("balanced", [ap, negated(&p[0])], [q[0], aq], true),
        ("wrong sign", [ap, p[0]], [q[0], aq], false),
        ("unrelated", [p[1], p[2]], q, false),
        ("first at infinity", [infinity, p[1]], q, false),
        ("second at infinity", [p[1], infinity], q, false),
        ("both at infinity", [infinity, infinity], q, true),
    ];
    for (name, points, g2, want) in cases {
        let pairs = [(affine(&points[0]), g2[0]), (affine(&points[1]), g2[1])];
        assert_eq!(spec_pairing::pairing_check(&pairs), want, "{name}: the spec");
        assert_eq!(blst_pairing_check(&pairs), want, "{name}: blst");
        // SAFETY: `kernels_run` held.
        let got = unsafe { lines_of(&g2).pairing_check(&pair_lanes(&points)) };
        assert_eq!(got, want, "{name}");
    }
}
