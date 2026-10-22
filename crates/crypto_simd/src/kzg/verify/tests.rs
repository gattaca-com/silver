use blst::{blst_fp, blst_fp_from_uint64, blst_p1, blst_p1_generator, blst_p1_mult};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{Lincomb, pairing_points_in_lanes};
use crate::{
    bls::blst_p1_affine,
    kernels_run,
    kzg::blst_ops::{g1_add, g1_neg, g1_to_affine},
};

/// [k]G for a random k, in the Jacobian form blst's multiplication leaves.
fn random_point(rng: &mut ChaCha8Rng) -> blst_p1 {
    let mut scalar: [u8; 32] = rng.r#gen();
    scalar[31] &= 0x3f;
    let mut point = blst_p1::default();
    // SAFETY: blst returns a pointer to its static generator; valid pointers to
    // single values, and blst reads 255 bits of the 32-byte scalar.
    unsafe { blst_p1_mult(&mut point, blst_p1_generator(), scalar.as_ptr(), 255) };
    point
}

/// p in another Jacobian form: (p + q) − q.
fn rescaled(p: &blst_p1, q: &blst_p1) -> blst_p1 {
    g1_add(&g1_add(p, q), &g1_neg(q))
}

fn blst_pairing_points(sums: &[blst_p1; 4]) -> (blst_p1_affine, blst_p1_affine) {
    let rl = g1_add(&g1_add(&sums[1], &g1_neg(&sums[2])), &sums[3]);
    (g1_to_affine(&sums[0]), g1_to_affine(&rl))
}

/// LL, RLC, RLI and RLP: random points, infinity in each place in blst's
/// all-zero form and in `Msm8`'s (1, 1, 0), RLC − RLI at P − P and P + P,
/// and RL by doubling or cancelling at the last addition.
fn cases(rng: &mut ChaCha8Rng) -> Vec<[blst_p1; 4]> {
    let mut one = blst_fp::default();
    // SAFETY: blst reads one word and writes one value.
    unsafe { blst_fp_from_uint64(&mut one, [1u64].as_ptr()) };
    let infinities = [blst_p1::default(), blst_p1 { x: one, y: one, z: blst_fp::default() }];
    let mut cases = Vec::new();
    for _ in 0..16 {
        let sums = [random_point(rng), random_point(rng), random_point(rng), random_point(rng)];
        cases.push(sums);
        for infinity in &infinities {
            for k in 0..4 {
                let mut with_infinity = sums;
                with_infinity[k] = *infinity;
                cases.push(with_infinity);
            }
            cases.push([*infinity; 4]);
        }
        let [ll, rlc, _, rlp] = sums;
        let other = random_point(rng);
        for rli in [rlc, rescaled(&rlc, &other), g1_neg(&rlc), g1_neg(&rescaled(&rlc, &other))] {
            cases.push([ll, rlc, rli, rlp]);
            let difference = g1_add(&rlc, &g1_neg(&rli));
            cases.push([ll, rlc, rli, rescaled(&difference, &other)]);
            cases.push([ll, rlc, rli, g1_neg(&difference)]);
        }
    }
    cases
}

#[test]
fn pairing_points_match_blst() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x9a1);
    for (case, sums) in cases(&mut rng).iter().enumerate() {
        let (want_left, want_right) = blst_pairing_points(sums);
        // SAFETY: `kernels_run` checked `simd_available`.
        let (x, y) = unsafe {
            let (x, y) =
                pairing_points_in_lanes(&sums[0], &sums[1], &sums[2], &sums[3]).to_affine();
            (x.to_blst_limbs(), y.to_blst_limbs())
        };
        assert!(x[0] == want_left.x.l && y[0] == want_left.y.l, "case {case}: LL");
        assert!(x[1] == want_right.x.l && y[1] == want_right.y.l, "case {case}: RL");
    }
}

/// The lanes' verdict is blst's on every case, some of which hold: LL and RL
/// at infinity together.
#[test]
fn pairing_check_matches_blst() {
    if !kernels_run() {
        return;
    }
    let lanes = Lincomb::new();
    let blst = Lincomb { msm: None, ..Lincomb::new() };
    let mut rng = ChaCha8Rng::seed_from_u64(0x9a2);
    let mut held = 0;
    for (case, sums) in cases(&mut rng).iter().enumerate() {
        let want = blst.pairing_check(&sums[0], &sums[1], &sums[2], &sums[3]);
        assert_eq!(
            lanes.pairing_check(&sums[0], &sums[1], &sums[2], &sums[3]),
            want,
            "case {case}"
        );
        held += want as usize;
    }
    assert!(held > 0, "no case holds");
}
