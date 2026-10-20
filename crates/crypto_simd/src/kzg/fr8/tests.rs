//! `Fr8::mul` against a reference Montgomery reduction, limb for limb. The
//! refinement of `mul` holds without a precondition, so the inputs go beyond
//! its contract of normalised operands. Also `normalise` against signed
//! carries, and the range of carried products.

use std::arch::x86_64::{
    __m512i, _mm512_add_epi64, _mm512_and_si512, _mm512_madd52lo_epu64, _mm512_srli_epi64,
};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{
    Fr8, LANES, LIMBS, MASK52, R, R_INV52, muladd_row, multiplier, splat, splat_limbs,
    transpose_in, unpack52, zero,
};
use crate::{kernels_run, kzg::blst_ops::fr_from_u64};

type Limbs = [u64; LIMBS];

/// The bound on a limb of `Fr8::mul`'s result.
const PRODUCT_LIMB: u64 = 1 << 57;

#[target_feature(enable = "avx512f,avx512ifma")]
fn reduce_row_reference(
    t: &mut [__m512i; 2 * LIMBS + 1],
    r: &[__m512i; LIMBS],
    rinv: __m512i,
    i: usize,
) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], rinv);
    muladd_row(t, r, q, i);
    t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
}

/// The uncarried Montgomery product whose reduction rows each add the low
/// product that clears their limb, then carry out of the sum.
#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_reference(a: &Fr8, b: &Fr8) -> Fr8 {
    let r = splat_limbs(&R);
    let rinv = splat(R_INV52);
    let mut t = [zero(); 2 * LIMBS + 1];
    for i in 0..LIMBS {
        muladd_row(&mut t, &a.0, b.0[i], i);
    }
    for i in 0..LIMBS {
        reduce_row_reference(&mut t, &r, rinv, i);
    }
    Fr8([t[LIMBS], t[LIMBS + 1], t[LIMBS + 2], t[LIMBS + 3], t[LIMBS + 4]])
}

/// The unsigned carry pass that ended `Fr8::mul` while it returned normalised
/// limbs.
#[target_feature(enable = "avx512f,avx512ifma")]
fn carried_reference(x: &Fr8) -> Fr8 {
    let mask = splat(MASK52);
    let mut out = x.0;
    for j in 0..LIMBS - 1 {
        out[j + 1] = _mm512_add_epi64(out[j + 1], _mm512_srli_epi64::<52>(out[j]));
        out[j] = _mm512_and_si512(out[j], mask);
    }
    Fr8(out)
}

/// k·r + d in normalised limbs.
fn near_multiple_of_r(k: i128, d: i128) -> Limbs {
    let mut out = [0u64; LIMBS];
    let mut carry = d;
    for j in 0..LIMBS {
        let limb = R[j] as i128 * k + carry;
        out[j] = (limb & MASK52 as i128) as u64;
        carry = limb >> 52;
    }
    assert!(carry == 0, "k·r + d lies in [0, 2^260)");
    out
}

fn below(rng: &mut ChaCha8Rng, bound: &Limbs) -> Limbs {
    loop {
        let mut x = [0u64; LIMBS];
        for j in 0..LIMBS - 1 {
            x[j] = rng.r#gen::<u64>() & MASK52;
        }
        x[LIMBS - 1] = rng.gen_range(0..=bound[LIMBS - 1]);
        if is_below(&x, bound) {
            return x;
        }
    }
}

/// Every pair of 0, 1, r − 1, r, r + 1, 2r − 2, 2r − 1, 2^260 mod r (the
/// multiplier of 1), 2r and 2^260 − 1, eight pairs to a vector; then random
/// values below 2r, random normalised limbs, and random 64-bit limbs.
fn operands(rng: &mut ChaCha8Rng) -> Vec<([Limbs; LANES], [Limbs; LANES])> {
    let mut edges: Vec<_> = [(0, 0), (0, 1), (1, -1), (1, 0), (1, 1), (2, -2), (2, -1), (2, 0)]
        .iter()
        .map(|&(k, d)| near_multiple_of_r(k, d))
        .collect();
    edges.extend([unpack52(&multiplier(&fr_from_u64(1)).l), [MASK52; LIMBS]]);
    let pairs: Vec<_> = edges.iter().flat_map(|a| edges.iter().map(move |b| (*a, *b))).collect();
    let mut out: Vec<_> = pairs
        .chunks(LANES)
        .map(|chunk| {
            let lane = |l: usize| chunk[l % chunk.len()];
            (std::array::from_fn(|l| lane(l).0), std::array::from_fn(|l| lane(l).1))
        })
        .collect();

    let two_r = near_multiple_of_r(2, 0);
    for _ in 0..64 {
        out.push((
            std::array::from_fn(|_| below(rng, &two_r)),
            std::array::from_fn(|_| below(rng, &two_r)),
        ));
    }
    for _ in 0..16 {
        out.push((
            std::array::from_fn(|_| std::array::from_fn(|_| rng.r#gen::<u64>() & MASK52)),
            std::array::from_fn(|_| std::array::from_fn(|_| rng.r#gen::<u64>() & MASK52)),
        ));
    }
    for _ in 0..16 {
        out.push((rng.r#gen(), rng.r#gen()));
    }
    out
}

fn is_below(x: &Limbs, bound: &Limbs) -> bool {
    x.iter().rev().lt(bound.iter().rev())
}

#[test]
fn mul_matches_reference_reduction() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0xf58);
    for (case, (a, b)) in operands(&mut rng).iter().enumerate() {
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe {
            let (a, b) = (Fr8(transpose_in(a)), Fr8(transpose_in(b)));
            assert!(a.mul(&b).lane_limbs() == mul_reference(&a, &b).lane_limbs(), "case {case}");
        }
    }
}

/// Callers that carry a product get the limbs `mul` returned when it carried
/// them itself.
#[test]
fn normalised_products_match_carried_reference() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0xca2);
    for (case, (a, b)) in operands(&mut rng).iter().enumerate() {
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe {
            let (a, b) = (Fr8(transpose_in(a)), Fr8(transpose_in(b)));
            let expected = carried_reference(&mul_reference(&a, &b));
            assert!(a.mul(&b).normalise().lane_limbs() == expected.lane_limbs(), "case {case}");
        }
    }
}

/// Moving a signed multiple of 2^52 between neighbouring limbs keeps the
/// value, so `normalise` must restore the normalised limbs, up to 2^61 in
/// limb magnitude.
#[test]
fn normalise_restores_limbs_with_moved_excess() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x0e1);
    for case in 0..256 {
        let mut values = [[0u64; LIMBS]; LANES];
        let mut moved = [[0u64; LIMBS]; LANES];
        for lane in 0..LANES {
            for j in 0..LIMBS {
                values[lane][j] = match case % 4 {
                    0 => MASK52,
                    1 => 0,
                    _ => rng.r#gen::<u64>() & MASK52,
                };
            }
            moved[lane] = values[lane];
            for j in 0..LIMBS - 1 {
                let k = rng.gen_range(-(1i64 << 9)..=1 << 9);
                moved[lane][j] = moved[lane][j].wrapping_add((k << 52) as u64);
                moved[lane][j + 1] = moved[lane][j + 1].wrapping_sub(k as u64);
            }
        }
        // SAFETY: `kernels_run` checked `simd_available`.
        let out = unsafe { Fr8(transpose_in(&moved)).normalise().lane_limbs() };
        assert!(out == values, "case {case}");
    }
}

/// The products the transforms form: normalised data below 2^260 by a
/// multiplier below r.
#[test]
fn products_have_bounded_limbs_and_lie_below_two_r() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x2b0);
    let r = near_multiple_of_r(1, 0);
    let two_r = near_multiple_of_r(2, 0);
    let mut edges = vec![[MASK52; LIMBS], [0; LIMBS], near_multiple_of_r(2, -1)];
    edges.push(near_multiple_of_r(34, 0));
    let multipliers = [near_multiple_of_r(1, -1), [0; LIMBS], near_multiple_of_r(0, 1)];
    for case in 0..128 {
        let data: [Limbs; LANES] = std::array::from_fn(|lane| match (case + lane) % 8 {
            0..4 => edges[(case + lane) % 4],
            _ => std::array::from_fn(|_| rng.r#gen::<u64>() & MASK52),
        });
        let w: [Limbs; LANES] = std::array::from_fn(|lane| match (case + lane) % 4 {
            0..3 => multipliers[(case + lane) % 4],
            _ => below(&mut rng, &r),
        });
        // SAFETY: `kernels_run` checked `simd_available`.
        let (raw, carried) = unsafe {
            let product = Fr8(transpose_in(&data)).mul(&Fr8(transpose_in(&w)));
            (product.lane_limbs(), product.normalise().lane_limbs())
        };
        for lane in 0..LANES {
            assert!(raw[lane].iter().all(|&limb| limb < PRODUCT_LIMB), "case {case} lane {lane}");
            assert!(is_below(&carried[lane], &two_r), "case {case} lane {lane}");
        }
    }
}
