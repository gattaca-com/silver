//! `Fr8::mul` against a reference Montgomery reduction, limb for limb. The
//! refinement of `mul` holds without a precondition, so the inputs go beyond
//! its contract of normalised values below 2r.

use std::arch::x86_64::{
    __m512i, _mm512_add_epi64, _mm512_and_si512, _mm512_madd52lo_epu64, _mm512_srli_epi64,
};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{
    Fr8, LANES, LIMBS, MASK52, R, R_INV52, lanes, muladd_row, multiplier, splat, splat_limbs,
    transpose_in, unpack52, zero,
};
use crate::{kernels_run, kzg::blst_ops::fr_from_u64};

type Limbs = [u64; LIMBS];

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

/// The Montgomery product whose reduction rows each add the low product that
/// clears their limb, then carry out of the sum.
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

    let mask = splat(MASK52);
    let mut out = [zero(); LIMBS];
    out[0] = t[LIMBS];
    for j in 0..LIMBS - 1 {
        out[j + 1] = _mm512_add_epi64(t[LIMBS + j + 1], _mm512_srli_epi64::<52>(out[j]));
        out[j] = _mm512_and_si512(out[j], mask);
    }
    Fr8(out)
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn limbs_of(v: &Fr8) -> [Limbs; LANES] {
    let mut out = [[0u64; LIMBS]; LANES];
    for j in 0..LIMBS {
        let l = lanes(v.0[j]);
        for lane in 0..LANES {
            out[lane][j] = l[lane];
        }
    }
    out
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
        if x.iter().rev().lt(bound.iter().rev()) {
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
            assert!(limbs_of(&a.mul(&b)) == limbs_of(&mul_reference(&a, &b)), "case {case}");
        }
    }
}
