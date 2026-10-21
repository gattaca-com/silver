//! `Fp8::mul` and `Fp8::square` against a reference Montgomery product, limb
//! for limb. The refinement of `mul` holds without a precondition, so the
//! inputs go beyond its contract of normalised values below 2p. Also the
//! widened bound of `mul`, the lazy steps, `carry_of_cleared` and
//! `transpose8`.

use std::arch::x86_64::{
    __m512i, _mm512_add_epi64, _mm512_and_si512, _mm512_madd52lo_epu64, _mm512_srli_epi64,
};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{
    Fp8, LANES, Limbs, carry_of_cleared, lanes, muladd_row, splat, splat_limbs, transpose8, zero,
};
use crate::{
    bls::constants::{LIMBS, MASK52, P, P_INV52, R_MOD_P},
    kernels_run,
};

impl Fp8 {
    /// For the reference formulas, which double where the kernels add lazily.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub(crate) fn double(&self) -> Self {
        self.add(self)
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn reduce_row_reference(
    t: &mut [__m512i; 2 * LIMBS + 1],
    p: &[__m512i; LIMBS],
    pinv: __m512i,
    i: usize,
) {
    let q = _mm512_madd52lo_epu64(zero(), t[i], pinv);
    muladd_row(t, p, q, i);
    t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64::<52>(t[i]));
}

/// The Montgomery product whose reduction rows each add the low product that
/// clears their limb, then carry out of the sum.
#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_reference(a: &Fp8, b: &Fp8) -> Fp8 {
    let p = splat_limbs(&P);
    let pinv = splat(P_INV52);
    let mut t = [zero(); 2 * LIMBS + 1];
    for i in 0..LIMBS {
        muladd_row(&mut t, &a.0, b.0[i], i);
    }
    for i in 0..LIMBS {
        reduce_row_reference(&mut t, &p, pinv, i);
    }

    let mask = splat(MASK52);
    let mut r = [zero(); LIMBS];
    r[0] = t[LIMBS];
    for j in 0..LIMBS - 1 {
        r[j + 1] = _mm512_add_epi64(t[LIMBS + j + 1], _mm512_srli_epi64::<52>(r[j]));
        r[j] = _mm512_and_si512(r[j], mask);
    }
    Fp8(r)
}

/// k·p + d in normalised limbs.
pub(crate) fn near_multiple_of_p(k: i128, d: i128) -> Limbs {
    let mut out = [0u64; LIMBS];
    let mut carry = d;
    for j in 0..LIMBS {
        let limb = P[j] as i128 * k + carry;
        out[j] = (limb & MASK52 as i128) as u64;
        carry = limb >> 52;
    }
    assert!(carry == 0, "k·p + d lies in [0, 2^416)");
    out
}

pub(crate) fn below(rng: &mut ChaCha8Rng, bound: &Limbs) -> Limbs {
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

/// Every pair of `edges`, eight pairs to a vector.
fn every_pair(edges: &[Limbs]) -> Vec<([Limbs; LANES], [Limbs; LANES])> {
    let pairs: Vec<_> = edges.iter().flat_map(|a| edges.iter().map(move |b| (*a, *b))).collect();
    pairs
        .chunks(LANES)
        .map(|chunk| {
            let lane = |l: usize| chunk[l % chunk.len()];
            (std::array::from_fn(|l| lane(l).0), std::array::from_fn(|l| lane(l).1))
        })
        .collect()
}

fn random_pairs_below(
    rng: &mut ChaCha8Rng,
    bound: &Limbs,
    count: usize,
) -> Vec<([Limbs; LANES], [Limbs; LANES])> {
    (0..count)
        .map(|_| {
            (std::array::from_fn(|_| below(rng, bound)), std::array::from_fn(|_| below(rng, bound)))
        })
        .collect()
}

/// Every pair of 0, 1, p − 1, p, p + 1, 2p − 2, 2p − 1, the Montgomery one,
/// 2p and 2^416 − 1, eight pairs to a vector; then random values below 2p,
/// random normalised limbs, and random 64-bit limbs.
fn operands(rng: &mut ChaCha8Rng) -> Vec<([Limbs; LANES], [Limbs; LANES])> {
    let mut edges: Vec<_> = [(0, 0), (0, 1), (1, -1), (1, 0), (1, 1), (2, -2), (2, -1), (2, 0)]
        .iter()
        .map(|&(k, d)| near_multiple_of_p(k, d))
        .collect();
    edges.extend([R_MOD_P, [MASK52; LIMBS]]);
    let mut out = every_pair(&edges);
    out.extend(random_pairs_below(rng, &near_multiple_of_p(2, 0), 64));
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
    let mut rng = ChaCha8Rng::seed_from_u64(0xf98);
    for (case, (a, b)) in operands(&mut rng).iter().enumerate() {
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe {
            let (a, b) = (Fp8::load(a), Fp8::load(b));
            assert!(a.mul(&b).store() == mul_reference(&a, &b).store(), "case {case}");
        }
    }
}

/// The model of `square` is `mul(x, x)`.
#[test]
fn square_matches_reference_product() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x5a);
    for (case, (a, b)) in operands(&mut rng).iter().enumerate() {
        for x in [a, b] {
            // SAFETY: `kernels_run` checked `simd_available`.
            unsafe {
                let x = Fp8::load(x);
                assert!(x.square().store() == mul_reference(&x, &x).store(), "case {case}");
            }
        }
    }
}

/// d + k·p in normalised limbs.
pub(crate) fn plus_multiple_of_p(d: &Limbs, k: u64) -> Limbs {
    let mut out = [0u64; LIMBS];
    let mut carry = 0u128;
    for j in 0..LIMBS {
        let limb = d[j] as u128 + P[j] as u128 * k as u128 + carry;
        out[j] = limb as u64 & MASK52;
        carry = limb >> 52;
    }
    assert!(carry == 0, "d + k·p lies in [0, 2^416)");
    out
}

/// Operands up to 2^34·p against ones below 2p, and up to 2^17·p against
/// each other, give products below 2p with the values of their residues'
/// products. The first case puts every operand at its bound.
#[test]
fn mul_reduces_operands_within_its_bound() {
    if !kernels_run() {
        return;
    }
    const MAX_34: u64 = (1 << 34) - 1;
    const MAX_17: u64 = (1 << 17) - 1;
    let mut rng = ChaCha8Rng::seed_from_u64(0x17);
    let p = near_multiple_of_p(1, 0);
    let two_p = near_multiple_of_p(2, 0);
    for case in 0..16 {
        let mut residues = [[[0u64; LIMBS]; LANES]; 2];
        let mut operands = [[[0u64; LIMBS]; LANES]; 2];
        for lane in 0..LANES {
            let multiples = match lane % 4 {
                0 => [MAX_34, 1],
                1 => [rng.gen_range(0..=1), rng.gen_range(0..=MAX_34)],
                2 => [MAX_17, MAX_17],
                _ => [rng.gen_range(0..=MAX_17), rng.gen_range(0..=MAX_17)],
            };
            for k in 0..2 {
                residues[k][lane] =
                    if case == 0 { near_multiple_of_p(1, -1) } else { below(&mut rng, &p) };
                operands[k][lane] = plus_multiple_of_p(&residues[k][lane], multiples[k]);
            }
        }
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe {
            let product = Fp8::load(&operands[0]).mul(&Fp8::load(&operands[1]));
            for limbs in product.store() {
                assert!(limbs.iter().rev().lt(two_p.iter().rev()), "case {case}: {limbs:x?}");
            }
            let want = Fp8::load(&residues[0]).mul(&Fp8::load(&residues[1]));
            assert!(product.canonical().store() == want.canonical().store(), "case {case}");
        }
    }
}

#[test]
fn multiple_of_p_is_normalised_c_times_p() {
    if !kernels_run() {
        return;
    }
    for c in [0, 1, 2, 4, 8, (1 << 12) - 1] {
        // SAFETY: `kernels_run` checked `simd_available`.
        let got = unsafe { Fp8::multiple_of_p(c).store() };
        assert!(got == [near_multiple_of_p(c as i128, 0); LANES], "c = {c}");
    }
}

/// On every pair of 0, 1, p − 1, p, p + 1, 2p − 2 and 2p − 1, and on random
/// pairs below 2p, the lazy steps reach the limbs of `add` and `sub`.
#[test]
fn lazy_steps_match_add_and_sub() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x1a27);
    let edges: Vec<_> = [(0, 0), (0, 1), (1, -1), (1, 0), (1, 1), (2, -2), (2, -1)]
        .iter()
        .map(|&(k, d)| near_multiple_of_p(k, d))
        .collect();
    let mut pairs = every_pair(&edges);
    pairs.extend(random_pairs_below(&mut rng, &near_multiple_of_p(2, 0), 64));
    for (case, (a, b)) in pairs.iter().enumerate() {
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe {
            let (a, b, two_p) = (Fp8::load(a), Fp8::load(b), Fp8::multiple_of_p(2));
            let sum = a.add_raw(&b).normalise().cond_sub(&two_p);
            assert!(sum.store() == a.add(&b).store(), "sum, case {case}");
            let difference = a.sub_raw(&b, &two_p).normalise().cond_sub(&two_p);
            assert!(difference.store() == a.sub(&b).store(), "difference, case {case}");
        }
    }
}

/// The identity the early carry rests on, at the 64-bit boundaries where the
/// sums wrap as well as at random.
#[test]
fn carry_of_cleared_matches_the_carry_of_the_cleared_sum() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0xca7);
    let mut limbs = vec![0, 1, MASK52, MASK52 + 1, MASK52 + 2, 7 << 52, (7 << 52) + 1];
    limbs.extend([u64::MAX - MASK52, u64::MAX - MASK52 + 1, u64::MAX - 1, u64::MAX]);
    limbs.extend((0..64).map(|_| rng.r#gen::<u64>()));
    for chunk in limbs.chunks(LANES) {
        let t: [u64; LANES] = std::array::from_fn(|l| chunk[l % chunk.len()]);
        let mut cleared = [0u64; LANES];
        for l in 0..LANES {
            let q = (t[l] & MASK52).wrapping_mul(P_INV52) & MASK52;
            let low = q.wrapping_mul(P[0]) & MASK52;
            cleared[l] = t[l].wrapping_add(low) >> 52;
        }
        // SAFETY: `kernels_run` checked `simd_available`.
        let got = unsafe {
            let t = Fp8::load(&std::array::from_fn(|l| [t[l]; LIMBS]));
            lanes(carry_of_cleared(t.0[0]))
        };
        assert!(got == cleared, "{t:x?}");
    }
}

/// Reduced inputs, canonical or not: 0, 1, p − 1, p, p + 1, 2p − 1, the
/// Montgomery one, and random values below 2p. Zero, also as p, maps to zero;
/// every other lane multiplies back to one.
#[test]
fn inverse_multiplies_back_to_one() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x1a7e);
    let mut values: Vec<_> = [(0, 0), (0, 1), (1, -1), (1, 0), (1, 1), (2, -1)]
        .iter()
        .map(|&(k, d)| near_multiple_of_p(k, d))
        .collect();
    values.push(R_MOD_P);
    values.extend((0..57).map(|_| below(&mut rng, &near_multiple_of_p(2, 0))));
    for chunk in values.chunks(LANES) {
        let lanes_of: [Limbs; LANES] = std::array::from_fn(|l| chunk[l % chunk.len()]);
        // SAFETY: `kernels_run` checked `simd_available`.
        let (zero_lanes, zero_inverses, ones) = unsafe {
            let a = Fp8::load(&lanes_of);
            let inverse = a.inverse();
            (a.is_zero_mask(), inverse.is_zero_mask(), a.mul(&inverse).eq_mask(&Fp8::one()))
        };
        assert!(zero_inverses == zero_lanes, "{lanes_of:x?}");
        assert!(ones == !zero_lanes, "{lanes_of:x?}");
    }
}

/// Every lane holds a distinct value, so any misplaced lane shows.
#[test]
fn transpose8_swaps_rows_and_lanes() {
    if !kernels_run() {
        return;
    }
    let value = |row: usize, lane: usize| (LANES * row + lane) as u64;
    // SAFETY: `kernels_run` checked `simd_available`.
    let out = unsafe {
        let rows =
            Fp8::load(&std::array::from_fn(|lane| std::array::from_fn(|row| value(row, lane))));
        transpose8(&rows.0)
    };
    for row in 0..LANES {
        for lane in 0..LANES {
            assert!(lanes(out[lane])[row] == value(row, lane), "lane {lane} of row {row}");
        }
    }
}
