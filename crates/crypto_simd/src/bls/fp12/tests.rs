use blst::{
    blst_final_exp, blst_fp, blst_fp2, blst_fp6, blst_fp12, blst_fp12_conjugate,
    blst_fp12_cyclotomic_sqr, blst_fp12_frobenius_map, blst_fp12_inverse, blst_fp12_mul,
    blst_fp12_mul_by_xy00z0, blst_fp12_sqr,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{BOUND, Fp12};
use crate::{
    bls::{
        constants::{LIMB_BITS, LIMBS, MASK52, P, P_U64},
        fp2x8::Fp2x8,
        fp8::Fp8,
        limbs::LANES,
        spec_pairing,
    },
    ifma_kernels_run,
};

fn random_fp(rng: &mut ChaCha8Rng) -> blst_fp {
    loop {
        let mut l = [0u64; 6];
        rng.fill(&mut l[..]);
        l[5] &= (1 << 61) - 1;
        let mut j = 6;
        while j > 0 && l[j - 1] == P_U64[j - 1] {
            j -= 1;
        }
        if j > 0 && l[j - 1] < P_U64[j - 1] {
            return blst_fp { l };
        }
    }
}

fn p_minus_one() -> blst_fp {
    let mut l = P_U64;
    l[0] -= 1;
    blst_fp { l }
}

fn random_fp2(rng: &mut ChaCha8Rng) -> blst_fp2 {
    blst_fp2 { fp: [random_fp(rng), random_fp(rng)] }
}

pub(crate) fn random_fp12(rng: &mut ChaCha8Rng) -> blst_fp12 {
    let mut f = blst_fp12::default();
    for h in 0..2 {
        for k in 0..3 {
            f.fp6[h].fp2[k] = random_fp2(rng);
        }
    }
    f
}

pub(crate) fn extreme_fp12() -> blst_fp12 {
    let mut f = blst_fp12::default();
    for h in 0..2 {
        for k in 0..3 {
            f.fp6[h].fp2[k] = blst_fp2 { fp: [p_minus_one(), p_minus_one()] };
        }
    }
    f
}

pub(crate) fn random_line(rng: &mut ChaCha8Rng) -> blst_fp6 {
    blst_fp6 { fp2: [random_fp2(rng), random_fp2(rng), random_fp2(rng)] }
}

pub(crate) fn blst_mul(a: &blst_fp12, b: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_mul(&mut out, a, b) };
    out
}

pub(crate) fn blst_square(a: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_sqr(&mut out, a) };
    out
}

pub(crate) fn blst_mul_by_line(a: &blst_fp12, line: &blst_fp6) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_mul_by_xy00z0(&mut out, a, line) };
    out
}

pub(crate) fn blst_cyclotomic_square(a: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_cyclotomic_sqr(&mut out, a) };
    out
}

pub(crate) fn blst_frobenius(a: &blst_fp12, n: usize) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_frobenius_map(&mut out, a, n) };
    out
}

pub(crate) fn blst_inverse(a: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_fp12_inverse(&mut out, a) };
    out
}

pub(crate) fn blst_conjugate(a: &blst_fp12) -> blst_fp12 {
    let mut out = *a;
    // SAFETY: a valid pointer to a single value.
    unsafe { blst_fp12_conjugate(&mut out) };
    out
}

/// f^((p^6 − 1)(p^2 + 1)), in the cyclotomic subgroup.
pub(crate) fn cyclotomic(f: &blst_fp12) -> blst_fp12 {
    let g = blst_mul(&blst_conjugate(f), &blst_inverse(f));
    blst_mul(&blst_frobenius(&g, 2), &g)
}

fn limbs(f: &blst_fp12) -> [[[[u64; 6]; 2]; 3]; 2] {
    let mut out = [[[[0u64; 6]; 2]; 3]; 2];
    for h in 0..2 {
        for k in 0..3 {
            for c in 0..2 {
                out[h][k][c] = f.fp6[h].fp2[k].fp[c].l;
            }
        }
    }
    out
}

/// Fp2 values into lanes 0 to `values.len() − 1`, the rest 0.
#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) fn fp2_lanes(values: &[blst_fp2]) -> Fp2x8 {
    let mut c0 = [[0u64; 6]; LANES];
    let mut c1 = [[0u64; 6]; LANES];
    for (lane, value) in values.iter().enumerate() {
        c0[lane] = value.fp[0].l;
        c1[lane] = value.fp[1].l;
    }
    Fp2x8 { c0: Fp8::from_blst_limbs(&c0), c1: Fp8::from_blst_limbs(&c1) }
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) fn lanes_of(f: &blst_fp12) -> Fp12 {
    let a = [&f.fp6[0].fp2[..], &f.fp6[1].fp2[..]].concat();
    Fp12(fp2_lanes(&a))
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn line_lanes(line: &blst_fp6) -> Fp2x8 {
    fp2_lanes(&line.fp2)
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub(crate) fn blst_of_lanes(f: &Fp12) -> blst_fp12 {
    let c0 = f.0.c0.to_blst_limbs();
    let c1 = f.0.c1.to_blst_limbs();
    let mut out = blst_fp12::default();
    for lane in 0..6 {
        out.fp6[lane / 3].fp2[lane % 3].fp[0].l = c0[lane];
        out.fp6[lane / 3].fp2[lane % 3].fp[1].l = c1[lane];
    }
    out
}

/// Lanes 0 to 5 normalised and below k·p.
fn in_range(x: &Fp8, k: u64) -> bool {
    // SAFETY: called only where `ifma_kernels_run` held.
    let bound = unsafe { Fp8::multiple_of_p(k) }.store();
    let value = x.store();
    (0..6).all(|lane| {
        value[lane].iter().all(|&limb| limb <= MASK52) &&
            (0..LIMBS).rev().map(|j| value[lane][j].cmp(&bound[lane][j])).find(|o| o.is_ne()) ==
                Some(std::cmp::Ordering::Less)
    })
}

fn fp12_in_range(f: &Fp12, k: u64) -> bool {
    in_range(&f.0.c0, k) && in_range(&f.0.c1, k)
}

/// The same values, every c0 lifted by `c0`·p and every c1 by `c1`·p.
#[target_feature(enable = "avx512f,avx512ifma")]
fn lifted(x: &Fp2x8, c0: u64, c1: u64) -> Fp2x8 {
    Fp2x8 {
        c0: x.c0.add_raw(&Fp8::multiple_of_p(c0)).normalise(),
        c1: x.c1.add_raw(&Fp8::multiple_of_p(c1)).normalise(),
    }
}

/// Reduced values lift to the top of the accepted range, K = `BOUND`: both
/// components, then each alone, since a gather subtracting c1 from c0 is
/// worst with c1 alone lifted.
const LIFTS: [(u64, u64); 4] = [(0, 0), (BOUND - 1, BOUND - 1), (BOUND - 1, 0), (0, BOUND - 1)];

fn full_line(line: &blst_fp6) -> blst_fp12 {
    let mut f = blst_fp12::default();
    f.fp6[0].fp2[0] = line.fp2[0];
    f.fp6[0].fp2[1] = line.fp2[1];
    f.fp6[1].fp2[1] = line.fp2[2];
    f
}

#[test]
fn blst_fixtures_hold() {
    let mut rng = ChaCha8Rng::seed_from_u64(0x5a);
    for _ in 0..8 {
        let f = random_fp12(&mut rng);
        let line = random_line(&mut rng);
        assert_eq!(
            limbs(&blst_mul_by_line(&f, &line)),
            limbs(&blst_mul(&f, &full_line(&line))),
            "blst's line is (x, y, 0) + (0, z, 0)·w"
        );
        let g = cyclotomic(&f);
        assert_eq!(limbs(&blst_cyclotomic_square(&g)), limbs(&blst_square(&g)));
        assert_ne!(
            limbs(&blst_cyclotomic_square(&f)),
            limbs(&blst_square(&f)),
            "a random f lies off the cyclotomic subgroup"
        );
    }
}

/// Random, extreme (p − 1 everywhere), sparse (a line's zero coefficients)
/// and cyclotomic elements.
fn cases() -> Vec<(blst_fp12, blst_fp12, blst_fp6)> {
    let mut rng = ChaCha8Rng::seed_from_u64(0x9b);
    let extreme_line = blst_fp6 { fp2: [blst_fp2 { fp: [p_minus_one(), p_minus_one()] }; 3] };
    let mut cases = vec![(extreme_fp12(), extreme_fp12(), extreme_line)];
    let (line, other) = (random_line(&mut rng), random_line(&mut rng));
    cases.push((full_line(&line), full_line(&other), line));
    for i in 0..48 {
        let a = random_fp12(&mut rng);
        let b = random_fp12(&mut rng);
        let line = random_line(&mut rng);
        cases.push(if i % 2 == 0 { (a, b, line) } else { (cyclotomic(&a), cyclotomic(&b), line) });
    }
    cases
}

/// Each operation against blst, from reduced inputs and from each of their
/// `LIFTS`.
#[test]
fn operations_match_blst() {
    if !ifma_kernels_run() {
        return;
    }
    for (a, b, line) in cases() {
        // SAFETY: `ifma_kernels_run` held.
        unsafe {
            let reduced = (lanes_of(&a), lanes_of(&b), line_lanes(&line));
            for (c0, c1) in LIFTS {
                let la = Fp12(lifted(&reduced.0.0, c0, c1));
                let lb = Fp12(lifted(&reduced.1.0, c0, c1));
                let ll = lifted(&reduced.2, c0, c1);
                assert!(fp12_in_range(&la, BOUND) && fp12_in_range(&lb, BOUND));
                let results = [
                    (la.mul(&lb), blst_mul(&a, &b), "mul"),
                    (la.square(), blst_square(&a), "square"),
                    (la.mul_by_line(&ll), blst_mul_by_line(&a, &line), "line"),
                    (la.cyclotomic_square(), blst_cyclotomic_square(&a), "cyclotomic"),
                    (la.conjugate(), blst_conjugate(&a), "conjugate"),
                    (la.frobenius(), blst_frobenius(&a, 1), "frobenius"),
                    (la.frobenius().frobenius(), blst_frobenius(&a, 2), "frobenius 2"),
                    (la.frobenius().frobenius().frobenius(), blst_frobenius(&a, 3), "frobenius 3"),
                    (la.inverse(), blst_inverse(&a), "inverse"),
                ];
                for (got, want, name) in results {
                    assert!(fp12_in_range(&got, BOUND), "{name} out of range");
                    assert_eq!(limbs(&blst_of_lanes(&got)), limbs(&want), "{name}");
                }
            }
        }
    }
}

/// Chains feed each operation the lazy output of another, so the ranges are
/// exercised where they matter: every output must stay below `BOUND`·p.
#[test]
fn chains_match_blst_within_range() {
    if !ifma_kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x3c);
    for start in [extreme_fp12(), random_fp12(&mut rng), cyclotomic(&random_fp12(&mut rng))] {
        let other = random_fp12(&mut rng);
        let line = random_line(&mut rng);
        let mut want = start;
        // SAFETY: `ifma_kernels_run` held.
        unsafe {
            let (mut got, lo, ll) = (lanes_of(&start), lanes_of(&other), line_lanes(&line));
            for step in 0..80 {
                (got, want) = match step % 8 {
                    0 => (got.mul(&lo), blst_mul(&want, &other)),
                    1 => (got.square(), blst_square(&want)),
                    2 => (got.mul_by_line(&ll), blst_mul_by_line(&want, &line)),
                    3 => (got.cyclotomic_square(), blst_cyclotomic_square(&want)),
                    4 => (got.frobenius(), blst_frobenius(&want, 1)),
                    5 => (got.conjugate(), blst_conjugate(&want)),
                    6 => (got.inverse(), blst_inverse(&want)),
                    _ => (got.mul(&got), blst_mul(&want, &want)),
                };
                assert!(fp12_in_range(&got, BOUND), "step {step}");
                assert_eq!(limbs(&blst_of_lanes(&got)), limbs(&want), "step {step}");
            }
            // Forty cyclotomic squarings in a row; the final exponentiation runs
            // up to 32 between products.
            let mut got = lanes_of(&cyclotomic(&start));
            let mut want = cyclotomic(&start);
            for step in 0..40 {
                got = got.cyclotomic_square();
                want = blst_cyclotomic_square(&want);
                assert!(fp12_in_range(&got, BOUND), "run {step}");
            }
            assert_eq!(limbs(&blst_of_lanes(&got)), limbs(&want));
        }
    }
}

fn blst_final_exponentiation(f: &blst_fp12) -> blst_fp12 {
    let mut out = blst_fp12::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_final_exp(&mut out, f) };
    out
}

/// The final exponentiation is the spec's cubed, f^(3·(p¹² − 1)/r), from
/// reduced inputs and from each of their `LIFTS`; so is blst's.
#[test]
fn final_exponentiation_is_the_spec_one_cubed() {
    if !ifma_kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0xfe);
    let line = random_line(&mut rng);
    let inputs = [extreme_fp12(), full_line(&line), random_fp12(&mut rng), random_fp12(&mut rng)];
    for f in inputs {
        let spec = spec_pairing::final_exponentiation(&f);
        let cubed = blst_mul(&blst_mul(&spec, &spec), &spec);
        assert_ne!(limbs(&spec), limbs(&blst_mul(&spec, &spec)), "the spec's value is not 1");
        assert_eq!(limbs(&blst_final_exponentiation(&f)), limbs(&cubed), "blst's");
        // SAFETY: `ifma_kernels_run` held.
        unsafe {
            for (c0, c1) in LIFTS {
                let got = Fp12(lifted(&lanes_of(&f).0, c0, c1)).final_exponentiation();
                assert!(fp12_in_range(&got, BOUND), "lift ({c0}, {c1}) out of range");
                assert_eq!(limbs(&blst_of_lanes(&got)), limbs(&cubed), "lift ({c0}, {c1})");
            }
        }
    }
}

#[test]
fn is_one_reads_every_value_lane() {
    if !ifma_kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(0x11);
    // SAFETY: `ifma_kernels_run` held.
    unsafe {
        let one = Fp12::one();
        assert!(one.is_one());
        assert!(Fp12(lifted(&one.0, BOUND - 1, BOUND - 1)).is_one(), "lazy representations count");
        let free = Fp8::multiple_of_p(3).permute2(&Fp8::zero(), &[8, 8, 8, 8, 8, 8, 0, 0]);
        assert!(Fp12(Fp2x8 { c0: one.0.c0.add_raw(&free), c1: free }).is_one(), "lanes 6, 7");
        assert!(!lanes_of(&random_fp12(&mut rng)).is_one());
        for lane in 0..6 {
            for component in 0..2 {
                let mut from = [8i64; LANES];
                from[lane] = 0;
                let bump = Fp8::one().permute2(&Fp8::zero(), &from);
                let mut f = one;
                if component == 0 {
                    f.0.c0 = f.0.c0.add_raw(&bump).normalise();
                } else {
                    f.0.c1 = f.0.c1.add_raw(&bump).normalise();
                }
                assert!(!f.is_one(), "lane {lane}, c{component}");
            }
        }
    }
}

/// Each lane's integer value over p: Σ limb_j·2^(52j) / p, the top limb
/// signed, so a negative value shows. f64 resolves these to far below 1/p.
fn lane_values_over_p(x: &Fp8) -> [f64; LANES] {
    let p: f64 = (0..LIMBS).map(|j| P[j] as f64 * 2f64.powi((LIMB_BITS * j as u32) as i32)).sum();
    let value = x.store();
    let mut out = [0f64; LANES];
    for lane in 0..LANES {
        let mut sum = 0f64;
        for j in 0..LIMBS {
            let limb =
                if j == LIMBS - 1 { value[lane][j] as i64 as f64 } else { value[lane][j] as f64 };
            sum += limb * 2f64.powi((LIMB_BITS * j as u32) as i32);
        }
        out[lane] = sum / p;
    }
    out
}

/// The least and greatest value over p of output lanes 0 to 5, both
/// components, over every input in `ranges`: for each input vector, the
/// multiple of p each lane may reach. `recombine` is affine in its inputs,
/// with no product or reduction inside, so probing each input lane with p
/// gives its exact weight, and the extremes sit at the vertices.
fn extremes(
    inputs: usize,
    ranges: &[[u64; LANES]],
    recombine: &dyn Fn(&[Fp8]) -> Fp2x8,
) -> (f64, f64) {
    // SAFETY: called only where `ifma_kernels_run` held.
    let (zero, p) = unsafe { (Fp8::zero(), Fp8::multiple_of_p(1)) };
    let read = |f: &Fp2x8| [lane_values_over_p(&f.c0), lane_values_over_p(&f.c1)];
    let base = read(&recombine(&vec![zero; inputs]));
    let mut least = base;
    let mut greatest = base;
    for vector in 0..inputs {
        for lane in 0..LANES {
            let reach = ranges[vector][lane] as f64;
            if reach == 0.0 {
                continue;
            }
            let mut probe = vec![zero; inputs];
            let mut from = [8i64; LANES];
            from[lane] = 0;
            // SAFETY: called only where `ifma_kernels_run` held.
            probe[vector] = unsafe { p.permute2(&zero, &from) };
            let probed = read(&recombine(&probe));
            for component in 0..2 {
                for out in 0..6 {
                    let weight = (probed[component][out] - base[component][out]).round();
                    if weight < 0.0 {
                        least[component][out] += weight * reach;
                    } else {
                        greatest[component][out] += weight * reach;
                    }
                }
            }
        }
    }
    let mut low = f64::MAX;
    let mut high = f64::MIN;
    for component in 0..2 {
        for out in 0..6 {
            low = low.min(least[component][out]);
            high = high.max(greatest[component][out]);
        }
    }
    (low, high)
}

/// The worst cases of each recombination, over every product below 2p and,
/// for the cyclotomic square, every input below K·p: never negative, and
/// within the bound each documents. Random inputs do not reach these.
#[test]
fn recombinations_stay_in_range_for_every_product() {
    if !ifma_kernels_run() {
        return;
    }
    let products = |count: usize| vec![[2u64; LANES]; count];

    // SAFETY (each closure): called only where `ifma_kernels_run` held.
    let product = |q: &[Fp8]| unsafe { Fp12::from_product_lanes(&q.try_into().unwrap()).0 };
    let (low, high) = extremes(7, &products(7), &product);
    assert!(low >= 0.0 && high < 108.0, "product: {low} to {high}");

    let square = |q: &[Fp8]| unsafe { Fp12::from_square_lanes(&q.try_into().unwrap()).0 };
    let (low, high) = extremes(5, &products(5), &square);
    assert!(low >= 0.0 && high < 112.0, "square: {low} to {high}");

    let line = |q: &[Fp8]| unsafe { Fp12::from_line_lanes(&q.try_into().unwrap()).0 };
    let (low, high) = extremes(5, &products(5), &line);
    assert!(low >= 0.0 && high < 120.0, "line: {low} to {high}");

    // Inputs: q's two components (lanes 0 to 6), m (lanes 0 to 3), and a.
    let cyclotomic = |v: &[Fp8]| unsafe {
        Fp12::cyclotomic_sum(&Fp2x8 { c0: v[0], c1: v[1] }, &v[2], &Fp2x8 { c0: v[3], c1: v[4] })
    };
    let squares = [2, 2, 2, 2, 2, 2, 2, 0];
    let a = [BOUND, BOUND, BOUND, BOUND, BOUND, BOUND, 0, 0];
    let ranges = [squares, squares, [2, 2, 2, 2, 0, 0, 0, 0], a, a];
    let (low, high) = extremes(5, &ranges, &cyclotomic);
    assert!(low >= 0.0 && high < 572.0, "cyclotomic: {low} to {high}");
}
