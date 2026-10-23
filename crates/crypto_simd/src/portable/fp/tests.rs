use blst::{
    blst_fp, blst_fp_add, blst_fp_cneg, blst_fp_inverse, blst_fp_mul, blst_fp_sqr, blst_fp_sqrt,
    blst_fp_sub, blst_uint64_from_fp,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{Fp, Wide};
use crate::bls::constants::P_U64;
#[cfg(target_arch = "x86_64")]
use crate::bmi2_available;

fn below_p(rng: &mut ChaCha8Rng) -> Fp {
    loop {
        let mut l = [0u64; 6];
        rng.fill(&mut l[..]);
        l[5] &= (1 << 61) - 1;
        let mut j = 6;
        while j > 0 && l[j - 1] == P_U64[j - 1] {
            j -= 1;
        }
        if j > 0 && l[j - 1] < P_U64[j - 1] {
            return Fp(l);
        }
    }
}

/// 0, 1, 2 and p − 1, p − 2 as stored words, and random values.
pub(crate) fn inputs() -> Vec<Fp> {
    let mut rng = ChaCha8Rng::seed_from_u64(0xf9);
    let mut top = P_U64;
    top[0] -= 1;
    let mut next = top;
    next[0] -= 1;
    let mut values =
        vec![Fp([0; 6]), Fp([1, 0, 0, 0, 0, 0]), Fp([2, 0, 0, 0, 0, 0]), Fp(top), Fp(next)];
    for _ in 0..64 {
        values.push(below_p(&mut rng));
    }
    values
}

fn blst(a: &Fp) -> blst_fp {
    blst_fp { l: a.0 }
}

fn binary(
    a: &Fp,
    b: &Fp,
    op: unsafe extern "C" fn(*mut blst_fp, *const blst_fp, *const blst_fp),
) -> Fp {
    let mut out = blst_fp::default();
    // SAFETY: valid pointers to single values.
    unsafe { op(&mut out, &blst(a), &blst(b)) };
    Fp(out.l)
}

fn unary(a: &Fp, op: unsafe extern "C" fn(*mut blst_fp, *const blst_fp)) -> Fp {
    let mut out = blst_fp::default();
    // SAFETY: valid pointers to single values.
    unsafe { op(&mut out, &blst(a)) };
    Fp(out.l)
}

#[test]
fn operations_match_blst() {
    let values = inputs();
    for a in &values {
        for b in values.iter().take(24) {
            assert_eq!(a.mul(b), binary(a, b, blst_fp_mul), "mul");
            assert_eq!(a.add(b), binary(a, b, blst_fp_add), "add");
            assert_eq!(a.sub(b), binary(a, b, blst_fp_sub), "sub");
        }
        let mut negated = blst(a);
        let mut plain = [0u64; 6];
        // SAFETY: valid pointers to single values and six words.
        unsafe {
            blst_fp_cneg(&mut negated, &blst(a), true);
            blst_uint64_from_fp(plain.as_mut_ptr(), &blst(a));
        }
        assert_eq!(a.square(), unary(a, blst_fp_sqr), "square");
        assert_eq!(a.neg(), Fp(negated.l), "neg");
        assert_eq!(a.inverse(), unary(a, blst_fp_inverse), "inverse");
        assert_eq!(a.to_plain(), plain, "to_plain");
        assert_eq!(Fp::from_plain(&plain), *a, "from_plain");
    }
}

/// k·p as six words.
fn times_p(k: u64) -> [u64; 6] {
    let mut out = [0u64; 6];
    let mut carry = 0u128;
    for (w, word) in P_U64.iter().enumerate() {
        let t = *word as u128 * k as u128 + carry;
        out[w] = t as u64;
        carry = t >> 64;
    }
    assert!(carry == 0, "{k}·p fits six words");
    out
}

/// No `Fp` operation returns a multiple of p but 0, yet `inverse` ends on
/// every multiple of p that six words hold, with 0.
#[test]
fn inverse_is_total() {
    for k in 0..=9 {
        assert_eq!(Fp(times_p(k)).inverse(), Fp::ZERO, "{k}·p");
    }
}

/// Where BMI2 runs, the products' twins built for it agree with the copies
/// built for baseline x86-64, which other CPUs run.
#[cfg(target_arch = "x86_64")]
#[test]
fn product_twins_agree() {
    if !bmi2_available() {
        return;
    }
    let values = inputs();
    for a in &values {
        for b in values.iter().take(24) {
            // SAFETY: `bmi2_available` checked BMI2 on this CPU.
            let on_bmi2 = unsafe { a.mul_on_bmi2(b) };
            assert_eq!(on_bmi2, a.mul_on_baseline(b), "{a:?} · {b:?}");
        }
    }
}

/// A product's reduction is the Montgomery product, also on sums below 2p,
/// and differences of products reduce to their differences in Fp.
#[test]
fn wide_products_reduce_to_montgomery_products() {
    let values = inputs();
    for a in &values {
        for b in values.iter().take(24) {
            let ab = Wide::product(&a.0, &b.0);
            let bb = Wide::product(&b.0, &b.0);
            assert_eq!(ab.reduce(), a.mul(b), "reduce");
            assert_eq!(ab.minus_mod(&bb).reduce(), a.mul(b).sub(&b.square()), "minus_mod");
            assert_eq!(bb.minus_mod(&ab).reduce(), b.square().sub(&a.mul(b)), "minus_mod");
            let sum = a.unreduced_add(b);
            let squared_sum = Wide::product(&sum, &sum);
            assert_eq!(squared_sum.reduce(), a.add(b).square(), "unreduced sums");
            let cross = squared_sum.minus(&Wide::product(&a.0, &a.0)).minus(&bb);
            assert_eq!(cross.reduce(), a.mul(b).double(), "minus");
        }
    }
}

/// `sqrt` finds a root exactly where blst does, the same up to sign, and
/// `is_larger_root` picks the root whose plain value exceeds (p − 1)/2.
#[test]
fn square_roots_match_blst() {
    for a in inputs() {
        let mut root = blst_fp::default();
        // SAFETY: valid pointers to single values.
        let has_root = unsafe { blst_fp_sqrt(&mut root, &blst(&a)) };
        let ours = a.sqrt();
        assert_eq!(ours.is_some(), has_root, "{a:?}");
        if let Some(r) = ours {
            assert!(r == Fp(root.l) || r == Fp(root.l).neg(), "{a:?}");
            if !r.is_zero() {
                assert_ne!(r.is_larger_root(), r.neg().is_larger_root());
                let plain = r.to_plain();
                let half = halved_p_minus_one();
                let larger = (0..6).rev().map(|j| plain[j].cmp(&half[j])).find(|o| o.is_ne());
                assert_eq!(r.is_larger_root(), larger == Some(std::cmp::Ordering::Greater));
            }
        }
    }
}

fn halved_p_minus_one() -> [u64; 6] {
    let mut half = [0u64; 6];
    for j in 0..6 {
        half[j] = (P_U64[j] >> 1) | if j < 5 { P_U64[j + 1] << 63 } else { 0 };
    }
    half
}
