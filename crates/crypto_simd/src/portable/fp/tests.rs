use blst::{
    blst_fp, blst_fp_add, blst_fp_cneg, blst_fp_inverse, blst_fp_mul, blst_fp_sqr, blst_fp_sqrt,
    blst_fp_sub, blst_uint64_from_fp,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::Fp;
use crate::{bls::constants::P_U64, portable::portable_available};

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
fn inputs() -> Vec<Fp> {
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
    if !portable_available() {
        return;
    }
    let values = inputs();
    for a in &values {
        for b in values.iter().take(24) {
            // SAFETY: `portable_available` held.
            unsafe {
                assert_eq!(a.mul(b), binary(a, b, blst_fp_mul), "mul");
                assert_eq!(a.add(b), binary(a, b, blst_fp_add), "add");
                assert_eq!(a.sub(b), binary(a, b, blst_fp_sub), "sub");
            }
        }
        let mut negated = blst(a);
        // SAFETY: valid pointers to single values.
        unsafe { blst_fp_cneg(&mut negated, &blst(a), true) };
        // SAFETY: `portable_available` held.
        unsafe {
            assert_eq!(a.square(), unary(a, blst_fp_sqr), "square");
            assert_eq!(a.neg(), Fp(negated.l), "neg");
            assert_eq!(a.inverse(), unary(a, blst_fp_inverse), "inverse");
            let mut plain = [0u64; 6];
            blst_uint64_from_fp(plain.as_mut_ptr(), &blst(a));
            assert_eq!(a.to_plain(), plain, "to_plain");
            assert_eq!(Fp::from_plain(&plain), *a, "from_plain");
        }
    }
}

/// `sqrt` finds a root exactly where blst does, the same up to sign, and
/// `is_larger_root` picks the root whose plain value exceeds (p − 1)/2.
#[test]
fn square_roots_match_blst() {
    if !portable_available() {
        return;
    }
    for a in inputs() {
        let mut root = blst_fp::default();
        // SAFETY: valid pointers to single values.
        let has_root = unsafe { blst_fp_sqrt(&mut root, &blst(&a)) };
        // SAFETY: `portable_available` held.
        unsafe {
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
}

fn halved_p_minus_one() -> [u64; 6] {
    let mut half = [0u64; 6];
    for j in 0..6 {
        half[j] = (P_U64[j] >> 1) | if j < 5 { P_U64[j + 1] << 63 } else { 0 };
    }
    half
}
