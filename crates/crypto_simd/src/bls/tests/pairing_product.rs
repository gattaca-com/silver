use std::ptr;

use blst::{
    Pairing, blst_fp_cneg, blst_hash_to_g2, blst_p1_affine, blst_p1_affine_generator,
    blst_p1_affine_is_inf, blst_p2, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_affine_is_inf,
    blst_p2_affine_on_curve, blst_p2_is_inf, blst_p2_mult, blst_p2_to_affine,
    min_pk::{AggregateSignature, SecretKey},
};
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha8Rng;

use super::g2_cases::G2Cases;
use crate::{
    bls::{
        PairingProduct,
        pairing_product::{AffinePair, BLST_PAIR_COUNT},
    },
    ifma_kernels_run,
};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

struct ProductCase {
    pairs: Vec<AffinePair>,
}

impl ProductCase {
    fn signed(count: usize, distinct_messages: bool) -> Self {
        assert!(count >= 2);
        let mut pairs = Vec::new();
        let mut signatures = Vec::new();
        for index in 0..count - 1 {
            let key = SecretKey::key_gen(&[index as u8 + 1; 32], &[]).unwrap();
            let message = [if distinct_messages { index as u8 } else { 0 }; 32];
            let mut q = blst_p2::default();
            let mut affine = blst_p2_affine::default();
            unsafe {
                blst_hash_to_g2(
                    &mut q,
                    message.as_ptr(),
                    message.len(),
                    DST.as_ptr(),
                    DST.len(),
                    ptr::null(),
                    0,
                );
                blst_p2_to_affine(&mut affine, &q);
            }
            pairs.push(AffinePair { p: key.sk_to_pk().into(), q: affine });
            signatures.push(key.sign(&message, DST, &[]));
        }
        let sum = AggregateSignature::aggregate(&signatures.iter().collect::<Vec<_>>(), false)
            .unwrap()
            .to_signature();
        pairs.push(AffinePair { p: negative_generator(), q: sum.into() });
        Self { pairs }
    }

    fn oracle(&self) -> bool {
        let mut pairing = Pairing::new(false, &[]);
        let mut count = 0;
        for pair in &self.pairs {
            if unsafe { !blst_p1_affine_is_inf(&pair.p) && !blst_p2_affine_is_inf(&pair.q) } {
                pairing.raw_aggregate(&pair.q, &pair.p);
                count += 1;
            }
        }
        if count == 0 {
            return true;
        }
        pairing.commit();
        pairing.finalverify(None)
    }

    fn check(&self, product: &mut PairingProduct, expected: bool, degenerate: bool) {
        assert_eq!(self.oracle(), expected, "fixture verdict");
        product.clear();
        let mut finite = 0;
        for pair in &self.pairs {
            product.push(&pair.p, &pair.q);
            if unsafe { !blst_p1_affine_is_inf(&pair.p) && !blst_p2_affine_is_inf(&pair.q) } {
                finite += 1;
            }
        }
        let expected_blst = (finite > 0 && (degenerate || !ifma_kernels_run())).then_some(finite);
        for _ in 0..2 {
            BLST_PAIR_COUNT.set(None);
            assert_eq!(product.is_one(), expected, "{} input pairs", self.pairs.len());
            // The order-13 verdict alone cannot distinguish a missing fallback.
            assert_eq!(BLST_PAIR_COUNT.get(), expected_blst, "whole-product blst route");
        }
        if self.pairs.len() == 2 {
            let [a, b] = [self.pairs[0], self.pairs[1]];
            BLST_PAIR_COUNT.set(None);
            assert_eq!(PairingProduct::two_pairs_are_one(&a.p, &a.q, &b.p, &b.q), expected);
            assert_eq!(BLST_PAIR_COUNT.get(), expected_blst, "fixed two-pair route");
        }
    }
}

fn negative_generator() -> blst_p1_affine {
    let mut p = unsafe { *blst_p1_affine_generator() };
    unsafe { blst_fp_cneg(&mut p.y, &p.y, true) };
    p
}

fn order_13() -> blst_p2_affine {
    let mut cases = G2Cases(ChaCha8Rng::seed_from_u64(13));
    for _ in 0..128 {
        let point = cases.torsion();
        let mut multiple = blst_p2::default();
        unsafe { blst_p2_mult(&mut multiple, &point, [13u8].as_ptr(), 8) };
        if unsafe { blst_p2_is_inf(&multiple) } {
            let mut affine = blst_p2_affine::default();
            unsafe {
                blst_p2_to_affine(&mut affine, &point);
                assert!(!blst_p2_affine_is_inf(&affine));
                assert!(blst_p2_affine_on_curve(&affine));
                assert!(!blst_p2_affine_in_g2(&affine));
            }
            return affine;
        }
    }
    panic!("seed did not produce an order-13 point");
}

#[test]
fn pairing_products_match_blst_across_lane_sets() {
    let mut product = PairingProduct::with_capacity(2);
    let mut rng = ChaCha8Rng::seed_from_u64(19);
    for count in 2..=20 {
        let mut case = ProductCase::signed(count, true);
        case.check(&mut product, true, false);
        case.pairs.shuffle(&mut rng);
        case.check(&mut product, true, false);
        case.pairs.reverse();
        case.check(&mut product, true, false);

        unsafe { blst_fp_cneg(&mut case.pairs[0].p.y, &case.pairs[0].p.y, true) };
        case.check(&mut product, false, false);
    }
}

#[test]
fn pairing_products_reject_independent_pairs() {
    let mut cases = G2Cases(ChaCha8Rng::seed_from_u64(23));
    let mut product = PairingProduct::default();
    let mut case = ProductCase { pairs: Vec::new() };
    for count in 1..=20 {
        let mut q = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut q, &cases.member()) };
        let key = SecretKey::key_gen(&[count as u8; 32], &[]).unwrap();
        case.pairs.push(AffinePair { p: key.sk_to_pk().into(), q });
        case.check(&mut product, false, false);
    }
}

#[test]
fn pairing_products_accept_duplicate_g2_points() {
    let mut product = PairingProduct::default();
    for count in [3, 8, 9, 16, 17, 20] {
        let case = ProductCase::signed(count, false);
        assert_eq!(case.pairs[0].q, case.pairs[count - 2].q);
        case.check(&mut product, true, false);
    }
}

#[test]
fn pairing_products_skip_either_infinity() {
    let mut product = PairingProduct::default();
    let valid = ProductCase::signed(2, true);
    let pair = valid.pairs[0];
    let skipped = [
        AffinePair { p: blst_p1_affine::default(), q: pair.q },
        AffinePair { p: pair.p, q: blst_p2_affine::default() },
        AffinePair { p: blst_p1_affine::default(), q: blst_p2_affine::default() },
    ];
    ProductCase { pairs: Vec::new() }.check(&mut product, true, false);
    for pair in skipped {
        ProductCase { pairs: vec![pair] }.check(&mut product, true, false);
    }
    for count in [2, 9, 17, 20] {
        let mut case = ProductCase::signed(count, true);
        for (index, pair) in skipped.into_iter().enumerate() {
            case.pairs.insert(index * (count / 3 + 1), pair);
        }
        case.check(&mut product, true, false);
        case.pairs.reverse();
        case.check(&mut product, true, false);
        let finite = case
            .pairs
            .iter()
            .position(|pair| unsafe {
                !blst_p1_affine_is_inf(&pair.p) && !blst_p2_affine_is_inf(&pair.q)
            })
            .unwrap();
        case.pairs.remove(finite);
        case.check(&mut product, false, false);
    }
    ProductCase { pairs: skipped.repeat(7) }.check(&mut product, true, false);
    ProductCase { pairs: vec![skipped[0], skipped[1]] }.check(&mut product, true, false);
    ProductCase { pairs: vec![pair, skipped[1]] }.check(&mut product, false, false);
    ProductCase { pairs: vec![skipped[0], pair] }.check(&mut product, false, false);
}

#[test]
fn pairing_products_fall_back_for_order_13() {
    let q = order_13();
    let p = unsafe { *blst_p1_affine_generator() };
    let mut product = PairingProduct::default();
    ProductCase { pairs: vec![AffinePair { p, q }, AffinePair { p: negative_generator(), q }] }
        .check(&mut product, false, true);

    for prefix in [8, 16] {
        let mut case = ProductCase::signed(prefix, true);
        case.pairs.push(AffinePair { p, q });
        case.check(&mut product, false, true);
        case.pairs.reverse();
        case.check(&mut product, false, true);
        ProductCase::signed(prefix + 1, true).check(&mut product, true, false);
    }
}

#[test]
fn pairing_product_reuse_preserves_only_pushed_pairs() {
    let valid = ProductCase::signed(2, true);
    let mut product = PairingProduct::with_capacity(2);
    valid.check(&mut product, true, false);
    product.clear();
    assert!(product.is_one());
    product.push(&valid.pairs[0].p, &valid.pairs[0].q);
    assert!(!product.is_one());
    product.push(&valid.pairs[1].p, &valid.pairs[1].q);
    assert!(product.is_one());

    let q = order_13();
    ProductCase { pairs: vec![AffinePair { p: valid.pairs[0].p, q }] }.check(
        &mut product,
        false,
        true,
    );
    product.clear();
    assert!(product.is_one());
    valid.check(&mut product, true, false);
}
