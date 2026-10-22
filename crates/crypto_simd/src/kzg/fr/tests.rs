use std::cmp::Ordering;

use blst::blst_fr;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{R, R_INV64, fr_add, fr_mul, fr_sub};
use crate::kzg::{FR_ONE, FR_ZERO, blst_ops};

/// Limbs at the edges of [0, r): 0, 1, r − 1, the largest top word below
/// r's with every lower word full, and blst's forms of 1 and r − 1.
fn edges() -> Vec<blst_fr> {
    vec![
        FR_ZERO,
        blst_fr { l: [1, 0, 0, 0] },
        blst_fr { l: [R[0] - 1, R[1], R[2], R[3]] },
        blst_fr { l: [u64::MAX, u64::MAX, u64::MAX, R[3] - 1] },
        FR_ONE,
        blst_ops::fr_sub(&FR_ZERO, &FR_ONE),
    ]
}

/// Uniform below r, by rejection.
fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
    loop {
        let mut l: [u64; 4] = rng.r#gen();
        l[3] >>= 1;
        if l.iter().rev().cmp(R.iter().rev()) == Ordering::Less {
            return blst_fr { l };
        }
    }
}

fn values() -> Vec<blst_fr> {
    let mut rng = ChaCha8Rng::seed_from_u64(0xf7);
    let mut values = edges();
    for _ in 0..64 {
        values.push(random_fr(&mut rng));
    }
    values
}

#[test]
fn arithmetic_matches_blst() {
    let values = values();
    for a in &values {
        for b in &values {
            assert!(fr_add(a, b) == blst_ops::fr_add(a, b), "{:x?} + {:x?}", a.l, b.l);
            assert!(fr_sub(a, b) == blst_ops::fr_sub(a, b), "{:x?} − {:x?}", a.l, b.l);
            assert!(fr_mul(a, b) == blst_ops::fr_mul(a, b), "{:x?} · {:x?}", a.l, b.l);
        }
    }
}

#[test]
fn r_inv64_is_minus_r_inverse() {
    assert!(R_INV64.wrapping_mul(R[0]) == u64::MAX);
}
