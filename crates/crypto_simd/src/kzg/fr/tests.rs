use std::cmp::Ordering;

use blst::blst_fr;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use super::{R, R_INV64, R_SQUARED, fr_add, fr_from_bytes, fr_mul, fr_sub, fr_to_bytes};
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

/// Uniform below r, or in [r, 2^255), by rejection.
fn random_words(rng: &mut ChaCha8Rng, below_r: bool) -> [u64; 4] {
    loop {
        let mut l: [u64; 4] = rng.r#gen();
        l[3] >>= 1;
        if (l.iter().rev().cmp(R.iter().rev()) == Ordering::Less) == below_r {
            return l;
        }
    }
}

fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
    blst_fr { l: random_words(rng, true) }
}

fn be_bytes(words: &[u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (k, word) in words.iter().rev().enumerate() {
        bytes[8 * k..8 * k + 8].copy_from_slice(&word.to_be_bytes());
    }
    bytes
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

/// R² over R is R, blst's form of 1.
#[test]
fn r_squared_over_r_is_blst_one() {
    assert!(fr_mul(&blst_fr { l: R_SQUARED }, &blst_fr { l: [1, 0, 0, 0] }) == FR_ONE);
}

/// Decoding against blst at 0, 1, r − 1, r, r + 1, 2^256 − 1, and random
/// values below r, in [r, 2^255) and at or above 2^255; encoding against
/// blst at `values`, and back through decoding.
#[test]
fn byte_conversions_match_blst() {
    let mut rng = ChaCha8Rng::seed_from_u64(0xb7);
    let mut inputs = vec![
        be_bytes(&[0; 4]),
        be_bytes(&[1, 0, 0, 0]),
        be_bytes(&[R[0] - 1, R[1], R[2], R[3]]),
        be_bytes(&R),
        be_bytes(&[R[0] + 1, R[1], R[2], R[3]]),
        [0xff; 32],
    ];
    let mut above_r = 3;
    for _ in 0..32 {
        inputs.push(be_bytes(&random_words(&mut rng, true)));
        inputs.push(be_bytes(&random_words(&mut rng, false)));
        let mut high: [u64; 4] = rng.r#gen();
        high[3] |= 1 << 63;
        inputs.push(be_bytes(&high));
        above_r += 2;
    }
    let mut rejected = 0;
    for bytes in &inputs {
        let decoded = fr_from_bytes(bytes);
        assert!(decoded == blst_ops::fr_from_bytes(bytes), "{bytes:x?}");
        match decoded {
            Some(value) => assert!(fr_to_bytes(&value) == *bytes, "{bytes:x?} back"),
            None => rejected += 1,
        }
    }
    assert!(rejected == above_r, "exactly the inputs at or above r are rejected");
    for value in values() {
        let encoded = fr_to_bytes(&value);
        assert!(encoded == blst_ops::fr_to_bytes(&value), "{:x?}", value.l);
        assert!(fr_from_bytes(&encoded) == Some(value), "{:x?} back", value.l);
    }
}
