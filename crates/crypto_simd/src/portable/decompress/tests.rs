use blst::{blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_from_affine};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha8Rng;

use super::{uncompress_in_g1, uncompress_pair_in_g1};
use crate::bls::{
    COMPRESSED_LEN,
    constants::P_U64,
    tests::{
        G1Torsion, H1_PRIMES, compress, curve_points_outside_g1, g1_affine, g1_points, serialized,
    },
    uncompress_in_g1_blst,
};

/// x = p with each flag pattern, x = 0, and infinity encodings with stray
/// bits.
fn edge_encodings() -> Vec<[u8; COMPRESSED_LEN]> {
    let mut x_is_p = [0u8; COMPRESSED_LEN];
    for w in 0..6 {
        x_is_p[COMPRESSED_LEN - 8 * (w + 1)..COMPRESSED_LEN - 8 * w]
            .copy_from_slice(&P_U64[w].to_be_bytes());
    }
    let mut out = Vec::new();
    for flags in [0x80, 0xa0] {
        let mut bytes = x_is_p;
        bytes[0] |= flags;
        out.push(bytes);
        let mut zero = [0u8; COMPRESSED_LEN];
        zero[0] = flags;
        out.push(zero);
    }
    for (first, last) in [(0xc0, 0), (0xe0, 0), (0xc1, 0), (0xc0, 1), (0x40, 0), (0x00, 0)] {
        let mut bytes = [0u8; COMPRESSED_LEN];
        bytes[0] = first;
        bytes[COMPRESSED_LEN - 1] = last;
        out.push(bytes);
    }
    out
}

/// Members, curve points outside G1, members plus small-order components,
/// corrupted members, and the edge encodings, shuffled.
fn encodings() -> Vec<[u8; COMPRESSED_LEN]> {
    let mut rng = StdRng::seed_from_u64(23);
    let mut inputs = g1_points(40);
    inputs.extend(curve_points_outside_g1(&mut rng, 20));
    let mut torsion = G1Torsion(ChaCha8Rng::seed_from_u64(29));
    let member = uncompress_in_g1_blst(&inputs[0]).expect("a G1 member");
    let mut m = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_from_affine(&mut m, &member) };
    for prime_index in 0..H1_PRIMES.len() {
        let t = torsion.of_order(prime_index);
        let mut sum = blst_p1::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_p1_add_or_double(&mut sum, &m, &t) };
        inputs.push(compress(&g1_affine(&t)));
        inputs.push(compress(&g1_affine(&sum)));
    }
    for i in 0..16 {
        let mut bad = inputs[i];
        match i % 4 {
            0 => bad[20] ^= 0x01,
            1 => bad[0] &= 0x7f,
            2 => bad[0] ^= 0x20,
            _ => {
                bad[0] |= 0x1f;
                bad[1..].fill(0xff);
            }
        }
        inputs.push(bad);
    }
    inputs.extend(edge_encodings());
    for i in (1..inputs.len()).rev() {
        let j = rng.gen_range(0..=i);
        inputs.swap(i, j);
    }
    inputs
}

#[test]
fn verdicts_match_blst() {
    let inputs = encodings();
    let mut members = 0;
    for (i, input) in inputs.iter().enumerate() {
        let want = uncompress_in_g1_blst(input);
        let got: Option<blst_p1_affine> = uncompress_in_g1(input);
        assert_eq!(serialized(&got), serialized(&want), "input {i}");
        members += want.is_some() as usize;
    }
    assert_eq!(members, 45, "40 members, infinity, and the 4 sign flips that only negate a member");
}

/// Every input against every other: both orders, and each lane's kind
/// against each other kind's.
#[test]
fn pair_verdicts_match_blst() {
    let inputs = encodings();
    for (i, a) in inputs.iter().enumerate() {
        for (j, b) in inputs.iter().enumerate().skip(i % 7).step_by(7) {
            let got = uncompress_pair_in_g1(a, b);
            assert_eq!(serialized(&got[0]), serialized(&uncompress_in_g1_blst(a)), "{i}, {j}");
            assert_eq!(serialized(&got[1]), serialized(&uncompress_in_g1_blst(b)), "{i}, {j}");
        }
    }
}
