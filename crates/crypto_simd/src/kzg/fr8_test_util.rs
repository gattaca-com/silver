use blst::blst_fr;
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::simd_available,
    kzg::{
        blst_ops::{fr_from_bytes, fr_from_u64, fr_inverse, fr_mul},
        fr8::{Fr8Soa, LANES, LIMBS, MASK52, R52},
    },
};

pub fn available() -> bool {
    let ok = simd_available();
    assert!(
        ok || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    ok
}

pub fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[1..]);
    fr_from_bytes(&bytes).expect("top byte zero is below r")
}

pub fn soa(lanes: &[[u64; LIMBS]; LANES]) -> Fr8Soa {
    let mut out = Fr8Soa([[0; LANES]; LIMBS]);
    for lane in 0..LANES {
        for j in 0..LIMBS {
            out.0[j][lane] = lanes[lane][j];
        }
    }
    out
}

pub fn lanes(soa: &Fr8Soa) -> [[u64; LIMBS]; LANES] {
    let mut out = [[0; LIMBS]; LANES];
    for lane in 0..LANES {
        for j in 0..LIMBS {
            out[lane][j] = soa.0[j][lane];
        }
    }
    out
}

/// `x + k·r` as normalised limbs.
pub fn plus_multiple_of_r(x: &[u64; LIMBS], k: u64) -> [u64; LIMBS] {
    let mut out = [0u64; LIMBS];
    let mut carry = 0;
    for j in 0..LIMBS {
        let sum = x[j] + k * R52[j] + carry;
        out[j] = sum & MASK52;
        carry = sum >> 52;
    }
    assert_eq!(carry, 0, "fits in 260 bits");
    out
}

/// The element whose `to_r260` is the plain value `x`.
pub fn fr_with_r260(x: &[u64; 4]) -> blst_fr {
    let sixteenth = fr_inverse(&fr_from_u64(16));
    fr_mul(&blst_fr { l: *x }, &sixteenth)
}
