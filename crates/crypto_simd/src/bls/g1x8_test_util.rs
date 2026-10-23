use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::bls::{
    constants::P_U64,
    fp8::{Fp8, LANES, Limbs, pack64, unpack52},
    g1x8::G1x8,
};

pub fn rng(seed: u64) -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(seed)
}

pub fn random_below_p(rng: &mut ChaCha8Rng) -> Limbs {
    loop {
        let mut words: [u64; 6] = rng.r#gen();
        words[5] &= (1 << 61) - 1;
        if words.iter().rev().lt(P_U64.iter().rev()) {
            return unpack52(&words);
        }
    }
}

/// The canonical coordinates of every lane.
#[target_feature(enable = "avx512f,avx512ifma")]
pub fn plain(p: &G1x8) -> [[[u64; 6]; LANES]; 3] {
    [p.x, p.y, p.z].map(|v| v.to_plain().map(|limbs| pack64(&limbs)))
}

/// One below a multiple of p whose low limb is nonzero.
pub fn below(multiple_of_p: Limbs) -> Limbs {
    let mut limbs = multiple_of_p;
    limbs[0] -= 1;
    limbs
}

#[target_feature(enable = "avx512f,avx512ifma")]
pub fn splat_value(limbs: Limbs) -> Fp8 {
    Fp8::load(&[limbs; LANES])
}
