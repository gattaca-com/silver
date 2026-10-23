//! Inversion of eight field elements at once, as a fixed exponentiation.

use crate::bls::{constants::P_U64, fp8::Fp8};

const WINDOW_BITS: usize = 4;
const _: () = assert!(64 % WINDOW_BITS == 0);
const P_BITS: usize = 381;
const WINDOWS: usize = P_BITS.div_ceil(WINDOW_BITS);

/// p − 2 as 4-bit windows, least significant first.
const P_MINUS_2_WINDOWS: [u8; WINDOWS] = windows_of(&p_minus_2());

const fn p_minus_2() -> [u64; 6] {
    let mut exponent = P_U64;
    exponent[0] -= 2;
    exponent
}

const fn windows_of(exponent: &[u64; 6]) -> [u8; WINDOWS] {
    let mut windows = [0u8; WINDOWS];
    let mut w = 0;
    while w < WINDOWS {
        let bit = w * WINDOW_BITS;
        windows[w] = ((exponent[bit / 64] >> (bit % 64)) & 0xf) as u8;
        w += 1;
    }
    windows
}

impl Fp8 {
    /// `self^(p−2)` per lane: the inverse, and 0 for 0. The exponent is shared
    /// by every lane, so the 4-bit windows need no per-lane table lookups.
    #[target_feature(enable = "avx512f,avx512ifma")]
    pub fn inverse(&self) -> Self {
        let mut table = [Self::one(); 16];
        table[1] = *self;
        for k in 2..16 {
            table[k] = table[k - 1].mul(self);
        }
        let mut result = table[P_MINUS_2_WINDOWS[WINDOWS - 1] as usize];
        for w in (0..WINDOWS - 1).rev() {
            result = result.square().square().square().square();
            let digit = P_MINUS_2_WINDOWS[w] as usize;
            if digit != 0 {
                result = result.mul(&table[digit]);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    use super::*;
    use crate::bls::{
        fp8::{LANES, Limbs, pack64, unpack52},
        simd_available,
    };

    fn random_below_p(rng: &mut ChaCha8Rng) -> Limbs {
        loop {
            let mut words: [u64; 6] = rng.r#gen();
            words[5] &= (1 << 61) - 1;
            if words.iter().rev().lt(P_U64.iter().rev()) {
                return unpack52(&words);
            }
        }
    }

    #[test]
    fn inverse_multiplies_to_one_and_fixes_zero() {
        let available = simd_available();
        assert!(
            available || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
            "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
        );
        if !available {
            return;
        }
        let mut rng = ChaCha8Rng::seed_from_u64(0x1213_7e5e);
        for round in 0..8 {
            let mut values: [Limbs; LANES] = std::array::from_fn(|_| random_below_p(&mut rng));
            values[0] = [0; 8];
            values[1] = unpack52(&{
                let mut one = [0u64; 6];
                one[0] = 1;
                one
            });
            let mut minus_one = P_U64;
            minus_one[0] -= 1;
            values[2] = unpack52(&minus_one);
            // SAFETY: `available` was checked above.
            let products = unsafe {
                let a = Fp8::from_plain(&values);
                a.mul(&a.inverse()).to_plain()
            };
            for lane in 0..LANES {
                let expected = if lane == 0 { [0; 6] } else { [1, 0, 0, 0, 0, 0] };
                assert_eq!(pack64(&products[lane]), expected, "round {round}, lane {lane}");
            }
        }
    }
}
