use blst::blst_fr;
use rand::Rng;
use rand_chacha::ChaCha8Rng;

use super::{LIMBS, MASK52};
use crate::kzg::blst_ops::{fr_from_u64, fr_sub, fr_to_bytes};

/// Five 52-bit limbs, little-endian, as `Fr8` lanes hold them, in plain
/// integer arithmetic to check lanes against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limbs(pub(crate) [u64; LIMBS]);

impl Limbs {
    pub(crate) fn single_bit(bit: usize) -> Self {
        let mut x = [0; LIMBS];
        x[bit / 52] = 1 << (bit % 52);
        Self(x)
    }

    /// r, from blst rather than from `fr8`'s constant.
    pub(crate) fn r() -> Self {
        let largest = fr_to_bytes(&fr_sub(&fr_from_u64(0), &fr_from_u64(1)));
        Self::from_bytes(&largest).plus_multiple(1, &Self::single_bit(0))
    }

    /// k·r + d, which must lie in [0, 2^260).
    pub(crate) fn near_multiple_of_r(k: i128, d: i128) -> Self {
        Self([0; LIMBS]).plus_multiple(k, &Self::r()).plus_multiple(d, &Self::single_bit(0))
    }

    /// Bit by bit, from 32 big-endian bytes.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut x = [0; LIMBS];
        for bit in 0..256 {
            x[bit / 52] |= u64::from(bytes[31 - bit / 8] >> (bit % 8) & 1) << (bit % 52);
        }
        Self(x)
    }

    /// Bit by bit, the inverse of `from_bytes` on values below 2^256.
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        assert!(self.0[4] >> (256 - 4 * 52) == 0, "below 2^256");
        let mut bytes = [0u8; 32];
        for bit in 0..256 {
            bytes[31 - bit / 8] |= ((self.0[bit / 52] >> (bit % 52) & 1) as u8) << (bit % 8);
        }
        bytes
    }

    /// The blst element whose 64-bit limbs, which `Fr8::load` takes as they
    /// are, hold this value.
    pub(crate) fn to_raw_fr(&self) -> blst_fr {
        let bytes = self.to_bytes();
        let mut l = [0; 4];
        for k in 0..4 {
            l[k] = u64::from_be_bytes(bytes[24 - 8 * k..32 - 8 * k].try_into().unwrap());
        }
        blst_fr { l }
    }

    /// The value of the limbs read as signed 64-bit integers, which must lie
    /// in [0, 2^260), in normalised limbs.
    pub(crate) fn carried(&self) -> Self {
        Self([0; LIMBS]).plus_multiple(1, self)
    }

    /// self + k·b in normalised limbs, every limb read as a signed 64-bit
    /// integer. The result must lie in [0, 2^260).
    pub(crate) fn plus_multiple(&self, k: i128, b: &Self) -> Self {
        let mut x = [0; LIMBS];
        let mut carry = 0i128;
        for j in 0..LIMBS {
            let limb = self.0[j] as i64 as i128 + k * (b.0[j] as i64 as i128) + carry;
            x[j] = (limb & MASK52 as i128) as u64;
            carry = limb >> 52;
        }
        assert!(carry == 0, "result in [0, 2^260)");
        Self(x)
    }

    pub(crate) fn is_below(&self, bound: &Self) -> bool {
        self.0.iter().rev().lt(bound.0.iter().rev())
    }

    /// Random normalised limbs below this value.
    pub(crate) fn random_below(&self, rng: &mut ChaCha8Rng) -> Self {
        loop {
            let mut x = [0; LIMBS];
            for j in 0..LIMBS - 1 {
                x[j] = rng.r#gen::<u64>() & MASK52;
            }
            x[LIMBS - 1] = rng.gen_range(0..=self.0[LIMBS - 1]);
            if Self(x).is_below(self) {
                return Self(x);
            }
        }
    }
}
