use super::wei_from_gwei;

/// Big-endian limbs hold a uint256 wei value multiplied by a uint64 percentage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct BidWeight([u64; 5]);

impl BidWeight {
    pub(super) fn external(gwei: u128, boost: u64) -> Self {
        Self::from_wei(&wei_from_gwei(gwei), boost)
    }

    pub(super) fn local(wei: &[u8; 32]) -> Self {
        Self::from_wei(wei, 100)
    }

    fn from_wei(wei: &[u8; 32], boost: u64) -> Self {
        let mut limbs = [0; 5];
        let mut carry = 0u128;
        for (i, bytes) in wei.chunks_exact(8).enumerate() {
            let value = u64::from_le_bytes(bytes.try_into().expect("8 bytes"));
            let product = u128::from(value) * u128::from(boost) + carry;
            limbs[4 - i] = product as u64;
            carry = product >> 64;
        }
        limbs[0] = carry as u64;
        Self(limbs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_wei_without_rounding_or_saturation() {
        let mut local = wei_from_gwei(3);
        assert_eq!(BidWeight::local(&local), BidWeight::external(2, 150));
        local[..16].copy_from_slice(&3_000_000_001u128.to_le_bytes());
        assert!(BidWeight::local(&local) > BidWeight::external(2, 150));
        local[..16].copy_from_slice(&2_999_999_999u128.to_le_bytes());
        assert!(BidWeight::local(&local) < BidWeight::external(2, 150));
        let maximum = BidWeight::external(2 * u128::from(u64::MAX), u64::MAX);
        assert!(maximum > BidWeight::external(u128::from(u64::MAX), u64::MAX));
        assert!(BidWeight::local(&[255; 32]) > maximum);
        let mut above_u128 = [0; 32];
        above_u128[16] = 1;
        assert!(maximum > BidWeight::local(&above_u128));
    }
}
