use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};

/// The schemas' `Uint64`: a decimal inside a JSON string.
pub fn uint64<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let text = <&str>::deserialize(deserializer)?;
    parse_uint64(text).ok_or_else(|| de::Error::custom("not a Uint64"))
}

/// The schemas' `Uint256`: a decimal inside a JSON string, as 32 little-endian
/// bytes.
pub fn uint256<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
    let text = <&str>::deserialize(deserializer)?;
    parse_uint256(text).ok_or_else(|| de::Error::custom("not a Uint256"))
}

/// The schemas' `Bytes`: `0x`-prefixed hex spelling exactly `N` bytes.
pub fn bytes<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let text = <&str>::deserialize(deserializer)?;
    parse_hex(text).ok_or_else(|| de::Error::custom("not a byte string"))
}

/// The schemas' variable-length `Bytes`: `0x`-prefixed hex of at most `N`
/// bytes.
pub struct BoundedHex<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> BoundedHex<N> {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedHex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        let hex = text.strip_prefix("0x").filter(|hex| hex.len() <= 2 * N);
        let mut bytes = [0u8; N];
        let len = hex.map_or(0, |hex| hex.len() / 2);
        match hex.map(|hex| hex::decode_to_slice(hex, &mut bytes[..len])) {
            Some(Ok(())) => Ok(Self { bytes, len }),
            _ => Err(de::Error::custom("not a byte string of the allowed length")),
        }
    }
}

/// `u64::from_str` alone also accepts a leading `+`, which the schemas call an
/// invalid identifier rather than a number.
pub fn parse_uint64(text: &str) -> Option<u64> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse().ok()).flatten()
}

fn parse_uint256(text: &str) -> Option<[u8; 32]> {
    if text.is_empty() {
        return None;
    }
    let mut limbs = [0u64; 4];
    for digit in text.bytes() {
        let mut carry = u128::from(digit.checked_sub(b'0').filter(|d| *d < 10)?);
        for limb in &mut limbs {
            let next = u128::from(*limb) * 10 + carry;
            *limb = next as u64;
            carry = next >> 64;
        }
        if carry != 0 {
            return None;
        }
    }
    let mut out = [0; 32];
    for (bytes, limb) in out.chunks_exact_mut(8).zip(limbs) {
        bytes.copy_from_slice(&limb.to_le_bytes());
    }
    Some(out)
}

pub fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    hex::decode_to_slice(text.strip_prefix("0x")?, &mut bytes).ok()?;
    Some(bytes)
}

/// Parses a JSON array of at most `max` entries one entry at a time, handing
/// each to `each` with its index, and returns how many there were. Entries
/// before a malformed one have already been handed over when the error
/// returns.
pub fn each_array_entry<'a, T: Deserialize<'a>>(
    json: &'a [u8],
    max: usize,
    each: impl FnMut(usize, T),
) -> Result<usize, &'static str> {
    let mut too_many = false;
    let mut deserializer = serde_json::Deserializer::from_slice(json);
    let entries = Entries { each, max, too_many: &mut too_many, entry: PhantomData };
    match deserializer.deserialize_seq(entries).and_then(|count| deserializer.end().map(|()| count))
    {
        Ok(count) => Ok(count),
        Err(_) if too_many => Err("too many entries in request body"),
        Err(_) => Err("invalid request body"),
    }
}

struct Entries<'f, F, T> {
    each: F,
    max: usize,
    too_many: &'f mut bool,
    entry: PhantomData<T>,
}

impl<'de, F: FnMut(usize, T), T: Deserialize<'de>> Visitor<'de> for Entries<'_, F, T> {
    type Value = usize;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an array")
    }

    fn visit_seq<A: SeqAccess<'de>>(mut self, mut seq: A) -> Result<usize, A::Error> {
        let mut count = 0;
        while let Some(entry) = seq.next_element()? {
            if count == self.max {
                *self.too_many = true;
                return Err(de::Error::custom("too many entries"));
            }
            (self.each)(count, entry);
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint256_spans_all_limbs_and_refuses_overflow() {
        let mut one_past_u128 = [0; 32];
        one_past_u128[16] = 1;
        assert_eq!(parse_uint256("340282366920938463463374607431768211456"), Some(one_past_u128));
        let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
        assert_eq!(parse_uint256(max), Some([0xff; 32]));
        assert_eq!(parse_uint256(&format!("{max}0")), None);
        assert_eq!(parse_uint256("12a"), None);
        assert_eq!(parse_uint256(""), None);
    }
}
