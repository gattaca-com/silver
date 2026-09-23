use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use silver_beacon_state_data::{B256, BLSPubkey};

use crate::http::response::Response;

/// How many validators one POST body may name. No schema that takes a list of
/// them sets a `maxItems`, and an unbounded list turns a 16 MiB body into
/// millions of entries to parse, check and answer inside a single request. A
/// quarter of a million is an order of magnitude past the largest single
/// validator client in production, against a mainnet registry of ~2M.
pub(crate) const MAX_BODY_IDS: usize = 256 * 1024;

/// The array a body carries, unchecked beyond its shape and length.
pub(crate) fn body_entries<'a, T: Deserialize<'a>>(
    body: &'a [u8],
    resp: &mut Response<'_>,
) -> Option<Vec<T>> {
    let mut entries = Vec::new();
    match each_body_entry(body, |_, entry| entries.push(entry)) {
        Ok(_) => Some(entries),
        Err(message) => {
            resp.error(400, message);
            None
        }
    }
}

/// Parses the body's array one entry at a time, handing each to `each` with
/// its index, and returns how many there were. Entries before a malformed one
/// have already been handed over when the error returns.
pub(crate) fn each_body_entry<'a, T: Deserialize<'a>>(
    body: &'a [u8],
    each: impl FnMut(usize, T),
) -> Result<usize, &'static str> {
    let mut too_many = false;
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let entries = Entries { each, too_many: &mut too_many, entry: PhantomData };
    match deserializer.deserialize_seq(entries).and_then(|count| deserializer.end().map(|()| count))
    {
        Ok(count) => Ok(count),
        Err(_) if too_many => Err("too many entries in request body"),
        Err(_) => Err("invalid request body"),
    }
}

struct Entries<'f, F, T> {
    each: F,
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
            if count == MAX_BODY_IDS {
                *self.too_many = true;
                return Err(de::Error::custom("too many entries"));
            }
            (self.each)(count, entry);
            count += 1;
        }
        Ok(count)
    }
}

/// The schemas' `Uint64`: a decimal inside a JSON string.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Uint64(pub(crate) u64);

impl<'de> Deserialize<'de> for Uint64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        parse_uint64(text).map(Self).ok_or_else(|| de::Error::custom("not a Uint64"))
    }
}

/// The schemas' `Bytes`: `0x`-prefixed hex spelling exactly `N` bytes.
pub(crate) struct Hex<const N: usize>(pub(crate) [u8; N]);

impl<'de, const N: usize> Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        parse_hex(text).map(Self).ok_or_else(|| de::Error::custom("not a byte string"))
    }
}

/// The schemas' variable-length `Bytes`: `0x`-prefixed hex of at most `N`
/// bytes.
pub(crate) struct BoundedHex<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> BoundedHex<N> {
    pub(crate) fn as_bytes(&self) -> &[u8] {
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
pub(crate) fn parse_uint64(text: &str) -> Option<u64> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse().ok()).flatten()
}

pub(crate) fn parse_root(text: &str) -> Option<B256> {
    parse_hex(text)
}

pub(crate) fn parse_pubkey(text: &str) -> Option<BLSPubkey> {
    parse_hex(text)
}

fn parse_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut bytes = [0u8; N];
    hex::decode_to_slice(text.strip_prefix("0x")?, &mut bytes).ok()?;
    Some(bytes)
}

pub(crate) fn is_recognized_id(id: &str) -> bool {
    matches!(id, "head" | "genesis" | "justified" | "finalized") ||
        parse_uint64(id).is_some() ||
        parse_root(id).is_some()
}

/// Whether `text` spells exactly `bytes` bytes in the `0x`-prefixed hex of the
/// schemas' `pattern`, either case, for a field a handler checks and discards.
pub(crate) fn is_hex_bytes(text: &str, bytes: usize) -> bool {
    text.strip_prefix("0x").is_some_and(|hex| {
        hex.len() == 2 * bytes && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}
