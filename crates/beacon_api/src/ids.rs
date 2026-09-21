use serde::{Deserialize, Deserializer, de};
use silver_beacon_state_data::{B256, BLSPubkey};

use crate::response::Response;

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
    let Ok(entries) = serde_json::from_slice::<Vec<T>>(body) else {
        resp.error(400, "invalid request body");
        return None;
    };
    if entries.len() > MAX_BODY_IDS {
        resp.error(400, "too many entries in request body");
        return None;
    }
    Some(entries)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ValidatorIndex(pub(crate) u64);

impl<'de> Deserialize<'de> for ValidatorIndex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        parse_uint64(text).map(Self).ok_or_else(|| de::Error::custom("not a Uint64"))
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
