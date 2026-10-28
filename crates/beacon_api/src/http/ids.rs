use serde::{Deserialize, Deserializer};
use silver_beacon_state_data::{B256, BLSPubkey, ExecutionAddress};
use silver_common::json_fields::{each_array_entry, parse_hex, parse_uint64, uint64};

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

/// [`each_array_entry`] bounded by [`MAX_BODY_IDS`].
pub(crate) fn each_body_entry<'a, T: Deserialize<'a>>(
    body: &'a [u8],
    each: impl FnMut(usize, T),
) -> Result<usize, &'static str> {
    each_array_entry(body, MAX_BODY_IDS, each)
}

/// A JSON array of quoted `Uint64`s.
pub(crate) fn uint64_list<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<u64>, D::Error> {
    #[derive(Deserialize)]
    struct Quoted(#[serde(deserialize_with = "uint64")] u64);
    let quoted = Vec::<Quoted>::deserialize(deserializer)?;
    Ok(quoted.into_iter().map(|Quoted(value)| value).collect())
}

pub(crate) fn parse_root(text: &str) -> Option<B256> {
    parse_hex(text)
}

pub(crate) fn parse_pubkey(text: &str) -> Option<BLSPubkey> {
    parse_hex(text)
}

pub(crate) fn parse_execution_address(text: &str) -> Option<ExecutionAddress> {
    parse_hex(text)
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
