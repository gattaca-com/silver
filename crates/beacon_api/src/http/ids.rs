use std::{fmt, marker::PhantomData};

use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use silver_beacon_state_data::{B256, BLSPubkey, ExecutionAddress};
use silver_common::json_fields::{parse_hex, parse_uint64, uint64};

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
