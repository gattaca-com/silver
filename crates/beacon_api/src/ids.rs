//! The forms an identifier arrives in. A bare `Uint64` is a slot for the
//! `state_id`/`block_id` of `params/index.yaml` and an epoch for the duties
//! endpoints, which declare that parameter themselves; the `0x`-prefixed
//! 32-byte root is a form those two parameters alone also take. Each
//! endpoint's keywords are its own.

use silver_beacon_state_data::B256;

/// How many validators one POST body may name. No schema that takes a list of
/// them sets a `maxItems`, and an unbounded list turns a 16 MiB body into
/// millions of entries to parse, check and answer inside a single request. A
/// quarter of a million is an order of magnitude past the largest single
/// validator client in production, against a mainnet registry of ~2M.
pub(crate) const MAX_BODY_IDS: usize = 256 * 1024;

/// `u64::from_str` alone also accepts a leading `+`, which the schemas call an
/// invalid identifier rather than a number.
pub(crate) fn parse_uint64(text: &str) -> Option<u64> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse().ok()).flatten()
}

pub(crate) fn parse_root(text: &str) -> Option<B256> {
    let mut root = B256::default();
    hex::decode_to_slice(text.strip_prefix("0x")?, &mut root).ok()?;
    Some(root)
}

/// Whether `text` spells exactly `bytes` bytes in the `0x`-prefixed hex of the
/// schemas' `pattern`, either case, for a field a handler checks and discards.
pub(crate) fn is_hex_bytes(text: &str, bytes: usize) -> bool {
    text.strip_prefix("0x").is_some_and(|hex| {
        hex.len() == 2 * bytes && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

/// The whole body of `validator/duties/sync/{epoch}` and
/// `validator/liveness/{epoch}`: an array of `Uint64` — quoted decimal
/// strings — with `minItems: 1`. Deduplicated, so a validator named twice is
/// answered once.
pub(crate) fn submitted_indices(body: &[u8]) -> Result<Vec<u64>, &'static str> {
    let submitted: Vec<&str> = serde_json::from_slice(body).map_err(|_| "invalid request body")?;
    if submitted.is_empty() {
        return Err("no validator index in request body");
    }
    if submitted.len() > MAX_BODY_IDS {
        return Err("too many validator indices in request body");
    }
    let mut indices = submitted
        .iter()
        .map(|text| parse_uint64(text).ok_or("invalid validator index"))
        .collect::<Result<Vec<_>, _>>()?;
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}
