//! The forms an identifier arrives in. A bare `Uint64` is a slot for the
//! `state_id`/`block_id` of `params/index.yaml` and an epoch for the duties
//! endpoints, which declare that parameter themselves; the `0x`-prefixed
//! 32-byte root is a form those two parameters alone also take. Each
//! endpoint's keywords are its own.

use silver_beacon_state_data::B256;

/// How many identifiers one POST body may name. The two schemas that take a
/// body of them (`beacon/states/{state_id}/validators`,
/// `validator/duties/sync/{epoch}`) set no `maxItems`, and an unbounded list
/// turns a 16 MiB body into millions of ids to resolve inside the seqlock
/// read. A quarter of a million is an order of magnitude past the largest
/// single validator client in production, against a mainnet registry of ~2M.
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
