//! The two identifier forms `state_id` and `block_id` share
//! (`params/index.yaml`): a slot, or a `0x`-prefixed 32-byte root. Each
//! endpoint's keywords are its own.

use silver_beacon_state_data::{B256, Slot};

/// `u64::from_str` alone also accepts a leading `+`, which the schemas call an
/// invalid identifier rather than a slot.
pub(crate) fn parse_slot(text: &str) -> Option<Slot> {
    text.bytes().all(|byte| byte.is_ascii_digit()).then(|| text.parse().ok()).flatten()
}

pub(crate) fn parse_root(text: &str) -> Option<B256> {
    let mut root = B256::default();
    hex::decode_to_slice(text.strip_prefix("0x")?, &mut root).ok()?;
    Some(root)
}
