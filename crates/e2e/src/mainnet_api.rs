//! Read-only canonical-state-root lookup against a public mainnet
//! archive. Used by e2e tests that replay `example_checkpoints` fixtures
//! as a best-effort correctness check (skip silently when offline).

use std::process::Command;

const BLOCK_URL_BASE: &str = "https://ethereum-beacon-api.publicnode.com/eth/v2/beacon/blocks";

/// Fetch the canonical post-state root for the block at `slot`. The
/// `/states/{slot}/root` route isn't available for deep history; block
/// bodies are retained much longer and the block JSON carries the
/// post-state `state_root` field directly. Returns `None` on any
/// network/parse failure so callers can skip cleanly when offline.
pub fn fetch_canonical_state_root(slot: u64) -> Option<[u8; 32]> {
    let url = format!("{BLOCK_URL_BASE}/{slot}");
    let out = Command::new("curl")
        .args(["--max-time", "15", "-H", "Accept: application/json", "-fsSL", "--retry", "2"])
        .arg(&url)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = std::str::from_utf8(&out.stdout).ok()?;
    let needle = "\"state_root\":\"";
    let mut start = body.find(needle)? + needle.len();
    if body.get(start..start + 2) == Some("0x") {
        start += 2;
    }
    let hex = body.get(start..start + 64)?;
    let mut root = [0u8; 32];
    hex::decode_to_slice(hex, &mut root).ok()?;
    Some(root)
}
