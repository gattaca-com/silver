//! Mainnet beacon API ground-truth lookups for tests.

/// Fetch the canonical post-state root for the block at `slot` from
/// lodestar's mainnet archive (same source the Makefile already pulls
/// `next_block_*.ssz` from). The bare `/states/{slot}/root` route is
/// unavailable for deep history; block bodies are retained much longer
/// and the block JSON carries the canonical `state_root`. Returns `None`
/// on any network/parse failure so callers can skip cleanly when offline.
pub fn fetch_canonical_state_root(slot: u64) -> Option<[u8; 32]> {
    let url = format!("https://lodestar-mainnet.chainsafe.io/eth/v2/beacon/blocks/{slot}");
    let out = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "15", "-H", "Accept: application/json", &url])
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
    for i in 0..32 {
        root[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(root)
}
