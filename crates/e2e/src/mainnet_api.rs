//! Curl-based fetches against public mainnet beacon archives. We shell
//! out to `curl` rather than pull in an HTTP crate; this module wraps
//! that so the three callers (perf-fixture anchor + block downloads,
//! ground-truth state-root lookups) stop repeating the same arg arrays.
//!
//! Public endpoints are policy-free one-shots: state/block writes are
//! atomic via a sibling `.tmp`, rate-limit responses are returned to the
//! caller so backoff stays with the caller's pacing budget.

use std::{path::Path, process::Command};

type Result<T> = std::result::Result<T, String>;

const STATE_BY_ID_BASE: &str =
    "https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states";
/// SSZ block source. lodestar returns binary SSZ for `Accept:
/// application/octet-stream` but rate-limits to ~1 req / 6 s per IP (429
/// above, no parallelism win). publicnode ignores Accept and always
/// returns JSON, so it's only usable for the header lookup below.
const BLOCK_URL_BASE: &str = "https://lodestar-mainnet.chainsafe.io/eth/v2/beacon/blocks";
/// Finalized-slot lookup. Tiny JSON, served fast + unlimited by publicnode.
const FINALIZED_HEADER_URL: &str =
    "https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/headers/finalized";
/// A `SignedBeaconBlock` SSZ begins with the 4-byte offset to its single
/// variable field (`message`), always `4 + sizeof(signature=96) = 100`.
/// We validate this to reject JSON/error bodies a misbehaving endpoint
/// might return with a 200.
const SIGNED_BLOCK_MESSAGE_OFFSET: u32 = 100;

/// Outcome of one block fetch attempt. The caller (perf/remote) drives
/// rate-limit backoff with its own pacing budget.
pub enum BlockFetch {
    /// 200 + atomic write to the requested path succeeded.
    Present,
    /// 404 or 500: the slot is empty / missing on the archive.
    Empty,
    /// 429: caller should back off and retry.
    RateLimited,
}

/// Fetch the canonical post-state root for the block at `slot` from
/// lodestar's mainnet archive. The bare `/states/{slot}/root` route is
/// unavailable for deep history; block bodies are retained much longer
/// and the block JSON carries the canonical `state_root`. Returns `None`
/// on any network/parse failure so callers can skip cleanly when offline.
pub fn fetch_canonical_state_root(slot: u64) -> Option<[u8; 32]> {
    let url = format!("{BLOCK_URL_BASE}/{slot}");
    let body = curl_get_text(&url, "application/json", 15).ok()?;
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

/// Resolve the current finalized slot from publicnode's JSON header
/// endpoint. Used to compute an epoch-aligned anchor slot.
pub fn resolve_finalized_slot() -> Result<u64> {
    let body = curl_get_text(FINALIZED_HEADER_URL, "application/json", 20)?;
    // {"data":{...,"header":{"message":{"slot":"<N>",...
    let needle = "\"slot\":\"";
    let start = body.find(needle).ok_or("no slot in header JSON")? + needle.len();
    let end = body[start..].find('"').ok_or("malformed slot field")? + start;
    body[start..end].parse().map_err(|e| format!("parse slot '{}': {e}", &body[start..end]))
}

/// Atomically download the BeaconState SSZ for `anchor_id` (either
/// `"finalized"` or a slot number) to `out`. Errors on any non-200; uses
/// curl's built-in retry-all-errors for transient network failures.
pub fn fetch_state_ssz_to(out: &Path, anchor_id: &str) -> Result<()> {
    let url = format!("{STATE_BY_ID_BASE}/{anchor_id}");
    let tmp = with_tmp_suffix(out);
    let status = Command::new("curl")
        .args([
            "--location",
            "--show-error",
            "--fail",
            "--retry",
            "3",
            "--retry-all-errors",
            "--max-time",
            "120",
            "-H",
            "Accept: application/octet-stream",
            "-o",
        ])
        .arg(&tmp)
        .arg(&url)
        .status()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "state fetch failed ({status}) for {url}. chainsafe retains only ~3 recent \
             epochs; reduce the anchor lag (slot may have been pruned)."
        ));
    }
    std::fs::rename(&tmp, out).map_err(|e| format!("rename state tmp: {e}"))
}

/// One-shot block fetch. On 200, validates the response is actually SSZ
/// (the endpoint can ignore the Accept header and return JSON) and
/// atomically writes to `out`. 404/500 → `Empty`, 429 → `RateLimited`.
pub fn fetch_block_ssz_to(out: &Path, slot: u64) -> Result<BlockFetch> {
    let url = format!("{BLOCK_URL_BASE}/{slot}");
    let tmp = with_tmp_suffix(out);
    let code = curl_to_file(&tmp, &url, "application/octet-stream", 30)?;
    match code {
        200 => {
            if !is_ssz_block_file(&tmp) {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!(
                    "slot {slot}: 200 but body is not SSZ (endpoint ignored \
                     Accept: octet-stream and returned JSON?)"
                ));
            }
            std::fs::rename(&tmp, out).map_err(|e| format!("rename block tmp: {e}"))?;
            Ok(BlockFetch::Present)
        }
        404 | 500 => {
            let _ = std::fs::remove_file(&tmp);
            Ok(BlockFetch::Empty)
        }
        429 => {
            let _ = std::fs::remove_file(&tmp);
            Ok(BlockFetch::RateLimited)
        }
        other => {
            let _ = std::fs::remove_file(&tmp);
            Err(format!("slot {slot}: unexpected HTTP {other}"))
        }
    }
}

fn curl_base(accept: &str, max_time_secs: u32) -> Command {
    let mut cmd = Command::new("curl");
    cmd.arg("--max-time").arg(max_time_secs.to_string()).arg("-H").arg(format!("Accept: {accept}"));
    cmd
}

/// GET `url` and return the response body as text. For small JSON
/// endpoints where streaming to disk would add no value.
fn curl_get_text(url: &str, accept: &str, max_time_secs: u32) -> Result<String> {
    let out = curl_base(accept, max_time_secs)
        .args(["-fsSL", "--retry", "2"])
        .arg(url)
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    if !out.status.success() {
        return Err(format!("curl {url} failed: {}", out.status));
    }
    String::from_utf8(out.stdout).map_err(|e| format!("curl {url} body not utf-8: {e}"))
}

/// GET `url`, save body to `out`, return the final HTTP status code via
/// `-w '%{http_code}'`. No `--fail`: caller branches on the code.
fn curl_to_file(out: &Path, url: &str, accept: &str, max_time_secs: u32) -> Result<u16> {
    let result = curl_base(accept, max_time_secs)
        .args(["--silent", "--location", "--show-error"])
        .arg("-o")
        .arg(out)
        .arg("-w")
        .arg("%{http_code}")
        .arg(url)
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    String::from_utf8_lossy(&result.stdout)
        .trim()
        .parse()
        .map_err(|e| format!("parse http code from curl {url}: {e}"))
}

fn is_ssz_block_file(path: &Path) -> bool {
    let mut buf = [0u8; 4];
    use std::io::Read;
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|()| u32::from_le_bytes(buf) == SIGNED_BLOCK_MESSAGE_OFFSET)
        .unwrap_or(false)
}

fn with_tmp_suffix(path: &Path) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    std::path::PathBuf::from(s)
}
