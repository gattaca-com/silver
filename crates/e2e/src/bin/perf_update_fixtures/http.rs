use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const STATE_BY_ID_BASE: &str =
    "https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states";
/// Returns binary SSZ for `Accept: application/octet-stream`. The previous
/// source, `lodestar-mainnet.chainsafe.io`, has been 503 since 2026-07-21.
const BLOCK_URL_BASE: &str = "http://testing.mainnet.beacon-api.nimbus.team/eth/v2/beacon/blocks";
const FINALIZED_HEADER_URL: &str =
    "https://ethereum-beacon-api.publicnode.com/eth/v1/beacon/headers/finalized";
// 4-byte offset to `message` + signature(96).
const SIGNED_BLOCK_MESSAGE_OFFSET: u32 = 4 + 96;

pub(super) enum BlockFetch {
    Present,
    Empty,
    RateLimited,
}

pub(super) fn resolve_finalized_slot() -> Result<u64, String> {
    let body = curl_get_text(FINALIZED_HEADER_URL, "application/json", 20)?;
    let needle = "\"slot\":\"";
    let start = body.find(needle).ok_or("no slot in header JSON")? + needle.len();
    let end = body[start..].find('"').ok_or("malformed slot field")? + start;
    body[start..end].parse().map_err(|e| format!("parse slot '{}': {e}", &body[start..end]))
}

pub(super) fn fetch_state_ssz_to(out: &Path, state_id: &str) -> Result<(), String> {
    let url = format!("{STATE_BY_ID_BASE}/{state_id}");
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
        let _ = fs::remove_file(&tmp);
        return Err(format!(
            "state fetch failed ({status}) for {url}. chainsafe retains only ~3 recent \
             epochs; reduce the finalized-slot lag (slot may have been pruned)."
        ));
    }
    fs::rename(&tmp, out).map_err(|e| format!("rename state tmp: {e}"))
}

pub(super) fn fetch_block_ssz_to(out: &Path, slot: u64) -> Result<BlockFetch, String> {
    let url = format!("{BLOCK_URL_BASE}/{slot}");
    let tmp = with_tmp_suffix(out);
    let code = curl_to_file(&tmp, &url, "application/octet-stream", 30)?;
    match code {
        200 => {
            if !is_ssz_block_file(&tmp) {
                let _ = fs::remove_file(&tmp);
                return Err(format!(
                    "slot {slot}: 200 but body is not SSZ (endpoint ignored \
                     Accept: octet-stream and returned JSON?)"
                ));
            }
            fs::rename(&tmp, out).map_err(|e| format!("rename block tmp: {e}"))?;
            Ok(BlockFetch::Present)
        }
        404 | 500 => {
            let _ = fs::remove_file(&tmp);
            Ok(BlockFetch::Empty)
        }
        // 000 = curl couldn't get a response (timeout / connection reset);
        // treat as transient and let the caller's retry loop back off.
        0 | 429 => {
            let _ = fs::remove_file(&tmp);
            Ok(BlockFetch::RateLimited)
        }
        other => {
            let _ = fs::remove_file(&tmp);
            Err(format!("slot {slot}: unexpected HTTP {other}"))
        }
    }
}

fn curl_base(accept: &str, max_time_secs: u32) -> Command {
    let mut cmd = Command::new("curl");
    cmd.arg("--max-time").arg(max_time_secs.to_string()).arg("-H").arg(format!("Accept: {accept}"));
    cmd
}

fn curl_get_text(url: &str, accept: &str, max_time_secs: u32) -> Result<String, String> {
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

fn curl_to_file(out: &Path, url: &str, accept: &str, max_time_secs: u32) -> Result<u16, String> {
    let result = curl_base(accept, max_time_secs)
        .args(["--silent", "--location", "--show-error", "--retry", "3", "--retry-all-errors"])
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
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut buf))
        .map(|()| u32::from_le_bytes(buf) == SIGNED_BLOCK_MESSAGE_OFFSET)
        .unwrap_or(false)
}

fn with_tmp_suffix(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}
