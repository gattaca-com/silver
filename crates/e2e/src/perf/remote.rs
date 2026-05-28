//! Remote-fetch policy for perf fixtures. Decides *when* to hit the
//! mainnet archive (TTL gate, lookahead probe, rate-limit backoff) and
//! delegates the actual HTTP to [`crate::mainnet_api`].

use std::{path::Path, thread, time::Duration};

use crate::{
    mainnet_api::{BlockFetch, fetch_block_ssz_to, fetch_state_ssz_to, resolve_finalized_slot},
    perf::cache,
};

const SLOTS_PER_EPOCH: u64 = 32;
/// Lodestar's per-IP block rate limit is ~1 req / 6 s; faster gets 429s.
const BLOCK_REQUEST_SPACING: Duration = Duration::from_secs(6);
const BLOCK_MAX_RETRIES: u32 = 4;
/// Deepest anchor we'll request: past chainsafe's ~3-epoch retention the
/// state fetch 500s, so we stay ~1 epoch inside it.
pub const MAX_ANCHOR_LAG_SLOTS: u64 = 64;

/// Fetch the anchor state when stale or absent; `Ok(true)` if a fetch
/// happened (caller invalidates the next-block cache). Anchor =
/// `finalized − clamp(anchor_lag_slots)`, epoch-aligned. `lag == 0` uses
/// chainsafe's `finalized` alias rather than a slot resolved via
/// publicnode: the by-slot route races at the boundary on cross-provider
/// finalized skew (404), and the alias is already epoch-aligned. For
/// `lag > 0` that skew is harmless.
pub fn fetch_anchor_state(
    path: &Path,
    anchor_lag_slots: u64,
    ttl: Duration,
) -> Result<bool, String> {
    if let Ok(meta) = std::fs::metadata(path) &&
        let Ok(modified) = meta.modified() &&
        modified.elapsed().map(|age| age < ttl).unwrap_or(false)
    {
        eprintln!("fixtures: reusing cached {} (within TTL)", path.display());
        return Ok(false);
    }

    let lag = anchor_lag_slots.min(MAX_ANCHOR_LAG_SLOTS);
    let anchor_id = if lag == 0 {
        eprintln!("fixtures: anchoring at latest finalized (alias)");
        "finalized".to_string()
    } else {
        let finalized = resolve_finalized_slot()?;
        let anchor = (finalized.saturating_sub(lag) / SLOTS_PER_EPOCH) * SLOTS_PER_EPOCH;
        eprintln!(
            "fixtures: finalized={finalized}, anchoring {} slots back at epoch-aligned slot {anchor}",
            finalized - anchor
        );
        anchor.to_string()
    };
    eprintln!("fixtures: fetching anchor {anchor_id} -> {}", path.display());
    fetch_state_ssz_to(path, &anchor_id)?;
    Ok(true)
}

/// Probe slots `anchor+1..=anchor+lookahead`, fetching block SSZ until
/// `n_blocks` are cached. Empty slots (404/500) are skipped, cached
/// slots cost no request. Serial with 6 s spacing + 429 backoff
/// (per-IP cap, no parallelism win).
pub fn fetch_following_blocks(
    dir: &Path,
    anchor: u64,
    n_blocks: usize,
    lookahead: u64,
) -> Result<(), String> {
    let cache = cache::FixtureCacheDir(dir);
    let mut got = cache.count_cached_blocks(anchor, lookahead);
    if got >= n_blocks {
        return Ok(());
    }
    for probe in 1..=lookahead {
        if got >= n_blocks {
            break;
        }
        let slot = anchor + probe;
        let out = cache.block_path(slot);
        if out.exists() {
            continue;
        }
        match fetch_one_block_with_backoff(&out, slot)? {
            true => {
                got += 1;
                eprintln!("fixtures: slot {slot}: ok ({got}/{n_blocks})");
            }
            false => eprintln!("fixtures: slot {slot}: empty, skipping"),
        }
        thread::sleep(BLOCK_REQUEST_SPACING);
    }
    if got < n_blocks {
        eprintln!("fixtures: WARN only {got}/{n_blocks} blocks within {lookahead}-slot lookahead");
    }
    Ok(())
}

/// One block fetch, retrying on 429 with linear backoff. `Ok(true)` for
/// a saved block, `Ok(false)` for an empty slot.
fn fetch_one_block_with_backoff(out: &Path, slot: u64) -> Result<bool, String> {
    for attempt in 1..=BLOCK_MAX_RETRIES {
        match fetch_block_ssz_to(out, slot)? {
            BlockFetch::Present => return Ok(true),
            BlockFetch::Empty => return Ok(false),
            BlockFetch::RateLimited => {
                if attempt >= BLOCK_MAX_RETRIES {
                    return Err(format!("slot {slot}: still 429 after {attempt} tries"));
                }
                let backoff = BLOCK_REQUEST_SPACING * attempt;
                eprintln!("fixtures: slot {slot}: 429, backing off {backoff:?}");
                thread::sleep(backoff);
            }
        }
    }
    unreachable!("loop returns or errs on the final attempt")
}
