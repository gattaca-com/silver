//! Refresh `crates/e2e/data/perf/` from public mainnet archives. Network
//! code lives only here; `just perf-local` stays hermetic.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::Duration,
};

use silver_e2e::{mainnet_api::fetch_canonical_state_root, perf::fixtures_dir::FixturesDir};

use self::http::BlockFetch;

mod http;

fn main() -> ExitCode {
    let args = parse_args();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/perf");
    if let Err(e) = run(&dir, args) {
        eprintln!("perf-update-fixtures: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

struct Args {
    blocks: usize,
    resume: bool,
}

fn parse_args() -> Args {
    let argv: Vec<String> = env::args().skip(1).collect();
    let mut blocks = None;
    let mut resume = false;
    let mut i = 0;
    while i < argv.len() {
        let a = &argv[i];
        if let Some(v) = a.strip_prefix("--blocks=") {
            blocks = v.parse().ok();
            i += 1;
        } else if a == "--blocks" &&
            let Some(next) = argv.get(i + 1) &&
            !next.starts_with("--")
        {
            blocks = next.parse().ok();
            i += 2;
        } else if a == "--continue" {
            resume = true;
            i += 1;
        } else {
            i += 1;
        }
    }
    Args { blocks: blocks.unwrap_or(128), resume }
}

const SLOTS_PER_EPOCH: u64 = 32;
/// Lodestar's per-IP block rate limit is ~1 req / 6 s; faster gets 429s.
const BLOCK_REQUEST_SPACING: Duration = Duration::from_secs(6);
const BLOCK_MAX_RETRIES: u32 = 4;
/// Deepest finalized slot we'll request: past chainsafe's ~3-epoch
/// retention the state fetch 500s, so we stay ~1 epoch inside it.
const MAX_FINALIZED_LAG_SLOTS: u64 = 64;

fn run(dir: &Path, args: Args) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|e| format!("create_dir_all({}): {e}", dir.display()))?;
    let fixtures = FixturesDir(dir);
    let Args { blocks: n_blocks, resume } = args;

    let finalized_slot = if resume {
        fixtures.read_finalized_slot().map_err(|e| {
            format!("--continue: no usable finalized_state.ssz ({e}); drop the flag to refetch")
        })?
    } else {
        fixtures.clear_next_blocks();
        fetch_finalized_state(&fixtures)?
    };

    let saved = fetch_following_blocks(&fixtures, finalized_slot, n_blocks)?;
    if saved < n_blocks {
        let lookahead = (n_blocks as u64 * 3 / 2).max(8);
        return Err(format!(
            "only {saved}/{n_blocks} blocks within {lookahead}-slot lookahead — \
             try a wider lookahead or fewer blocks"
        ));
    }

    let final_slot = fixtures
        .read_sorted_next_blocks()
        .last()
        .map(|(s, _)| *s)
        .ok_or("no blocks on disk after fetch")?;
    let head_state_root = fetch_canonical_state_root(final_slot)
        .ok_or_else(|| format!("canonical state_root unreachable for slot {final_slot}"))?;
    fixtures.write_expected(finalized_slot, final_slot, &head_state_root)?;

    eprintln!(
        "fixtures: ready in {} — finalized {finalized_slot}, {saved} blocks up to {final_slot}",
        dir.display()
    );
    eprintln!();
    eprintln!("Next: commit via git-lfs — see crates/e2e/data/perf/README.md");
    Ok(())
}

fn fetch_finalized_state(fixtures: &FixturesDir) -> Result<u64, String> {
    let head_finalized = http::resolve_finalized_slot()?;
    // Resolve a concrete epoch-aligned slot — alias 'finalized' races at the
    // boundary (cross-provider 404).
    let finalized_slot = (head_finalized.saturating_sub(MAX_FINALIZED_LAG_SLOTS / 2) /
        SLOTS_PER_EPOCH) *
        SLOTS_PER_EPOCH;
    let path = fixtures.finalized_state_path();
    eprintln!(
        "fixtures: head_finalized={head_finalized}, fetching epoch-aligned finalized state \
         at slot {finalized_slot} -> {}",
        path.display()
    );
    http::fetch_state_ssz_to(&path, &finalized_slot.to_string())?;
    Ok(finalized_slot)
}

fn fetch_following_blocks(
    fixtures: &FixturesDir,
    finalized_slot: u64,
    n_blocks: usize,
) -> Result<usize, String> {
    let lookahead = (n_blocks as u64 * 3 / 2).max(8);
    let mut got = 0usize;
    for probe in 1..=lookahead {
        if got >= n_blocks {
            break;
        }
        let slot = finalized_slot + probe;
        let out = fixtures.block_path(slot);
        if out.exists() {
            got += 1;
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
    Ok(got)
}

fn fetch_one_block_with_backoff(out: &Path, slot: u64) -> Result<bool, String> {
    for attempt in 1..BLOCK_MAX_RETRIES {
        match http::fetch_block_ssz_to(out, slot)? {
            BlockFetch::Present => return Ok(true),
            BlockFetch::Empty => return Ok(false),
            BlockFetch::RateLimited => {
                let backoff = BLOCK_REQUEST_SPACING * attempt;
                eprintln!("fixtures: slot {slot}: 429, backing off {backoff:?}");
                thread::sleep(backoff);
            }
        }
    }
    match http::fetch_block_ssz_to(out, slot)? {
        BlockFetch::Present => Ok(true),
        BlockFetch::Empty => Ok(false),
        BlockFetch::RateLimited => {
            Err(format!("slot {slot}: still 429 after {BLOCK_MAX_RETRIES} tries"))
        }
    }
}
