//! Refresh `crates/e2e/data/da/` from a running supernode
//! (`data_column_custody_group_count = 128`) — the only node holding a full
//! custody set together with the order it arrived in.
//!
//!   CH_URL=<telemetry clickhouse> just da-fixtures <user>@<beacon-host>
//!
//! Always the window after the node's newest checkpoint — the only window a
//! capture can anchor anyway.

use std::{
    fs,
    path::Path,
    process::{Command, ExitCode},
};

use silver_e2e::da_capture::{self, ColumnFixtures};

/// Store layout, relative to the remote home.
const STORE: &str = ".local/silver";
/// Spare slots cover ones that carried no blobs; the window stays inside the
/// 64-slot proposer lookahead `validate_fulu` resolves each sidecar against.
const WINDOW: u64 = 12;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let [host] = &argv[..] else {
        eprintln!("usage: CH_URL=<telemetry clickhouse> da_fixtures <ssh-host>");
        return ExitCode::FAILURE;
    };
    if let Err(e) = run(host) {
        eprintln!("da-fixtures: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn run(host: &str) -> Result<(), String> {
    let anchor = newest_checkpoint(host)?;
    let (first, last) = (anchor + 1, anchor + WINDOW);
    let dir = ColumnFixtures::da();
    eprintln!(
        "da-fixtures: anchor {anchor}, window {first}..{last} -> {}",
        dir.root().path().display()
    );

    // Cheapest first: a window with no telemetry behind it is not collectable,
    // and finding that out after the state leaves a half-written capture.
    let schedule = fetch_schedule(host, first, last)?;
    // A capture is one window against one anchor.
    let _ = fs::remove_dir_all(dir.root().path());
    fs::create_dir_all(dir.root().path())
        .map_err(|e| format!("create_dir_all({}): {e}", dir.root().path().display()))?;
    fetch_sidecars(host, &dir, first, last)?;
    scp(
        host,
        &format!("{STORE}/finalized_checkpoints/{anchor}/{anchor}.ssz"),
        &dir.root().finalized_state(),
    )?;
    fs::write(dir.schedule(), &schedule).map_err(|e| format!("write schedule: {e}"))?;

    let sidecars = fs::read_dir(dir.columns()).map(Iterator::count).unwrap_or_default();
    if sidecars == 0 {
        return Err(format!(
            "telemetry has {first}..{last} but the node kept no sidecar for them — its store \
             dropped the window (pick a window the store still holds)",
        ));
    }
    eprintln!(
        "da-fixtures: {sidecars} sidecars, {} schedule rows. The state is ~320 MB; see \
         docs/perf-regression-test.md before committing.",
        schedule.lines().count(),
    );
    Ok(())
}

/// Finalized sidecars are keyed by slot and unfinalized ones by slot and root,
/// which the copy strips; both sit under per-epoch buckets. Tarred on the node
/// so this is one round trip.
fn fetch_sidecars(host: &str, dir: &ColumnFixtures, first: u64, last: u64) -> Result<(), String> {
    let remote = format!(
        "cd {STORE} && rm -rf /tmp/da && mkdir -p /tmp/da/columns
         for s in $(seq {first} {last}); do
           cp columns/*/${{s}}_*.ssz /tmp/da/columns/ 2>/dev/null
           for f in unfinalized_columns/${{s}}_*.ssz; do
             [ -e \"$f\" ] && cp \"$f\" /tmp/da/columns/${{s}}_${{f##*_}}
           done
         done
         tar cz -C /tmp/da columns"
    );
    sh(&format!("ssh {host} {} | tar xz -C {}", quote(&remote), dir.root().path().display()))
}

fn fetch_schedule(host: &str, first: u64, last: u64) -> Result<String, String> {
    let node = host.rsplit('@').next().unwrap_or(host);
    let url = std::env::var("CH_URL")
        .map_err(|_| "set CH_URL to the telemetry clickhouse endpoint".to_owned())?;
    let query = da_capture::schedule_query(node, first, last);
    let out = Command::new("curl")
        .args(["-sS", "--fail-with-body", &url, "--data-binary", &query])
        .output()
        .map_err(|e| format!("spawn curl: {e}"))?;
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        return Err(format!("clickhouse {}: {body}", out.status));
    }
    if body.trim().is_empty() {
        return Err(format!(
            "no telemetry rows for {node} slots {first}..{last} — is the daemon running, and does \
             it carry the `column_recv` stage?"
        ));
    }
    Ok(body)
}

/// Globbing the state file rather than listing the directory: a checkpoint
/// being written is a directory of empty `.tmp` files, and anchoring to one
/// wipes the capture before the scp discovers there is nothing to fetch.
fn newest_checkpoint(host: &str) -> Result<u64, String> {
    let listing = ssh_out(host, &format!("ls {STORE}/finalized_checkpoints/*/*.ssz"))?;
    listing
        .split_whitespace()
        .filter_map(|path| path.rsplit('/').next()?.strip_suffix(".ssz")?.parse::<u64>().ok())
        .max()
        .ok_or_else(|| format!("no complete checkpoint on {host}: {listing}"))
}

fn ssh_out(host: &str, remote: &str) -> Result<String, String> {
    let out =
        Command::new("ssh").args([host, remote]).output().map_err(|e| format!("spawn ssh: {e}"))?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
        .ok_or_else(|| format!("ssh {host} {remote}: {}", String::from_utf8_lossy(&out.stderr)))
}

fn scp(host: &str, remote: &str, local: &Path) -> Result<(), String> {
    sh(&format!("scp -q {host}:{remote} {}", local.display()))
}

/// The remote copy is a shell one-liner and the tar is a pipe, so run them as
/// one: reproducing either in `Command` plumbing is longer, not clearer.
fn sh(script: &str) -> Result<(), String> {
    let status =
        Command::new("sh").args(["-c", script]).status().map_err(|e| format!("spawn sh: {e}"))?;
    status.success().then_some(()).ok_or_else(|| format!("{script}: {status}"))
}

fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
