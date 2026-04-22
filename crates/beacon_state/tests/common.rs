use std::{
    fs,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use flux::{spine::SpineAdapter, tile::Tile};
use serde::Deserialize;
use silver_beacon_state::{SlotTicker, tile::BeaconStateTile};
use silver_common::SilverSpine;

#[derive(Debug, Deserialize)]
pub struct Setup {
    /// Startup checkpoint state path (required; use `null` for no
    /// checkpoint).
    /// - relative: resolved against `consensus-spec-tests/`
    /// - absolute (leading `/`): taken as-is
    pub startup_checkpoint: Option<String>,
    /// Slots the wall clock sits ahead of the checkpoint state. The
    /// harness forces `wall_slot >= checkpoint_slot + 3` so bootstrap
    /// picks Syncing rather than Following.
    pub slots_missing: u64,
    pub steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Step {
    /// Advance the tile one `loop_body` call.
    Step,
    /// Assertions against observable state.
    Check(Checks),
}

#[derive(Debug, Default, Deserialize)]
pub struct Checks {
    pub mode: Option<String>,
    pub head_slot: Option<u64>,
}

pub struct Harness {
    #[allow(dead_code)] // kept alive to hold the shmem mmap for the adapter
    spine: Box<SilverSpine>,
    tile: BeaconStateTile,
    tile_adapter: SpineAdapter<SilverSpine>,
    _base_dir: PathBuf, // owned to keep temp files around for the run
}

impl Harness {
    pub fn new(wall_slot: u64, checkpoint_ssz: &[u8]) -> Self {
        // Unique temp base dir — shmem files live here.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let base =
            std::env::temp_dir().join(format!("silver-ef-{}-{}-{}", process::id(), seq, nanos));
        fs::create_dir_all(&base).expect("create temp base");

        let mut spine = Box::new(SilverSpine::new_with_base_dir(&base, None));

        // Ticker: genesis positioned so `current_slot()` == wall_slot at
        // construction.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let genesis = now.saturating_sub(wall_slot * 12);
        let ticker = SlotTicker::new(genesis, Duration::from_secs(12), Duration::from_secs(4));

        let tile = BeaconStateTile::new_heap(ticker, checkpoint_ssz);
        let tile_adapter = SpineAdapter::connect_tile(&tile, &mut spine);

        Self { spine, tile, tile_adapter, _base_dir: base }
    }

    pub fn mode(&self) -> &'static str {
        self.tile.observe_mode()
    }

    pub fn head_slot(&self) -> u64 {
        self.tile.observe_head_slot()
    }

    pub fn step(&mut self) {
        self.tile.loop_body(&mut self.tile_adapter);
    }

    pub fn assert_checks(&self, c: &Checks) {
        if let Some(m) = &c.mode {
            assert_eq!(self.mode(), m, "mode mismatch");
        }
        if let Some(s) = c.head_slot {
            assert_eq!(self.head_slot(), s, "head_slot mismatch");
        }
    }
}

pub fn run_scenario(case_dir: &Path) {
    let transcript_yaml = fs::read_to_string(case_dir.join("steps.yaml")).expect("read steps.yaml");
    let t: Setup = serde_yml::from_str(&transcript_yaml).expect("parse steps.yaml");

    let spec_root = spec_tests_dir();
    let resolve = |p: &str| -> PathBuf {
        if p.starts_with('/') { PathBuf::from(p) } else { spec_root.join(p) }
    };

    let checkpoint_ssz = match &t.startup_checkpoint {
        Some(p) => snappy_decode(&resolve(p)),
        None => Vec::new(),
    };

    // BeaconState SSZ layout: genesis_time(8) + genesis_validators_root(32) +
    // slot(8). Pull slot out directly; don't decompose the whole state.
    let checkpoint_slot = if checkpoint_ssz.len() >= 48 {
        u64::from_le_bytes(checkpoint_ssz[40..48].try_into().unwrap())
    } else {
        0
    };
    // Force Syncing: bootstrap compares `wall_slot > slot + 2`.
    let wall_slot = checkpoint_slot + t.slots_missing.max(3);

    let mut h = Harness::new(wall_slot, &checkpoint_ssz);
    // First `step` to let the tile do its post-bootstrap work before the
    // scenario's explicit steps run.
    h.step();

    for step in &t.steps {
        match step {
            Step::Step => h.step(),
            Step::Check(c) => h.assert_checks(c),
        }
    }
}

pub fn snappy_decode(path: &Path) -> Vec<u8> {
    let compressed = fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    snap::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("{}: snappy: {e}", path.display()))
}

pub fn spec_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("consensus-spec-tests")
}
