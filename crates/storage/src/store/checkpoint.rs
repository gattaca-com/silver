use std::{
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
};

use flux_disk::{DiskEvent, DiskIo, FailedOp, FileToken, OpenOptions, OperationId};
use silver_beacon_state_data::{BeaconStateReader, CheckpointChunk, CheckpointCursor};

use super::Store;

/// Sub-directory holding finalized-state checkpoints, one dir per epoch:
/// `finalized_checkpoints/<epoch>/<epoch>.ssz`.
const FINALIZED_CHECKPOINTS_DIR: &str = "finalized_checkpoints";

/// Newest finalized-state checkpoints to retain on disk; older dirs are
/// unlinked after a successful commit.
const MAX_FINALIZED_CHECKPOINTS: usize = 3;

/// Two, so encoding the next chunk overlaps writing the previous one. Each
/// grows to one validators chunk (~16 MiB on mainnet).
const CHUNK_BUFFERS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Streaming,
    /// The files sync one at a time, so the store keeps an io-wq worker.
    SyncingSsz,
    /// A link waits for the sync before it on its file.
    SyncingAndLinkingPubkeys,
    LinkingSsz,
    SyncingDirectories,
    /// Dropping the ring would block on the ops still in flight, so it
    /// drains first.
    Failing,
}

pub(super) enum CheckpointProgress {
    Pending,
    Committed(u64),
    Failed(u64),
}

/// Streams one finalized state into two unnamed files, then names them
/// `<slot>/<slot>.pubkeys` and `<slot>/<slot>.ssz`, the commit marker, and
/// syncs both directories. Unnamed files vanish on a crash or a restart, so
/// no partial file is ever reachable under a checkpoint name.
pub(super) struct CheckpointWriter {
    disk: DiskIo,
    reader: BeaconStateReader,
    cursor: CheckpointCursor,
    path: PathBuf,
    directory: FileToken,
    ssz: FileToken,
    pubkeys: FileToken,
    buffers: Vec<Vec<u8>>,
    stage: Stage,
    awaiting: usize,
    failure: Option<Error>,
}

impl CheckpointWriter {
    fn new(
        reader: BeaconStateReader,
        cursor: CheckpointCursor,
        path: PathBuf,
    ) -> Result<Self, Error> {
        let mut disk = super::disk_ring()?;
        let directory = disk.open_directory(&path)?;
        let (ssz, pubkeys) = Self::open_unnamed(&mut disk, &path)?;
        Ok(Self {
            disk,
            reader,
            cursor,
            path,
            directory,
            ssz,
            pubkeys,
            buffers: (0..CHUNK_BUFFERS).map(|_| Vec::new()).collect(),
            stage: Stage::Streaming,
            awaiting: 0,
            failure: None,
        })
    }

    fn open_unnamed(disk: &mut DiskIo, path: &Path) -> Result<(FileToken, FileToken), Error> {
        let unnamed = OpenOptions::new().write(true).tmpfile(true);
        Ok((disk.open(path, unnamed)?, disk.open(path, unnamed)?))
    }

    fn slot_path(&self) -> PathBuf {
        self.path.join(self.cursor.slot().to_string())
    }

    #[cfg(test)]
    pub(super) fn section(&self) -> Option<usize> {
        (self.stage == Stage::Streaming).then(|| self.cursor.section_index()).flatten()
    }

    /// Reaps completions, then encodes at most one chunk or starts the next
    /// commit stage once the current one completed. Dropping the writer
    /// closes its files.
    pub(super) fn step(&mut self) -> CheckpointProgress {
        self.reap();
        if let Some(error) = self.failure.take() &&
            self.stage != Stage::Failing
        {
            self.fail(error);
        }
        if self.stage == Stage::Failing {
            if !self.disk.is_idle() {
                return CheckpointProgress::Pending;
            }
            return CheckpointProgress::Failed(self.cursor.slot());
        }
        if self.awaiting > 0 {
            return CheckpointProgress::Pending;
        }
        let result = match self.stage {
            Stage::Streaming => self.stream(),
            Stage::SyncingSsz => self.sync_and_link_pubkeys(),
            Stage::SyncingAndLinkingPubkeys => self.link_ssz(),
            Stage::LinkingSsz => self.sync_directories(),
            Stage::SyncingDirectories => return CheckpointProgress::Committed(self.cursor.slot()),
            Stage::Failing => unreachable!("returned above"),
        };
        if let Err(error) = result {
            self.failure = Some(error);
        }
        CheckpointProgress::Pending
    }

    fn reap(&mut self) {
        let (buffers, awaiting, failure) =
            (&mut self.buffers, &mut self.awaiting, &mut self.failure);
        self.disk.poll_with(|event| match event {
            DiskEvent::WrittenOwned { buf, error, .. } => {
                buffers.push(buf);
                if let Some(error) = error {
                    failure.get_or_insert(error);
                }
            }
            DiskEvent::Synced { .. } |
            DiskEvent::DirectoryCreated { .. } |
            DiskEvent::Linked { .. } => *awaiting -= 1,
            DiskEvent::Failed { op: FailedOp::CreateDir, error, .. }
                if error.kind() == ErrorKind::AlreadyExists =>
            {
                *awaiting -= 1
            }
            DiskEvent::Failed { error, .. } => {
                failure.get_or_insert(error);
            }
            _ => {}
        });
    }

    fn fail(&mut self, error: Error) {
        silver_log::error!(?error, slot = self.cursor.slot(), stage = ?self.stage, "checkpoint persist failed");
        self.disk.close(self.ssz);
        self.disk.close(self.pubkeys);
        self.stage = Stage::Failing;
    }

    fn stream(&mut self) -> Result<(), Error> {
        let Some(mut buf) = self.buffers.pop() else { return Ok(()) };
        let file = match self.reader.checkpoint_chunk(&mut self.cursor, &mut buf) {
            Ok(CheckpointChunk::Ssz) => self.ssz,
            Ok(CheckpointChunk::Pubkeys) => self.pubkeys,
            Ok(CheckpointChunk::Restarted) => {
                self.buffers.push(buf);
                return self.restart();
            }
            Ok(CheckpointChunk::Done) => {
                self.buffers.push(buf);
                return self.sync_ssz();
            }
            Err(error) => {
                self.buffers.push(buf);
                return Err(error);
            }
        };
        if buf.is_empty() {
            self.buffers.push(buf);
        } else if self.disk.write_owned(file, buf).is_err() {
            return Err(Error::other("checkpoint file closed"));
        }
        Ok(())
    }

    fn restart(&mut self) -> Result<(), Error> {
        silver_log::debug!(
            slot = self.cursor.slot(),
            "checkpoint superseded; restarting onto the newer state"
        );
        // Writes still in flight land in the closed files, which vanish with
        // them.
        self.disk.close(self.ssz);
        self.disk.close(self.pubkeys);
        (self.ssz, self.pubkeys) = Self::open_unnamed(&mut self.disk, &self.path)?;
        Ok(())
    }

    fn sync_ssz(&mut self) -> Result<(), Error> {
        let created = self.disk.create_dir(self.directory, self.slot_path())?;
        let synced = self.disk.sync_all(self.ssz);
        self.wait_for(&[synced, created], Stage::SyncingSsz)
    }

    fn sync_and_link_pubkeys(&mut self) -> Result<(), Error> {
        let path = self.named("pubkeys");
        let synced = self.disk.sync_all(self.pubkeys);
        let linked = self.disk.link(self.pubkeys, path).unwrap_or(None);
        self.wait_for(&[synced, linked], Stage::SyncingAndLinkingPubkeys)
    }

    fn link_ssz(&mut self) -> Result<(), Error> {
        let linked = self.disk.link(self.ssz, self.named("ssz"))?;
        self.wait_for(&[linked], Stage::LinkingSsz)
    }

    fn named(&self, extension: &str) -> PathBuf {
        let slot = self.cursor.slot();
        self.slot_path().join(format!("{slot}.{extension}"))
    }

    fn sync_directories(&mut self) -> Result<(), Error> {
        let slot_directory = self.disk.open_directory(self.slot_path())?;
        let queued = [self.disk.sync_all(slot_directory), self.disk.sync_all(self.directory)];
        self.wait_for(&queued, Stage::SyncingDirectories)
    }

    /// Counts what was queued even when an op was not, so its completions
    /// never outnumber `awaiting`.
    fn wait_for(&mut self, queued: &[Option<OperationId>], next: Stage) -> Result<(), Error> {
        self.awaiting = queued.iter().flatten().count();
        if self.awaiting < queued.len() {
            return Err(Error::other("checkpoint op not queued"));
        }
        self.stage = next;
        Ok(())
    }
}

/// Committed checkpoint slots (`<slot>/<slot>.ssz` present), newest first.
/// Malformed / incomplete dirs are skipped.
fn committed_checkpoint_slots(dir: &Path) -> Vec<u64> {
    let mut slots = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Some(slot) = entry.file_name().to_str().and_then(|n| n.parse::<u64>().ok()) &&
                entry.path().join(format!("{slot}.ssz")).exists()
            {
                slots.push(slot);
            }
        }
    }
    slots.sort_unstable_by(|a, b| b.cmp(a));
    slots
}

pub fn latest_local_checkpoint(store_dir: &str) -> Option<(u64, PathBuf, Option<PathBuf>)> {
    let dir = Path::new(store_dir).join(FINALIZED_CHECKPOINTS_DIR);
    let slot = *committed_checkpoint_slots(&dir).first()?;
    let slot_dir = dir.join(slot.to_string());
    let pubkeys = slot_dir.join(format!("{slot}.pubkeys"));
    let pubkeys = pubkeys.exists().then_some(pubkeys);
    Some((slot, slot_dir.join(format!("{slot}.ssz")), pubkeys))
}

/// Initialise the checkpoints dir on load: create it, drop incomplete dirs
/// (crashed mid-write, no committed `<slot>.ssz`), prune to the newest
/// MAX_FINALIZED_CHECKPOINTS, and return the newest committed slot (0 if none).
pub(super) fn init_checkpoints_dir(store_dir: &str) -> Result<u64, Error> {
    let dir = Path::new(store_dir).join(FINALIZED_CHECKPOINTS_DIR);
    std::fs::create_dir_all(&dir)?;
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            if let Some(slot) = entry.file_name().to_str().and_then(|n| n.parse::<u64>().ok()) &&
                !entry.path().join(format!("{slot}.ssz")).exists()
            {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    }
    let committed = committed_checkpoint_slots(&dir);
    for &old in committed.iter().skip(MAX_FINALIZED_CHECKPOINTS) {
        let _ = std::fs::remove_dir_all(dir.join(old.to_string()));
    }
    Ok(committed.first().copied().unwrap_or(0))
}

impl Store {
    fn finalized_checkpoints_dir(&self) -> PathBuf {
        Path::new(&self.store_dir).join(FINALIZED_CHECKPOINTS_DIR)
    }

    #[inline]
    pub(crate) fn last_persisted_finalized_slot(&self) -> u64 {
        self.last_persisted_finalized_slot
    }

    #[cfg(test)]
    pub(crate) fn reset_persist_watermark(&mut self) {
        self.last_persisted_finalized_slot = 0;
    }

    #[inline]
    pub(crate) fn checkpoint_in_flight(&self) -> bool {
        self.checkpoint.is_some()
    }

    #[cfg(test)]
    pub(crate) fn checkpoint_section(&self) -> Option<usize> {
        self.checkpoint.as_ref().and_then(CheckpointWriter::section)
    }

    pub(crate) fn begin_checkpoint(&mut self, reader: BeaconStateReader) {
        if self.checkpoint.is_some() {
            return;
        }
        // `None` only pre-snapshot — a checkpoint trigger can't usefully fire
        // before bootstrap publishes.
        let Some(cursor) = reader.begin_checkpoint() else {
            silver_log::warn!("checkpoint requested before the first beacon state snapshot");
            return;
        };
        let slot = cursor.slot();
        if slot <= self.last_persisted_finalized_slot {
            return;
        }
        match CheckpointWriter::new(reader, cursor, self.finalized_checkpoints_dir()) {
            Ok(writer) => self.checkpoint = Some(writer),
            Err(error) => silver_log::error!(?error, slot, "failed to start checkpoint persist"),
        }
    }

    pub(super) fn step_checkpoint(&mut self) {
        let Some(writer) = self.checkpoint.as_mut() else { return };
        match writer.step() {
            CheckpointProgress::Pending => {}
            CheckpointProgress::Failed(slot) => {
                self.checkpoint = None;
                let slot_dir = self.finalized_checkpoints_dir().join(slot.to_string());
                if let Err(error) = std::fs::remove_dir_all(&slot_dir) &&
                    error.kind() != ErrorKind::NotFound
                {
                    silver_log::warn!(?error, ?slot_dir, "failed checkpoint dir not removed");
                }
            }
            CheckpointProgress::Committed(slot) => {
                self.checkpoint = None;
                self.last_persisted_finalized_slot = self.last_persisted_finalized_slot.max(slot);
                silver_log::info!(slot, "persisted finalized checkpoint");
                let base = self.finalized_checkpoints_dir();
                for old in
                    committed_checkpoint_slots(&base).into_iter().skip(MAX_FINALIZED_CHECKPOINTS)
                {
                    self.remover.remove(base.join(old.to_string()));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use silver_beacon_state_data::{BeaconState, BeaconStateOwner, SpecConfig};
    use silver_common::{TCache, TCacheId};
    use tempfile::TempDir;

    use super::{FINALIZED_CHECKPOINTS_DIR, Store};
    use crate::tile::IoEvent;

    /// Owner over a decomposed state with its anchor published — the minimal
    /// setup for `reader.begin_checkpoint()` to return a stream.
    fn published_owner(bs: BeaconState) -> BeaconStateOwner {
        let mut owner = BeaconStateOwner::new(bs);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        owner
    }

    fn file_io_until(store: &mut Store, done: impl Fn(&Store) -> bool) {
        let mut producer = TCache::producer(TCacheId::NetworkProcessing, 1 << 20);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(store) {
            assert!(Instant::now() < deadline, "checkpoint did not finish");
            store.file_io(|_| [0u8; 4], &mut producer, &mut |_: IoEvent| {}).unwrap();
        }
    }

    fn persist(store: &mut Store, slot: u64) {
        let owner = published_owner(BeaconState::empty_test(slot));
        store.begin_checkpoint(owner.reader());
        assert!(store.checkpoint_in_flight(), "begin_checkpoint should arm a job");
        file_io_until(store, |store| !store.checkpoint_in_flight());
    }

    /// Manual benchmark of the streamed checkpoint persist on a real mainnet
    /// state: whole-persist time, the longest single `file_io` turn, and the
    /// per-section split.
    ///
    /// Ignored by default — needs the ~312 MiB mainnet fixture.
    ///
    ///   cargo test -p silver_storage --release checkpoint_persist_bench \
    ///       -- --ignored --nocapture
    ///
    /// Override the state path with SILVER_CHECKPOINT_SSZ and the write target
    /// with SILVER_BENCH_DIR (point it at the data-store disk; tmpfs / `/tmp`
    /// understates the fsync cost).
    #[test]
    #[ignore = "manual benchmark; needs mainnet fixture, writes several GiB"]
    fn checkpoint_persist_bench() {
        let path = std::env::var("SILVER_CHECKPOINT_SSZ").map(PathBuf::from).unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../e2e/tests/example_checkpoints/finalized_state.ssz")
        });
        let Ok(ssz) = std::fs::read(&path) else {
            eprintln!("skipping: fixture {} not present", path.display());
            return;
        };

        let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).expect("decompose");
        let len = bs.ssz_len();
        assert_eq!(len, ssz.len(), "round-trip length mismatch");
        println!("state: {len} bytes ({} MiB)", len >> 20);

        use silver_beacon_state_data::FULU_CHECKPOINT_SECTIONS;

        // Section names in canonical order, for the per-section breakdown
        // (the data crate keeps its `Section` enum private).
        const SECTION_NAMES: [&str; FULU_CHECKPOINT_SECTIONS] = [
            "FixedPart",
            "HistoricalRoots",
            "Eth1Votes",
            "Validators",
            "Balances",
            "PreviousParticipation",
            "CurrentParticipation",
            "InactivityScores",
            "ExecutionPayloadHeader",
            "HistoricalSummaries",
            "PendingDeposits",
            "PendingPartialWithdrawals",
            "PendingConsolidations",
        ];

        let base = std::env::var("SILVER_BENCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let temp = TempDir::new_in(base).unwrap();
        let dir = temp.path().to_str().unwrap().to_owned();
        let mut store = Store::load(dir.clone(), crate::store::test_spec(u64::MAX), 0).unwrap();

        const ITERS: u64 = 23;
        const WARMUP: u64 = 3;
        let slot = bs.slot_states.finalized_view().slot_number();
        let slot_dir = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR).join(slot.to_string());

        let owner = published_owner(bs);
        let reader = owner.reader();
        let mut producer = TCache::producer(TCacheId::NetworkProcessing, 1 << 20);
        let mut streamed = Vec::new();
        // Validators spans several turns; all of them land in its bucket.
        let mut per_section = [Duration::ZERO; FULU_CHECKPOINT_SECTIONS];
        let mut counted = 0u32;
        let mut max_section_turn = Duration::ZERO;
        let mut max_other_turn = Duration::ZERO;
        let mut outside_sections = Duration::ZERO;
        for i in 0..ITERS {
            // The same slot is persisted every iteration; names are never
            // overwritten, so the previous commit goes first. Its files are
            // closed first: the last close of an unlinked file frees it inline.
            store.reset_persist_watermark();
            store.file_io(|_| [0u8; 4], &mut producer, &mut |_: IoEvent| {}).unwrap();
            let _ = std::fs::remove_dir_all(&slot_dir);
            let t = Instant::now();
            store.begin_checkpoint(reader.clone());
            while store.checkpoint_in_flight() {
                let section = store.checkpoint_section();
                let ct = Instant::now();
                store.file_io(|_| [0u8; 4], &mut producer, &mut |_: IoEvent| {}).unwrap();
                let cdt = ct.elapsed();
                if i >= WARMUP {
                    match section {
                        Some(s) => {
                            per_section[s] += cdt;
                            max_section_turn = max_section_turn.max(cdt);
                        }
                        None => {
                            outside_sections += cdt;
                            max_other_turn = max_other_turn.max(cdt);
                        }
                    }
                }
            }
            let elapsed = t.elapsed();
            assert_eq!(store.last_persisted_finalized_slot(), slot, "persist failed");
            if i >= WARMUP {
                streamed.push(elapsed);
                counted += 1;
            }
        }
        report("streamed_full(encode+write+commit)", &mut streamed, len);
        println!(
            "  max single file_io turn: SSZ sections {max_section_turn:?}, pubkeys + commit {max_other_turn:?}"
        );
        println!("  pubkeys + commit turns (mean, summed): {:?}", outside_sections / counted);
        println!("  streamed per-section (mean over {counted} persists):");
        for (idx, total) in per_section.iter().enumerate() {
            println!("    {}: {:?}", SECTION_NAMES[idx], *total / counted);
        }
    }

    fn report(name: &str, samples: &mut [Duration], bytes: usize) {
        samples.sort_unstable();
        let n = samples.len();
        let mean = samples.iter().sum::<Duration>() / n as u32;
        let median = samples[n / 2];
        let gib = bytes as f64 / (1u64 << 30) as f64;
        println!(
            "{name}: min {:?} median {median:?} mean {mean:?} ({:.2} GiB/s median)",
            samples[0],
            gib / median.as_secs_f64(),
        );
    }

    #[test]
    fn checkpoint_persist_retention_and_load() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_owned();

        let mut store = Store::load(dir.clone(), crate::store::test_spec(u64::MAX), 0).unwrap();
        assert_eq!(store.last_persisted_finalized_slot(), 0);

        // Commit four slots; only the newest three survive.
        for slot in [64u64, 96, 128, 160] {
            persist(&mut store, slot);
            assert_eq!(store.last_persisted_finalized_slot(), slot);
        }

        let cp = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR);
        file_io_until(&mut store, |_| !cp.join("64").exists());
        for slot in [96u64, 128, 160] {
            let ssz = std::fs::read(cp.join(slot.to_string()).join(format!("{slot}.ssz"))).unwrap();
            let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).unwrap();
            assert_eq!(bs.slot_states.finalized_view().slot_number(), slot);
        }

        // A crashed mid-write dir (no committed `.ssz`) is dropped on load;
        // `last_persisted` anchors at the newest committed slot.
        let incomplete = cp.join("999");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("999.pubkeys"), b"partial").unwrap();

        let reloaded = Store::load(dir.clone(), crate::store::test_spec(u64::MAX), 0).unwrap();
        assert_eq!(reloaded.last_persisted_finalized_slot(), 160);
        assert!(!cp.join("999").exists(), "incomplete checkpoint dropped on load");
        assert!(cp.join("160").exists());
    }

    /// A finalize mid-stream restarts the persist; bytes already written for
    /// the superseded attempt never reach the committed file.
    #[test]
    fn restarted_checkpoint_commits_only_the_new_attempt() {
        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_owned();
        let mut store = Store::load(dir.clone(), crate::store::test_spec(u64::MAX), 0).unwrap();
        let state = BeaconState::empty_test(64);
        let len = state.ssz_len();
        let mut owner = published_owner(state);

        store.begin_checkpoint(owner.reader());
        let mut producer = TCache::producer(TCacheId::NetworkProcessing, 1 << 20);
        for _ in 0..4 {
            store.file_io(|_| [0u8; 4], &mut producer, &mut |_: IoEvent| {}).unwrap();
        }
        drop(owner.write());
        file_io_until(&mut store, |store| !store.checkpoint_in_flight());

        assert_eq!(store.last_persisted_finalized_slot(), 64);
        let path = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR).join("64").join("64.ssz");
        let ssz = std::fs::read(path).unwrap();
        assert_eq!(ssz.len(), len);
        let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).unwrap();
        assert_eq!(bs.slot_states.finalized_view().slot_number(), 64);
    }

    /// End-to-end streamed persist: `begin_checkpoint` arms a job, `file_io`
    /// streams and commits it, and the committed files round-trip.
    #[test]
    fn streamed_checkpoint_persist_via_file_io() {
        use silver_beacon_state_data::decode_checkpoint_pubkeys;

        let temp = TempDir::new().unwrap();
        let dir = temp.path().to_str().unwrap().to_owned();
        let mut store = Store::load(dir.clone(), crate::store::test_spec(u64::MAX), 0).unwrap();

        assert!(!store.checkpoint_in_flight());
        persist(&mut store, 64);
        assert_eq!(store.last_persisted_finalized_slot(), 64);

        let slot_dir = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR).join("64");
        let mut names: Vec<_> = std::fs::read_dir(&slot_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(names, ["64.pubkeys", "64.ssz"], "only the committed names exist");
        let ssz = std::fs::read(slot_dir.join("64.ssz")).unwrap();
        let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).unwrap();
        assert_eq!(bs.slot_states.finalized_view().slot_number(), 64);

        // Sidecar committed alongside; zero validators => empty pubkey vec.
        let pk = std::fs::read(slot_dir.join("64.pubkeys")).unwrap();
        assert!(decode_checkpoint_pubkeys(&pk).unwrap().is_empty());
    }
}
