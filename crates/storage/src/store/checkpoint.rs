#[cfg(test)]
use std::io::Write;
use std::{
    fs::File,
    io::{BufWriter, Error},
    path::{Path, PathBuf},
};

use silver_beacon_state_data::{BeaconStateReader, CheckpointChunk, CheckpointCursor};

use super::{Store, io};

/// Sub-directory holding finalized-state checkpoints, one dir per epoch:
/// `finalized_checkpoints/<epoch>/<epoch>.ssz`.
const FINALIZED_CHECKPOINTS_DIR: &str = "finalized_checkpoints";

/// Newest finalized-state checkpoints to retain on disk; older dirs are
/// unlinked after a successful commit.
const MAX_FINALIZED_CHECKPOINTS: usize = 3;

/// `BufWriter` capacity for the streamed checkpoint: batches the per-record
/// section writes into ~MiB syscalls without materializing the whole ~312 MiB
/// blob.
const CHECKPOINT_WRITER_CAP: usize = 1 << 20;

/// In-flight streamed persist: the data crate owns the synchronization
/// (version capture, per-chunk validation, restart onto a newer finalized
/// state) behind [`BeaconStateReader::checkpoint_chunk`]; this type owns only
/// the files (temp paths, buffering, truncate-on-restart, atomic
/// rename-commit).
pub(super) struct CheckpointWriter {
    reader: BeaconStateReader,
    cursor: CheckpointCursor,
    // Reused chunk buffer `checkpoint_chunk` fills — only ever holds bytes
    // consistent with the cursor's captured state.
    chunk: Vec<u8>,
    writer: BufWriter<File>,
    tmp_path: PathBuf,
    // Decompressed-pubkey sidecar (`<slot>.pubkeys`), written as a second stage
    // after the SSZ sections so checkpoint load can skip the per-validator
    // decompression.
    pubkeys_writer: BufWriter<File>,
    pubkeys_tmp: PathBuf,
}

impl CheckpointWriter {
    fn discard(self) {
        drop(self.writer);
        drop(self.pubkeys_writer);
        remove_checkpoint_dir(&self.tmp_path);
    }
}

/// Drop everything buffered + written so far (a restart invalidated it):
/// flush the stale buffer out, then truncate and rewind the file.
fn truncate(w: &mut BufWriter<File>) -> Result<(), Error> {
    use std::io::{Seek, Write};
    w.flush()?;
    let f = w.get_mut();
    f.set_len(0)?;
    f.rewind()
}

fn remove_checkpoint_dir(tmp_path: &Path) {
    match tmp_path.parent() {
        Some(dir) => {
            let _ = std::fs::remove_dir_all(dir);
        }
        None => {
            let _ = std::fs::remove_file(tmp_path);
        }
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

    /// Create the per-slot checkpoint dir and open its temp file for writing.
    /// The streamed persist writes SSZ sections into the returned handle across
    /// `file_io` turns, then calls `commit_checkpoint`.
    fn open_checkpoint_tmp(&self, slot: u64) -> Result<(File, PathBuf), Error> {
        let dir = self.finalized_checkpoints_dir().join(slot.to_string());
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!("{slot}.ssz.tmp"));
        let file = io::open_file_write(&tmp, false)?;
        Ok((file, tmp))
    }

    /// Atomically commit a fully-written checkpoint: fsync the temp file(s),
    /// rename the optional `<slot>.pubkeys` sidecar first, then `<slot>.ssz`
    /// (the commit marker — load treats a dir without it as incomplete), fsync
    /// the dir tree, advance the watermark, and prune to the newest
    /// MAX_FINALIZED_CHECKPOINTS. The caller must have flushed all buffered
    /// writes first.
    fn commit_checkpoint(
        &mut self,
        slot: u64,
        ssz_file: File,
        ssz_tmp: &Path,
        pubkeys: Option<(File, &Path)>,
    ) -> Result<(), Error> {
        ssz_file.sync_all()?;
        drop(ssz_file);
        let base = self.finalized_checkpoints_dir();
        let dir = base.join(slot.to_string());
        std::fs::create_dir_all(&dir)?;
        if let Some((pubkeys_file, pubkeys_tmp)) = pubkeys {
            pubkeys_file.sync_all()?;
            drop(pubkeys_file);
            std::fs::rename(pubkeys_tmp, dir.join(format!("{slot}.pubkeys")))?;
        }
        std::fs::rename(ssz_tmp, dir.join(format!("{slot}.ssz")))?;
        // fsync up the tree: the per-slot dir so the rename is durable, then the
        // parent so the freshly-created `<slot>/` entry itself survives a crash
        // — without it the whole checkpoint dir can vanish on power loss.
        if let Ok(d) = File::open(&dir) {
            let _ = d.sync_all();
        }
        if let Ok(d) = File::open(&base) {
            let _ = d.sync_all();
        }

        self.last_persisted_finalized_slot = self.last_persisted_finalized_slot.max(slot);

        // Retention: unlink everything older than the newest N.
        for &old in committed_checkpoint_slots(&base).iter().skip(MAX_FINALIZED_CHECKPOINTS) {
            let _ = std::fs::remove_dir_all(base.join(old.to_string()));
        }
        Ok(())
    }

    #[inline]
    pub(crate) fn checkpoint_in_flight(&self) -> bool {
        self.checkpoint.is_some()
    }

    /// Index of the section the next `file_io` turn will write (for the
    /// persist benchmark's per-section breakdown). `None` when no checkpoint
    /// is in flight or once past the SSZ sections (pubkeys stage).
    #[cfg(test)]
    pub(crate) fn checkpoint_section(&self) -> Option<usize> {
        self.checkpoint.as_ref().and_then(|cw| cw.cursor.section_index())
    }

    pub(crate) fn begin_checkpoint(&mut self, reader: BeaconStateReader) {
        if self.checkpoint.is_some() {
            return;
        }
        // `None` only pre-snapshot — a checkpoint trigger can't usefully fire
        // before bootstrap publishes.
        let Some(cursor) = reader.begin_checkpoint() else {
            tracing::warn!("checkpoint requested before the first beacon state snapshot");
            return;
        };
        let slot = cursor.slot();
        if slot <= self.last_persisted_finalized_slot {
            return;
        }
        let (file, tmp_path) = match self.open_checkpoint_tmp(slot) {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(?e, slot, dir = ?self.finalized_checkpoints_dir().join(slot.to_string()), "failed to open checkpoint temp file");
                return;
            }
        };
        let pubkeys_tmp = tmp_path.with_file_name(format!("{slot}.pubkeys.tmp"));
        let pubkeys_file = match io::open_file_write(&pubkeys_tmp, false) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(?e, slot, "failed to open pubkeys temp file");
                remove_checkpoint_dir(&tmp_path);
                return;
            }
        };
        self.checkpoint = Some(CheckpointWriter {
            reader,
            cursor,
            chunk: Vec::new(),
            writer: BufWriter::with_capacity(CHECKPOINT_WRITER_CAP, file),
            tmp_path,
            pubkeys_writer: BufWriter::with_capacity(CHECKPOINT_WRITER_CAP, pubkeys_file),
            pubkeys_tmp,
        });
    }

    /// Advance the in-flight checkpoint by one chunk. Called once per
    /// `file_io` turn; commits after the last chunk. A superseding finalize
    /// surfaces as `Restarted` (the cursor is already back at part 0, on the
    /// newer state) — both temp files are truncated and stepping continues.
    pub(super) fn step_checkpoint(&mut self) {
        let step = match self.checkpoint.as_mut() {
            Some(cw) => {
                use std::io::Write;
                cw.reader.checkpoint_chunk(&mut cw.cursor, &mut cw.chunk).and_then(|c| {
                    match &c {
                        CheckpointChunk::Ssz => cw.writer.write_all(&cw.chunk)?,
                        CheckpointChunk::Pubkeys => cw.pubkeys_writer.write_all(&cw.chunk)?,
                        CheckpointChunk::Restarted => {
                            tracing::debug!(
                                slot = cw.cursor.slot(),
                                "checkpoint superseded; restarting onto the newer state"
                            );
                            truncate(&mut cw.writer)?;
                            truncate(&mut cw.pubkeys_writer)?;
                        }
                        CheckpointChunk::Done => {}
                    }
                    Ok(c)
                })
            }
            None => return,
        };
        match step {
            Ok(CheckpointChunk::Ssz | CheckpointChunk::Pubkeys | CheckpointChunk::Restarted) => {}
            Ok(CheckpointChunk::Done) => {
                let cw = self.checkpoint.take().expect("checkpoint present");
                self.commit_in_flight_checkpoint(cw);
            }
            Err(e) => {
                let cw = self.checkpoint.take().expect("checkpoint present");
                tracing::error!(?e, section = ?cw.cursor.section_index(), "checkpoint write failed");
                cw.discard();
            }
        }
    }

    /// Flush the writers, then atomically commit. The slot is re-read from the
    /// cursor — a restart may have advanced it past the temp paths' slot, in
    /// which case the renames move the files into the newer slot's dir and
    /// the stale temp dir is dropped.
    fn commit_in_flight_checkpoint(&mut self, cw: CheckpointWriter) {
        let slot = cw.cursor.slot();
        let CheckpointWriter { writer, tmp_path, pubkeys_writer, pubkeys_tmp, .. } = cw;
        let ssz_file = match writer.into_inner() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(err = ?e.into_error(), slot, "failed to flush checkpoint writer");
                remove_checkpoint_dir(&tmp_path);
                return;
            }
        };
        let pubkeys_file = match pubkeys_writer.into_inner() {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(err = ?e.into_error(), slot, "failed to flush pubkeys writer");
                remove_checkpoint_dir(&tmp_path);
                return;
            }
        };
        let result =
            self.commit_checkpoint(slot, ssz_file, &tmp_path, Some((pubkeys_file, &pubkeys_tmp)));
        match result {
            Ok(()) => {
                tracing::info!(slot, "persisted finalized checkpoint");
                // A restart moved the content to a newer slot: the begin-time
                // temp dir is now empty — drop it.
                if tmp_path.parent() !=
                    Some(self.finalized_checkpoints_dir().join(slot.to_string()).as_path())
                {
                    remove_checkpoint_dir(&tmp_path);
                }
            }
            Err(e) => {
                tracing::error!(?e, slot, "failed to commit checkpoint");
                remove_checkpoint_dir(&tmp_path);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn persist_finalized_checkpoint(
        &mut self,
        slot: u64,
        ssz: &[u8],
    ) -> Result<(), Error> {
        if slot <= self.last_persisted_finalized_slot {
            return Ok(());
        }
        let (mut file, tmp) = self.open_checkpoint_tmp(slot)?;
        file.write_all(ssz)?;
        self.commit_checkpoint(slot, file, &tmp, None)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    use silver_beacon_state_data::{BeaconState, BeaconStateOwner, SpecConfig};

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

    /// Minimal canonical state: encode the pre-bootstrap stub (via a throwaway
    /// owner), patch the fixed-part `slot` field (byte 40, Fulu layout), and
    /// decompose — public API only.
    fn synthetic_state(slot: u64) -> BeaconState {
        let stub = BeaconStateOwner::pre_bootstrap();
        let mut ssz = Vec::with_capacity(stub.state().ssz_len());
        stub.state().encode_ssz(&mut ssz).expect("encode stub");
        ssz[40..48].copy_from_slice(&slot.to_le_bytes());
        BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).expect("decompose stub")
    }

    /// Manual benchmark comparing the storage tile's two checkpoint-persist
    /// strategies on a real mainnet state, printing three medians:
    ///   - `oneshot_write_only` — write a pre-encoded blob (encode excluded);
    ///   - `oneshot_full`       — phase 1: encode into a buffer, then write it;
    ///   - `streamed_full`      — phase 2: the real `begin_checkpoint` +
    ///     `file_io` section loop (fused encode+write, version checks, commit).
    /// The headline comparison is `oneshot_full` vs `streamed_full`. Note this
    /// measures *total work* — it does not capture phase 2's wins (peak memory
    /// ~1 MiB vs the phase-1 ~400 MiB buffer, and no single multi-hundred-ms
    /// blocking write); streaming is expected to cost slightly more total.
    ///
    /// Ignored by default — needs the ~312 MiB mainnet fixture, writes tens of
    /// GiB (retention caps resident disk at the newest N).
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

        use silver_beacon_state_data::CHECKPOINT_SECTIONS;
        use silver_common::TCache;

        // Section names in canonical order, for the per-section breakdown
        // (the data crate keeps its `Section` enum private).
        const SECTION_NAMES: [&str; CHECKPOINT_SECTIONS] = [
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

        // Real persist target (atomic temp → fsync → rename → fsync dirs →
        // retention). The persist watermark is reset each iteration to bypass
        // the idempotency guard (the slot stays fixed — same per-slot dir,
        // overwritten in place). Unique subdir under SILVER_BENCH_DIR (default
        // `/tmp`; point it at the data-store disk — tmpfs understates fsync).
        // Removed at the end.
        let base = std::env::var("SILVER_BENCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let dir = format!("{base}/silver_bench_persist_{}", rand::random::<u32>());
        let mut store = Store::load(dir.clone()).unwrap();

        const ITERS: u64 = 23;
        const WARMUP: u64 = 3;
        let slot = bs.slot_states.finalized_view().slot_number();

        // Phase 1, write half only: write a pre-encoded blob (encode excluded).
        let mut buf = Vec::with_capacity(len);
        bs.encode_ssz(&mut buf).unwrap();
        let mut write_only = Vec::new();
        for i in 0..ITERS {
            store.reset_persist_watermark();
            let t = Instant::now();
            store.persist_finalized_checkpoint(slot, &buf).unwrap();
            let elapsed = t.elapsed();
            if i >= WARMUP {
                write_only.push(elapsed);
            }
        }
        report("oneshot_write_only", &mut write_only, len);

        // Phase 1, full: encode into the reused buffer, then write it.
        let mut oneshot = Vec::new();
        for i in 0..ITERS {
            store.reset_persist_watermark();
            let t = Instant::now();
            buf.clear();
            bs.encode_ssz(&mut buf).unwrap();
            store.persist_finalized_checkpoint(slot, &buf).unwrap();
            let elapsed = t.elapsed();
            if i >= WARMUP {
                oneshot.push(elapsed);
            }
        }
        report("oneshot_full(encode+write)", &mut oneshot, len);

        // Phase 2, streamed: the real `begin_checkpoint` + `file_io` section
        // loop (fused encode+write through the BufWriter, version checks,
        // commit, retention). The owner publishes its anchor so the reader can
        // open a stream.
        let owner = published_owner(bs);
        let reader = owner.reader();
        let mut producer = TCache::multi_producer("bench_persist_rpc", 1 << 20);
        let mut streamed = Vec::new();
        // Per-section total over the measured iterations (the per-turn `Instant`
        // overhead is ~ns/turn, negligible vs the section writes it brackets).
        let mut per_section = [Duration::ZERO; CHECKPOINT_SECTIONS];
        let mut counted = 0u32;
        for i in 0..ITERS {
            store.reset_persist_watermark();
            let t = Instant::now();
            store.begin_checkpoint(reader.clone());
            while store.checkpoint_in_flight() {
                let section = store.checkpoint_section();
                let ct = Instant::now();
                store.file_io(&[0u8; 4], 0, &mut producer, &mut |_: IoEvent| {}).unwrap();
                let cdt = ct.elapsed();
                // Validators spans several turns → all land in its bucket.
                if i >= WARMUP &&
                    let Some(s) = section
                {
                    per_section[s] += cdt;
                }
            }
            let elapsed = t.elapsed();
            if i >= WARMUP {
                streamed.push(elapsed);
                counted += 1;
            }
        }
        report("streamed_full(encode+write)", &mut streamed, len);
        println!("  streamed per-section (mean over {counted} persists):");
        for (idx, total) in per_section.iter().enumerate() {
            println!("    {}: {:?}", SECTION_NAMES[idx], *total / counted);
        }

        let _ = std::fs::remove_dir_all(&dir);
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
        let dir = format!("/tmp/silver_storage_cp_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&dir);

        let mut store = Store::load(dir.clone()).unwrap();
        assert_eq!(store.last_persisted_finalized_slot(), 0);

        // Commit four slots; only the newest three survive.
        for slot in [10u64, 11, 12, 13] {
            store.persist_finalized_checkpoint(slot, format!("state-{slot}").as_bytes()).unwrap();
            assert_eq!(store.last_persisted_finalized_slot(), slot);
        }

        let cp = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR);
        assert!(!cp.join("10").exists(), "oldest checkpoint must be unlinked");
        for slot in [11u64, 12, 13] {
            let f = cp.join(slot.to_string()).join(format!("{slot}.ssz"));
            assert_eq!(std::fs::read(&f).unwrap(), format!("state-{slot}").as_bytes());
            assert!(
                !cp.join(slot.to_string()).join(format!("{slot}.ssz.tmp")).exists(),
                "committed checkpoint must leave no temp file",
            );
        }

        // A crashed mid-write dir (temp only, no committed `.ssz`) is dropped
        // on load; `last_persisted` anchors at the newest committed slot.
        let incomplete = cp.join("99");
        std::fs::create_dir_all(&incomplete).unwrap();
        std::fs::write(incomplete.join("99.ssz.tmp"), b"partial").unwrap();

        let reloaded = Store::load(dir.clone()).unwrap();
        assert_eq!(reloaded.last_persisted_finalized_slot(), 13);
        assert!(!cp.join("99").exists(), "incomplete checkpoint dropped on load");
        assert!(cp.join("13").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// End-to-end streamed persist: `begin_checkpoint` arms a job, `file_io`
    /// writes one chunk per turn and commits on the last, and the committed
    /// file round-trips through `decompose`.
    #[test]
    fn streamed_checkpoint_persist_via_file_io() {
        use silver_beacon_state_data::decode_checkpoint_pubkeys;
        use silver_common::TCache;

        // Finalized base at slot 64 (epoch 2), zero validators — minimal but
        // canonical.
        let owner = published_owner(synthetic_state(64));
        let reader = owner.reader();

        let dir = format!("/tmp/silver_storage_streamcp_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::load(dir.clone()).unwrap();

        assert!(!store.checkpoint_in_flight());
        store.begin_checkpoint(reader);
        assert!(store.checkpoint_in_flight(), "begin_checkpoint should arm a job");

        // One chunk per file_io turn until the commit clears the job.
        let mut producer = TCache::multi_producer("streamcp_rpc", 1 << 20);
        let mut turns = 0;
        while store.checkpoint_in_flight() {
            store.file_io(&[0u8; 4], 0, &mut producer, &mut |_: IoEvent| {}).unwrap();
            turns += 1;
            assert!(turns <= 64, "checkpoint did not finish");
        }
        // CHECKPOINT_SECTIONS SSZ turns + one pubkeys-stage turn + the `Done`
        // turn that commits.
        assert_eq!(
            turns,
            silver_beacon_state_data::CHECKPOINT_SECTIONS + 2,
            "one turn per section + pubkeys + commit"
        );
        assert_eq!(store.last_persisted_finalized_slot(), 64);

        let slot_dir = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR).join("64");
        assert!(!slot_dir.join("64.ssz.tmp").exists(), "no temp left after commit");
        assert!(!slot_dir.join("64.pubkeys.tmp").exists(), "no pubkeys temp after commit");
        let ssz = std::fs::read(slot_dir.join("64.ssz")).unwrap();
        let bs = BeaconState::decompose(&ssz, &SpecConfig::mainnet(), None).unwrap();
        assert_eq!(bs.slot_states.finalized_view().slot_number(), 64);

        // Sidecar committed alongside; zero validators => empty pubkey vec.
        let pk = std::fs::read(slot_dir.join("64.pubkeys")).unwrap();
        assert!(decode_checkpoint_pubkeys(&pk).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
