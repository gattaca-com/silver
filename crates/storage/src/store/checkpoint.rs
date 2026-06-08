#[cfg(test)]
use std::io::Write;
use std::{
    fs::File,
    io::{BufWriter, Error},
    path::{Path, PathBuf},
};

use silver_beacon_state_data::{
    BeaconStateReader, CHECKPOINT_SECTIONS, CheckpointSnapshot, Section,
};

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

pub(super) struct CheckpointWriter {
    reader: BeaconStateReader,
    writer: BufWriter<File>,
    snapshot: CheckpointSnapshot,
    tmp_path: PathBuf,
    // Decompressed-pubkey sidecar (`<slot>.pubkeys`), written as a second stage
    // after the SSZ sections so checkpoint load can skip the per-validator
    // decompression.
    pubkeys_writer: BufWriter<File>,
    pubkeys_tmp: PathBuf,
    // Next section to write, in `0..CHECKPOINT_SECTIONS` (0 = fixed part); once
    // it reaches CHECKPOINT_SECTIONS the SSZ is done and the pubkeys stage runs.
    cursor: usize,
    // Chunk index within `cursor` — only the validators section spans >1.
    chunk: usize,
    // Chunk index within the pubkeys stage.
    pubkeys_chunk: usize,
}

enum CheckpointStep {
    More,
    Done,
    Superseded,
}

impl CheckpointWriter {
    /// Encode the next section to the temp file. Aborts (without writing) if a
    /// finalization has superseded the snapshot since it began.
    fn step(&mut self) -> Result<CheckpointStep, Error> {
        if !self.reader.checkpoint_version_matches(self.snapshot.version) {
            return Ok(CheckpointStep::Superseded);
        }

        if self.cursor < CHECKPOINT_SECTIONS {
            let complete = self.reader.write_checkpoint_chunk(
                Section::ALL[self.cursor],
                self.chunk,
                &self.snapshot.offsets,
                &mut self.writer,
            )?;
            if complete {
                self.cursor += 1;
                self.chunk = 0;
            } else {
                self.chunk += 1;
            }
            return Ok(CheckpointStep::More);
        }

        let complete = self
            .reader
            .write_checkpoint_pubkeys_chunk(self.pubkeys_chunk, &mut self.pubkeys_writer)?;
        if complete {
            Ok(CheckpointStep::Done)
        } else {
            self.pubkeys_chunk += 1;
            Ok(CheckpointStep::More)
        }
    }

    fn discard(self) {
        drop(self.writer);
        drop(self.pubkeys_writer);
        remove_checkpoint_dir(&self.tmp_path);
    }
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

    /// Section the next `file_io` turn will write (for the persist benchmark's
    /// per-section breakdown). `None` when no checkpoint is in flight.
    #[cfg(test)]
    pub(crate) fn checkpoint_section(&self) -> Option<Section> {
        // `None` once past the SSZ sections (pubkeys stage).
        self.checkpoint.as_ref().and_then(|cw| Section::ALL.get(cw.cursor).copied())
    }

    pub(crate) fn begin_checkpoint(&mut self, reader: BeaconStateReader) {
        if self.checkpoint.is_some() {
            return;
        }
        let snap = reader.begin_checkpoint();
        if snap.slot <= self.last_persisted_finalized_slot {
            return;
        }
        let (file, tmp_path) = match self.open_checkpoint_tmp(snap.slot) {
            Ok(x) => x,
            Err(e) => {
                tracing::error!(?e, slot = snap.slot, "failed to open checkpoint temp file");
                return;
            }
        };
        let pubkeys_tmp = tmp_path.with_file_name(format!("{}.pubkeys.tmp", snap.slot));
        let pubkeys_file = match io::open_file_write(&pubkeys_tmp, false) {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(?e, slot = snap.slot, "failed to open pubkeys temp file");
                remove_checkpoint_dir(&tmp_path);
                return;
            }
        };
        self.checkpoint = Some(CheckpointWriter {
            reader,
            writer: BufWriter::with_capacity(CHECKPOINT_WRITER_CAP, file),
            snapshot: snap,
            tmp_path,
            pubkeys_writer: BufWriter::with_capacity(CHECKPOINT_WRITER_CAP, pubkeys_file),
            pubkeys_tmp,
            cursor: 0,
            chunk: 0,
            pubkeys_chunk: 0,
        });
    }

    /// Advance the in-flight checkpoint by one section. Called once per
    /// `file_io` turn; commits after the last section (gated by a final version
    /// check) and discards the temp on supersede or write error.
    pub(super) fn step_checkpoint(&mut self) {
        let step = match self.checkpoint.as_mut() {
            Some(cw) => cw.step(),
            None => return,
        };
        match step {
            Ok(CheckpointStep::More) => {}
            Ok(CheckpointStep::Done) => {
                let cw = self.checkpoint.take().expect("checkpoint present");
                self.commit_in_flight_checkpoint(cw);
            }
            Ok(CheckpointStep::Superseded) => {
                let cw = self.checkpoint.take().expect("checkpoint present");
                tracing::debug!(
                    slot = cw.snapshot.slot,
                    "checkpoint persist superseded; discarded"
                );
                cw.discard();
            }
            Err(e) => {
                let cw = self.checkpoint.take().expect("checkpoint present");
                tracing::error!(?e, section = cw.cursor, "checkpoint section write failed");
                cw.discard();
            }
        }
    }

    /// Final version check, flush the writer, then atomically commit.
    fn commit_in_flight_checkpoint(&mut self, cw: CheckpointWriter) {
        if !cw.reader.checkpoint_version_matches(cw.snapshot.version) {
            cw.discard();
            return;
        }
        let slot = cw.snapshot.slot;
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
        match self.commit_checkpoint(slot, ssz_file, &tmp_path, Some((pubkeys_file, &pubkeys_tmp)))
        {
            Ok(()) => tracing::info!(slot, "persisted finalized checkpoint"),
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

    use silver_beacon_state_data::{Finalized, SpecConfig};

    use super::{FINALIZED_CHECKPOINTS_DIR, Store};
    use crate::tile::IoEvent;

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

        let mut fin = Box::new(Finalized::empty());
        fin.decompose(&ssz, &SpecConfig::mainnet()).expect("decompose");
        let base_slot = fin.slot();
        let len = fin.ssz_len();
        assert_eq!(len, ssz.len(), "round-trip length mismatch");
        println!("state: {len} bytes ({} MiB), base slot {base_slot}", len >> 20);

        use silver_beacon_state_data::{
            BeaconState, BeaconStateOwner, CHECKPOINT_SECTIONS, Section,
        };
        use silver_common::TCache;

        // Real persist target (atomic temp → fsync → rename → fsync dirs →
        // retention). A monotonically-increasing slot each iteration bypasses
        // the idempotency guard and exercises the per-slot mkdir + retention
        // prune; retention caps disk at the newest N. Unique subdir under
        // SILVER_BENCH_DIR (default `/tmp`; point it at the data-store disk —
        // tmpfs understates fsync). Removed at the end.
        let base = std::env::var("SILVER_BENCH_DIR").unwrap_or_else(|_| "/tmp".to_string());
        let dir = format!("{base}/silver_bench_persist_{}", rand::random::<u32>());
        let mut store = Store::load(dir.clone()).unwrap();

        const ITERS: u64 = 23;
        const WARMUP: u64 = 3;
        let mut slot = base_slot;

        // Phase 1, write half only: write a pre-encoded blob (encode excluded).
        let mut buf = Vec::with_capacity(len);
        fin.encode_ssz(&mut buf).unwrap();
        let mut write_only = Vec::new();
        for i in 0..ITERS {
            let t = Instant::now();
            store.persist_finalized_checkpoint(slot, &buf).unwrap();
            let elapsed = t.elapsed();
            slot += 1;
            if i >= WARMUP {
                write_only.push(elapsed);
            }
        }
        report("oneshot_write_only", &mut write_only, len);

        // Phase 1, full: encode into the reused buffer, then write it.
        let mut oneshot = Vec::new();
        for i in 0..ITERS {
            let t = Instant::now();
            buf.clear();
            fin.encode_ssz(&mut buf).unwrap();
            store.persist_finalized_checkpoint(slot, &buf).unwrap();
            let elapsed = t.elapsed();
            slot += 1;
            if i >= WARMUP {
                oneshot.push(elapsed);
            }
        }
        report("oneshot_full(encode+write)", &mut oneshot, len);

        // Phase 2, streamed: the real `begin_checkpoint` + `file_io` section
        // loop (fused encode+write through the BufWriter, version checks, commit,
        // retention). Consumes `fin` into an owner so the reader can drive it.
        let mut bs = BeaconState::empty();
        bs.finalized = *fin;
        let mut owner = BeaconStateOwner::new(bs);
        let reader = owner.reader();
        let mut producer = TCache::multi_producer("bench_persist_rpc", 1 << 20);
        let mut streamed = Vec::new();
        // Per-section total over the measured iterations (the per-turn `Instant`
        // overhead is ~ns/turn, negligible vs the section writes it brackets).
        let mut per_section = [Duration::ZERO; CHECKPOINT_SECTIONS];
        let mut counted = 0u32;
        for i in 0..ITERS {
            // Advance the finalized slot so each persist targets a fresh slot
            // (guard drops here → seqlock version even before the snapshot).
            {
                let mut g = owner.write();
                g.finalized.slot.slot.slot = slot;
            }
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
                    per_section[s as usize] += cdt;
                }
            }
            let elapsed = t.elapsed();
            slot += 1;
            if i >= WARMUP {
                streamed.push(elapsed);
                counted += 1;
            }
        }
        report("streamed_full(encode+write)", &mut streamed, len);
        println!("  streamed per-section (mean over {counted} persists):");
        for (idx, total) in per_section.iter().enumerate() {
            println!("    {:?}: {:?}", Section::ALL[idx], *total / counted);
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
    /// writes one section per turn and commits on the last, and the committed
    /// file round-trips through `decompose`.
    #[test]
    fn streamed_checkpoint_persist_via_file_io() {
        use silver_beacon_state_data::{BeaconState, BeaconStateOwner, decode_checkpoint_pubkeys};
        use silver_common::TCache;

        // Finalized base at slot 64 (epoch 2), zero validators — minimal but
        // canonical.
        let mut bs = BeaconState::empty();
        bs.finalized.slot.slot.slot = 64;
        let mut owner = BeaconStateOwner::new(bs);
        let reader = owner.reader();

        let dir = format!("/tmp/silver_storage_streamcp_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::load(dir.clone()).unwrap();

        assert!(!store.checkpoint_in_flight());
        store.begin_checkpoint(reader);
        assert!(store.checkpoint_in_flight(), "begin_checkpoint should arm a job");

        // One section per file_io turn until the commit clears the job.
        let mut producer = TCache::multi_producer("streamcp_rpc", 1 << 20);
        let mut turns = 0;
        while store.checkpoint_in_flight() {
            store.file_io(&[0u8; 4], 0, &mut producer, &mut |_: IoEvent| {}).unwrap();
            turns += 1;
            assert!(turns <= 64, "checkpoint did not finish");
        }
        // CHECKPOINT_SECTIONS SSZ turns + one pubkeys-stage turn.
        assert_eq!(turns, super::CHECKPOINT_SECTIONS + 1, "one turn per section + pubkeys");
        assert_eq!(store.last_persisted_finalized_slot(), 64);

        let slot_dir = Path::new(&dir).join(FINALIZED_CHECKPOINTS_DIR).join("64");
        assert!(!slot_dir.join("64.ssz.tmp").exists(), "no temp left after commit");
        assert!(!slot_dir.join("64.pubkeys.tmp").exists(), "no pubkeys temp after commit");
        let ssz = std::fs::read(slot_dir.join("64.ssz")).unwrap();
        let mut fin = Box::new(Finalized::empty());
        fin.decompose(&ssz, &SpecConfig::mainnet()).unwrap();
        assert_eq!(fin.slot.slot.slot, 64);

        // Sidecar committed alongside; zero validators => empty pubkey vec.
        let pk = std::fs::read(slot_dir.join("64.pubkeys")).unwrap();
        assert!(decode_checkpoint_pubkeys(&pk).unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
