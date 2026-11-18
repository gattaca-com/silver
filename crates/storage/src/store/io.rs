//! Disk I/O for the store: drains the queued writes and reads against the
//! on-disk layout (flat finalized store + the `unfinalized/` fork-tree and
//! `unfinalized_columns/` directories), plus the filename and file-open
//! helpers. The path builders (`slot_dir` etc.) stay with `Store` in the
//! parent module, since `load` needs the layout constants too.

use std::{
    fs::File,
    io::{Error, ErrorKind, Read, Write},
    os::fd::RawFd,
    path::{Path, PathBuf},
    ptr,
    time::{Duration, Instant},
};

use flux_profiler::timed;
use fxhash::FxHashSet;
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{DataKind, Enr, PeerEvent, TProducer, TRead, hex32, merkle::B256};

use super::{
    CheckpointWriter, Payload, PendingWrite, QueryUnit, SLOTS_PER_DIR, Store,
    backfill::BlockFacts,
    block_index, block_path, column_path,
    coverage::{self, Block},
    envelope_path,
    file_reader::ReadOutcome,
    file_writer::WriteOp,
    first_retained_slot, slot_dir,
    unfinalized::PayloadKey,
};
use crate::{StorageCounters, tile::IoEvent};

/// Bounds writes started per loop.
pub(super) const MAX_WRITES_PER_LOOP: usize = 10;
const MAX_WRITES_IN_FLIGHT: usize = 64;
const MAX_READS_IN_FLIGHT: usize = 64;
/// Bounds queries started or drained per call, so a burst of empty
/// (Complete-only) requests can't extend tile time.
const MAX_ITERATIONS_PER_LOOP: usize = 64;

impl Store {
    /// Returns the first failure, after which the write is dropped.
    #[timed]
    fn drain_pending_writes<F>(&mut self, emit: &mut F) -> (Result<(), Error>, bool)
    where
        F: FnMut(IoEvent),
    {
        let writes = self.write_queue.len() + self.writer.in_flight();
        StorageCounters::WriteQueueLength.set(writes as u64);
        let (finished, applied) = self.apply_finished_writes(emit);
        let (started, any_started) = self.start_queued_writes(emit);
        (finished.and(started), applied || any_started)
    }

    fn apply_finished_writes<F>(&mut self, emit: &mut F) -> (Result<(), Error>, bool)
    where
        F: FnMut(IoEvent),
    {
        let (mut outcome, mut applied) = (Ok(()), false);
        self.writer.step();
        while let Some((pending, result)) = self.writer.next_finished() {
            applied = true;
            outcome = outcome.and(self.write_landed(pending, result, emit));
        }
        (outcome, applied)
    }

    /// Starts queued writes in order. A write on a file that still has one in
    /// flight keeps its place, and so do later writes on that file; the rest
    /// pass it.
    fn start_queued_writes<F>(&mut self, emit: &mut F) -> (Result<(), Error>, bool)
    where
        F: FnMut(IoEvent),
    {
        let mut outcome = Ok(());
        // Waiting writes stay at the front, so `waiting` indexes the next
        // write to try. A key busy now stays busy for the whole pass.
        let (mut started, mut waiting) = (0, 0);
        for _ in 0..MAX_ITERATIONS_PER_LOOP {
            if started == MAX_WRITES_PER_LOOP || self.writer.in_flight() == MAX_WRITES_IN_FLIGHT {
                break;
            }
            let Some(pending) = self.write_queue.remove(waiting) else { break };
            if pending.waits_for_earlier_writes() && (waiting > 0 || self.writer.in_flight() > 0) {
                self.write_queue.insert(waiting, pending);
                break;
            }
            silver_log::debug!(?pending, "process pending write");
            match self.start_write(pending, emit) {
                Start::Done(result) => {
                    started += 1;
                    outcome = outcome.and(result);
                }
                Start::Busy(pending) => {
                    self.write_queue.insert(waiting, pending);
                    waiting += 1;
                }
            }
        }
        (outcome, started > 0)
    }

    /// Hands the write's I/O to the writer, or applies it at once when it has
    /// none. Gives the write back while its file is busy.
    fn start_write<F>(&mut self, pending: PendingWrite, emit: &mut F) -> Start
    where
        F: FnMut(IoEvent),
    {
        if self.below_retention(&pending) {
            silver_log::debug!(?pending, "backfilled below retention; dropped");
            self.write_queue.landed(&pending);
            return Start::Done(Ok(()));
        }
        let op = match self.write_op(&pending) {
            None => return Start::Done(self.apply_without_io(pending, emit)),
            Some(Err(error)) => return Start::Done(self.write_landed(pending, Err(error), emit)),
            Some(Ok(op)) => op,
        };
        // A create would truncate a file under an open read.
        if self.writer.conflicts_with(&op) || op.paths().any(|path| self.reader.busy_with(path)) {
            return Start::Busy(pending);
        }
        // SAFETY: the op's bytes are a `TRead` or a buffer that `pending`
        // holds, which the writer keeps until the write completes.
        unsafe { self.writer.start(op, pending) };
        Start::Done(Ok(()))
    }

    /// Its group is gone or being removed: writing would recreate it.
    fn below_retention(&self, pending: &PendingWrite) -> bool {
        pending.backfilled().is_some_and(|(payload, slot)| {
            self.history_floors[payload as usize].is_some_and(|floor| slot < floor)
        })
    }

    /// `None` for a write with no I/O on the writer.
    fn write_op(&mut self, pending: &PendingWrite) -> Option<Result<WriteOp, Error>> {
        Some(match pending {
            PendingWrite::Column { slot, column, ssz, .. } => {
                self.create(column_path(&self.store_dir, *slot, *column), ssz)
            }
            PendingWrite::WriteUnfinalized { slot, key, ssz } => {
                let path = self.unfinalized_dir(key.payload()).join(key.unfinalized_name(*slot));
                self.create(path, ssz)
            }
            PendingWrite::BackfillEnvelope { slot, ssz } => {
                self.create(envelope_path(&self.store_dir, *slot), ssz)
            }
            PendingWrite::BackfillBlock { block, ssz }
                if !self.finalized.written(&block.facts.block_root, block.facts.slot) =>
            {
                self.create(block_path(&self.store_dir, block.facts.slot), ssz)
            }
            PendingWrite::PromoteColumn { slot, block_root, column } => {
                self.promote(*slot, PayloadKey::Column { block_root: *block_root, column: *column })
            }
            PendingWrite::PromoteEnvelope { slot, block_root } => {
                self.promote(*slot, PayloadKey::Envelope { block_root: *block_root })
            }
            PendingWrite::PromoteBlock { block } => {
                let BlockFacts { slot, block_root, parent_root, .. } = block.facts;
                self.promote(slot, PayloadKey::Block { parent_root, block_root })
            }
            PendingWrite::Prune { slot, key } => {
                let path = self.unfinalized_dir(key.payload()).join(key.unfinalized_name(*slot));
                Ok(WriteOp::Unlink { path })
            }
            PendingWrite::IndexBlock { dir, records } => Ok(WriteOp::Append {
                path: block_index::file(dir),
                bytes: ptr::from_ref(&records[..]),
            }),
            PendingWrite::Coverage { bytes, .. } => {
                let (_, staged) = coverage::codec::files(&self.store_dir);
                Ok(WriteOp::Create { path: staged, bytes: ptr::from_ref(&bytes[..]) })
            }
            PendingWrite::CommitCoverage { .. } => {
                let (path, staged) = coverage::codec::files(&self.store_dir);
                Ok(WriteOp::Rename { from: staged, to: path })
            }
            PendingWrite::TruncateHistory { .. } |
            PendingWrite::BackfillBlock { .. } |
            PendingWrite::PersistPeer { .. } |
            PendingWrite::LoadPeers => return None,
        })
    }

    /// Only once nothing is queued or in flight, so the file describes data
    /// already down.
    fn persist_coverage(&mut self) -> bool {
        let settled = self.write_queue.is_empty() && self.writer.in_flight() == 0;
        if !settled || !self.finalized.coverage().changed() {
            return false;
        }
        let mut bytes = std::mem::take(&mut self.coverage_bytes);
        let version = self.finalized.coverage().encode_for_persist(&mut bytes);
        self.write_queue.push_back(PendingWrite::Coverage { version, bytes });
        true
    }

    fn create(&mut self, path: PathBuf, ssz: &TRead) -> Result<WriteOp, Error> {
        create_dir_once(&mut self.known_dirs, path.parent().expect("a slot directory"))?;
        let (bytes, _) = ssz.buffer().map_err(Error::other)?;
        Ok(WriteOp::Create { path, bytes: ptr::from_ref(bytes) })
    }

    fn promote(&mut self, slot: u64, key: PayloadKey) -> Result<WriteOp, Error> {
        let to = key.finalized_path(&self.store_dir, slot);
        create_dir_once(&mut self.known_dirs, to.parent().expect("a slot directory"))?;
        let from = self.unfinalized_dir(key.payload()).join(key.unfinalized_name(slot));
        Ok(WriteOp::Rename { from, to })
    }

    /// The bookkeeping once a write's I/O is down, or the failure that drops
    /// it.
    fn write_landed<F>(
        &mut self,
        pending: PendingWrite,
        result: Result<(), Error>,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        self.write_queue.landed(&pending);
        match pending {
            PendingWrite::Column { slot, column, custody_set_complete, .. } => {
                result?;
                self.finalized.column_landed(slot, column);
                StorageCounters::BackfillColumnsWritten.inc();
                if custody_set_complete {
                    emit(IoEvent::Need(self.finalized.persisted(DataKind::Columns, slot, None)));
                }
            }
            PendingWrite::WriteUnfinalized { key, .. } => {
                result?;
                key.payload().record_written();
            }
            PendingWrite::PromoteColumn { slot, column, .. } => {
                if promoted(result, slot, Payload::Column)? {
                    self.finalized.column_landed(slot, column);
                }
            }
            PendingWrite::PromoteEnvelope { slot, .. } => {
                if promoted(result, slot, Payload::Envelope)? {
                    self.finalized.envelope_landed(slot);
                }
            }
            PendingWrite::PromoteBlock { block } => {
                let slot = block.facts.slot;
                // Data before index: the record is appended only after the
                // rename, so a crash never indexes an unmoved block.
                if promoted(result, slot, Payload::Block)? {
                    self.index_landed(block);
                }
            }
            PendingWrite::Prune { key, .. } => match result {
                Err(error) if error.kind() != ErrorKind::NotFound => return Err(error),
                _ => key.payload().record_pruned(),
            },
            PendingWrite::BackfillBlock { block, ssz } => {
                result?;
                let BlockFacts { slot, parent_root, .. } = block.facts;
                self.index_landed(block);
                self.block_backfilled(slot, parent_root, &ssz, emit)?;
            }
            PendingWrite::BackfillEnvelope { slot, .. } => {
                result?;
                self.finalized.envelope_landed(slot);
                emit(IoEvent::Need(self.finalized.persisted(DataKind::Envelope, slot, None)));
            }
            // A failed write leaves the live file as it was.
            PendingWrite::Coverage { version, bytes } => {
                self.coverage_bytes = bytes;
                result?;
                self.write_queue.push_back(PendingWrite::CommitCoverage { version });
            }
            PendingWrite::CommitCoverage { version } => {
                result?;
                self.finalized.coverage_persisted(version);
            }
            PendingWrite::IndexBlock { .. } |
            PendingWrite::TruncateHistory { .. } |
            PendingWrite::PersistPeer { .. } |
            PendingWrite::LoadPeers => result?,
        }
        Ok(())
    }

    fn index_landed(&mut self, block: Block) {
        let dir = slot_dir(&self.store_dir, Payload::Block, block.facts.slot);
        let record = self.finalized.landed(block);
        self.write_queue.push_index_record(dir, record);
    }

    fn block_backfilled<F>(
        &mut self,
        slot: u64,
        parent_root: B256,
        ssz: &TRead,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        let (buffer, _) = ssz.buffer().map_err(Error::other)?;
        self.history.seed_pending(slot, buffer, &self.finalized);
        let parent_slot = self.finalized.slot_of(&parent_root);
        emit(IoEvent::Need(self.finalized.persisted(DataKind::Block, slot, parent_slot)));
        StorageCounters::BackfillBlocksWritten.inc();
        Ok(())
    }

    /// Writes with no I/O on the writer: bookkeeping, a block already on disk
    /// being linked again, and the rare peer files.
    fn apply_without_io<F>(&mut self, pending: PendingWrite, emit: &mut F) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        self.write_queue.landed(&pending);
        match pending {
            PendingWrite::TruncateHistory { payload, finalized_slot } => {
                self.truncate_history(payload, finalized_slot)
            }
            // A block whose file is indexed is re-served only to link it; a
            // root indexed in memory but never written is not.
            PendingWrite::BackfillBlock { block, ssz } => {
                let BlockFacts { slot, parent_root, .. } = block.facts;
                self.finalized.relinked(block);
                self.block_backfilled(slot, parent_root, &ssz, emit)
            }
            PendingWrite::PersistPeer { enr } => self.persist_peer_file(&enr),
            PendingWrite::LoadPeers => self.load_peer_files(emit),
            other => unreachable!("{other:?} has I/O for the writer"),
        }
    }

    fn truncate_history(&mut self, payload: Payload, finalized_slot: u64) -> Result<(), Error> {
        let epoch = finalized_slot / SLOTS_PER_EPOCH;
        let earliest_slot =
            finalized_slot.saturating_sub(payload.slots_retained(&self.spec, epoch));
        self.remove_history_below(payload, first_retained_slot(earliest_slot))?;
        self.finalized.truncated(payload, earliest_slot);
        Ok(())
    }

    fn persist_peer_file(&self, enr: &Enr) -> Result<(), Error> {
        let peer_file = self.peers_dir().join(format!("{}.enr", enr.public_key()));
        open_file_write(peer_file)?.write_all(enr.to_string().as_bytes())
    }

    fn load_peer_files<F>(&self, emit: &mut F) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        for entry in std::fs::read_dir(self.peers_dir())? {
            if let Ok(entry) = entry &&
                entry.metadata()?.is_file()
            {
                let mut enr_string = String::new();
                open_file_read(entry.path())?.read_to_string(&mut enr_string)?;
                let enr = Enr::from_base64(enr_string.as_str(), false).map_err(Error::other)?;
                emit(IoEvent::PeerEvent(PeerEvent::DiscNodeFound { enr, reload: true }));
            }
        }
        Ok(())
    }

    #[timed]
    fn serve_pending_reads<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        producer: &mut TProducer,
        emit: &mut F,
    ) -> bool
    where
        F: FnMut(IoEvent),
    {
        let reads = self.query_queue.len() + self.reader.in_flight();
        StorageCounters::ReadQueueLength.set(reads as u64);
        let delivered = self.deliver_finished_reads(fork_digest_at, producer, emit);
        self.start_reads(emit) || delivered
    }

    fn deliver_finished_reads<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        producer: &mut TProducer,
        emit: &mut F,
    ) -> bool
    where
        F: FnMut(IoEvent),
    {
        let (query_queue, mut delivered) = (&mut self.query_queue, false);
        self.reader.step(producer, |(mut query, unit), outcome| {
            delivered = true;
            match outcome {
                ReadOutcome::Sent(read) => {
                    // Context fork-digest for the served object's own slot's fork
                    // (a request can span a fork boundary).
                    if query.deliver(&unit, read, fork_digest_at(unit.slot()), emit) {
                        query_queue.push_back(query);
                    }
                }
                // Skipped slots and EMPTY payloads leave holes in any envelope range.
                ReadOutcome::Missing if unit.is_envelope() => query_queue.push_back(query),
                ReadOutcome::Missing => query.finish(true, emit),
                ReadOutcome::Failed(error) => {
                    silver_log::warn!(?error, ?unit, "serving a stored file failed");
                    query.finish(true, emit);
                }
            }
        });
        delivered
    }

    /// Round-robin, one unit in flight per query: a query's chunks go out in
    /// order, and a large range cannot block other peers' queries.
    /// `MAX_ITERATIONS_PER_LOOP` bounds drained-request churn.
    fn start_reads<F>(&mut self, emit: &mut F) -> bool
    where
        F: FnMut(IoEvent),
    {
        let (mut iterations, mut started) = (0, false);
        while iterations < MAX_ITERATIONS_PER_LOOP && self.reader.in_flight() < MAX_READS_IN_FLIGHT
        {
            iterations += 1;
            let Some(mut query) = self.query_queue.pop_front() else { break };
            let Some(unit) = query.units.pop_front() else {
                query.finish(false, emit);
                started = true;
                continue;
            };
            // A file still being written may be empty or partial, and one
            // still being promoted is not in place yet.
            let promoting = unit.is_finalized() && self.write_queue.promoting(unit.slot());
            let path = (!promoting)
                .then(|| self.unit_path(&unit))
                .filter(|path| !self.writer.busy_with(path));
            let Some(path) = path else {
                query.units.push_front(unit);
                self.query_queue.push_back(query);
                continue;
            };
            self.reader.start(path, (query, unit));
            started = true;
        }
        started
    }

    /// Blocks until a completion waits on any ring, `wake` turns readable, or
    /// `timeout` passes.
    #[cfg_attr(not(feature = "thread_park"), allow(dead_code))]
    pub(crate) fn wait(&mut self, wake: Option<RawFd>, timeout: Duration) {
        let checkpoint = self.checkpoint.as_mut().map_or(-1, CheckpointWriter::ring_fd);
        let descriptors = [
            self.writer.ring_fd(),
            self.reader.ring_fd(),
            self.remover.ring_fd(),
            checkpoint,
            wake.unwrap_or(-1),
        ];
        let mut fds = descriptors.map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 });
        let timeout = libc::timespec {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_nsec: timeout.subsec_nanos() as libc::c_long,
        };
        // SAFETY: `fds` and `timeout` outlive the call. An interrupted wait
        // only returns early.
        unsafe { libc::ppoll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, &timeout, ptr::null()) };
    }

    pub(crate) fn file_io<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        producer: &mut TProducer,
        emit: &mut F,
    ) -> Result<bool, Error>
    where
        F: FnMut(IoEvent),
    {
        let (writes, mut progressed) =
            if !self.write_queue.is_empty() || self.writer.in_flight() > 0 {
                self.drain_pending_writes(emit)
            } else {
                (Ok(()), false)
            };
        if !self.query_queue.is_empty() || self.reader.in_flight() > 0 {
            progressed |= self.serve_pending_reads(&fork_digest_at, producer, emit);
        }

        let queued = self.write_queue.len();
        self.history.link_buffered_blocks(
            self.head,
            &self.finalized,
            &self.unfinalized,
            &mut self.write_queue,
        );
        self.history.expire(Instant::now());
        if self.head.root != [0u8; 32] && self.write_queue.landing() == 0 {
            self.history.step(
                self.head,
                !self.sync_target.is_syncing(),
                &self.store_dir,
                &mut self.finalized,
                &self.unfinalized,
                emit,
            );
        }

        progressed |= self.write_queue.len() != queued;

        progressed |= self.persist_coverage();
        progressed |= self.step_checkpoint();
        progressed |= self.remover.step();
        writes.map(|()| progressed)
    }

    /// The first call of a run lists the payload's groups. Floors only rise,
    /// so later calls derive the groups the floor passed by number.
    fn remove_history_below(&mut self, payload: Payload, first_retained: u64) -> Result<(), Error> {
        let dir = Path::new(&self.store_dir).join(payload.finalized_dir_name());
        let floor = &mut self.history_floors[payload as usize];
        match *floor {
            Some(previous) => {
                for group in (previous..first_retained).step_by(SLOTS_PER_DIR as usize) {
                    let group = dir.join(group.to_string());
                    self.known_dirs.remove(&group);
                    self.remover.remove(group);
                }
            }
            None => {
                for entry in std::fs::read_dir(&dir)? {
                    let entry = entry?;
                    let group =
                        entry.file_name().to_str().and_then(|name| name.parse::<u64>().ok());
                    if group.is_some_and(|group| group < first_retained) {
                        self.known_dirs.remove(&entry.path());
                        self.remover.remove(entry.path());
                    }
                }
            }
        }
        *floor = Some(floor.map_or(first_retained, |previous| previous.max(first_retained)));
        Ok(())
    }

    fn unit_path(&self, unit: &QueryUnit) -> PathBuf {
        match unit {
            QueryUnit::Block { slot } => block_path(&self.store_dir, *slot),
            QueryUnit::UnfinalizedBlock { slot, parent_root, block_root } => self
                .unfinalized_dir(Payload::Block)
                .join(unfinalized_name(*slot, parent_root, block_root)),
            QueryUnit::Column { slot, column } => column_path(&self.store_dir, *slot, *column),
            QueryUnit::UnfinalizedColumn { slot, block_root, column } => self
                .unfinalized_dir(Payload::Column)
                .join(unfinalized_column_name(*slot, block_root, *column)),
            QueryUnit::Envelope { slot } => envelope_path(&self.store_dir, *slot),
            QueryUnit::UnfinalizedEnvelope { slot, block_root } => self
                .unfinalized_dir(Payload::Envelope)
                .join(unfinalized_envelope_name(*slot, block_root)),
        }
    }
}

#[allow(clippy::large_enum_variant)]
enum Start {
    Done(Result<(), Error>),
    /// Its file has a write in flight; it waits at the head of the queue.
    Busy(PendingWrite),
}

/// `Ok(false)` when the unfinalized file is gone: the payload stays missing.
fn promoted(result: Result<(), Error>, slot: u64, payload: Payload) -> Result<bool, Error> {
    match result {
        Ok(()) => {
            payload.record_promoted();
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            silver_log::warn!(
                slot,
                ?payload,
                "unfinalized file missing at promotion; left missing"
            );
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn create_dir_once(known: &mut FxHashSet<PathBuf>, dir: &Path) -> Result<(), Error> {
    if !known.contains(dir) {
        std::fs::create_dir_all(dir)?;
        known.insert(dir.to_path_buf());
    }
    Ok(())
}

pub(super) fn open_file_read<P: AsRef<Path>>(path: P) -> Result<File, Error> {
    File::open(path)
}

pub(super) fn open_file_write<P: AsRef<Path>>(path: P) -> Result<File, Error> {
    File::options().write(true).create(true).truncate(true).open(path)
}

/// `<slot>_<parent_root>_<block_root>.ssz` — the unfinalized fork-tree
/// filename, which durably encodes the tree edge.
pub(super) fn unfinalized_name(slot: u64, parent_root: &[u8; 32], block_root: &[u8; 32]) -> String {
    format!("{slot}_{}_{}.ssz", hex32(parent_root), hex32(block_root))
}

/// Inverse of `unfinalized_name`, returning `(block_root, slot, parent_root)`.
/// `None` on any malformed name so a stray file in `unfinalized/` is skipped
/// rather than aborting the load scan.
pub(super) fn parse_unfinalized_name(name: &str) -> Option<([u8; 32], u64, [u8; 32])> {
    let stem = name.strip_suffix(".ssz")?;
    let mut parts = stem.split('_');
    let slot: u64 = parts.next()?.parse().ok()?;
    let parent_root = parse_hex32(parts.next()?)?;
    let block_root = parse_hex32(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((block_root, slot, parent_root))
}

/// `<slot>_<block_root>_<column>.ssz` — the unfinalized column filename.
pub(super) fn unfinalized_column_name(slot: u64, block_root: &[u8; 32], column: u64) -> String {
    format!("{slot}_{}_{column}.ssz", hex32(block_root))
}

/// Inverse of `unfinalized_column_name`, returning `(block_root, slot,
/// column)`. `None` on a malformed name so a stray file is skipped on load.
pub(super) fn parse_unfinalized_column_name(name: &str) -> Option<([u8; 32], u64, u64)> {
    let stem = name.strip_suffix(".ssz")?;
    let mut parts = stem.split('_');
    let slot: u64 = parts.next()?.parse().ok()?;
    let block_root = parse_hex32(parts.next()?)?;
    let column: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((block_root, slot, column))
}

pub(super) fn unfinalized_envelope_name(slot: u64, block_root: &[u8; 32]) -> String {
    format!("{slot}_{}.ssz", hex32(block_root))
}

pub(super) fn parse_unfinalized_envelope_name(name: &str) -> Option<([u8; 32], u64)> {
    let stem = name.strip_suffix(".ssz")?;
    let mut parts = stem.split('_');
    let slot: u64 = parts.next()?.parse().ok()?;
    let block_root = parse_hex32(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((block_root, slot))
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}
