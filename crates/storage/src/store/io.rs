//! Disk I/O for the store: drains the queued writes and reads against the
//! on-disk layout (flat finalized store + the `unfinalized/` fork-tree and
//! `unfinalized_columns/` directories), plus the filename and file-open
//! helpers. The path builders (`slot_dir` etc.) stay with `Store` in the
//! parent module, since `load` needs the layout constants too.

use std::{
    fs::File,
    io::{Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

use flux_profiler::timed;
use fxhash::FxHashSet;
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{DataKind, Enr, PeerEvent, TProducer, TRead, hex32, merkle::B256};

use super::{
    Payload, PendingWrite, QueryUnit, SLOTS_PER_DIR, Store, WriteTag,
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
    /// Applies finished writes, then starts queued ones in order. A write on
    /// a file that still has one in flight waits, and so does everything
    /// queued behind it. Returns the first failure, after which the write is
    /// dropped.
    #[timed]
    fn drain_pending_writes<F>(&mut self, emit: &mut F) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        StorageCounters::WriteQueueLength.set(self.write_queue.len() as u64);
        let mut outcome = Ok(());

        let mut completed = std::mem::take(&mut self.completed_writes);
        self.writer.step(|pending, result| completed.push((pending, result)));
        for (tag, result) in completed.drain(..) {
            outcome = outcome.and(match tag {
                WriteTag::Queued(pending) => {
                    self.landing_in_flight -= usize::from(pending.lands());
                    self.write_landed(pending, result, emit)
                }
                WriteTag::Coverage { version } => {
                    result.map(|()| self.finalized.coverage_persisted(version))
                }
            });
        }
        self.completed_writes = completed;

        let mut started = 0;
        while started < MAX_WRITES_PER_LOOP && self.writer.in_flight() < MAX_WRITES_IN_FLIGHT {
            let Some(pending) = self.write_queue.pop_front() else { break };
            silver_log::debug!(?pending, "process pending write");
            started += 1;
            match self.start_write(pending, emit) {
                Start::Done(result) => outcome = outcome.and(result),
                Start::Busy(pending) => {
                    self.write_queue.push_front(pending);
                    break;
                }
            }
        }
        outcome
    }

    /// Hands the write's I/O to the writer, or applies it at once when it has
    /// none. Gives the write back while its file is busy.
    fn start_write<F>(&mut self, pending: PendingWrite, emit: &mut F) -> Start
    where
        F: FnMut(IoEvent),
    {
        let op = match &pending {
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
            PendingWrite::IndexBlock { dir, record } => {
                let path = block_index::file(dir);
                if self.writer.busy_with(&path) {
                    return Start::Busy(pending);
                }
                // SAFETY: an append copies its bytes before `start` returns.
                unsafe {
                    let op = WriteOp::Append { path, bytes: &record.encode() };
                    self.writer.start(op, WriteTag::Queued(pending))
                };
                return Start::Done(Ok(()));
            }
            PendingWrite::TruncateHistory { .. } |
            PendingWrite::BackfillBlock { .. } |
            PendingWrite::PersistPeer { .. } |
            PendingWrite::LoadPeers => return Start::Done(self.apply_without_io(pending, emit)),
        };
        let op = match op {
            Ok(op) => op,
            Err(error) => return Start::Done(self.write_landed(pending, Err(error), emit)),
        };
        if self.writer.busy_with(op.key()) {
            return Start::Busy(pending);
        }
        self.landing_in_flight += usize::from(pending.lands());
        // SAFETY: a `Create` points into the `TRead` that `pending` holds,
        // which the writer keeps until the write completes.
        unsafe { self.writer.start(op, WriteTag::Queued(pending)) };
        Start::Done(Ok(()))
    }

    /// Started once nothing is queued or in flight, so the file describes
    /// data already down.
    fn persist_coverage(&mut self) {
        let (path, staged) = coverage::codec::files(&self.store_dir);
        let (bytes, version) = self.finalized.encode_coverage();
        let op = WriteOp::Replace { path, staged, bytes };
        // SAFETY: a replace copies its bytes before `start` returns.
        unsafe { self.writer.start(op, WriteTag::Coverage { version }) };
    }

    fn create<'a>(&mut self, path: PathBuf, ssz: &TRead) -> Result<WriteOp<'a>, Error> {
        create_dir_once(&mut self.known_dirs, path.parent().expect("a slot directory"))?;
        let (bytes, _) = ssz.buffer().map_err(Error::other)?;
        Ok(WriteOp::Create { path, source: bytes.as_ptr(), len: bytes.len() })
    }

    fn promote<'a>(&mut self, slot: u64, key: PayloadKey) -> Result<WriteOp<'a>, Error> {
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
            PendingWrite::IndexBlock { .. } => result?,
            PendingWrite::TruncateHistory { .. } |
            PendingWrite::PersistPeer { .. } |
            PendingWrite::LoadPeers => result?,
        }
        Ok(())
    }

    fn index_landed(&mut self, block: Block) {
        let dir = slot_dir(&self.store_dir, Payload::Block, block.facts.slot);
        let record = self.finalized.landed(block);
        self.write_queue.push_back(PendingWrite::IndexBlock { dir, record });
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
        match pending {
            PendingWrite::TruncateHistory { payload, finalized_slot } => {
                let epoch = finalized_slot / SLOTS_PER_EPOCH;
                let earliest_slot =
                    finalized_slot.saturating_sub(payload.slots_retained(&self.spec, epoch));
                self.remove_history_below(payload, first_retained_slot(earliest_slot))?;
                self.finalized.truncated(payload, earliest_slot);
            }
            // A block whose file is indexed is re-served only to link it; a
            // root indexed in memory but never written is not.
            PendingWrite::BackfillBlock { block, ssz } => {
                let BlockFacts { slot, parent_root, .. } = block.facts;
                self.finalized.relinked(block);
                self.block_backfilled(slot, parent_root, &ssz, emit)?;
            }
            PendingWrite::PersistPeer { enr } => {
                let peer_file = self.peers_dir().join(format!("{}.enr", enr.public_key()));
                open_file_write(peer_file, false)?.write_all(enr.to_string().as_bytes())?;
            }
            PendingWrite::LoadPeers => {
                let peer_files = std::fs::read_dir(self.peers_dir())?;
                for entry in peer_files {
                    if let Ok(entry) = entry &&
                        entry.metadata()?.is_file()
                    {
                        let mut enr_string = String::new();
                        open_file_read(entry.path())?.read_to_string(&mut enr_string)?;
                        let enr =
                            Enr::from_base64(enr_string.as_str(), false).map_err(Error::other)?;
                        emit(IoEvent::PeerEvent(PeerEvent::DiscNodeFound { enr, reload: true }));
                    }
                }
            }
            other => unreachable!("{other:?} has I/O for the writer"),
        }
        Ok(())
    }

    #[timed]
    fn serve_pending_reads<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        producer: &mut TProducer,
        emit: &mut F,
    ) where
        F: FnMut(IoEvent),
    {
        StorageCounters::ReadQueueLength.set(self.query_queue.len() as u64);

        let query_queue = &mut self.query_queue;
        self.reader.step(producer, |(mut query, unit), outcome| match outcome {
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
        });

        // Round-robin, one unit in flight per query: a query's chunks go out
        // in order, and a large range cannot block other peers' queries.
        // `MAX_ITERATIONS_PER_LOOP` bounds drained-request churn.
        let mut iterations = 0;
        while iterations < MAX_ITERATIONS_PER_LOOP && self.reader.in_flight() < MAX_READS_IN_FLIGHT
        {
            iterations += 1;
            let Some(mut query) = self.query_queue.pop_front() else { break };
            let Some(unit) = query.units.pop_front() else {
                query.finish(false, emit);
                continue;
            };
            let path = self.unit_path(&unit);
            // A file still being written may be empty or partial.
            if self.writer.busy_with(&path) {
                query.units.push_front(unit);
                self.query_queue.push_back(query);
                continue;
            }
            self.reader.start(&path, (query, unit));
        }
    }

    /// Work queued or on the disk: completions arrive only by polling, so the
    /// tile must not park meanwhile.
    pub(crate) fn has_pending_io(&self) -> bool {
        !self.write_queue.is_empty() ||
            self.writer.in_flight() > 0 ||
            !self.query_queue.is_empty() ||
            self.reader.in_flight() > 0 ||
            self.checkpoint.is_some() ||
            !self.remover.is_idle()
    }

    pub(crate) fn file_io<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        producer: &mut TProducer,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        let writes = if !self.write_queue.is_empty() || self.writer.in_flight() > 0 {
            self.drain_pending_writes(emit)
        } else {
            Ok(())
        };
        if !self.query_queue.is_empty() || self.reader.in_flight() > 0 {
            self.serve_pending_reads(&fork_digest_at, producer, emit);
        }

        self.history.link_buffered_blocks(
            self.head,
            &self.finalized,
            &self.unfinalized,
            &mut self.write_queue,
        );
        self.history.expire(Instant::now());
        if self.head.root != [0u8; 32] && self.write_queue.landing() + self.landing_in_flight == 0 {
            self.history.step(
                self.head,
                !self.sync_target.is_syncing(),
                &self.store_dir,
                &mut self.finalized,
                &self.unfinalized,
                emit,
            );
        }

        if self.write_queue.is_empty() &&
            self.writer.in_flight() == 0 &&
            self.finalized.coverage_changed()
        {
            self.persist_coverage();
        }

        self.step_checkpoint();
        self.remover.step();

        writes
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

pub(super) fn open_file_write<P: AsRef<Path>>(path: P, append: bool) -> Result<File, Error> {
    if append {
        File::options().append(true).create(true).open(path)
    } else {
        File::options().write(true).create(true).truncate(true).open(path)
    }
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
