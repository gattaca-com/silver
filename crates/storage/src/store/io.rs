//! Disk I/O for the store: drains the queued writes and reads against the
//! on-disk layout (flat finalized store + the `unfinalized/` fork-tree and
//! `unfinalized_columns/` directories), plus the filename and file-open
//! helpers. The path builders (`slot_dir` etc.) stay with `Store` in the
//! parent module, since `load` needs the layout constants too.

use std::{
    fs::File,
    io::{Error, ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use flux_profiler::timed;
use silver_common::{
    Enr, P2pSend, PeerEvent, RpcOutbound, RpcResponse, RpcResponseOutbound, TCacheProducer,
    TCacheRead, TMultiProducer, hex32, merkle::B256, ssz_view::SignedBeaconBlockView,
};

use super::{
    BlockBackfillStage, ColumnScan, Payload, PendingWrite, QueryUnit, Store,
    unfinalized::{PayloadKey, columns_of},
};
use crate::{
    StorageCounters,
    store::{BLOCK_SLOTS_RETAINED, Backfill, COLUMN_SLOTS_RETAINED, ColumnBackfill, SLOTS_PER_DIR},
    tile::IoEvent,
    util,
};

/// Slots scanned per `file_io` turn during the column-backfill disk scan.
/// Each scanned slot may read a block file; bounded so the scan can't extend
/// tile time on a large retention window.
const COLUMN_SCAN_SLOTS_PER_LOOP: u64 = 64;

/// Per-loop op budgets. Disk I/O on regular files is synchronous —
/// O_NONBLOCK has no effect there — so each op blocks the tile until done;
/// these bound the op count (not the wall-clock) per loop iteration.
const MAX_WRITES_PER_LOOP: usize = 10;
const MAX_READS_PER_LOOP: usize = 10;
/// Hard ceiling on read-loop turns per call, independent of
/// `MAX_READS_PER_LOOP`, so a burst of drained (Complete-only) requests
/// can't extend tile time.
const MAX_ITERATIONS_PER_LOOP: usize = 64;

enum ServeResult {
    Sent(TCacheRead),
    Missing,
    ProducerFull,
}

impl Store {
    #[timed]
    fn drain_pending_writes<F>(
        &mut self,
        custody_group_columns: u128,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        let mut writes = 0;
        while writes < MAX_WRITES_PER_LOOP &&
            let Some(pending) = self.write_queue.front()
        {
            writes += 1;
            tracing::debug!(?pending, "process pending write");
            match pending {
                PendingWrite::Index { block_root, slot } => {
                    let dir = self.finalized_slot_dir(Payload::Block, *slot);
                    std::fs::create_dir_all(&dir)?;
                    let path = dir.join("block_index.bin");
                    let mut file = open_file_write(path, true)?;
                    // Pack the 40-byte record and write atomically — a
                    // partial append would misalign every subsequent
                    // fixed-width record on retry.
                    let mut record = [0u8; 40];
                    record[..32].copy_from_slice(block_root);
                    record[32..].copy_from_slice(&slot.to_le_bytes());
                    file.write_all(&record)?;
                    self.write_queue.pop_front();
                }
                PendingWrite::Column { slot, column, ssz } => {
                    let dir = self.finalized_slot_dir(Payload::Column, *slot);
                    std::fs::create_dir_all(&dir)?;
                    let path = dir.join(format!("{slot}_{column}.ssz"));
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(path, false)?.write_all(buffer)?;
                    StorageCounters::BackfillColumnsWritten.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::WriteUnfinalized { slot, key, ssz } => {
                    let path =
                        self.unfinalized_dir(key.payload()).join(key.unfinalized_name(*slot));
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(&path, false)?.write_all(buffer)?;
                    key.payload().record_written();
                    self.write_queue.pop_front();
                }
                PendingWrite::Promote { slot, key } => {
                    let payload = key.payload();
                    let dir = self.finalized_slot_dir(payload, *slot);
                    std::fs::create_dir_all(&dir)?;
                    let from = self.unfinalized_dir(payload).join(key.unfinalized_name(*slot));
                    rename_tolerant(&from, &dir.join(key.finalized_name(*slot)))?;
                    // Data before index: a block's index record is appended only
                    // after the rename, so a crash never indexes an unmoved block.
                    if let PayloadKey::Block { block_root, .. } = key {
                        let mut record = [0u8; 40];
                        record[..32].copy_from_slice(block_root);
                        record[32..].copy_from_slice(&slot.to_le_bytes());
                        open_file_write(dir.join("block_index.bin"), true)?.write_all(&record)?;
                    }
                    payload.record_promoted();
                    self.write_queue.pop_front();
                }
                PendingWrite::Prune { slot, key } => {
                    let path =
                        self.unfinalized_dir(key.payload()).join(key.unfinalized_name(*slot));
                    remove_tolerant(&path)?;
                    key.payload().record_pruned();
                    self.write_queue.pop_front();
                }
                PendingWrite::TruncateHistory { payload, finalized_slot } => {
                    let earliest_slot = finalized_slot.saturating_sub(payload.slots_retained());
                    let dir =
                        PathBuf::new().join(&self.store_dir).join(payload.finalized_dir_name());
                    remove_subdirs(dir, earliest_slot)?;
                    self.write_queue.pop_front();
                }
                PendingWrite::Backfill { finalized_slot, finalized_root } => {
                    let start_slot = finalized_slot.saturating_sub(BLOCK_SLOTS_RETAINED).max(1);
                    let dir = PathBuf::new()
                        .join(&self.store_dir)
                        .join(Payload::Block.finalized_dir_name());
                    let range = match earliest_block(dir)? {
                        Some((slot, parent_root)) if slot > start_slot => {
                            Some((start_slot..slot.min(*finalized_slot), parent_root))
                        }
                        // No blocks on disk: backfill `[start_slot, finalized_slot]`
                        // anchored at the finalized block. Skip when nothing is
                        // finalized yet — the zero `finalized_root` is not a real
                        // block root, so the chain can never link and backfill
                        // would respin on slot 0 (genesis is already the anchor).
                        None if *finalized_root != [0u8; 32] => {
                            Some((start_slot..*finalized_slot + 1, *finalized_root))
                        }
                        _ => None,
                    };
                    if let Some((backfill_range, parent_root)) = range {
                        // Report the gap; the SyncEngine schedules the fetches.
                        emit(IoEvent::PeerEvent(PeerEvent::BackfillState {
                            block_floor: backfill_range.start,
                            earliest_present: backfill_range.end,
                            column_floor: self.column_floor,
                        }));
                        self.backfill = Some(Backfill::new(backfill_range, parent_root));
                        self.block_backfill_stage = BlockBackfillStage::Running;
                    } else {
                        // No block gap — block backfill is trivially done; the
                        // tick's teardown will finalise once columns drain.
                        self.block_backfill_stage = BlockBackfillStage::Done;
                    }
                    self.write_queue.pop_front();
                }
                PendingWrite::ColumnBackfillScan { finalized_slot, finalized_root } => {
                    // Window of slots for which columns are retained/servable.
                    let floor = finalized_slot.saturating_sub(COLUMN_SLOTS_RETAINED).max(1);
                    self.column_floor = floor;
                    self.column_backfill = Some(ColumnBackfill::new(floor..*finalized_slot + 1));
                    self.column_scan = Some(ColumnScan { cursor: *finalized_slot, floor });
                    self.block_backfill_stage = BlockBackfillStage::AwaitingColumns {
                        finalized_slot: *finalized_slot,
                        finalized_root: *finalized_root,
                    };
                    // Conservative initial claim: only the recent region until the
                    // whole window is backfilled (then we drop to `column_floor`).
                    emit(IoEvent::PeerEvent(PeerEvent::EarliestSlot(*finalized_slot)));
                    self.write_queue.pop_front();
                }
                PendingWrite::BackfillBlock { block_root, slot, ssz } => {
                    let dir = self.finalized_slot_dir(Payload::Block, *slot);
                    std::fs::create_dir_all(&dir)?;
                    let path = dir.join(format!("{slot}_block.ssz"));

                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(path, false)?.write_all(buffer)?;
                    if !self.root_index.contains_key(block_root) {
                        let mut record = [0u8; 40];
                        record[..32].copy_from_slice(block_root);
                        record[32..].copy_from_slice(&slot.to_le_bytes());
                        open_file_write(dir.join("block_index.bin"), true)?.write_all(&record)?;
                        self.root_index.insert(*block_root, *slot);
                    }
                    // Set 2: a block fetched by block backfill that falls in the
                    // column window needs its columns too (the pre-block disk
                    // scan couldn't see it — it wasn't on disk yet). Feed the
                    // still-live column backfill. Just-written ⇒ no columns on
                    // disk yet, so the full custody set is missing.
                    if SignedBeaconBlockView::has_data_columns_fulu(buffer) &&
                        let Some(cb) = self.column_backfill.as_mut()
                    {
                        cb.seed_block(
                            *block_root,
                            *slot,
                            buffer,
                            custody_group_columns,
                            &mut |evt| emit(IoEvent::PeerEvent(evt)),
                        );
                    }
                    StorageCounters::BackfillBlocksWritten.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::PersistPeer { enr } => {
                    let peer_file = self.peers_dir().join(format!("{}.enr", enr.public_key()));
                    open_file_write(peer_file, false)?.write_all(enr.to_string().as_bytes())?;
                    self.write_queue.pop_front();
                }
                PendingWrite::LoadPeers => {
                    self.write_queue.pop_front();
                    let peer_files = std::fs::read_dir(self.peers_dir())?;
                    for entry in peer_files {
                        if let Ok(entry) = entry &&
                            entry.metadata()?.is_file()
                        {
                            let mut enr_string = String::new();
                            open_file_read(entry.path())?.read_to_string(&mut enr_string)?;
                            let enr = Enr::from_base64(enr_string.as_str(), false)
                                .map_err(Error::other)?;
                            emit(IoEvent::PeerEvent(PeerEvent::DiscNodeFound {
                                enr,
                                reload: true,
                            }));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[timed]
    fn serve_pending_reads<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        producer: &mut TMultiProducer,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        // Pending reads. Round-robin across in-flight requests: serve one
        // chunk, then rotate the request to the back so a large range can't
        // block other peers' queries (head-of-line fairness). `Complete` is
        // emitted once a request's units drain. `MAX_ITERATIONS_PER_LOOP`
        // bounds drained-request churn so a burst of empty requests can't
        // extend tile time.
        let mut reads = 0;
        let mut iters = 0;
        while iters < MAX_ITERATIONS_PER_LOOP && reads < MAX_READS_PER_LOOP {
            iters += 1;
            let Some(mut query) = self.query_queue.pop_front() else {
                break;
            };
            let Some(unit) = query.units.pop_front() else {
                // Request fully served — terminate the stream and drop it.
                emit(IoEvent::P2pSend(P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                    stream_id: query.stream_id,
                    response: RpcResponse::Complete,
                }))));
                continue;
            };
            reads += 1;
            let path = self.unit_path(&unit);
            match Self::serve_file(&path, producer)? {
                ServeResult::Sent(read) => {
                    // Context fork-digest for the served object's own slot's fork
                    // (a request can span a fork boundary).
                    let fork_digest = fork_digest_at(unit.slot());
                    let response = match unit {
                        QueryUnit::Block { .. } | QueryUnit::UnfinalizedBlock { .. } => {
                            RpcResponse::BeaconBlock { fork_digest, ssz: read }
                        }
                        QueryUnit::Column { .. } | QueryUnit::UnfinalizedColumn { .. } => {
                            RpcResponse::DataColumnSidecar { fork_digest, ssz: read }
                        }
                        QueryUnit::Envelope { .. } | QueryUnit::UnfinalizedEnvelope { .. } => {
                            RpcResponse::ExecutionPayloadEnvelope { fork_digest, ssz: read }
                        }
                    };
                    emit(IoEvent::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                        RpcResponseOutbound { stream_id: query.stream_id, response },
                    ))));
                    self.query_queue.push_back(query);
                }
                ServeResult::Missing => {
                    let error = "resource unavailable".as_bytes();
                    let mut msg = [0u8; 256];
                    msg[..error.len()].copy_from_slice(error);
                    let response = RpcResponse::Error { error: 3, msg, len: error.len() };
                    emit(IoEvent::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                        RpcResponseOutbound { stream_id: query.stream_id, response },
                    ))));
                }
                ServeResult::ProducerFull => {
                    // Tcache full — un-consume and retry this request first
                    // next loop; trying others would fail too.
                    query.units.push_front(unit);
                    self.query_queue.push_front(query);
                    break;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn file_io<F>(
        &mut self,
        fork_digest_at: impl Fn(u64) -> [u8; 4],
        custody_group_columns: u128,
        producer: &mut TMultiProducer,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        if !self.write_queue.is_empty() {
            self.drain_pending_writes(custody_group_columns, emit)?;
        }
        if !self.query_queue.is_empty() {
            self.serve_pending_reads(&fork_digest_at, producer, emit)?;
        }

        // Column backfill runs first: advance the disk scan (set 1), reporting
        // missing columns via `ColumnNeed`. Re-request/retry is the engine's.
        if self.column_scan.is_some() {
            self.scan_columns_step(custody_group_columns, &mut |evt| emit(IoEvent::PeerEvent(evt)));
        }

        // Promote to block backfill once the disk scan finished and its set-1
        // column requests drained — block backfill then feeds set 2 back in.
        let scan_done = self.column_scan.is_none();
        let columns_drained =
            self.column_backfill.as_ref().map(ColumnBackfill::is_complete).unwrap_or(true);
        if let BlockBackfillStage::AwaitingColumns { finalized_slot, finalized_root } =
            self.block_backfill_stage &&
            scan_done &&
            columns_drained
        {
            self.write_queue.push_back(PendingWrite::Backfill { finalized_slot, finalized_root });
            self.block_backfill_stage = BlockBackfillStage::Queued;
        }

        if self.backfill.as_ref().map(Backfill::is_complete).unwrap_or_default() {
            self.backfill = None;
            self.block_backfill_stage = BlockBackfillStage::Done;
        }

        // Teardown: both phases finished AND every window column on disk. Only
        // now drop the earliest-available claim to the column floor.
        if matches!(self.block_backfill_stage, BlockBackfillStage::Done) &&
            self.column_backfill.as_ref().map(ColumnBackfill::is_complete).unwrap_or(true)
        {
            if self.column_backfill.take().is_some() {
                emit(IoEvent::PeerEvent(PeerEvent::EarliestSlot(self.column_floor)));
            }
            self.block_backfill_stage = BlockBackfillStage::Idle;
        }

        self.step_checkpoint();

        Ok(())
    }

    /// Advance the column-backfill disk scan by up to
    /// `COLUMN_SCAN_SLOTS_PER_LOOP` slots, descending from the finalized slot.
    /// For each persisted block carrying blob commitments whose custody columns
    /// aren't all on disk, seed `column_backfill` with the missing set. Marks
    /// the scan complete on reaching the retention floor.
    #[timed]
    fn scan_columns_step<F>(&mut self, custody: u128, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let Some(mut scan) = self.column_scan.take() else {
            return;
        };
        let mut budget = COLUMN_SCAN_SLOTS_PER_LOOP;
        // floor is inclusive; `saturating_sub` keeps the cursor from underflowing
        // below it (floor ≥ 1), so the loop exits cleanly at `cursor < floor`.
        while budget > 0 && scan.cursor >= scan.floor {
            let slot = scan.cursor;
            scan.cursor = scan.cursor.saturating_sub(1);
            budget -= 1;

            let path =
                self.finalized_slot_dir(Payload::Block, slot).join(format!("{slot}_block.ssz"));
            let Ok(ssz) = std::fs::read(&path) else {
                continue; // no block persisted at this slot
            };
            if !SignedBeaconBlockView::check_size(&ssz) {
                tracing::error!(?path, "persisted block ssz has invalid size");
                continue;
            }
            if !SignedBeaconBlockView::has_data_columns_fulu(&ssz) {
                continue;
            }
            let missing = custody & !self.present_columns(slot, custody);
            if missing == 0 {
                continue;
            }
            if let Some(cb) = self.column_backfill.as_mut() {
                let block_root = util::block_root_fulu(&ssz);
                cb.seed_block(block_root, slot, &ssz, missing, emit);
            }
        }

        if scan.cursor >= scan.floor {
            self.column_scan = Some(scan); // budget exhausted; resume next loop
        } else if let Some(cb) = self.column_backfill.as_mut() {
            cb.mark_scan_complete();
        }
    }

    /// Bitmask of custody columns already on disk for `slot` (flat store).
    fn present_columns(&self, slot: u64, custody: u128) -> u128 {
        let dir = self.finalized_slot_dir(Payload::Column, slot);
        let mut present = 0u128;
        for c in columns_of(custody) {
            if dir.join(format!("{slot}_{c}.ssz")).exists() {
                present |= 1u128 << c;
            }
        }
        present
    }

    fn unit_path(&self, unit: &QueryUnit) -> PathBuf {
        match unit {
            QueryUnit::Block { slot } => {
                self.finalized_slot_dir(Payload::Block, *slot).join(format!("{slot}_block.ssz"))
            }
            QueryUnit::UnfinalizedBlock { slot, parent_root, block_root } => self
                .unfinalized_dir(Payload::Block)
                .join(unfinalized_name(*slot, parent_root, block_root)),
            QueryUnit::Column { slot, column } => {
                self.finalized_slot_dir(Payload::Column, *slot).join(format!("{slot}_{column}.ssz"))
            }
            QueryUnit::UnfinalizedColumn { slot, block_root, column } => self
                .unfinalized_dir(Payload::Column)
                .join(unfinalized_column_name(*slot, block_root, *column)),
            QueryUnit::Envelope { slot } => self
                .finalized_slot_dir(Payload::Envelope, *slot)
                .join(format!("{slot}_envelope.ssz")),
            QueryUnit::UnfinalizedEnvelope { slot, block_root } => self
                .unfinalized_dir(Payload::Envelope)
                .join(unfinalized_envelope_name(*slot, block_root)),
        }
    }

    /// Read the whole file at `path` into a freshly-reserved tcache slot.
    /// `Missing` if the file doesn't exist (skip the query), `ProducerFull`
    /// if the tcache has no room (retry next loop).
    fn serve_file(path: &Path, producer: &mut TMultiProducer) -> Result<ServeResult, Error> {
        let mut file = match open_file_read(path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(ServeResult::Missing),
            Err(e) => return Err(e),
        };
        let ssz_len = file.metadata()?.len() as usize;
        let Some(mut reservation) = producer.reserve(ssz_len, true) else {
            return Ok(ServeResult::ProducerFull);
        };
        file.read_exact(&mut reservation.buffer()?[..ssz_len])?;
        reservation.increment_offset(ssz_len);
        Ok(ServeResult::Sent(reservation.read()))
    }
}

pub(super) fn open_file_read<P: AsRef<Path>>(path: P) -> Result<File, Error> {
    File::open(path)
}

/// Rename tolerating an already-moved/pruned source: a `NotFound` means the
/// promote raced a prior move/prune and is treated as done. Rename is atomic.
fn rename_tolerant(from: &Path, to: &Path) -> Result<(), Error> {
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Unlink tolerating an already-removed target (idempotent prune).
fn remove_tolerant(path: &Path) -> Result<(), Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

fn parse_finalized_block_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".ssz")?;
    let mut parts = stem.split('_');
    let slot: u64 = parts.next()?.parse().ok()?;
    Some(slot)
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

fn remove_subdirs<P: AsRef<Path>>(dir: P, earliest_slot: u64) -> Result<(), Error> {
    let contents = std::fs::read_dir(dir)?;
    for entry in contents {
        let entry = entry?;
        let dir_entry = entry.file_name();
        if let Ok(dir_number) =
            dir_entry.to_str().ok_or(Error::other("unparsable dir name"))?.parse::<u64>()
        {
            if dir_number + SLOTS_PER_DIR < earliest_slot {
                // `entry.path()` is the full path; `file_name()` alone would
                // resolve relative to CWD, not `dir`.
                std::fs::remove_dir_all(entry.path())?;
            }
        }
    }
    Ok(())
}

/// Returns the slot number and parent_root of the earliest block in on-disk
/// history.
fn earliest_block<P: AsRef<Path>>(dir: P) -> Result<Option<(u64, B256)>, Error> {
    let contents = std::fs::read_dir(&dir)?;
    let Some(min_dir) = contents
        .filter_map(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().into_string().ok())
                .and_then(|s| s.parse::<u64>().ok())
        })
        .min()
    else {
        return Ok(None);
    };

    let sub_dir = PathBuf::new().join(&dir).join(min_dir.to_string());
    let sub_dir_contents = std::fs::read_dir(&sub_dir)?;
    let Some(min_file) = sub_dir_contents
        .filter_map(|entry| {
            entry.ok().and_then(|e| e.file_name().to_str().and_then(parse_finalized_block_name))
        })
        .min()
    else {
        return Ok(None);
    };

    let block_file = sub_dir.join(format!("{min_file}_block.ssz"));
    let ssz = std::fs::read(&block_file)?; // one time allocation
    let parent_root = SignedBeaconBlockView::parent_root(&ssz);

    Ok(Some((min_file, *parent_root)))
}
