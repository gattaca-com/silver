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

use silver_common::{
    P2pSend, PeerEvent, RpcOutbound, RpcResponse, RpcResponseOutbound, TCacheProducer, TCacheRead,
    TMultiProducer, metrics::timed, ssz_hash::B256, ssz_view::SignedBeaconBlockView,
};

use super::{PendingWrite, QueryUnit, Store, UnfinalizedBlock};
use crate::{
    StorageCounters,
    store::{
        BLOCK_SLOTS_RETAINED, BLOCKS_DIR, Backfill, COLUMN_SLOTS_RETAINED, COLUMNS_DIR,
        SLOTS_PER_DIR,
    },
    tile::IoEvent,
};

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
    pub(crate) fn file_io<F>(
        &mut self,
        fork_digest: &[u8; 4],
        custody_group_columns: u128,
        producer: &mut TMultiProducer,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        // Pending writes.
        let mut writes = 0;
        while writes < MAX_WRITES_PER_LOOP &&
            let Some(pending) = self.write_queue.front()
        {
            writes += 1;
            tracing::debug!(?pending, "process pending write");
            match pending {
                PendingWrite::Index { block_root, slot } => {
                    let dir = self.block_slot_dir(*slot);
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
                    let dir = self.column_slot_dir(*slot);
                    std::fs::create_dir_all(&dir)?;
                    let path = dir.join(format!("{slot}_{column}.ssz"));
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(path, false)?.write_all(buffer)?;
                    StorageCounters::BackfillColumnsWritten.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::UnfinalizedBlock { slot, parent_root, block_root, ssz } => {
                    let dir = self.unfinalized_dir();
                    let path = dir.join(unfinalized_name(*slot, parent_root, block_root));
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(&path, false)?.write_all(buffer)?;
                    StorageCounters::UnfinalizedBlocksWritten.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::Promote { slot, parent_root, block_root } => {
                    let dir = self.block_slot_dir(*slot);
                    std::fs::create_dir_all(&dir)?;
                    let from = self.unfinalized_dir().join(unfinalized_name(
                        *slot,
                        parent_root,
                        block_root,
                    ));
                    // Rename is atomic; data before index. A NotFound means the
                    // file was already moved/pruned — treat the move as done.
                    match std::fs::rename(&from, dir.join(format!("{slot}_block.ssz"))) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                    let mut record = [0u8; 40];
                    record[..32].copy_from_slice(block_root);
                    record[32..].copy_from_slice(&slot.to_le_bytes());
                    open_file_write(dir.join("block_index.bin"), true)?.write_all(&record)?;
                    StorageCounters::BlocksPromoted.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::Prune { slot, parent_root, block_root } => {
                    let path = self.unfinalized_dir().join(unfinalized_name(
                        *slot,
                        parent_root,
                        block_root,
                    ));
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                    StorageCounters::BlocksPruned.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::UnfinalizedColumn { slot, block_root, column, ssz } => {
                    let dir = self.unfinalized_columns_dir();
                    let path = dir.join(unfinalized_column_name(*slot, block_root, *column));
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(path, false)?.write_all(buffer)?;
                    StorageCounters::UnfinalizedColumnsWritten.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::PromoteColumn { slot, block_root, column } => {
                    let dir = self.column_slot_dir(*slot);
                    std::fs::create_dir_all(&dir)?;
                    let from = self
                        .unfinalized_columns_dir()
                        .join(unfinalized_column_name(*slot, block_root, *column));
                    // Rename is atomic; NotFound means already moved/pruned.
                    match std::fs::rename(&from, dir.join(format!("{slot}_{column}.ssz"))) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                    StorageCounters::ColumnsPromoted.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::PruneColumn { slot, block_root, column } => {
                    let path = self
                        .unfinalized_columns_dir()
                        .join(unfinalized_column_name(*slot, block_root, *column));
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == ErrorKind::NotFound => {}
                        Err(e) => return Err(e),
                    }
                    StorageCounters::ColumnsPruned.inc();
                    self.write_queue.pop_front();
                }
                PendingWrite::TruncateBlockHistory { finalized_slot } => {
                    let earliest_slot = finalized_slot.saturating_sub(BLOCK_SLOTS_RETAINED);
                    let dir = PathBuf::new().join(&self.store_dir).join(BLOCKS_DIR);
                    remove_subdirs(dir, earliest_slot)?;
                    self.write_queue.pop_front();
                }
                PendingWrite::TruncateColumnHistory { finalized_slot } => {
                    let earliest_slot = finalized_slot.saturating_sub(COLUMN_SLOTS_RETAINED);
                    let dir = PathBuf::new().join(&self.store_dir).join(COLUMNS_DIR);
                    remove_subdirs(dir, earliest_slot)?;
                    self.write_queue.pop_front();
                }
                PendingWrite::Backfill { finalized_slot, finalized_root } => {
                    let start_slot = finalized_slot.saturating_sub(BLOCK_SLOTS_RETAINED);
                    let dir = PathBuf::new().join(&self.store_dir).join(BLOCKS_DIR);
                    let range = match earliest_block(dir)? {
                        Some((slot, parent_root)) if slot > start_slot => {
                            Some((start_slot..slot.min(*finalized_slot), parent_root))
                        }
                        None => Some((start_slot..*finalized_slot + 1, *finalized_root)),
                        _ => None,
                    };
                    if let Some((backfill_range, parent_root)) = range {
                        emit(IoEvent::PeerEvent(PeerEvent::EarliestSlot(backfill_range.end)));
                        self.backfill = Some(Backfill::new(backfill_range, parent_root));
                        self.backfill
                            .as_mut()
                            .unwrap()
                            .start(&mut |evt| emit(IoEvent::PeerEvent(evt)));
                    }
                    self.write_queue.pop_front();
                }
                PendingWrite::BackfillBlock { block_root, slot, ssz } => {
                    let dir = self.block_slot_dir(*slot);
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
                    if let Some(backfill) = self.backfill.as_mut() {
                        backfill.block_persisted(
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
            }
        }

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
                    let response = match unit {
                        QueryUnit::Block { .. } | QueryUnit::UnfinalizedBlock { .. } => {
                            RpcResponse::BeaconBlock { fork_digest: *fork_digest, ssz: read }
                        }
                        QueryUnit::Column { .. } | QueryUnit::UnfinalizedColumn { .. } => {
                            RpcResponse::DataColumnSidecar { fork_digest: *fork_digest, ssz: read }
                        }
                    };
                    emit(IoEvent::P2pSend(P2pSend::Rpc(RpcOutbound::Response(
                        RpcResponseOutbound { stream_id: query.stream_id, response },
                    ))));
                    self.query_queue.push_back(query);
                }
                ServeResult::Missing => {
                    self.query_queue.push_back(query);
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

        if let Some(backfill) = self.backfill.as_mut() {
            backfill.tick(&mut |evt| emit(IoEvent::PeerEvent(evt)));
        }
        if self.backfill.as_ref().map(Backfill::is_complete).unwrap_or_default() {
            self.backfill = None;
        }

        Ok(())
    }

    fn unit_path(&self, unit: &QueryUnit) -> PathBuf {
        match unit {
            QueryUnit::Block { slot } => {
                self.block_slot_dir(*slot).join(format!("{slot}_block.ssz"))
            }
            QueryUnit::UnfinalizedBlock { slot, parent_root, block_root } => {
                self.unfinalized_dir().join(unfinalized_name(*slot, parent_root, block_root))
            }
            QueryUnit::Column { slot, column } => {
                self.column_slot_dir(*slot).join(format!("{slot}_{column}.ssz"))
            }
            QueryUnit::UnfinalizedColumn { slot, block_root, column } => self
                .unfinalized_columns_dir()
                .join(unfinalized_column_name(*slot, block_root, *column)),
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

/// Inverse of `unfinalized_name`. `None` on any malformed name so a stray
/// file in `unfinalized/` is skipped rather than aborting the load scan.
pub(super) fn parse_unfinalized_name(name: &str) -> Option<([u8; 32], UnfinalizedBlock)> {
    let stem = name.strip_suffix(".ssz")?;
    let mut parts = stem.split('_');
    let slot: u64 = parts.next()?.parse().ok()?;
    let parent_root = parse_hex32(parts.next()?)?;
    let block_root = parse_hex32(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((block_root, UnfinalizedBlock { slot, parent_root }))
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

fn parse_finalized_block_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".ssz")?;
    let mut parts = stem.split('_');
    let slot: u64 = parts.next()?.parse().ok()?;
    Some(slot)
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
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
        let dir_entry = entry?.file_name();
        if let Ok(dir_number) =
            dir_entry.to_str().ok_or(Error::other("unparsable dir name"))?.parse::<u64>()
        {
            if dir_number + SLOTS_PER_DIR < earliest_slot {
                std::fs::remove_dir_all(dir_entry)?;
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
