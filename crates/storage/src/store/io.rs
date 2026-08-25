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
use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{
    DataKind, Enr, P2pSend, PeerEvent, RpcOutbound, RpcResponse, RpcResponseOutbound,
    TCacheProducer, TCacheRead, TMultiProducer, hex32,
};

use super::{
    Payload, PendingWrite, QueryUnit, Store, backfill::BlockFacts, block_path, column_path,
    envelope_path, slot_dir, unfinalized::PayloadKey,
};
use crate::{StorageCounters, store::SLOTS_PER_DIR, tile::IoEvent};

/// Per-loop op budgets. Disk I/O on regular files is synchronous —
/// O_NONBLOCK has no effect there — so each op blocks the tile until done;
/// these bound the op count (not the wall-clock) per loop iteration.
pub(super) const MAX_WRITES_PER_LOOP: usize = 10;
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
    fn drain_pending_writes<F>(&mut self, emit: &mut F) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        StorageCounters::WriteQueueLength.set(self.write_queue.len() as u64);

        let mut writes = 0;
        while writes < MAX_WRITES_PER_LOOP &&
            let Some(pending) = self.write_queue.pop_front()
        {
            writes += 1;
            tracing::debug!(?pending, "process pending write");
            match pending {
                PendingWrite::Column { slot, column, custody_set_complete, ssz } => {
                    let path = column_path(&self.store_dir, slot, column);
                    std::fs::create_dir_all(path.parent().expect("a slot directory"))?;
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    tracing::info!(?path, len = buffer.len(), "writing data column");
                    open_file_write(path, false)?.write_all(buffer)?;
                    self.finalized.column_landed(slot, column);
                    StorageCounters::BackfillColumnsWritten.inc();
                    if custody_set_complete {
                        emit(IoEvent::Need(self.finalized.persisted(
                            DataKind::Columns,
                            slot,
                            None,
                        )));
                    }
                }
                PendingWrite::WriteUnfinalized { slot, key, ssz } => {
                    let path = self.unfinalized_dir(key.payload()).join(key.unfinalized_name(slot));
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(&path, false)?.write_all(buffer)?;
                    key.payload().record_written();
                }
                PendingWrite::PromoteColumn { slot, block_root, column } => {
                    if self.promote(slot, PayloadKey::Column { block_root, column })? {
                        self.finalized.column_landed(slot, column);
                    }
                }
                PendingWrite::PromoteEnvelope { slot, block_root } => {
                    if self.promote(slot, PayloadKey::Envelope { block_root })? {
                        self.finalized.envelope_landed(slot);
                    }
                }
                PendingWrite::PromoteBlock { block } => {
                    let BlockFacts { slot, block_root, parent_root, .. } = block.facts;
                    if !self.promote(slot, PayloadKey::Block { parent_root, block_root })? {
                        continue;
                    }
                    // Data before index: the record is appended only after the
                    // rename, so a crash never indexes an unmoved block.
                    let dir = slot_dir(&self.store_dir, Payload::Block, slot);
                    self.finalized.landed(&dir, block)?;
                }
                PendingWrite::Prune { slot, key } => {
                    let path = self.unfinalized_dir(key.payload()).join(key.unfinalized_name(slot));
                    remove_tolerant(&path)?;
                    key.payload().record_pruned();
                }
                PendingWrite::TruncateHistory { payload, finalized_slot } => {
                    let epoch = finalized_slot / SLOTS_PER_EPOCH;
                    let earliest_slot =
                        finalized_slot.saturating_sub(payload.slots_retained(&self.spec, epoch));
                    let dir =
                        PathBuf::new().join(&self.store_dir).join(payload.finalized_dir_name());
                    remove_subdirs(dir, earliest_slot)?;
                    self.finalized.truncated(payload, earliest_slot);
                }
                PendingWrite::BackfillBlock { block, ssz } => {
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    let BlockFacts { slot, block_root, parent_root, .. } = block.facts;
                    // A block whose file is indexed is re-served only to link
                    // it; a root indexed in memory but never written is not.
                    if self.finalized.written(&block_root, slot) {
                        self.finalized.relinked(block);
                    } else {
                        let path = block_path(&self.store_dir, slot);
                        let dir = path.parent().expect("a slot directory");
                        std::fs::create_dir_all(dir)?;
                        open_file_write(&path, false)?.write_all(buffer)?;
                        self.finalized.landed(dir, block)?;
                    }
                    self.history.seed_pending(slot, buffer, &self.finalized);
                    let parent_slot = self.finalized.slot_of(&parent_root);
                    emit(IoEvent::Need(self.finalized.persisted(
                        DataKind::Block,
                        slot,
                        parent_slot,
                    )));
                    StorageCounters::BackfillBlocksWritten.inc();
                }
                PendingWrite::BackfillEnvelope { slot, ssz } => {
                    let path = envelope_path(&self.store_dir, slot);
                    std::fs::create_dir_all(path.parent().expect("a slot directory"))?;
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    open_file_write(path, false)?.write_all(buffer)?;
                    self.finalized.envelope_landed(slot);
                    emit(IoEvent::Need(self.finalized.persisted(DataKind::Envelope, slot, None)));
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
        StorageCounters::ReadQueueLength.set(self.query_queue.len() as u64);

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
                emit(IoEvent::PeerEvent(query.outcome(false)));
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
                    query.units_sent += 1;
                    query.first_chunk_at.get_or_insert_with(Instant::now);
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
                    emit(IoEvent::PeerEvent(query.outcome(true)));
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
        producer: &mut TMultiProducer,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(IoEvent),
    {
        if !self.write_queue.is_empty() {
            self.drain_pending_writes(emit)?;
        }
        if !self.query_queue.is_empty() {
            self.serve_pending_reads(&fork_digest_at, producer, emit)?;
        }

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
                self.sync_target.is_following(),
                &self.store_dir,
                &mut self.finalized,
                &self.unfinalized,
                emit,
            );
        }

        if self.write_queue.is_empty() {
            self.finalized.persist(&self.store_dir)?;
        }

        self.step_checkpoint();

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

    fn promote(&mut self, slot: u64, key: PayloadKey) -> Result<bool, Error> {
        let payload = key.payload();
        let to = key.finalized_path(&self.store_dir, slot);
        std::fs::create_dir_all(to.parent().expect("a slot directory"))?;
        let from = self.unfinalized_dir(payload).join(key.unfinalized_name(slot));
        match std::fs::rename(&from, &to) {
            Ok(()) => {
                payload.record_promoted();
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                tracing::warn!(
                    slot,
                    ?payload,
                    "unfinalized file missing at promotion; left missing"
                );
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
}

pub(super) fn open_file_read<P: AsRef<Path>>(path: P) -> Result<File, Error> {
    File::open(path)
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
