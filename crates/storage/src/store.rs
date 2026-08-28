use std::{
    collections::{VecDeque, hash_map::Entry},
    io::{Error, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use flux_profiler::timed;
use fxhash::FxHashMap;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    DataKind, Enr, P2pStreamId, PeerEvent, RpcRequestInbound, RpcSeverity, SyncNeed, SyncUpdate,
    TCacheRead, TRandomAccess, TRead,
    merkle::B256,
    ssz_view::{
        BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView,
        DataColumnSidecarsByRangeRequestView, DataColumnsByRootIdentifierView,
        DataColumnsByRootRequestView, ExecutionPayloadEnvelopesByRangeRequestView,
        ExecutionPayloadEnvelopesByRootRequestView, MAX_REQUEST_BLOCKS_DENEB,
    },
};

use crate::StorageCounters;

mod backfill;
mod checkpoint;
mod history;
mod io;
mod unfinalized;

use backfill::VerifiedColumns;
use checkpoint::CheckpointWriter;
pub use checkpoint::latest_local_checkpoint;
use history::HistoryBackfill;
use unfinalized::{PayloadKey, UnfinalizedBlocks, UnfinalizedColumns, UnfinalizedEnvelopes};

/// `DataColumnSidecarsByRange` is bounded by
/// `count * NUMBER_OF_COLUMNS <= MAX_REQUEST_DATA_COLUMN_SIDECARS`
/// (16384), i.e. `count <= MAX_REQUEST_BLOCKS_DENEB`.
const MAX_REQUEST_BLOCKS: u64 = MAX_REQUEST_BLOCKS_DENEB as u64;

/// Cap on concurrent in-flight read requests. Past this, a new request is
/// answered with an empty (Complete-only) response — sheds load under a peer
/// flood and bounds the count of unit-bearing `query_queue` entries (each
/// entry's `units` is already capped by the range limits above).
const MAX_INFLIGHT_QUERIES: usize = 256;

/// Slots per on-disk group directory (`slot & !(SLOTS_PER_DIR - 1)`).
/// 128 keeps per-directory file counts (~128 slots × (block + columns))
/// manageable for the startup index scan.
const SLOTS_PER_DIR: u64 = 128;

const PEERS_DIR: &str = "peers";

const COLUMN_SLOTS_RETAINED: u64 = 4096 * 32;

const ALL_PAYLOADS: [Payload; 3] = [Payload::Block, Payload::Column, Payload::Envelope];

#[derive(Clone, Copy, Debug)]
pub(super) enum Payload {
    Block,
    Column,
    Envelope,
}

impl Payload {
    fn finalized_dir_name(self) -> &'static str {
        match self {
            Payload::Block => UnfinalizedBlocks::FINALIZED_DIR,
            Payload::Column => UnfinalizedColumns::FINALIZED_DIR,
            Payload::Envelope => UnfinalizedEnvelopes::FINALIZED_DIR,
        }
    }

    fn unfinalized_dir_name(self) -> &'static str {
        match self {
            Payload::Block => UnfinalizedBlocks::UNFINALIZED_DIR,
            Payload::Column => UnfinalizedColumns::UNFINALIZED_DIR,
            Payload::Envelope => UnfinalizedEnvelopes::UNFINALIZED_DIR,
        }
    }

    fn slots_retained(self, spec: &SpecConfig, epoch: u64) -> u64 {
        match self {
            Payload::Block | Payload::Envelope => {
                spec.min_epochs_for_block_requests(epoch) * SLOTS_PER_EPOCH
            }
            Payload::Column => COLUMN_SLOTS_RETAINED,
        }
    }

    fn record_written(self) {
        match self {
            Payload::Block => StorageCounters::UnfinalizedBlocksWritten.inc(),
            Payload::Column => StorageCounters::UnfinalizedColumnsWritten.inc(),
            Payload::Envelope => {}
        }
    }

    fn record_promoted(self) {
        match self {
            Payload::Block => StorageCounters::BlocksPromoted.inc(),
            Payload::Column => StorageCounters::ColumnsPromoted.inc(),
            Payload::Envelope => {}
        }
    }

    fn record_pruned(self) {
        match self {
            Payload::Block => StorageCounters::BlocksPruned.inc(),
            Payload::Column => StorageCounters::ColumnsPruned.inc(),
            Payload::Envelope => {}
        }
    }
}

pub(super) struct ReplayEntry {
    pub(super) slot: u64,
    pub(super) block: PathBuf,
    pub(super) columns_on_disk: bool,
    pub(super) envelope: Option<PathBuf>,
}

#[derive(Debug)]
enum PendingWrite {
    Index {
        block_root: [u8; 32],
        slot: u64,
    },
    Column {
        slot: u64,
        column: u64,
        /// Set for backfill completions.
        block_root: Option<[u8; 32]>,
        ssz: TRead,
    },
    /// New unfinalized payload → `<unfinalized dir>/<key>.ssz`.
    WriteUnfinalized {
        slot: u64,
        key: PayloadKey,
        ssz: TRead,
    },
    /// Backfilled payload envelope → the flat slot store.
    BackfillEnvelope {
        slot: u64,
        ssz: TRead,
    },
    /// Finalized: rename the unfinalized file into the flat slot store (a block
    /// additionally appends its index record).
    Promote {
        slot: u64,
        key: PayloadKey,
    },
    /// Orphaned fork below finality: unlink the unfinalized file.
    Prune {
        slot: u64,
        key: PayloadKey,
    },
    TruncateHistory {
        payload: Payload,
        finalized_slot: u64,
    },
    /// Size the block-backfill gap from what is on disk and start the walk.
    StartBlockBackfill {
        finalized_slot: u64,
        finalized_root: B256,
    },
    BackfillBlock {
        block_root: B256,
        slot: u64,
        ssz: TRead,
    },
    /// Bootstrap historical backfill: size the column and envelope windows,
    /// start the disk scan, and stage block backfill behind it. One-shot, at
    /// the first `Following` transition.
    StartBackfill {
        finalized_slot: u64,
        finalized_root: B256,
    },
    PersistPeer {
        enr: Enr,
    },
    LoadPeers,
}

/// One served file = one response chunk. The unit's resolution (canonical
/// vs flat store) is decided up-front in `rpc_request`.
#[derive(Debug)]
enum QueryUnit {
    Block { slot: u64 },
    UnfinalizedBlock { slot: u64, parent_root: [u8; 32], block_root: [u8; 32] },
    Column { slot: u64, column: u64 },
    UnfinalizedColumn { slot: u64, block_root: [u8; 32], column: u64 },
    Envelope { slot: u64 },
    UnfinalizedEnvelope { slot: u64, block_root: [u8; 32] },
}

impl QueryUnit {
    fn slot(&self) -> u64 {
        match self {
            QueryUnit::Block { slot } |
            QueryUnit::UnfinalizedBlock { slot, .. } |
            QueryUnit::Column { slot, .. } |
            QueryUnit::UnfinalizedColumn { slot, .. } |
            QueryUnit::Envelope { slot } |
            QueryUnit::UnfinalizedEnvelope { slot, .. } => *slot,
        }
    }
}

/// An in-flight read request: the stream and the ordered chunks still to
/// serve for it. `file_io` serves one unit per turn then rotates the
/// request to the back of `query_queue` (head-of-line fairness across
/// streams), emitting `Complete` once `units` drains.
#[derive(Debug)]
struct PendingQuery {
    stream_id: P2pStreamId,
    units: VecDeque<QueryUnit>,
    received_at: Instant,
    first_chunk_at: Option<Instant>,
    units_total: u32,
    units_sent: u32,
}

impl PendingQuery {
    fn new(stream_id: P2pStreamId, units: VecDeque<QueryUnit>) -> Self {
        Self {
            stream_id,
            received_at: Instant::now(),
            first_chunk_at: None,
            units_total: units.len() as u32,
            units_sent: 0,
            units,
        }
    }

    /// The `RpcServeOutcome` for this query terminating now.
    fn outcome(&self, missing: bool) -> PeerEvent {
        PeerEvent::RpcServeOutcome {
            p2p_peer: self.stream_id.peer(),
            protocol: self.stream_id.protocol(),
            units_total: self.units_total,
            units_sent: self.units_sent,
            missing,
            first_chunk_ms: self
                .first_chunk_at
                .map(|t| t.duration_since(self.received_at).as_millis() as u64)
                .unwrap_or(0),
            elapsed_ms: self.received_at.elapsed().as_millis() as u64,
        }
    }
}

/// Unified blocks and data columns disk store.
pub(super) struct Store {
    spec: Arc<SpecConfig>,
    store_dir: String,
    // Finalized block index: block_root → slot, persisted in block_index.bin.
    root_index: FxHashMap<[u8; 32], u64>,

    unfinalized: UnfinalizedBlocks,
    unfinalized_columns: UnfinalizedColumns,
    unfinalized_envelopes: UnfinalizedEnvelopes,
    // Latest fork-choice head + finalization watermark from Status.
    head_root: [u8; 32],
    head_slot: u64,
    finalized_slot: u64,
    finalized_root: [u8; 32],
    // Historical backfill.
    sync_target: SyncUpdate,
    history: HistoryBackfill,
    // Slot of the newest finalized-state checkpoint committed to disk.
    last_persisted_finalized_slot: u64,
    // In-flight streamed checkpoint, advanced one section per `file_io` turn.
    checkpoint: Option<CheckpointWriter>,

    write_queue: VecDeque<PendingWrite>,
    query_queue: VecDeque<PendingQuery>,
}

impl Store {
    pub(super) fn load(store_dir: String, spec: Arc<SpecConfig>) -> Result<Self, Error> {
        let mut root_index = FxHashMap::default();

        // Try to create dirs if they do not exist.
        if !std::fs::exists(&store_dir)? {
            tracing::info!(store_dir, "create data store");
            std::fs::create_dir_all(&store_dir)?;
        }

        for payload in ALL_PAYLOADS {
            ensure_dir(&store_dir, payload.finalized_dir_name())?;
        }
        ensure_dir(&store_dir, PEERS_DIR)?;
        let blocks_dir = Path::new(&store_dir).join(UnfinalizedBlocks::FINALIZED_DIR);

        for sub_dir in std::fs::read_dir(&blocks_dir)? {
            let index_path = sub_dir?.path().join("block_index.bin");
            if let Ok(mut index_file) = io::open_file_read(index_path) {
                let mut buffer = [0u8; 40];
                while index_file.read_exact(&mut buffer).is_ok() {
                    let block_root: [u8; 32] = buffer[..32].try_into().unwrap();
                    let slot = u64::from_le_bytes(buffer[32..].try_into().unwrap());
                    root_index.insert(block_root, slot);
                }
            }
        }

        let unfinalized = UnfinalizedBlocks::load(&store_dir)?;
        let unfinalized_columns = UnfinalizedColumns::load(&store_dir)?;
        let unfinalized_envelopes = UnfinalizedEnvelopes::load(&store_dir)?;

        // Finalized-state checkpoints: drop incomplete dirs, prune to the
        // newest N, and anchor `last_persisted` at the newest committed slot.
        let last_persisted_finalized_slot = checkpoint::init_checkpoints_dir(&store_dir)?;

        Ok(Self {
            spec,
            store_dir,
            root_index,
            unfinalized,
            unfinalized_columns,
            unfinalized_envelopes,
            head_root: [0u8; 32],
            head_slot: 0,
            finalized_slot: 0,
            finalized_root: [0u8; 32],
            history: HistoryBackfill::default(),
            sync_target: SyncUpdate::default(),
            last_persisted_finalized_slot,
            checkpoint: None,
            write_queue: Default::default(),
            query_queue: Default::default(),
        })
    }

    pub(super) fn add_data_column(
        &mut self,
        block_root: [u8; 32],
        column_index: u64,
        sidecar_ssz: TRead,
        slot: u64,
        complete: bool,
    ) {
        if slot <= self.finalized_slot {
            // Finalized history (backfill): flat store keyed by slot.
            self.write_queue.push_back(PendingWrite::Column {
                slot,
                column: column_index,
                block_root: complete.then_some(block_root),
                ssz: sidecar_ssz,
            });
            if let Entry::Vacant(e) = self.root_index.entry(block_root) {
                e.insert(slot);
                self.write_queue.push_back(PendingWrite::Index { block_root, slot });
            }
        } else {
            // Unfinalized: keyed by owning block_root, promoted/pruned with
            // the block. The caller (tile) has already validated the sidecar.
            if self.unfinalized_columns.record(block_root, slot, column_index) {
                self.write_queue.push_back(PendingWrite::WriteUnfinalized {
                    slot,
                    key: PayloadKey::Column { block_root, column: column_index },
                    ssz: sidecar_ssz,
                });
            }
        }
    }

    #[cfg(test)]
    fn earliest_servable(&self, custody_columns: u128) -> u64 {
        self.history.earliest_servable(custody_columns, &self.spec, self.finalized_slot)
    }

    /// The claim this tile makes about the history it can serve, when it moved.
    pub(super) fn take_earliest_slot_claim(&mut self, custody_columns: u128) -> Option<u64> {
        if self.head_root == [0u8; 32] {
            return None;
        }
        self.history.take_claim(custody_columns, &self.spec, self.finalized_slot)
    }

    pub(super) fn is_envelope_owed(&self, block_root: &[u8; 32], slot: u64) -> bool {
        slot > self.finalized_slot && self.unfinalized_envelopes.slot_of(block_root).is_none()
    }

    pub(super) fn add_envelope(&mut self, block_root: [u8; 32], envelope_ssz: TRead) {
        let slot = match self.unfinalized.get(&block_root) {
            Some((slot, _)) => slot,
            None => match self.root_index.get(&block_root) {
                Some(&slot) => slot,
                None => {
                    tracing::debug!(
                        block_root = hex::encode(block_root),
                        "envelope for unknown block; dropping"
                    );
                    return;
                }
            },
        };
        if slot <= self.finalized_slot {
            return;
        }

        if self.unfinalized_envelopes.insert(block_root, slot) {
            self.write_queue.push_back(PendingWrite::WriteUnfinalized {
                slot,
                key: PayloadKey::Envelope { block_root },
                ssz: envelope_ssz,
            });
        }
    }

    #[timed]
    pub(super) fn add_block(
        &mut self,
        block_root: [u8; 32],
        block_ssz: TRead,
        slot: u64,
        parent_root: [u8; 32],
    ) {
        // Guard (not a canonicity decision): at/below finality the chain is
        // settled — finalized blocks already live in the flat store and
        // anything else is an orphan. Dedup repeats. Canonicity is resolved
        // by the head walk at query time and by finalization promotion.
        if slot <= self.finalized_slot || self.has_block(&block_root) {
            return;
        }
        self.unfinalized.insert(block_root, slot, parent_root);
        self.write_queue.push_back(PendingWrite::WriteUnfinalized {
            slot,
            key: PayloadKey::Block { parent_root, block_root },
            ssz: block_ssz,
        });
    }

    pub(super) fn backfill_block(&mut self, ssz: TRead) {
        self.history.add_block(ssz, &mut self.write_queue);
    }

    pub(super) fn backfill_envelope<F>(&mut self, signed: TRead, emit: &mut F)
    where
        F: FnMut(SyncNeed),
    {
        if let Some((block_root, slot)) = self.history.add_envelope(&signed, &self.root_index) {
            self.write_queue.push_back(PendingWrite::BackfillEnvelope { slot, ssz: signed });
            emit(SyncNeed::Arrived { root: block_root, slot, kind: DataKind::Envelope });
        }
    }

    pub(super) fn backfill_data_column<F>(
        &mut self,
        sidecar: TRead,
        peer: usize,
        now: Instant,
        emit: &mut F,
    ) where
        F: FnMut(PeerEvent),
    {
        let (verified, rejected) = self.history.add_sidecar(sidecar, peer, now);
        for bad in rejected {
            tracing::warn!(
                peer = bad.peer,
                column_index = bad.column_index,
                "backfill sidecar rejected"
            );
            emit(PeerEvent::RpcMisbehaviour { p2p_peer: bad.peer, severity: RpcSeverity::Fatal });
        }
        if let Some(VerifiedColumns { block_root, slot, sidecars }) = verified {
            let last = sidecars.len().saturating_sub(1);
            for (i, parked) in sidecars.into_iter().enumerate() {
                self.add_data_column(block_root, parked.column_index, parked.ssz, slot, i == last);
            }
        }
    }

    pub(super) fn expire_incomplete_backfill_columns(&mut self, now: Instant) {
        self.history.expire_incomplete_columns(now);
    }

    pub(super) fn sync_update(&mut self, sync_update: SyncUpdate) {
        self.sync_target = sync_update;
        if sync_update.is_following() && self.history.check_disk_once() {
            self.write_queue.push_back(PendingWrite::StartBackfill {
                finalized_slot: self.finalized_slot,
                finalized_root: self.finalized_root,
            });
        }
    }

    /// Update fork-choice head and finalization watermark from a Status. On a
    /// finalization advance, promote the finalized chain (blocks and their
    /// columns) to the flat store and prune orphaned forks.
    pub(super) fn update_head(
        &mut self,
        head_slot: u64,
        head_root: [u8; 32],
        finalized_slot: u64,
        finalized_root: [u8; 32],
    ) {
        self.head_slot = head_slot;
        self.head_root = head_root;
        tracing::debug!(head_slot, head_root = hex::encode(head_root), "storage head update");

        if finalized_slot <= self.finalized_slot {
            return;
        }

        self.finalized_slot = finalized_slot;
        self.finalized_root = finalized_root;

        // Promote the finalized chain: walk ancestors of `finalized_root`
        // through the tree, moving each block and its columns to the flat
        // store. `remove` strips the promoted chain from `unfinalized`, so the
        // prune pass below sees only orphaned forks.
        //
        // The in-memory maps update here but the on-disk rename runs later in
        // `file_io`. A by-root/by-range query for a just-finalized root that
        // was queued (as an `Unfinalized*` read) before this point reads the
        // now-renamed unfinalized path → Missing → serves nothing for one loop;
        // the requester re-requests and the next pass serves it from the flat
        // store. We deliberately do NOT fall back to the flat slot path on
        // Missing: a pruned orphan's by-root query would then read the
        // canonical block's file and serve the wrong block's data under that
        // root. Missing-skip keeps the fork-correctness guarantee intact.
        let mut root = finalized_root;
        while let Some((slot, parent_root)) = self.unfinalized.remove(&root) {
            self.root_index.insert(root, slot);
            self.write_queue.push_back(PendingWrite::Promote {
                slot,
                key: PayloadKey::Block { parent_root, block_root: root },
            });
            self.unfinalized_columns.promote(root, &mut self.write_queue);
            self.unfinalized_envelopes.promote(root, &mut self.write_queue);
            root = parent_root;
        }

        self.unfinalized.prune_below(finalized_slot, &mut self.write_queue);
        self.unfinalized_columns.prune_below(finalized_slot, &mut self.write_queue);
        self.unfinalized_envelopes.prune_below(finalized_slot, &mut self.write_queue);

        for payload in ALL_PAYLOADS {
            self.write_queue.push_back(PendingWrite::TruncateHistory { payload, finalized_slot });
        }
    }

    /// BS-accepted block, any fork: every `PersistBlock` lands in
    /// `unfinalized` (or `root_index` once promoted), so membership here is
    /// "validated", independent of the current head chain.
    pub(super) fn has_block(&self, root: &[u8; 32]) -> bool {
        self.unfinalized.contains(root) || self.root_index.contains_key(root)
    }

    pub(super) fn store_dir(&self) -> &str {
        &self.store_dir
    }

    pub(super) fn replay_entries(&self, custody: u128) -> Vec<ReplayEntry> {
        let checkpoint_slot = self.last_persisted_finalized_slot;
        let mut entries = Vec::with_capacity(self.unfinalized.len());
        for (block_root, slot, parent_root) in self.unfinalized.iter() {
            if slot > checkpoint_slot {
                let block = self.unfinalized_dir(Payload::Block).join(io::unfinalized_name(
                    slot,
                    &parent_root,
                    block_root,
                ));
                let envelope = self.unfinalized_envelopes.slot_of(block_root).map(|slot| {
                    self.unfinalized_dir(Payload::Envelope)
                        .join(io::unfinalized_envelope_name(slot, block_root))
                });

                entries.push(ReplayEntry {
                    slot,
                    block,
                    columns_on_disk: self.unfinalized_columns.has_full_custody(block_root, custody),
                    envelope,
                });
            }
        }
        for &slot in self.root_index.values() {
            if slot > checkpoint_slot {
                let block =
                    self.finalized_slot_dir(Payload::Block, slot).join(format!("{slot}_block.ssz"));

                // Promoted envelopes are keyed by slot, so presence on disk is
                // the whole test
                let envelope = (slot >= self.spec.gloas_fork_slot())
                    .then(|| {
                        self.finalized_slot_dir(Payload::Envelope, slot)
                            .join(format!("{slot}_envelope.ssz"))
                    })
                    .filter(|path| path.exists());

                entries.push(ReplayEntry { slot, block, columns_on_disk: true, envelope });
            }
        }
        entries
    }

    #[timed]
    pub(super) fn rpc_request(
        &mut self,
        rpc_consumer: &mut TRandomAccess,
        request: RpcRequestInbound,
    ) {
        let stream_id = request.stream_id;
        // Shed load past the in-flight cap: an empty `units` drains straight to
        // a `Complete`, giving the peer a clean empty response without letting
        // the unit-bearing `query_queue` entries grow without bound.

        // TODO should not return 'Complete' should return rate limit error
        if self.query_queue.len() >= MAX_INFLIGHT_QUERIES {
            tracing::warn!(?stream_id, "queries at capacity");
            self.query_queue.push_back(PendingQuery::new(stream_id, VecDeque::new()));
            return;
        }

        // Resolve each requested chunk to a `QueryUnit` up-front (canonical vs
        // flat decided against the head snapshot). `file_io` then serves them
        // one at a time, interleaved fairly with other requests.

        // TODO queries assume we have all data that we should - i.e. if there is no
        // block for a slot is was a missed slot, if no data column then block
        // had none - need to check that responses are not misreporting missing
        // data.

        let mut units = VecDeque::new();
        match request.request {
            silver_common::RpcRequest::DataColumnsByRange { ssz, len } => {
                if DataColumnSidecarsByRangeRequestView::check_size(&ssz[..len]) {
                    let start = DataColumnSidecarsByRangeRequestView::start_slot(&ssz[..len]);
                    let count = DataColumnSidecarsByRangeRequestView::count(&ssz[..len])
                        .min(MAX_REQUEST_BLOCKS);
                    let end = start.saturating_add(count);
                    let columns: Vec<u64> =
                        DataColumnSidecarsByRangeRequestView::columns(&ssz[..len])
                            .chunks_exact(8)
                            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                            .collect();

                    tracing::info!(?stream_id, start, count, "storage query");

                    // `(slot, column)` order per fulu p2p-interface: outer slot,
                    // inner column.
                    self.resolve_canonical_range(start, end, |slot, canonical| {
                        for &column in &columns {
                            units.push_back(match canonical {
                                Some((_parent_root, block_root)) => {
                                    QueryUnit::UnfinalizedColumn { slot, block_root, column }
                                }
                                None => QueryUnit::Column { slot, column },
                            });
                        }
                    });
                }
            }
            silver_common::RpcRequest::DataColumnsByRoot(read) => {
                with_root_request(
                    rpc_consumer,
                    read,
                    DataColumnsByRootRequestView::check_size,
                    |buf| {
                        let ids = DataColumnsByRootRequestView::count(buf);
                        tracing::info!(?stream_id, ids, len = buf.len(), "storage query");

                        for i in 0..ids {
                            let id = DataColumnsByRootRequestView::identifier(buf, i);
                            let root = DataColumnsByRootIdentifierView::block_root(id);
                            let request_columns = DataColumnsByRootIdentifierView::columns(id)
                                .chunks_exact(8)
                                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));

                            // Serve a specific block's columns regardless of
                            // canonicity: unfinalized (by block_root) first,
                            // else the finalized flat store.
                            if let Some(slot) = self.unfinalized_columns.slot_of(root) {
                                for column in request_columns {
                                    units.push_back(QueryUnit::UnfinalizedColumn {
                                        slot,
                                        block_root: *root,
                                        column,
                                    });
                                }
                            } else if let Some(&slot) = self.root_index.get(root) {
                                for column in request_columns {
                                    units.push_back(QueryUnit::Column { slot, column });
                                }
                            }
                        }
                    },
                );
            }
            silver_common::RpcRequest::BlocksByRange(req_bytes) => {
                let start = BeaconBlocksByRangeRequestView::start_slot(&req_bytes);
                let count =
                    BeaconBlocksByRangeRequestView::count(&req_bytes).min(MAX_REQUEST_BLOCKS);
                let end = start.saturating_add(count);

                tracing::info!(?stream_id, start, count, "storage query");

                self.resolve_canonical_range(start, end, |slot, canonical| {
                    units.push_back(match canonical {
                        Some((parent_root, block_root)) => {
                            QueryUnit::UnfinalizedBlock { slot, parent_root, block_root }
                        }
                        None => QueryUnit::Block { slot },
                    });
                });
            }
            silver_common::RpcRequest::BlockByRoot(read) => {
                with_root_request(
                    rpc_consumer,
                    read,
                    BeaconBlocksByRootRequestView::check_size,
                    |buf| {
                        let count = BeaconBlocksByRootRequestView::count(buf);

                        tracing::info!(?stream_id, count, len = buf.len(), "storage query");

                        for i in 0..count {
                            let root = BeaconBlocksByRootRequestView::root(buf, i);
                            // Serve any block we hold by root regardless of
                            // canonicity: unfinalized fork tree first, then the
                            // finalized flat store.
                            if let Some((slot, parent_root)) = self.unfinalized.get(root) {
                                units.push_back(QueryUnit::UnfinalizedBlock {
                                    slot,
                                    parent_root,
                                    block_root: *root,
                                });
                            } else if let Some(&slot) = self.root_index.get(root) {
                                units.push_back(QueryUnit::Block { slot });
                            } else {
                                tracing::warn!(
                                    block_root = hex::encode(root),
                                    "BlockByRoot - root not found"
                                );
                            }
                        }
                    },
                );
            }
            silver_common::RpcRequest::ExecutionPayloadEnvelopesByRange(ssz) => {
                let start = ExecutionPayloadEnvelopesByRangeRequestView::start_slot(&ssz);
                let count = ExecutionPayloadEnvelopesByRangeRequestView::count(&ssz)
                    .min(MAX_REQUEST_BLOCKS);
                let end = start.saturating_add(count);
                // One envelope per canonical block; `serve_file` skips a slot
                // with no envelope (pre-Gloas or a missed slot).
                self.resolve_canonical_range(start, end, |slot, canonical| {
                    units.push_back(match canonical {
                        Some((_parent_root, block_root)) => {
                            QueryUnit::UnfinalizedEnvelope { slot, block_root }
                        }
                        None => QueryUnit::Envelope { slot },
                    });
                });
            }
            silver_common::RpcRequest::ExecutionPayloadEnvelopesByRoot(read) => {
                with_root_request(
                    rpc_consumer,
                    read,
                    ExecutionPayloadEnvelopesByRootRequestView::check_size,
                    |buf| {
                        let count = ExecutionPayloadEnvelopesByRootRequestView::count(buf);
                        for i in 0..count {
                            let root = ExecutionPayloadEnvelopesByRootRequestView::root(buf, i);
                            // Serve a specific block's envelope regardless of
                            // canonicity: unfinalized (by block_root) first, else
                            // the finalized flat store.
                            if let Some(slot) = self.unfinalized_envelopes.slot_of(root) {
                                units.push_back(QueryUnit::UnfinalizedEnvelope {
                                    slot,
                                    block_root: *root,
                                });
                            } else if let Some(&slot) = self.root_index.get(root) {
                                units.push_back(QueryUnit::Envelope { slot });
                            }
                        }
                    },
                );
            }
            // Unhandled request kind: no response (matches prior behaviour).
            _ => return,
        }
        self.query_queue.push_back(PendingQuery::new(stream_id, units));
    }

    fn resolve_canonical_range(
        &self,
        start: u64,
        end: u64,
        mut push: impl FnMut(u64, Option<([u8; 32], [u8; 32])>),
    ) {
        let canonical =
            self.unfinalized.canonical_chain_in_range(self.head_root, self.head_slot, start, end);
        for slot in start..end {
            push(slot, canonical.get(&slot).copied());
        }
    }

    pub(super) fn persist_peer(&mut self, enr: Enr) {
        self.write_queue.push_back(PendingWrite::PersistPeer { enr });
    }

    pub(super) fn load_peers(&mut self) {
        self.write_queue.push_back(PendingWrite::LoadPeers);
    }

    fn finalized_slot_dir(&self, payload: Payload, slot: u64) -> PathBuf {
        let group_dir = slot & !(SLOTS_PER_DIR - 1);
        PathBuf::new()
            .join(&self.store_dir)
            .join(payload.finalized_dir_name())
            .join(group_dir.to_string())
    }

    fn unfinalized_dir(&self, payload: Payload) -> PathBuf {
        Path::new(&self.store_dir).join(payload.unfinalized_dir_name())
    }

    fn peers_dir(&self) -> PathBuf {
        Path::new(&self.store_dir).join(PEERS_DIR)
    }
}

/// Join `name` under `store_dir` and ensure the directory exists.
fn ensure_dir(store_dir: &str, name: &str) -> Result<PathBuf, Error> {
    let dir = Path::new(store_dir).join(name);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn with_root_request(
    rpc_consumer: &mut TRandomAccess,
    read: TCacheRead,
    check_size: fn(&[u8]) -> bool,
    resolve: impl FnOnce(&[u8]),
) {
    let read = rpc_consumer.acquire(read);
    if let Ok((buf, _)) = read.buffer() &&
        check_size(buf)
    {
        resolve(buf);
    } else {
        // Fall through with no units: the caller still enqueues the query,
        // so the peer gets an immediate bare `Complete`, not a hung stream.
        tracing::warn!("root request buffer not resolved!");
    }
}

#[cfg(test)]
fn test_spec(gloas_fork_epoch: u64) -> Arc<SpecConfig> {
    Arc::new(SpecConfig { gloas_fork_epoch, ..SpecConfig::mainnet() })
}

#[cfg(test)]
mod tests {
    // NOTE: tests that stage reads via `add_block`/`add_data_column` must drain
    // the write queue with `file_io` before scope exit. `AcquiredRead`s parked
    // in `write_queue` hold raw `*const` pointers into their consumer; if the
    // consumer drops first, releasing them on drop is use-after-free.
    use std::{
        io::{ErrorKind, Read, Write},
        thread,
        time::{Duration, Instant},
    };

    use silver_common::{DataKind, SyncNeed};

    /// These fixtures are all fulu-era, so the fork never activates.
    fn load_fulu(store_dir: String) -> super::Store {
        super::Store::load(store_dir, super::test_spec(u64::MAX)).unwrap()
    }

    /// Gloas active from genesis. A store holding payload envelopes is
    /// post-fork by definition, so a fulu-era spec would contradict the
    /// fixture.
    fn load_gloas(store_dir: String) -> super::Store {
        super::Store::load(store_dir, super::test_spec(0)).unwrap()
    }

    use silver_common::column_util;

    use crate::tile::IoEvent;

    #[test]
    fn concurrent_read_write() {
        let path = format!("/tmp/silver_storage_rw_{}.txt", rand::random::<u32>());
        let _ = std::fs::remove_file(&path);
        let mut file = super::io::open_file_write(&path, false).unwrap();

        let mut handles = vec![];
        for i in 0..10 {
            let path = path.clone();
            let h = thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1));
                let start = Instant::now();
                let mut file = super::io::open_file_read(&path).unwrap();
                let mut data = vec![0u8; 128 * 1024];
                let mut read = 0;
                for _ in 0..400 {
                    match file.read(&mut data) {
                        Ok(wrote) if wrote == data.len() => {
                            read += wrote;
                        }
                        Ok(n) => {
                            read += n;
                            //println!("read {n }/{}", data.len());
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            println!("would block!");
                        }
                        Err(e) => panic!("{e:?}"),
                    }
                }
                println!("{i} read {read} in {:?}", start.elapsed());
            });
            handles.push(h);
        }
        let data = vec![0u8; 128 * 1024];
        for _ in 0..400 {
            match file.write(&data) {
                Ok(wrote) if wrote == data.len() => {}
                Ok(n) => {
                    println!("wrote {n }/{}", data.len());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    println!("would block!");
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn fork_tree_persist_serve_promote() {
        use silver_common::{
            P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
            RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
        };

        let store_path = format!("/tmp/test_store_fork_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        // Two competing blocks at slot 42 sharing parent CC: A canonical, B fork.
        let parent_root = [0xCC; 32];
        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];
        let slot = 42u64;
        let bytes_a = [0xA7u8; 100];
        let bytes_b = [0xB7u8; 80];

        // Stage both payloads in a tcache and acquire reads to hand to the store.
        let mut blocks = TCache::producer("fork_blocks", 1024 * 1024);
        let mut res_a = blocks.reserve(bytes_a.len(), true).unwrap();
        res_a.write_all(&bytes_a).unwrap();
        res_a.flush().unwrap();
        let ssz_a = res_a.read();
        let mut res_b = blocks.reserve(bytes_b.len(), true).unwrap();
        res_b.write_all(&bytes_b).unwrap();
        res_b.flush().unwrap();
        let ssz_b = res_b.read();
        let mut blocks_consumer =
            blocks.cache_ref().random_access("fork_blocks_cons", true).unwrap();
        let read_a = blocks_consumer.acquire(ssz_a);
        let read_b = blocks_consumer.acquire(ssz_b);

        store.add_block(root_a, read_a, slot, parent_root);
        store.add_block(root_b, read_b, slot, parent_root);
        assert!(store.unfinalized.contains(&root_a));
        assert!(store.unfinalized.contains(&root_b));

        // Head selects A; not yet finalized.
        store.update_head(slot, root_a, 0, [0u8; 32]);

        let fork_digest = [1, 2, 3, 4];
        let producer_cache = TCache::multi_producer("fork_rpc_in", 1024 * 1024);
        let mut producer = producer_cache.clone();
        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();

        let path_a = store
            .unfinalized_dir(super::Payload::Block)
            .join(super::io::unfinalized_name(slot, &parent_root, &root_a));
        let path_b = store
            .unfinalized_dir(super::Payload::Block)
            .join(super::io::unfinalized_name(slot, &parent_root, &root_b));
        assert!(path_a.exists());
        assert!(path_b.exists());

        // Asserts a response is a BeaconBlock carrying `expected` bytes.
        let mut read_consumer =
            producer_cache.cache_ref().random_access("fork_read", true).unwrap();
        let mut assert_block = |resp: &P2pSend, expected: &[u8]| {
            let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                response: RpcResponse::BeaconBlock { ssz, .. },
                ..
            })) = resp
            else {
                panic!("expected BeaconBlock response, got {resp:?}");
            };
            let acquired = read_consumer.acquire(*ssz);
            let (buf, _) = acquired.buffer().unwrap();
            assert_eq!(buf, expected);
        };

        // BeaconBlocksByRange [42,43) serves the canonical block A only.
        let mut range = [0u8; 24];
        range[0..8].copy_from_slice(&slot.to_le_bytes()); // start_slot
        range[8..16].copy_from_slice(&1u64.to_le_bytes()); // count
        range[16..24].copy_from_slice(&1u64.to_le_bytes()); // step
        let sid = P2pStreamId::new(1234, 1, StreamProtocol::BeaconBlocksByRange, false);

        // BlockByRoot request buffer (one root) staged in a tcache.
        let mut req_producer = TCache::producer("fork_req", 1024 * 1024);
        let mut byroot_res = req_producer.reserve(32, true).unwrap();
        byroot_res.write_all(&root_b).unwrap();
        byroot_res.flush().unwrap();
        let byroot_ssz = byroot_res.read();
        let mut req_consumer =
            req_producer.cache_ref().random_access("fork_req_cons", true).unwrap();

        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::BlocksByRange(range),
        });
        let mut responses = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => responses.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(responses.len(), 2); // canonical block A + Complete
        assert_block(&responses[0], &bytes_a);
        assert!(matches!(
            &responses[1],
            P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                response: RpcResponse::Complete,
                ..
            }))
        ));

        // BlockByRoot serves the non-canonical fork B regardless of canonicity.
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::BlockByRoot(byroot_ssz),
        });
        let mut byroot = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => byroot.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(byroot.len(), 2);
        assert_block(&byroot[0], &bytes_b);

        // Finalize at slot 42 on A: promote A, prune the orphan B.
        store.update_head(slot, root_a, slot, root_a);
        assert_eq!(store.root_index.get(&root_a), Some(&slot));
        assert!(!store.unfinalized.contains(&root_a));
        assert!(!store.unfinalized.contains(&root_b));

        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();
        let flat_a =
            store.finalized_slot_dir(super::Payload::Block, slot).join(format!("{slot}_block.ssz"));
        assert!(flat_a.exists());
        assert!(!path_a.exists()); // moved to flat store
        assert!(!path_b.exists()); // orphan pruned

        // Range still serves A, now from the flat finalized store.
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::BlocksByRange(range),
        });
        let mut after = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => after.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(after.len(), 2);
        assert_block(&after[0], &bytes_a);

        // Reload: finalized index persisted, unfinalized tree empty.
        let reloaded = load_fulu(store_path.clone());
        assert_eq!(reloaded.root_index.get(&root_a), Some(&slot));
        assert!(reloaded.unfinalized.is_empty());

        let _ = std::fs::remove_dir_all(&store_path);
    }

    // Envelopes: persist unfinalized, promote the canonical one to the flat
    // store on finalization, prune the orphan, and rebuild the index on reload.
    #[test]
    fn envelope_persist_promote_prune() {
        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_env_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_gloas(store_path.clone());

        // Canonical block A + fork block B at slot 42, shared parent CC; each
        // gets an envelope.
        let parent_root = [0xCC; 32];
        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];
        let slot = 42u64;
        let block_a = [0xA7u8; 100];
        let block_b = [0xB7u8; 80];
        let env_a = [0x1Au8; 120];
        let env_b = [0x1Bu8; 60];

        let mut cache = TCache::producer("env_blocks", 1024 * 1024);
        let stage = |cache: &mut _, bytes: &[u8]| {
            let mut res = TCacheProducer::reserve(cache, bytes.len(), true).unwrap();
            res.write_all(bytes).unwrap();
            res.flush().unwrap();
            res.read()
        };
        let ssz_ba = stage(&mut cache, &block_a);
        let ssz_bb = stage(&mut cache, &block_b);
        let ssz_ea = stage(&mut cache, &env_a);
        let ssz_eb = stage(&mut cache, &env_b);
        let mut cons = cache.cache_ref().random_access("env_cons", true).unwrap();

        // Block before envelope: `add_envelope` derives the slot from the block.
        store.add_block(root_a, cons.acquire(ssz_ba), slot, parent_root);
        store.add_block(root_b, cons.acquire(ssz_bb), slot, parent_root);
        store.add_envelope(root_a, cons.acquire(ssz_ea));
        store.add_envelope(root_b, cons.acquire(ssz_eb));
        assert_eq!(store.unfinalized_envelopes.slot_of(&root_a), Some(slot));
        assert_eq!(store.unfinalized_envelopes.slot_of(&root_b), Some(slot));

        // Head selects A; nothing finalized yet.
        store.update_head(slot, root_a, 0, [0u8; 32]);

        let fork_digest = [1, 2, 3, 4];
        let producer_cache = TCache::multi_producer("env_rpc_in", 1024 * 1024);
        let mut producer = producer_cache.clone();
        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();

        let unf_a = store
            .unfinalized_dir(super::Payload::Envelope)
            .join(super::io::unfinalized_envelope_name(slot, &root_a));
        let unf_b = store
            .unfinalized_dir(super::Payload::Envelope)
            .join(super::io::unfinalized_envelope_name(slot, &root_b));
        assert!(unf_a.exists());
        assert!(unf_b.exists());

        // Replay pairs each block with its envelope: a gloas child's precheck
        // only passes once the parent's payload is verified.
        let entries = store.replay_entries(0);
        assert_eq!(entries.len(), 2, "both forks replayable");
        assert_eq!(
            entries.iter().filter(|e| e.envelope.as_ref() == Some(&unf_a)).count(),
            1,
            "A paired with its unfinalized envelope"
        );
        assert_eq!(
            entries.iter().filter(|e| e.envelope.as_ref() == Some(&unf_b)).count(),
            1,
            "B paired with its own, not A's"
        );

        // Finalize at slot 42 on A: promote A's envelope, prune orphan B's.
        store.update_head(slot, root_a, slot, root_a);
        assert!(store.unfinalized_envelopes.is_empty());
        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();

        let flat_a = store
            .finalized_slot_dir(super::Payload::Envelope, slot)
            .join(format!("{slot}_envelope.ssz"));
        assert!(flat_a.exists(), "canonical envelope promoted to flat store");
        assert_eq!(std::fs::read(&flat_a).unwrap(), env_a);
        assert!(!unf_a.exists(), "promoted out of unfinalized");
        assert!(!unf_b.exists(), "orphan envelope pruned");

        let entries = store.replay_entries(0);
        assert_eq!(entries.len(), 1, "only the promoted block replays");
        assert_eq!(
            entries[0].envelope.as_ref(),
            Some(&flat_a),
            "paired with the promoted envelope, found by slot"
        );

        // Reload rebuilds the (now empty) unfinalized envelope index.
        let reloaded = load_gloas(store_path.clone());
        assert!(reloaded.unfinalized_envelopes.is_empty());

        let _ = std::fs::remove_dir_all(&store_path);
    }

    // A self-parenting block (cycle) must not hang the canonical walk.
    #[test]
    fn range_query_terminates_on_cycle() {
        use silver_common::{
            P2pStreamId, RpcRequest, RpcRequestInbound, StreamProtocol, TCache, TCacheProducer,
        };

        let store_path = format!("/tmp/test_store_cycle_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        // parent_root == block_root: a self-loop in the fork tree.
        let root_x = [0xEE; 32];
        let slot = 10u64;
        let mut blocks = TCache::producer("cycle_blocks", 1024 * 1024);
        let mut res = blocks.reserve(8, true).unwrap();
        res.write_all(&[0u8; 8]).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut consumer = blocks.cache_ref().random_access("cycle_cons", true).unwrap();
        let read = consumer.acquire(ssz);
        store.add_block(root_x, read, slot, root_x);
        store.update_head(slot, root_x, 0, [0u8; 32]);

        // Drain the staged write so the acquired read is released while its
        // consumer is still alive (`read` is parked in the write queue).
        let mut producer = TCache::multi_producer("cycle_rpc_in", 1024 * 1024).clone();
        store.file_io(|_| [0u8; 4], 0, &mut producer, &mut |_| {}).unwrap();

        // A range spanning the self-loop slot must return rather than spin.
        let mut range = [0u8; 24];
        range[0..8].copy_from_slice(&5u64.to_le_bytes()); // start_slot
        range[8..16].copy_from_slice(&10u64.to_le_bytes()); // count
        range[16..24].copy_from_slice(&1u64.to_le_bytes()); // step
        let sid = P2pStreamId::new(1, 1, StreamProtocol::BeaconBlocksByRange, false);
        let req_producer = TCache::producer("cycle_req", 1024 * 1024);
        let mut req_consumer =
            req_producer.cache_ref().random_access("cycle_req_cons", true).unwrap();
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::BlocksByRange(range),
        });
        // Reaching here proves the walk terminated.
        assert!(!store.query_queue.is_empty());

        let _ = std::fs::remove_dir_all(&store_path);
    }

    #[test]
    fn envelope_range_request_served_empty() {
        use silver_common::{
            P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
            RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
            ssz_view::EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE,
        };

        let store_path = format!("/tmp/test_store_env_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        // We don't persist envelopes, but an inbound range request must still get
        // a clean empty response (`Complete` only), never a hung stream.
        let req_producer = TCache::producer("env_req", 1024 * 1024);
        let mut req_consumer =
            req_producer.cache_ref().random_access("env_req_cons", true).unwrap();
        let sid = P2pStreamId::new(9, 1, StreamProtocol::ExecutionPayloadEnvelopesByRange, false);
        let mut req = [0u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE];
        req[0..8].copy_from_slice(&10u64.to_le_bytes());
        req[8..16].copy_from_slice(&5u64.to_le_bytes());
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::ExecutionPayloadEnvelopesByRange(req),
        });

        let fork_digest = [1, 2, 3, 4];
        let producer_cache = TCache::multi_producer("env_rpc_in", 1024 * 1024);
        let mut producer = producer_cache.clone();
        let mut responses = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| {
                if let IoEvent::P2pSend(s) = s {
                    responses.push(s);
                }
            })
            .unwrap();

        assert_eq!(responses.len(), 1, "empty envelope response is just Complete");
        assert!(matches!(
            &responses[0],
            P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                response: RpcResponse::Error { error: 3, .. },
                ..
            }))
        ));
    }

    #[test]
    fn column_fork_persist_serve_promote() {
        use silver_common::{
            P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
            RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
            ssz_view::DC_BY_RANGE_REQ_MAX,
        };

        let store_path = format!("/tmp/test_store_colfork_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());
        let ucol_dir = store.unfinalized_dir(super::Payload::Column);
        let flat_dir = store.finalized_slot_dir(super::Payload::Column, 42);

        let parent_root = [0xCC; 32];
        let root_a = [0xAA; 32];
        let root_b = [0xBB; 32];
        let slot = 42u64;
        let a3 = [0xA3u8; 64];
        let a7 = [0xA7u8; 64];
        let b3 = [0xB3u8; 64];

        // Stage block + column payloads in a tcache.
        let mut tc = TCache::producer("colfork_data", 1 << 20);
        let mut stage = |bytes: &[u8]| {
            let mut r = tc.reserve(bytes.len(), true).unwrap();
            r.write_all(bytes).unwrap();
            r.flush().unwrap();
            r.read()
        };
        let ssz_ba = stage(&[0xA0u8; 100]);
        let ssz_bb = stage(&[0xB0u8; 100]);
        let ssz_a3 = stage(&a3);
        let ssz_a7 = stage(&a7);
        let ssz_b3 = stage(&b3);

        let mut consumer = tc.cache_ref().random_access("colfork_cons", true).unwrap();
        store.add_block(root_a, consumer.acquire(ssz_ba), slot, parent_root);
        store.add_block(root_b, consumer.acquire(ssz_bb), slot, parent_root);
        store.add_data_column(root_a, 3, consumer.acquire(ssz_a3), slot, false);
        store.add_data_column(root_a, 7, consumer.acquire(ssz_a7), slot, false);
        store.add_data_column(root_b, 3, consumer.acquire(ssz_b3), slot, false);
        assert!(store.unfinalized_columns.contains(&root_a));
        assert!(store.unfinalized_columns.contains(&root_b));

        store.update_head(slot, root_a, 0, [0u8; 32]);

        let fork_digest = [9, 9, 9, 9];
        let producer_cache = TCache::multi_producer("colfork_rpc_in", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();
        assert!(ucol_dir.join(super::io::unfinalized_column_name(slot, &root_a, 3)).exists());
        assert!(ucol_dir.join(super::io::unfinalized_column_name(slot, &root_a, 7)).exists());
        assert!(ucol_dir.join(super::io::unfinalized_column_name(slot, &root_b, 3)).exists());

        let mut read_consumer =
            producer_cache.cache_ref().random_access("colfork_read", true).unwrap();
        let mut assert_col = |resp: &P2pSend, expected: &[u8]| {
            let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                response: RpcResponse::DataColumnSidecar { ssz, .. },
                ..
            })) = resp
            else {
                panic!("expected DataColumnSidecar response, got {resp:?}");
            };
            let acquired = read_consumer.acquire(*ssz);
            let (buf, _) = acquired.buffer().unwrap();
            assert_eq!(buf, expected);
        };

        // DataColumnsByRange [42,43) for columns {3,7}: SSZ container is
        // start_slot | count | offset(=20) | column list (u64 LE each).
        let mut range = [0u8; DC_BY_RANGE_REQ_MAX];
        range[0..8].copy_from_slice(&slot.to_le_bytes());
        range[8..16].copy_from_slice(&1u64.to_le_bytes());
        range[16..20].copy_from_slice(&20u32.to_le_bytes());
        range[20..28].copy_from_slice(&3u64.to_le_bytes());
        range[28..36].copy_from_slice(&7u64.to_le_bytes());
        let sid = P2pStreamId::new(1, 1, StreamProtocol::DataColumnSidecarsByRange, false);

        let mut req_producer = TCache::producer("colfork_req", 1 << 20);
        let mut req_consumer =
            req_producer.cache_ref().random_access("colfork_req_cons", true).unwrap();
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::DataColumnsByRange { ssz: range, len: 36 },
        });
        let mut responses = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => responses.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(responses.len(), 3); // canonical A columns 3 + 7, then Complete
        assert_col(&responses[0], &a3);
        assert_col(&responses[1], &a7);

        // DataColumnsByRoot spanning both roots in one request: A's column 7
        // and non-canonical B's column 3. Wire format is
        // List[DataColumnsByRootIdentifier]: outer offset table (u32 LE per
        // element), then per element root | inner offset(=36) | column list.
        let mut byroot = Vec::new();
        byroot.extend_from_slice(&8u32.to_le_bytes()); // element 0 at 8
        byroot.extend_from_slice(&52u32.to_le_bytes()); // element 1 at 8 + 44
        for (root, column) in [(&root_a, 7u64), (&root_b, 3u64)] {
            byroot.extend_from_slice(root);
            byroot.extend_from_slice(&36u32.to_le_bytes());
            byroot.extend_from_slice(&column.to_le_bytes());
        }
        let mut br_res = req_producer.reserve(byroot.len(), true).unwrap();
        br_res.write_all(&byroot).unwrap();
        br_res.flush().unwrap();
        let byroot_ssz = br_res.read();
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::DataColumnsByRoot(byroot_ssz),
        });
        let mut br = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => br.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(br.len(), 3); // A column 7, B column 3, Complete
        assert_col(&br[0], &a7);
        assert_col(&br[1], &b3);

        // A bare identifier (no outer offset table — the pre-fix encoding) is
        // rejected: no units resolve, the peer still gets an immediate bare
        // Complete rather than a hung stream.
        let mut bare = [0u8; 44];
        bare[0..32].copy_from_slice(&root_b);
        bare[32..36].copy_from_slice(&36u32.to_le_bytes());
        bare[36..44].copy_from_slice(&3u64.to_le_bytes());
        let mut bare_res = req_producer.reserve(44, true).unwrap();
        bare_res.write_all(&bare).unwrap();
        bare_res.flush().unwrap();
        let bare_ssz = bare_res.read();
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::DataColumnsByRoot(bare_ssz),
        });
        let mut rejected = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => rejected.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(rejected.len(), 1, "malformed by-root request answers a bare Complete");
        assert!(matches!(
            &rejected[0],
            P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                response: RpcResponse::Complete,
                ..
            }))
        ));

        // Finalize on A at slot 42: promote A's columns, prune B's.
        store.update_head(slot, root_a, slot, root_a);
        assert!(store.unfinalized_columns.is_empty());

        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();
        assert!(flat_dir.join(format!("{slot}_3.ssz")).exists());
        assert!(flat_dir.join(format!("{slot}_7.ssz")).exists());
        assert!(!ucol_dir.join(super::io::unfinalized_column_name(slot, &root_a, 3)).exists());
        assert!(!ucol_dir.join(super::io::unfinalized_column_name(slot, &root_b, 3)).exists());

        // Range still serves A's columns, now from the flat finalized store.
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::DataColumnsByRange { ssz: range, len: 36 },
        });
        let mut after = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => after.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(after.len(), 3);
        assert_col(&after[0], &a3);
        assert_col(&after[1], &a7);

        // Reload: finalized index persisted, unfinalized column index empty.
        let reloaded = load_fulu(store_path.clone());
        assert!(reloaded.unfinalized_columns.is_empty());
        assert_eq!(reloaded.root_index.get(&root_a), Some(&slot));

        let _ = std::fs::remove_dir_all(&store_path);
    }

    #[test]
    fn backfill_block_persists_root_index() {
        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_backfill_index_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        let slot = 64u64;
        let parent_root = [0x42; 32];
        let state_root = [0x24; 32];
        let mut block = vec![0u8; 184];
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        block[108..116].copy_from_slice(&7u64.to_le_bytes());
        block[116..148].copy_from_slice(&parent_root);
        block[148..180].copy_from_slice(&state_root);
        let block_root = column_util::block_root_fulu(&block);

        let mut blocks = TCache::producer("backfill_index_blocks", 1 << 20);
        let mut res = blocks.reserve(block.len(), true).unwrap();
        res.write_all(&block).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut consumer = blocks.cache_ref().random_access("backfill_index_cons", true).unwrap();

        store.history.blocks = Some(super::backfill::Backfill::new(
            slot..slot + 1,
            block_root,
            super::test_spec(u64::MAX),
        ));
        store.backfill_block(consumer.acquire(ssz));

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("backfill_index_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap();

        assert_eq!(store.root_index.get(&block_root), Some(&slot));
        assert!(
            store
                .finalized_slot_dir(super::Payload::Block, slot)
                .join(format!("{slot}_block.ssz"))
                .exists()
        );

        let reloaded = load_fulu(store_path.clone());
        assert_eq!(reloaded.root_index.get(&block_root), Some(&slot));

        let _ = std::fs::remove_dir_all(&store_path);
    }

    #[test]
    fn column_already_on_disk_is_not_written_again() {
        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_col_dedupe_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        let (slot, block_root) = (9u64, [3u8; 32]);
        let mut tc = TCache::producer("dedupe_data", 1 << 20);
        let mut stage = |bytes: &[u8]| {
            let mut r = tc.reserve(bytes.len(), true).unwrap();
            r.write_all(bytes).unwrap();
            r.flush().unwrap();
            r.read()
        };
        let (first, second) = (stage(&[0xC1u8; 64]), stage(&[0xC1u8; 64]));
        let mut consumer = tc.cache_ref().random_access("dedupe_cons", true).unwrap();

        store.add_data_column(block_root, 3, consumer.acquire(first), slot, false);
        assert_eq!(store.write_queue.len(), 1, "the first copy is written");

        store.add_data_column(block_root, 3, consumer.acquire(second), slot, false);
        assert_eq!(store.write_queue.len(), 1, "the second is already on disk");

        store
            .file_io(
                |_| [0u8; 4],
                0,
                &mut TCache::multi_producer("dedupe_rpc", 1 << 16),
                &mut |_| {},
            )
            .unwrap();
        let _ = std::fs::remove_dir_all(&store_path);
    }

    /// Claiming a slot invites requests for it, and answering nothing is what
    /// peers score as a bad response — so the claim is what is held: the anchor
    /// until a walk descends below it, then wherever the walks have reached.
    #[test]
    fn the_claim_is_what_the_walks_have_reached() {
        use silver_common::{PeerEvent, TCache};

        let store_path = format!("/tmp/test_store_claim_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());
        let custody = (1u128 << 3) | (1u128 << 7);

        let anchor = 256u64;
        store.head_root = [1u8; 32];
        store.finalized_slot = anchor;
        assert_eq!(
            store.earliest_servable(custody),
            anchor,
            "nothing below the anchor is held until a walk gets there"
        );

        // Armed as `StartBackfill` arms them: the column window is what they
        // mean to fill, not what is held, and no block walk has descended yet.
        store.history.columns = Some(super::backfill::ColumnBackfill::new(1..anchor + 1));
        store.history.scan = Some(super::history::ColumnScan { cursor: anchor, floor: 1 });
        assert_eq!(store.earliest_servable(custody), anchor);

        // Block backfill walking: the blocks it has yet to link are the claim.
        store.history.scan = None;
        store.history.blocks =
            Some(super::backfill::Backfill::new(1..129, [9u8; 32], super::test_spec(u64::MAX)));
        assert_eq!(store.earliest_servable(custody), 129);

        // Both walks done: the floor they reached is all that is left of them,
        // and it is published as soon as it changes.
        store.history.blocks = None;
        store.history.stage = super::history::BlockBackfillStage::Done;
        let mut columns = super::backfill::ColumnBackfill::new(1..anchor + 1);
        columns.mark_scan_complete();
        store.history.columns = Some(columns);

        let producer_cache = TCache::multi_producer("claim_rpc", 1 << 16);
        let mut producer = producer_cache.clone();
        let mut claims = Vec::new();
        store
            .file_io(|_| [0u8; 4], custody, &mut producer, &mut |io| {
                if let IoEvent::PeerEvent(PeerEvent::EarliestSlot(slot)) = io {
                    claims.push(slot);
                }
            })
            .unwrap();

        assert!(store.history.columns.is_none(), "torn down");
        assert_eq!(store.history.retired_floor, Some(1), "where the walk reached");
        assert_eq!(claims, vec![1], "the new claim, published once: {claims:?}");

        let _ = std::fs::remove_dir_all(&store_path);
    }

    /// Retention keeps deleting the bottom of the window, so a claim that stood
    /// still would go on advertising history that has been pruned.
    #[test]
    fn pruning_raises_the_claim() {
        use silver_common::{PeerEvent, TCache};

        let store_path = format!("/tmp/test_store_prune_claim_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        store.head_root = [1u8; 32];
        store.finalized_slot = super::COLUMN_SLOTS_RETAINED + 5000;
        store.history.retired_floor = Some(1);
        store.history.claimed_earliest = Some(1);
        store.write_queue.push_back(super::PendingWrite::TruncateHistory {
            payload: super::Payload::Column,
            finalized_slot: store.finalized_slot,
        });

        let producer_cache = TCache::multi_producer("prune_claim_rpc", 1 << 16);
        let mut producer = producer_cache.clone();
        let mut claims = Vec::new();
        store
            .file_io(|_| [0u8; 4], 1, &mut producer, &mut |io| {
                if let IoEvent::PeerEvent(PeerEvent::EarliestSlot(slot)) = io {
                    claims.push(slot);
                }
            })
            .unwrap();

        assert_eq!(claims, vec![5000], "claim follows the truncation up: {claims:?}");

        let _ = std::fs::remove_dir_all(&store_path);
    }

    /// Synthetic fulu `SignedBeaconBlock` carrying blob commitments, so the
    /// column walk owes it a custody set. Message at 100, body at 184,
    /// commitments spanning body[396..404).
    fn blob_block(slot: u64, parent_root: [u8; 32], state_root: [u8; 32]) -> Vec<u8> {
        let (body_start, body_len) = (184usize, 404usize);
        let mut block = vec![0u8; body_start + body_len];
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        block[108..116].copy_from_slice(&11u64.to_le_bytes());
        block[116..148].copy_from_slice(&parent_root);
        block[148..180].copy_from_slice(&state_root);
        block[body_start + 388..body_start + 392].copy_from_slice(&396u32.to_le_bytes());
        block[body_start + 392..body_start + 396].copy_from_slice(&404u32.to_le_bytes());
        block
    }

    /// Beacon state announces an envelope again every time it is handed one it
    /// already verified — that is how window coverage comes back after it was
    /// dropped. Only this store knows whether the bytes got down, so only this
    /// store can drop the second copy.
    #[test]
    fn envelope_already_on_disk_is_not_written_again() {
        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_env_dedupe_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_gloas(store_path.clone());

        let (slot, block_root, parent_root) = (9u64, [3u8; 32], [0u8; 32]);
        let mut tc = TCache::producer("env_dedupe_data", 1 << 20);
        let mut stage = |bytes: &[u8]| {
            let mut r = tc.reserve(bytes.len(), true).unwrap();
            r.write_all(bytes).unwrap();
            r.flush().unwrap();
            r.read()
        };
        let block = stage(&[0xB0u8; 100]);
        let (first, second) = (stage(&[0xE1u8; 200]), stage(&[0xE1u8; 200]));
        let mut consumer = tc.cache_ref().random_access("env_dedupe_cons", true).unwrap();

        store.add_block(block_root, consumer.acquire(block), slot, parent_root);
        assert_eq!(store.write_queue.len(), 1, "the block it belongs to");

        assert!(store.is_envelope_owed(&block_root, slot), "nothing on disk for it yet");
        store.add_envelope(block_root, consumer.acquire(first));
        assert_eq!(store.write_queue.len(), 2, "the first copy is written");

        assert!(!store.is_envelope_owed(&block_root, slot), "and now it is not owed");
        store.add_envelope(block_root, consumer.acquire(second));
        assert_eq!(store.write_queue.len(), 2, "the second is already on disk");

        store
            .file_io(
                |_| [0u8; 4],
                0,
                &mut TCache::multi_producer("env_dedupe_rpc", 1 << 16),
                &mut |_| {},
            )
            .unwrap();
        let _ = std::fs::remove_dir_all(&store_path);
    }

    /// The engine sweeps whatever span it was last told about, so a walk torn
    /// down mid-span would leave it asking for ranges this tile can no longer
    /// accept — a request loop that only ends with the process. One publisher
    /// per tick is what closes that: teardown drops the walk, and the span it
    /// owed goes empty on its own. Unchanged spans are not republished, so the
    /// channel carries only what moved.
    #[test]
    fn the_span_a_torn_down_walk_owed_goes_empty_on_its_own() {
        use silver_common::TCache;

        let store_path = format!("/tmp/test_store_teardown_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_gloas(store_path.clone());

        let producer_cache = TCache::multi_producer("teardown_rpc", 1 << 16);
        let mut producer = producer_cache.clone();
        let mut gaps = Vec::new();
        let mut tick = |store: &mut super::Store, gaps: &mut Vec<_>| {
            store
                .file_io(|_| [0u8; 4], 0, &mut producer, &mut |io| {
                    if let IoEvent::Need(SyncNeed::BackfillGap { kind, floor, next }) = io {
                        gaps.push((kind, floor, next));
                    }
                })
                .unwrap();
        };

        // A walk with a slot owed. The scan is unfinished, so nothing tears down.
        let block = blob_block(40, [0x31; 32], [0x13; 32]);
        let spec = store.spec.clone();
        let mut columns = super::backfill::ColumnBackfill::new(1..97);
        columns.seed_block(column_util::block_root_fulu(&block), 40, &block, 0b1, &spec);
        store.history.columns = Some(columns);
        tick(&mut store, &mut gaps);
        assert_eq!(gaps, vec![(DataKind::Columns, 40, 41)], "what it owes, once");

        gaps.clear();
        tick(&mut store, &mut gaps);
        assert!(gaps.is_empty(), "and not again while it has not moved");

        // Complete by the walks' own definition — scan done, nothing owed —
        // which is the state teardown fires in.
        let mut columns = super::backfill::ColumnBackfill::new(1..97);
        columns.mark_scan_complete();
        store.history.columns = Some(columns);
        let mut envelopes = super::backfill::EnvelopeBackfill::new(1..97);
        envelopes.mark_scan_complete();
        store.history.envelopes = Some(envelopes);
        store.history.stage = super::history::BlockBackfillStage::Done;

        tick(&mut store, &mut gaps);

        assert!(store.history.columns.is_none(), "torn down");
        assert!(store.history.envelopes.is_none(), "torn down");
        assert_eq!(
            gaps,
            vec![(DataKind::Columns, 0, 0)],
            "the span it owed goes empty; the envelope walk never owed one: {gaps:?}"
        );

        let _ = std::fs::remove_dir_all(&store_path);
    }

    #[test]
    fn persisted_backfill_block_requests_data_columns() {
        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_column_backfill_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        let slot = 96u64;
        let block = blob_block(slot, [0x31; 32], [0x13; 32]);
        let block_root = column_util::block_root_fulu(&block);

        let mut blocks = TCache::producer("column_backfill_blocks", 1 << 20);
        let mut res = blocks.reserve(block.len(), true).unwrap();
        res.write_all(&block).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut consumer = blocks.cache_ref().random_access("column_backfill_cons", true).unwrap();

        // Column backfill is live across the block-backfill phase: a block
        // fetched by block backfill in the column window (set 2) must request
        // its columns via the `BackfillBlock` feed.
        store.history.columns = Some(super::backfill::ColumnBackfill::new(1..slot + 1));
        store.history.blocks = Some(super::backfill::Backfill::new(
            slot..slot + 1,
            block_root,
            super::test_spec(u64::MAX),
        ));
        store.backfill_block(consumer.acquire(ssz));

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("column_backfill_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        let custody_columns = (1u128 << 3) | (1u128 << 7);
        let mut gaps = Vec::new();
        store
            .file_io(|_| fork_digest, custody_columns, &mut producer, &mut |io| {
                if let IoEvent::Need(SyncNeed::BackfillGap {
                    kind: DataKind::Columns,
                    floor,
                    next,
                }) = io
                {
                    gaps.push((floor, next));
                }
            })
            .unwrap();

        // Blocks arrive from block backfill densely and in order, so their
        // columns are asked for as a span that keeps pace with the block walk —
        // one by-root request per block could not.
        assert_eq!(gaps.last(), Some(&(slot, slot + 1)), "the written block's slot is owed");
        assert_eq!(store.root_index.get(&block_root), Some(&slot));
        assert_eq!(
            store.history.columns.as_ref().map(super::backfill::ColumnBackfill::owed_span),
            Some((slot, slot + 1)),
            "and it is what the walk will sweep"
        );
        // The block linked, so blocks are held from its slot — but its columns
        // are not, and the claim answers for every kind we serve.
        assert_eq!(
            store.earliest_servable(custody_columns),
            slot + 1,
            "a slot whose columns are owed holds the claim above it"
        );

        let _ = std::fs::remove_dir_all(&store_path);
    }

    /// Set 2 on restart: block backfill re-fetches a block whose columns an
    /// earlier run already wrote. Only the columns absent from disk are owed
    /// — asking for the full custody set rewrote every column below finalized.
    #[test]
    fn refetched_backfill_block_owes_only_absent_columns() {
        use std::io::Write;

        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_refetch_columns_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        let slot = 96u64;
        let block = blob_block(slot, [0x31; 32], [0x13; 32]);
        let block_root = column_util::block_root_fulu(&block);
        let custody_columns = (1u128 << 3) | (1u128 << 7);

        // Column 3 is already on disk from the previous run; 7 is not.
        let col_dir = store.finalized_slot_dir(super::Payload::Column, slot);
        std::fs::create_dir_all(&col_dir).unwrap();
        std::fs::write(col_dir.join(format!("{slot}_3.ssz")), b"col3").unwrap();

        let mut blocks = TCache::producer("refetch_columns_blocks", 1 << 20);
        let mut res = blocks.reserve(block.len(), true).unwrap();
        res.write_all(&block).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut consumer = blocks.cache_ref().random_access("refetch_columns_cons", true).unwrap();

        store.history.columns = Some(super::backfill::ColumnBackfill::new(1..slot + 1));
        store.history.blocks = Some(super::backfill::Backfill::new(
            slot..slot + 1,
            block_root,
            super::test_spec(u64::MAX),
        ));
        store.backfill_block(consumer.acquire(ssz));

        let producer_cache = TCache::multi_producer("refetch_columns_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(|_| [0u8; 4], custody_columns, &mut producer, &mut |_| {}).unwrap();

        let columns = store.history.columns.as_ref().expect("column walk live");
        assert_eq!(columns.owed_span(), (slot, slot + 1), "the block is still owed something");
        assert_eq!(
            columns.requested_columns(&block_root),
            Some(1u128 << 7),
            "only the column absent from disk is requested"
        );

        let _ = std::fs::remove_dir_all(&store_path);
    }

    // Set 1: a block already on disk (from sync, columns skipped) with missing
    // columns must be picked up by the column-backfill disk scan and requested
    // — block backfill is never triggered for it (the block is present).
    #[test]
    fn column_scan_requests_missing_columns_for_persisted_block() {
        use silver_common::TCache;

        use crate::tile::IoEvent;

        let store_path = format!("/tmp/test_store_column_scan_{}", rand::random::<u32>());
        let mut store = load_fulu(store_path.clone());

        let slot = 96u64;
        let parent_root = [0x31; 32];
        let state_root = [0x13; 32];
        let body_start = 184usize;
        let body_len = 404usize;
        let mut block = vec![0u8; body_start + body_len];
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        block[108..116].copy_from_slice(&11u64.to_le_bytes());
        block[116..148].copy_from_slice(&parent_root);
        block[148..180].copy_from_slice(&state_root);
        block[body_start + 388..body_start + 392].copy_from_slice(&396u32.to_le_bytes());
        block[body_start + 392..body_start + 396].copy_from_slice(&404u32.to_le_bytes());

        // Block on disk, no columns — exactly the post-sync state.
        let dir = store.finalized_slot_dir(super::Payload::Block, slot);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{slot}_block.ssz")), &block).unwrap();

        // Trigger the scan (as sync_update(Following) would) and run file_io.
        store.finalized_slot = slot;
        store.write_queue.push_back(super::PendingWrite::StartBackfill {
            finalized_slot: slot,
            finalized_root: [0u8; 32],
        });

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("column_scan_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        let custody_columns = (1u128 << 3) | (1u128 << 7);
        let mut gaps = Vec::new();
        store
            .file_io(|_| fork_digest, custody_columns, &mut producer, &mut |io| {
                if let IoEvent::Need(SyncNeed::BackfillGap {
                    kind: DataKind::Columns,
                    floor,
                    next,
                }) = io
                {
                    gaps.push((floor, next));
                }
            })
            .unwrap();

        // The scan's finds are swept by range, like block backfill's — one
        // mechanism, not a by-root chase per block.
        assert_eq!(gaps.last(), Some(&(slot, slot + 1)), "the persisted block's slot is owed");
        assert_eq!(
            store.history.columns.as_ref().map(super::backfill::ColumnBackfill::pending_len),
            Some(1),
            "and the block is held for verifying the sidecars when they arrive"
        );

        let _ = std::fs::remove_dir_all(&store_path);
    }

    /// The scan can turn up one need per blob-carrying block across the whole
    /// retention window, and every one is a by-root need the engine holds until
    /// its columns arrive. Left unpaced it would hand over the entire backlog
    /// at once; the cursor stays put instead, and resumes when the backlog
    /// drains.
    #[test]
    fn the_column_scan_pauses_while_the_backlog_is_full() {
        use silver_common::TCache;

        use crate::tile::IoEvent;

        let store_path = format!("/tmp/test_store_scan_pause_{}", rand::random::<u32>());
        let mut store = load_fulu(store_path.clone());

        let finalized = 4096u64;
        store.finalized_slot = finalized;
        store.history.columns = Some(super::backfill::ColumnBackfill::new(1..finalized + 1));
        store.history.scan = Some(super::history::ColumnScan { cursor: finalized, floor: 1 });

        // Stand the backlog up at the cap without touching the cursor.
        let cb = store.history.columns.as_mut().unwrap();
        let block = vec![0u8; 184 + 404];
        for i in 0..super::io::MAX_OPEN_COLUMN_NEEDS {
            cb.seed_block([i as u8; 32], (i as u64) + 1, &block, 0b1, &super::test_spec(u64::MAX));
        }
        assert_eq!(cb.pending_len(), super::io::MAX_OPEN_COLUMN_NEEDS, "backlog is at the cap");

        let before = store.history.scan.as_ref().map(|s| s.cursor);
        let producer_cache = TCache::multi_producer("scan_pause_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(|_| [0u8; 4], 0b1, &mut producer, &mut |_: IoEvent| {}).unwrap();
        assert_eq!(
            store.history.scan.as_ref().map(|s| s.cursor),
            before,
            "cursor held while the engine still has a windowful to chase"
        );

        let _ = std::fs::remove_dir_all(&store_path);
    }

    // Two concurrent range requests must interleave chunk-by-chunk, not
    // serialize (head-of-line fairness).
    #[test]
    fn range_queries_interleave_fairly() {
        use silver_common::{
            P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
            RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
        };

        let store_path = format!("/tmp/test_store_fair_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = load_fulu(store_path.clone());

        // Chain of two unfinalized blocks: slot 10 (parent CC) ← slot 11.
        let parent = [0xCC; 32];
        let root_10 = [0x10; 32];
        let root_11 = [0x11; 32];
        let mut blocks = TCache::producer("fair_blocks", 1 << 20);
        let mut stage = |bytes: &[u8]| {
            let mut r = blocks.reserve(bytes.len(), true).unwrap();
            r.write_all(bytes).unwrap();
            r.flush().unwrap();
            r.read()
        };
        let ssz_10 = stage(&[0x10u8; 50]);
        let ssz_11 = stage(&[0x11u8; 50]);
        let mut consumer = blocks.cache_ref().random_access("fair_cons", true).unwrap();
        store.add_block(root_10, consumer.acquire(ssz_10), 10, parent);
        store.add_block(root_11, consumer.acquire(ssz_11), 11, root_10);
        store.update_head(11, root_11, 0, [0u8; 32]);

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("fair_rpc_in", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(|_| fork_digest, 0, &mut producer, &mut |_| {}).unwrap(); // flush block writes

        // Two BlocksByRange [10,12) on distinct streams, queued before draining.
        let mut range = [0u8; 24];
        range[0..8].copy_from_slice(&10u64.to_le_bytes());
        range[8..16].copy_from_slice(&2u64.to_le_bytes());
        range[16..24].copy_from_slice(&1u64.to_le_bytes());
        let stream_a = P2pStreamId::new(1, 1, StreamProtocol::BeaconBlocksByRange, false);
        let stream_b = P2pStreamId::new(2, 2, StreamProtocol::BeaconBlocksByRange, false);
        let req_producer = TCache::producer("fair_req", 1 << 20);
        let mut req_consumer =
            req_producer.cache_ref().random_access("fair_req_cons", true).unwrap();
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: stream_a,
            request: RpcRequest::BlocksByRange(range),
        });
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: stream_b,
            request: RpcRequest::BlocksByRange(range),
        });

        let mut responses = vec![];
        store
            .file_io(|_| fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => responses.push(s),
                _ => {}
            })
            .unwrap();

        // Expect A10, B10, A11, B11, A-Complete, B-Complete — strict round-robin.
        let ids: Vec<_> = responses
            .iter()
            .map(|s| {
                let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound { stream_id, .. })) = s
                else {
                    panic!("expected RPC response, got {s:?}");
                };
                stream_id.stream_id()
            })
            .collect();
        let (a, b) = (stream_a.stream_id(), stream_b.stream_id());
        assert_ne!(a, b);
        assert_eq!(responses.len(), 6);
        assert_eq!(ids, vec![a, b, a, b, a, b], "responses must interleave across streams");
        for resp in &responses[4..] {
            let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound { response, .. })) = resp
            else {
                panic!("expected RPC response");
            };
            assert!(matches!(response, RpcResponse::Complete));
        }

        let _ = std::fs::remove_dir_all(&store_path);
    }
}
