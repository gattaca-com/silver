use std::{
    collections::VecDeque,
    io::Error,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use flux_profiler::timed;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{
    Enr, P2pStreamId, PeerEvent, RpcRequestInbound, SyncUpdate, TCacheRead, TRandomAccess, TRead,
    merkle::B256,
    ssz_view::{
        BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView,
        DataColumnSidecarsByRangeRequestView, DataColumnsByRootIdentifierView,
        DataColumnsByRootRequestView, ExecutionPayloadEnvelopesByRangeRequestView,
        ExecutionPayloadEnvelopesByRootRequestView, MAX_REQUEST_BLOCKS_DENEB,
        SignedBeaconBlockView,
    },
};

use crate::{StorageCounters, tile::IoEvent};

mod backfill;
mod block_index;
mod checkpoint;
mod coverage;
mod finalized;
mod history;
mod io;
mod unfinalized;

use backfill::{BlockFacts, PayloadFacts, VerifiedColumns};
use checkpoint::CheckpointWriter;
pub use checkpoint::latest_local_checkpoint;
use coverage::Block;
use finalized::Finalized;
use history::History;
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
    Column {
        slot: u64,
        column: u64,
        custody_set_complete: bool,
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
    PromoteColumn {
        slot: u64,
        block_root: B256,
        column: u64,
    },
    PromoteEnvelope {
        slot: u64,
        block_root: B256,
    },
    PromoteBlock {
        block: Block,
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
    BackfillBlock {
        block: Block,
        ssz: TRead,
    },
    PersistPeer {
        enr: Enr,
    },
    LoadPeers,
}

impl PendingWrite {
    fn lands(&self) -> bool {
        match self {
            PendingWrite::Column { .. } |
            PendingWrite::PromoteColumn { .. } |
            PendingWrite::PromoteEnvelope { .. } |
            PendingWrite::PromoteBlock { .. } |
            PendingWrite::BackfillBlock { .. } |
            PendingWrite::BackfillEnvelope { .. } => true,
            PendingWrite::WriteUnfinalized { .. } |
            PendingWrite::Prune { .. } |
            PendingWrite::TruncateHistory { .. } |
            PendingWrite::PersistPeer { .. } |
            PendingWrite::LoadPeers => false,
        }
    }
}

/// The coverage is mid-change while writes that land are queued, so nothing
/// is published or linked from it until `landing` is zero.
#[derive(Default)]
struct WriteQueue {
    queue: VecDeque<PendingWrite>,
    landing: usize,
}

impl WriteQueue {
    fn push_back(&mut self, write: PendingWrite) {
        self.landing += usize::from(write.lands());
        self.queue.push_back(write);
    }

    fn pop_front(&mut self) -> Option<PendingWrite> {
        let write = self.queue.pop_front()?;
        self.landing -= usize::from(write.lands());
        Some(write)
    }

    fn landing(&self) -> usize {
        self.landing
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
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

pub(super) fn slot_dir(store_dir: &str, payload: Payload, slot: u64) -> PathBuf {
    let group_dir = slot & !(SLOTS_PER_DIR - 1);
    Path::new(store_dir).join(payload.finalized_dir_name()).join(group_dir.to_string())
}

pub(super) fn block_path(store_dir: &str, slot: u64) -> PathBuf {
    slot_dir(store_dir, Payload::Block, slot).join(format!("{slot}_block.ssz"))
}

pub(super) fn column_path(store_dir: &str, slot: u64, column: u64) -> PathBuf {
    slot_dir(store_dir, Payload::Column, slot).join(format!("{slot}_{column}.ssz"))
}

pub(super) fn envelope_path(store_dir: &str, slot: u64) -> PathBuf {
    slot_dir(store_dir, Payload::Envelope, slot).join(format!("{slot}_envelope.ssz"))
}

#[derive(Clone, Copy, Default)]
pub(super) struct Head {
    pub(super) slot: u64,
    pub(super) root: B256,
    pub(super) finalized_slot: u64,
    pub(super) finalized_root: B256,
}

/// Unified blocks and data columns disk store.
pub(super) struct Store {
    spec: Arc<SpecConfig>,
    store_dir: String,
    finalized: Finalized,

    unfinalized: UnfinalizedBlocks,
    unfinalized_columns: UnfinalizedColumns,
    unfinalized_envelopes: UnfinalizedEnvelopes,
    // Latest fork-choice head + finalization watermark from Status.
    head: Head,
    sync_target: SyncUpdate,
    history: History,
    // Slot of the newest finalized-state checkpoint committed to disk.
    last_persisted_finalized_slot: u64,
    // In-flight streamed checkpoint, advanced one section per `file_io` turn.
    checkpoint: Option<CheckpointWriter>,

    write_queue: WriteQueue,
    query_queue: VecDeque<PendingQuery>,
}

impl Store {
    pub(super) fn load(
        store_dir: String,
        spec: Arc<SpecConfig>,
        custody: u128,
    ) -> Result<Self, Error> {
        // Try to create dirs if they do not exist.
        if !std::fs::exists(&store_dir)? {
            tracing::info!(store_dir, "create data store");
            std::fs::create_dir_all(&store_dir)?;
        }

        for payload in ALL_PAYLOADS {
            ensure_dir(&store_dir, payload.finalized_dir_name())?;
        }
        ensure_dir(&store_dir, PEERS_DIR)?;
        let finalized = Finalized::load(&store_dir, custody, &spec)?;

        let unfinalized = UnfinalizedBlocks::load(&store_dir, &spec)?;
        let unfinalized_columns = UnfinalizedColumns::load(&store_dir)?;
        let unfinalized_envelopes = UnfinalizedEnvelopes::load(&store_dir)?;

        // Finalized-state checkpoints: drop incomplete dirs, prune to the
        // newest N, and anchor `last_persisted` at the newest committed slot.
        let last_persisted_finalized_slot = checkpoint::init_checkpoints_dir(&store_dir)?;

        Ok(Self {
            history: History::new(spec.clone()),
            spec,
            store_dir,
            finalized,
            unfinalized,
            unfinalized_columns,
            unfinalized_envelopes,
            head: Head::default(),
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
        if slot <= self.head.finalized_slot {
            // Finalized history (backfill): flat store keyed by slot.
            self.write_queue.push_back(PendingWrite::Column {
                slot,
                column: column_index,
                custody_set_complete: complete,
                ssz: sidecar_ssz,
            });
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

    pub(super) fn is_envelope_owed(&self, block_root: &[u8; 32], slot: u64) -> bool {
        slot > self.head.finalized_slot && self.unfinalized_envelopes.slot_of(block_root).is_none()
    }

    pub(super) fn add_envelope(&mut self, block_root: [u8; 32], envelope_ssz: TRead) {
        let slot = match self.unfinalized.get(&block_root) {
            Some((slot, _)) => slot,
            None => match self.finalized.slot_of(&block_root) {
                Some(slot) => slot,
                None => {
                    tracing::debug!(
                        block_root = hex::encode(block_root),
                        "envelope for unknown block; dropping"
                    );
                    return;
                }
            },
        };
        if slot <= self.head.finalized_slot {
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
        if slot <= self.head.finalized_slot || self.has_block(&block_root) {
            return;
        }
        let facts = match block_ssz.buffer() {
            Ok((buffer, _)) if SignedBeaconBlockView::check_size(buffer) => {
                PayloadFacts::of(buffer, self.spec.is_gloas_at_slot(slot))
            }
            _ => PayloadFacts::default(),
        };
        self.unfinalized.insert(block_root, slot, parent_root, facts);
        self.write_queue.push_back(PendingWrite::WriteUnfinalized {
            slot,
            key: PayloadKey::Block { parent_root, block_root },
            ssz: block_ssz,
        });
    }

    pub(super) fn backfill_block(&mut self, ssz: TRead) {
        self.history.backfill_block(
            ssz,
            self.head,
            &self.finalized,
            &self.unfinalized,
            &mut self.write_queue,
        );
    }

    pub(super) fn backfill_envelope(&mut self, signed: TRead, emit: &mut impl FnMut(IoEvent)) {
        self.history.backfill_envelope(signed, &self.finalized, &mut self.write_queue, emit);
    }

    pub(super) fn backfill_data_column(
        &mut self,
        sidecar: TRead,
        peer: usize,
        now: Instant,
        emit: &mut impl FnMut(IoEvent),
    ) {
        let verified = self.history.backfill_data_column(sidecar, peer, now, &self.finalized, emit);
        if let Some(VerifiedColumns { slot, sidecars }) = verified {
            let last = sidecars.len().saturating_sub(1);
            for (i, parked) in sidecars.into_iter().enumerate() {
                self.write_queue.push_back(PendingWrite::Column {
                    slot,
                    column: parked.column_index,
                    custody_set_complete: i == last,
                    ssz: parked.ssz,
                });
            }
        }
    }

    pub(super) fn sync_update(&mut self, sync_update: SyncUpdate) {
        self.sync_target = sync_update;
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
        self.head.slot = head_slot;
        self.head.root = head_root;
        tracing::debug!(head_slot, head_root = hex::encode(head_root), "storage head update");

        if finalized_slot <= self.head.finalized_slot {
            return;
        }

        self.head.finalized_slot = finalized_slot;
        self.head.finalized_root = finalized_root;

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
        let mut child_payload =
            self.unfinalized.child_payload_parent(head_slot, head_root, &finalized_root);
        while let Some((slot, parent_root, payload)) = self.unfinalized.remove(&root) {
            self.finalized.index(root, slot);
            let facts = BlockFacts { slot, block_root: root, parent_root, payload };
            let needs = facts.needs(&self.spec, child_payload);
            let block = Block::new(facts, needs, finalized_slot, finalized_root);
            self.write_queue.push_back(PendingWrite::PromoteBlock { block });
            self.unfinalized_columns.promote(root, &mut self.write_queue);
            self.unfinalized_envelopes.promote(root, &mut self.write_queue);
            child_payload = Some(payload.parent_payload_hash);
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
    /// `unfinalized` (or the block index once promoted), so membership here is
    /// "validated", independent of the current head chain.
    pub(super) fn has_block(&self, root: &[u8; 32]) -> bool {
        self.unfinalized.contains(root) || self.finalized.contains(root)
    }

    pub(super) fn store_dir(&self) -> &str {
        &self.store_dir
    }

    pub(super) fn replay_entries(&self) -> Vec<ReplayEntry> {
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
                    columns_on_disk: self
                        .unfinalized_columns
                        .has_full_custody(block_root, self.finalized.custody()),
                    envelope,
                });
            }
        }
        for slot in self.finalized.slots() {
            if slot > checkpoint_slot {
                let block = block_path(&self.store_dir, slot);

                // Promoted envelopes are keyed by slot, so presence on disk is
                // the whole test
                let envelope = (slot >= self.spec.gloas_fork_slot())
                    .then(|| envelope_path(&self.store_dir, slot))
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
                            } else if let Some(slot) = self.finalized.slot_of(root) {
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
                            } else if let Some(slot) = self.finalized.slot_of(root) {
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
                            } else if let Some(slot) = self.finalized.slot_of(root) {
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
            self.unfinalized.canonical_chain_in_range(self.head.root, self.head.slot, start, end);
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

    #[cfg(test)]
    fn finalized_slot_dir(&self, payload: Payload, slot: u64) -> PathBuf {
        slot_dir(&self.store_dir, payload, slot)
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
mod tests;
