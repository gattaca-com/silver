use std::{
    collections::{VecDeque, hash_map::Entry},
    io::{Error, Read},
    path::{Path, PathBuf},
};

use flux_profiler::timed;
use fxhash::FxHashMap;
use silver_common::{
    Enr, P2pStreamId, PeerEvent, RpcRequestInbound, SyncUpdate, TRandomAccess, TRead,
    ssz_hash::B256,
    ssz_view::{
        BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView,
        DataColumnSidecarsByRangeRequestView, DataColumnsByRootIdentifierView,
    },
};

use crate::store::backfill::{Backfill, ColumnBackfill};

mod backfill;
mod checkpoint;
mod io;

use checkpoint::CheckpointWriter;
pub use checkpoint::latest_local_checkpoint;

/// `DataColumnSidecarsByRange` is bounded by
/// `count * NUMBER_OF_COLUMNS <= MAX_REQUEST_DATA_COLUMN_SIDECARS`
/// (16384), i.e. `count <= MAX_REQUEST_BLOCKS_DENEB`.
const MAX_REQUEST_BLOCKS: u64 = 32;

/// Cap on concurrent in-flight read requests. Past this, a new request is
/// answered with an empty (Complete-only) response — sheds load under a peer
/// flood and bounds the count of unit-bearing `query_queue` entries (each
/// entry's `units` is already capped by the range limits above).
const MAX_INFLIGHT_QUERIES: usize = 256;

/// Slots per on-disk group directory (`slot & !(SLOTS_PER_DIR - 1)`).
/// 128 keeps per-directory file counts (~128 slots × (block + columns))
/// manageable for the startup index scan.
const SLOTS_PER_DIR: u64 = 128;

/// Sub-directory holding the unfinalized block fork-tree. Flat (no slot
/// grouping) — bounded by the `[finalized, head]` window, a few epochs.
/// Files: `<slot>_<parent_root>_<block_root>.ssz`.
const UNFINALIZED_DIR: &str = "unfinalized";

/// Sub-directory holding unfinalized data columns, keyed by owning block
/// (columns have no fork of their own — canonicity follows the block).
/// Files: `<slot>_<block_root>_<column>.ssz`.
const UNFINALIZED_COLUMNS_DIR: &str = "unfinalized_columns";

const BLOCKS_DIR: &str = "blocks";
const COLUMNS_DIR: &str = "columns";
const PEERS_DIR: &str = "peers";

const BLOCK_SLOTS_RETAINED: u64 = 33024 * 32;
const COLUMN_SLOTS_RETAINED: u64 = 4096 * 32;

/// One node of the unfinalized fork tree. The edge (`parent_root`) is
/// durable in the on-disk filename; this is the in-memory index rebuilt
/// from `readdir` on load for O(1) ancestor walks.
struct UnfinalizedBlock {
    slot: u64,
    parent_root: [u8; 32],
}

/// SSZ bytes for an unfinalized column write: either a tcache ref (the usual
/// gossip/RPC path, needing a `buffer()` step to deref) or bytes owned by the
/// tile (a sidecar reconstructed in-tile from EL blobs).
#[derive(Debug)]
enum ColumnSsz {
    Ref(TRead),
    Owned(Vec<u8>),
}

impl ColumnSsz {
    fn bytes(&self) -> Result<&[u8], Error> {
        match self {
            ColumnSsz::Ref(ssz) => Ok(ssz.buffer().map_err(Error::other)?.0),
            ColumnSsz::Owned(ssz) => Ok(ssz),
        }
    }
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
        ssz: TRead,
    },
    /// New block → `unfinalized/<slot>_<parent>_<root>.ssz`.
    UnfinalizedBlock {
        slot: u64,
        parent_root: [u8; 32],
        block_root: [u8; 32],
        ssz: TRead,
    },
    /// Finalized: rename `unfinalized/…` → flat `<slot>_block.ssz`, then index.
    Promote {
        slot: u64,
        parent_root: [u8; 32],
        block_root: [u8; 32],
    },
    /// Orphaned fork below finality: unlink `unfinalized/…`.
    Prune {
        slot: u64,
        parent_root: [u8; 32],
        block_root: [u8; 32],
    },
    /// New column → `unfinalized_columns/<slot>_<block_root>_<column>.ssz`.
    UnfinalizedColumn {
        slot: u64,
        block_root: [u8; 32],
        column: u64,
        ssz: ColumnSsz,
    },
    /// Finalized: rename `unfinalized_columns/…` → flat `<slot>_<column>.ssz`.
    PromoteColumn {
        slot: u64,
        block_root: [u8; 32],
        column: u64,
    },
    /// Orphaned fork column below finality: unlink `unfinalized_columns/…`.
    PruneColumn {
        slot: u64,
        block_root: [u8; 32],
        column: u64,
    },
    TruncateBlockHistory {
        finalized_slot: u64,
    },
    TruncateColumnHistory {
        finalized_slot: u64,
    },
    Backfill {
        finalized_slot: u64,
        finalized_root: B256,
    },
    BackfillBlock {
        block_root: B256,
        slot: u64,
        ssz: TRead,
    },
    /// Kick off the data-column backfill disk scan. Runs to completion before
    /// block backfill (`Backfill`) is queued — see `io::file_io`.
    ColumnBackfillScan {
        finalized_slot: u64,
        finalized_root: B256,
    },
    PersistPeer {
        enr: Enr,
    },
    LoadPeers,
}

/// Descending cursor for the data-column backfill disk scan. Walks persisted
/// blocks from `finalized_slot` down to `floor` (= finalized − retention),
/// seeding `ColumnBackfill` with blocks whose custody columns are incomplete.
pub(super) struct ColumnScan {
    pub(super) cursor: u64,
    pub(super) floor: u64,
}

/// Sequences the two backfill phases. Column backfill runs first (disk scan of
/// present blocks = set 1, plus the columns of blocks fetched by block backfill
/// = set 2); block backfill is queued only once the scan + its set-1 requests
/// drain. `EarliestSlot` drops to the column floor only at `Done` + columns
/// complete, so we never over-advertise servable column history.
#[derive(Clone, Copy)]
pub(super) enum BlockBackfillStage {
    Idle,
    AwaitingColumns { finalized_slot: u64, finalized_root: B256 },
    Queued,
    Running,
    Done,
}

/// One served file = one response chunk. The unit's resolution (canonical
/// vs flat store) is decided up-front in `rpc_request`.
#[derive(Debug)]
enum QueryUnit {
    Block { slot: u64 },
    UnfinalizedBlock { slot: u64, parent_root: [u8; 32], block_root: [u8; 32] },
    Column { slot: u64, column: u64 },
    UnfinalizedColumn { slot: u64, block_root: [u8; 32], column: u64 },
}

/// An in-flight read request: the stream and the ordered chunks still to
/// serve for it. `file_io` serves one unit per turn then rotates the
/// request to the back of `query_queue` (head-of-line fairness across
/// streams), emitting `Complete` once `units` drains.
#[derive(Debug)]
struct PendingQuery {
    stream_id: P2pStreamId,
    units: VecDeque<QueryUnit>,
}

/// Unified blocks and data columns disk store.
pub(super) struct Store {
    store_dir: String,
    // Finalized block index: block_root → slot, persisted in block_index.bin.
    root_index: FxHashMap<[u8; 32], u64>,

    // Unfinalized block fork tree: block_root → (slot, parent_root).
    // Rebuilt from unfinalized/ filenames on load.
    unfinalized: FxHashMap<[u8; 32], UnfinalizedBlock>,
    // Unfinalized custodied columns: block_root → (slot, bitmask of columns
    // on disk). Canonicity follows the owning block; rebuilt from
    // unfinalized_columns/ filenames on load.
    unfinalized_columns: FxHashMap<[u8; 32], (u64, u128)>,
    // Latest fork-choice head + finalization watermark from Status.
    head_root: [u8; 32],
    head_slot: u64,
    finalized_slot: u64,
    finalized_root: [u8; 32],
    // Historical backfill.
    is_synced: bool,
    backfill_checked: bool,
    backfill: Option<Backfill>,
    // Data-column backfill, driven independently of block backfill and run
    // first. `column_scan` is the in-progress disk scan that seeds
    // `column_backfill`; `column_floor` is the window's lowest slot, advertised
    // as earliest-available once both backfills finish. `block_backfill_stage`
    // sequences column-then-block (see `BlockBackfillStage`).
    column_backfill: Option<ColumnBackfill>,
    column_scan: Option<ColumnScan>,
    column_floor: u64,
    block_backfill_stage: BlockBackfillStage,
    // Slot of the newest finalized-state checkpoint committed to disk.
    last_persisted_finalized_slot: u64,
    // In-flight streamed checkpoint, advanced one section per `file_io` turn.
    checkpoint: Option<CheckpointWriter>,

    write_queue: VecDeque<PendingWrite>,
    query_queue: VecDeque<PendingQuery>,
}

impl Store {
    pub(super) fn load(store_dir: String) -> Result<Self, Error> {
        let mut root_index = FxHashMap::default();

        // Try to create dirs if they do not exist.
        if !std::fs::exists(&store_dir)? {
            tracing::info!(store_dir, "create data store");
            std::fs::create_dir_all(&store_dir)?;
        }

        let blocks_dir = Path::new(&store_dir).join(BLOCKS_DIR);
        std::fs::create_dir_all(&blocks_dir)?;

        let columns_dir = Path::new(&store_dir).join(COLUMNS_DIR);
        std::fs::create_dir_all(&columns_dir)?;

        let peers_dir = Path::new(&store_dir).join(PEERS_DIR);
        std::fs::create_dir_all(&peers_dir)?;

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

        // Rebuild the unfinalized fork tree from filenames — the edges are
        // encoded in the names, so no block bodies are read.
        let unfinalized_dir = Path::new(&store_dir).join(UNFINALIZED_DIR);
        std::fs::create_dir_all(&unfinalized_dir)?;

        let mut unfinalized = FxHashMap::default();
        if let Ok(entries) = std::fs::read_dir(unfinalized_dir) {
            for entry in entries {
                if let Some(name) = entry?.file_name().to_str() &&
                    let Some((block_root, block)) = io::parse_unfinalized_name(name)
                {
                    unfinalized.insert(block_root, block);
                }
            }
        }

        // Rebuild the unfinalized column index from filenames (slot + owning
        // block_root + column index), no bodies read.
        let unfinalized_columns_dir = Path::new(&store_dir).join(UNFINALIZED_COLUMNS_DIR);
        std::fs::create_dir_all(&unfinalized_columns_dir)?;

        let mut unfinalized_columns: FxHashMap<[u8; 32], (u64, u128)> = FxHashMap::default();
        if let Ok(entries) = std::fs::read_dir(unfinalized_columns_dir) {
            for entry in entries {
                if let Some(name) = entry?.file_name().to_str() &&
                    let Some((block_root, slot, column)) =
                        io::parse_unfinalized_column_name(name)
                {
                    let e = unfinalized_columns.entry(block_root).or_insert((slot, 0));
                    e.1 |= 1u128 << column;
                }
            }
        }

        // Finalized-state checkpoints: drop incomplete dirs, prune to the
        // newest N, and anchor `last_persisted` at the newest committed slot.
        let last_persisted_finalized_slot = checkpoint::init_checkpoints_dir(&store_dir)?;

        Ok(Self {
            store_dir,
            root_index,
            unfinalized,
            unfinalized_columns,
            head_root: [0u8; 32],
            head_slot: 0,
            finalized_slot: 0,
            finalized_root: [0u8; 32],
            backfill: None,
            column_backfill: None,
            column_scan: None,
            column_floor: 0,
            block_backfill_stage: BlockBackfillStage::Idle,
            backfill_checked: false,
            is_synced: false,
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
    ) {
        if slot <= self.finalized_slot {
            // Finalized history (backfill): flat store keyed by slot.
            self.write_queue.push_back(PendingWrite::Column {
                slot,
                column: column_index,
                ssz: sidecar_ssz,
            });
            if let Entry::Vacant(e) = self.root_index.entry(block_root) {
                e.insert(slot);
                self.write_queue.push_back(PendingWrite::Index { block_root, slot });
            }
        } else {
            // Unfinalized: keyed by owning block_root, promoted/pruned with
            // the block. The caller (tile) has already validated the sidecar.
            self.unfinalized_columns.entry(block_root).or_insert((slot, 0)).1 |=
                1u128 << column_index;
            self.write_queue.push_back(PendingWrite::UnfinalizedColumn {
                slot,
                block_root,
                column: column_index,
                ssz: ColumnSsz::Ref(sidecar_ssz),
            });
        }
    }

    /// Store a data column sidecar whose bytes are owned by the tile (built
    /// in-tile from EL blobs, not borrowed from a tcache). Always unfinalized:
    /// the caller only reconstructs columns for blocks above finality.
    pub(super) fn add_unfinalized_data_column(
        &mut self,
        block_root: [u8; 32],
        column_index: u64,
        sidecar_ssz: Vec<u8>,
        slot: u64,
    ) {
        self.unfinalized_columns.entry(block_root).or_insert((slot, 0)).1 |= 1u128 << column_index;
        self.write_queue.push_back(PendingWrite::UnfinalizedColumn {
            slot,
            block_root,
            column: column_index,
            ssz: ColumnSsz::Owned(sidecar_ssz),
        });
    }

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
        if slot <= self.finalized_slot ||
            self.unfinalized.contains_key(&block_root) ||
            self.root_index.contains_key(&block_root)
        {
            return;
        }
        self.unfinalized.insert(block_root, UnfinalizedBlock { slot, parent_root });
        self.write_queue.push_back(PendingWrite::UnfinalizedBlock {
            slot,
            parent_root,
            block_root,
            ssz: block_ssz,
        });
    }

    pub(super) fn backfill_block(&mut self, ssz: TRead) {
        match self.backfill.as_mut() {
            Some(backfill) => backfill.add_block(ssz, &mut self.write_queue),
            None => {
                tracing::error!("recevied backfill lbock, but no active backfill!");
            }
        }
    }

    pub(super) fn backfill_data_column<F>(&mut self, sidecar: TRead, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let accepted = match self.column_backfill.as_mut() {
            Some(column_backfill) => column_backfill.add_sidecar(&sidecar, emit),
            None => {
                tracing::error!("received backfill data column, but no active column backfill!");
                None
            }
        };

        if let Some(accepted) = accepted {
            self.add_data_column(
                accepted.block_root,
                accepted.column_index,
                sidecar,
                accepted.slot,
            );
        }
        // Completion + earliest-available emission is polled in `file_io`'s
        // tick once both column and block backfill have drained.
    }

    pub(super) fn sync_update(&mut self, sync_update: SyncUpdate) {
        match sync_update {
            SyncUpdate::Following if !self.is_synced => {
                // First update - check whether we need to backfill history.
                tracing::info!("storage synced");
                self.is_synced = true;

                if !self.backfill_checked {
                    self.backfill_checked = true;
                    // Column backfill first: scan persisted blocks for missing
                    // columns and fetch them. Block backfill is queued by
                    // `file_io` only once this completes.
                    self.write_queue.push_back(PendingWrite::ColumnBackfillScan {
                        finalized_slot: self.finalized_slot,
                        finalized_root: self.finalized_root,
                    });
                }
            }
            _ => {
                tracing::info!("storage not synced");
                self.is_synced = false;
            }
        }
    }

    pub(super) fn is_synced(&self) -> bool {
        self.is_synced
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
        while let Some(block) = self.unfinalized.remove(&root) {
            self.root_index.insert(root, block.slot);
            self.write_queue.push_back(PendingWrite::Promote {
                slot: block.slot,
                parent_root: block.parent_root,
                block_root: root,
            });
            if let Some((slot, bitmask)) = self.unfinalized_columns.remove(&root) {
                for column in columns_of(bitmask) {
                    self.write_queue.push_back(PendingWrite::PromoteColumn {
                        slot,
                        block_root: root,
                        column,
                    });
                }
            }
            root = block.parent_root;
        }

        // Prune orphaned forks: anything left at/below finality cannot be
        // canonical (finality forbids a reorg below it).
        prune_orphaned_blocks(finalized_slot, &mut self.unfinalized, &mut self.write_queue);

        // Prune orphaned columns: any column set left at/below finality whose
        // block did not promote above.
        prune_orphaned_columns(
            finalized_slot,
            &mut self.unfinalized_columns,
            &mut self.write_queue,
        );

        // Truncate history
        self.write_queue.push_back(PendingWrite::TruncateBlockHistory { finalized_slot });
        self.write_queue.push_back(PendingWrite::TruncateColumnHistory { finalized_slot });
    }

    pub(super) fn head_slot(&self) -> u64 {
        self.head_slot
    }

    pub(super) fn finalized_slot(&self) -> u64 {
        self.finalized_slot
    }

    pub(super) fn store_dir(&self) -> &str {
        &self.store_dir
    }

    pub(super) fn head_root(&self) -> &[u8; 32] {
        &self.head_root
    }

    pub(super) fn replay_block_paths(&self, custody: u128) -> Vec<(u64, PathBuf, bool)> {
        let checkpoint_slot = self.last_persisted_finalized_slot;
        let mut paths = Vec::with_capacity(self.unfinalized.len());
        for (block_root, block) in &self.unfinalized {
            if block.slot > checkpoint_slot {
                let mask = self.unfinalized_columns.get(block_root).map_or(0, |&(_, m)| m);
                paths.push((
                    block.slot,
                    self.unfinalized_dir().join(io::unfinalized_name(
                        block.slot,
                        &block.parent_root,
                        block_root,
                    )),
                    mask & custody == custody,
                ));
            }
        }
        for &slot in self.root_index.values() {
            if slot > checkpoint_slot {
                paths.push((
                    slot,
                    self.block_slot_dir(slot).join(format!("{slot}_block.ssz")),
                    true,
                ));
            }
        }
        paths
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
            self.query_queue.push_back(PendingQuery { stream_id, units: VecDeque::new() });
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
                    let canonical = self.canonical_chain_in_range(start, end);
                    let columns: Vec<u64> =
                        DataColumnSidecarsByRangeRequestView::columns(&ssz[..len])
                            .chunks_exact(8)
                            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                            .collect();
                    // `(slot, column)` order per fulu p2p-interface: outer slot,
                    // inner column. Serve the canonical block's column from the
                    // unfinalized store, else the finalized flat store.
                    for slot in start..end {
                        for &column in &columns {
                            if let Some(&(_parent_root, block_root)) = canonical.get(&slot) {
                                units.push_back(QueryUnit::UnfinalizedColumn {
                                    slot,
                                    block_root,
                                    column,
                                });
                            } else {
                                units.push_back(QueryUnit::Column { slot, column });
                            }
                        }
                    }
                }
            }
            silver_common::RpcRequest::DataColumnsByRoot(tcache_read) => {
                let read = rpc_consumer.acquire(tcache_read);
                if let Ok((buf, _)) = read.buffer() {
                    if DataColumnsByRootIdentifierView::check_size(buf) {
                        let root = DataColumnsByRootIdentifierView::block_root(buf);
                        let request_columns = DataColumnsByRootIdentifierView::columns(buf)
                            .chunks_exact(8)
                            .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));
                        // Serve a specific block's columns regardless of
                        // canonicity: unfinalized (by block_root) first, else
                        // the finalized flat store.
                        if let Some(&(slot, _bitmask)) = self.unfinalized_columns.get(root) {
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
                }
            }
            silver_common::RpcRequest::BlocksByRange(req_bytes) => {
                let start = BeaconBlocksByRangeRequestView::start_slot(&req_bytes);
                let count =
                    BeaconBlocksByRangeRequestView::count(&req_bytes).min(MAX_REQUEST_BLOCKS);
                let end = start.saturating_add(count);
                // Per slot: the unfinalized canonical block if present, else the
                // finalized flat store (`serve_file` skips an absent slot).
                let canonical = self.canonical_chain_in_range(start, end);
                for slot in start..end {
                    if let Some(&(parent_root, block_root)) = canonical.get(&slot) {
                        units.push_back(QueryUnit::UnfinalizedBlock {
                            slot,
                            parent_root,
                            block_root,
                        });
                    } else {
                        units.push_back(QueryUnit::Block { slot });
                    }
                }
            }
            silver_common::RpcRequest::BlockByRoot(tcache_read) => {
                let read = rpc_consumer.acquire(tcache_read);
                if let Ok((buf, _)) = read.buffer() {
                    if BeaconBlocksByRootRequestView::check_size(buf) {
                        let count = BeaconBlocksByRootRequestView::count(buf);
                        for i in 0..count {
                            let root = BeaconBlocksByRootRequestView::root(buf, i);
                            // Serve any block we hold by root regardless of
                            // canonicity: unfinalized fork tree first, then the
                            // finalized flat store.
                            if let Some(&UnfinalizedBlock { slot, parent_root }) =
                                self.unfinalized.get(root)
                            {
                                units.push_back(QueryUnit::UnfinalizedBlock {
                                    slot,
                                    parent_root,
                                    block_root: *root,
                                });
                            } else if let Some(&slot) = self.root_index.get(root) {
                                units.push_back(QueryUnit::Block { slot });
                            }
                        }
                    }
                }
            }
            // Request-only for envelopes: we don't persist/serve them. Reply
            // with an empty list (empty `units` drains straight to `Complete`),
            // giving the peer a clean "none held" rather than a hung stream that
            // times out and scores us down. `ByRoot` carries a tcache handle —
            // acquire it so the inbound slot is released.
            silver_common::RpcRequest::ExecutionPayloadEnvelopesByRange(_) => {}
            silver_common::RpcRequest::ExecutionPayloadEnvelopesByRoot(tcache_read) => {
                let _ = rpc_consumer.acquire(tcache_read);
            }
            // Unhandled request kind: no response (matches prior behaviour).
            _ => return,
        }
        self.query_queue.push_back(PendingQuery { stream_id, units });
    }

    pub(super) fn persist_peer(&mut self, enr: Enr) {
        self.write_queue.push_back(PendingWrite::PersistPeer { enr });
    }

    pub(super) fn load_peers(&mut self) {
        self.write_queue.push_back(PendingWrite::LoadPeers);
    }

    /// Canonical chain blocks with slot in `[start, end)`, found by walking
    /// ancestors of the current head through the unfinalized tree. Maps
    /// slot → (parent_root, block_root). Empty before the first Status.
    fn canonical_chain_in_range(
        &self,
        start: u64,
        end: u64,
    ) -> FxHashMap<u64, ([u8; 32], [u8; 32])> {
        let mut chain = FxHashMap::default();
        let mut root = self.head_root;
        // Enforce strictly-decreasing slots towards the root. A cycle — a
        // self-parenting block or A→B→A from malformed gossip or a stale
        // on-disk filename — would otherwise spin forever: a remote DoS via
        // any BlocksByRange. Seed at head_slot+1 so the head block (whose slot
        // is head_slot) is admitted.
        let mut prev_slot = self.head_slot.saturating_add(1);
        while let Some(block) = self.unfinalized.get(&root) {
            if block.slot >= prev_slot || block.slot < start {
                break;
            }
            if block.slot < end {
                chain.insert(block.slot, (block.parent_root, root));
            }
            prev_slot = block.slot;
            root = block.parent_root;
        }
        chain
    }

    fn block_slot_dir(&self, slot: u64) -> PathBuf {
        let group_dir = slot & !(SLOTS_PER_DIR - 1);
        PathBuf::new().join(&self.store_dir).join(BLOCKS_DIR).join(group_dir.to_string())
    }

    fn column_slot_dir(&self, slot: u64) -> PathBuf {
        let group_dir = slot & !(SLOTS_PER_DIR - 1);
        PathBuf::new().join(&self.store_dir).join(COLUMNS_DIR).join(group_dir.to_string())
    }

    fn unfinalized_dir(&self) -> PathBuf {
        Path::new(&self.store_dir).join(UNFINALIZED_DIR)
    }

    fn unfinalized_columns_dir(&self) -> PathBuf {
        Path::new(&self.store_dir).join(UNFINALIZED_COLUMNS_DIR)
    }

    fn peers_dir(&self) -> PathBuf {
        Path::new(&self.store_dir).join(PEERS_DIR)
    }
}

/// Set bit positions of a column bitmask, ascending.
fn columns_of(bitmask: u128) -> impl Iterator<Item = u64> {
    (0..128u64).filter(move |c| bitmask & (1u128 << c) != 0)
}

fn prune_orphaned_columns(
    finalized_slot: u64,
    unfinalized_columns: &mut FxHashMap<[u8; 32], (u64, u128)>,
    write_queue: &mut VecDeque<PendingWrite>,
) {
    unfinalized_columns.retain(|block_root, (slot, bitmask)| {
        if *slot <= finalized_slot {
            for column in columns_of(*bitmask) {
                write_queue.push_back(PendingWrite::PruneColumn {
                    slot: *slot,
                    block_root: *block_root,
                    column,
                })
            }
            false
        } else {
            true
        }
    });
}

fn prune_orphaned_blocks(
    finalized_slot: u64,
    unfinalized: &mut FxHashMap<[u8; 32], UnfinalizedBlock>,
    write_queue: &mut VecDeque<PendingWrite>,
) {
    unfinalized.retain(|block_root, block| {
        if block.slot <= finalized_slot {
            write_queue.push_back(PendingWrite::Prune {
                slot: block.slot,
                parent_root: block.parent_root,
                block_root: *block_root,
            });
            false
        } else {
            true
        }
    });
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

    use crate::{tile::IoEvent, util};

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
        let mut store = super::Store::load(store_path.clone()).unwrap();

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
        assert!(store.unfinalized.contains_key(&root_a));
        assert!(store.unfinalized.contains_key(&root_b));

        // Head selects A; not yet finalized.
        store.update_head(slot, root_a, 0, [0u8; 32]);

        let fork_digest = [1, 2, 3, 4];
        let producer_cache = TCache::multi_producer("fork_rpc_in", 1024 * 1024);
        let mut producer = producer_cache.clone();
        store.file_io(&fork_digest, 0, &mut producer, &mut |_| {}).unwrap();

        let path_a =
            store.unfinalized_dir().join(super::io::unfinalized_name(slot, &parent_root, &root_a));
        let path_b =
            store.unfinalized_dir().join(super::io::unfinalized_name(slot, &parent_root, &root_b));
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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => byroot.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(byroot.len(), 2);
        assert_block(&byroot[0], &bytes_b);

        // Finalize at slot 42 on A: promote A, prune the orphan B.
        store.update_head(slot, root_a, slot, root_a);
        assert_eq!(store.root_index.get(&root_a), Some(&slot));
        assert!(!store.unfinalized.contains_key(&root_a));
        assert!(!store.unfinalized.contains_key(&root_b));

        store.file_io(&fork_digest, 0, &mut producer, &mut |_| {}).unwrap();
        let flat_a = store.block_slot_dir(slot).join(format!("{slot}_block.ssz"));
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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => after.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(after.len(), 2);
        assert_block(&after[0], &bytes_a);

        // Reload: finalized index persisted, unfinalized tree empty.
        let reloaded = super::Store::load(store_path.clone()).unwrap();
        assert_eq!(reloaded.root_index.get(&root_a), Some(&slot));
        assert!(reloaded.unfinalized.is_empty());

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
        let mut store = super::Store::load(store_path.clone()).unwrap();

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
        store.file_io(&[0u8; 4], 0, &mut producer, &mut |_| {}).unwrap();

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
        let mut store = super::Store::load(store_path.clone()).unwrap();

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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| {
                if let IoEvent::P2pSend(s) = s {
                    responses.push(s);
                }
            })
            .unwrap();

        assert_eq!(responses.len(), 1, "empty envelope response is just Complete");
        assert!(matches!(
            &responses[0],
            P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                response: RpcResponse::Complete,
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
        let mut store = super::Store::load(store_path.clone()).unwrap();
        let ucol_dir = store.unfinalized_columns_dir();
        let flat_dir = store.column_slot_dir(42);

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
        store.add_data_column(root_a, 3, consumer.acquire(ssz_a3), slot);
        store.add_data_column(root_a, 7, consumer.acquire(ssz_a7), slot);
        store.add_data_column(root_b, 3, consumer.acquire(ssz_b3), slot);
        assert!(store.unfinalized_columns.contains_key(&root_a));
        assert!(store.unfinalized_columns.contains_key(&root_b));

        store.update_head(slot, root_a, 0, [0u8; 32]);

        let fork_digest = [9, 9, 9, 9];
        let producer_cache = TCache::multi_producer("colfork_rpc_in", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(&fork_digest, 0, &mut producer, &mut |_| {}).unwrap();
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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => responses.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(responses.len(), 3); // canonical A columns 3 + 7, then Complete
        assert_col(&responses[0], &a3);
        assert_col(&responses[1], &a7);

        // DataColumnsByRoot for the fork B's column 3: served despite B being
        // non-canonical. SSZ: block_root | offset(=36) | column list.
        let mut byroot = [0u8; 44];
        byroot[0..32].copy_from_slice(&root_b);
        byroot[32..36].copy_from_slice(&36u32.to_le_bytes());
        byroot[36..44].copy_from_slice(&3u64.to_le_bytes());
        let mut br_res = req_producer.reserve(44, true).unwrap();
        br_res.write_all(&byroot).unwrap();
        br_res.flush().unwrap();
        let byroot_ssz = br_res.read();
        store.rpc_request(&mut req_consumer, RpcRequestInbound {
            stream_id: sid,
            request: RpcRequest::DataColumnsByRoot(byroot_ssz),
        });
        let mut br = vec![];
        store
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => br.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(br.len(), 2); // B column 3 + Complete
        assert_col(&br[0], &b3);

        // Finalize on A at slot 42: promote A's columns, prune B's.
        store.update_head(slot, root_a, slot, root_a);
        assert!(store.unfinalized_columns.is_empty());

        store.file_io(&fork_digest, 0, &mut producer, &mut |_| {}).unwrap();
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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
                IoEvent::P2pSend(s) => after.push(s),
                _ => {}
            })
            .unwrap();
        assert_eq!(after.len(), 3);
        assert_col(&after[0], &a3);
        assert_col(&after[1], &a7);

        // Reload: finalized index persisted, unfinalized column index empty.
        let reloaded = super::Store::load(store_path.clone()).unwrap();
        assert!(reloaded.unfinalized_columns.is_empty());
        assert_eq!(reloaded.root_index.get(&root_a), Some(&slot));

        let _ = std::fs::remove_dir_all(&store_path);
    }

    #[test]
    fn backfill_block_persists_root_index() {
        use silver_common::{TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_backfill_index_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = super::Store::load(store_path.clone()).unwrap();

        let slot = 64u64;
        let parent_root = [0x42; 32];
        let state_root = [0x24; 32];
        let mut block = vec![0u8; 184];
        block[100..108].copy_from_slice(&slot.to_le_bytes());
        block[108..116].copy_from_slice(&7u64.to_le_bytes());
        block[116..148].copy_from_slice(&parent_root);
        block[148..180].copy_from_slice(&state_root);
        let block_root = util::block_root_fulu(&block);

        let mut blocks = TCache::producer("backfill_index_blocks", 1 << 20);
        let mut res = blocks.reserve(block.len(), true).unwrap();
        res.write_all(&block).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut consumer = blocks.cache_ref().random_access("backfill_index_cons", true).unwrap();

        store.backfill = Some(super::Backfill::new(slot..slot + 1, block_root));
        store.backfill_block(consumer.acquire(ssz));

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("backfill_index_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        store.file_io(&fork_digest, 0, &mut producer, &mut |_| {}).unwrap();

        assert_eq!(store.root_index.get(&block_root), Some(&slot));
        assert!(store.block_slot_dir(slot).join(format!("{slot}_block.ssz")).exists());

        let reloaded = super::Store::load(store_path.clone()).unwrap();
        assert_eq!(reloaded.root_index.get(&block_root), Some(&slot));

        let _ = std::fs::remove_dir_all(&store_path);
    }

    #[test]
    fn persisted_backfill_block_requests_data_columns() {
        use silver_common::{PeerEvent, TCache, TCacheProducer};

        let store_path = format!("/tmp/test_store_column_backfill_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);
        let mut store = super::Store::load(store_path.clone()).unwrap();

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
        let block_root = util::block_root_fulu(&block);

        let mut blocks = TCache::producer("column_backfill_blocks", 1 << 20);
        let mut res = blocks.reserve(block.len(), true).unwrap();
        res.write_all(&block).unwrap();
        res.flush().unwrap();
        let ssz = res.read();
        let mut consumer = blocks.cache_ref().random_access("column_backfill_cons", true).unwrap();

        // Column backfill is live across the block-backfill phase: a block
        // fetched by block backfill in the column window (set 2) must request
        // its columns via the `BackfillBlock` feed.
        store.column_backfill = Some(super::ColumnBackfill::new(1..slot + 1));
        store.backfill = Some(super::Backfill::new(slot..slot + 1, block_root));
        store.backfill_block(consumer.acquire(ssz));

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("column_backfill_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        let custody_columns = (1u128 << 3) | (1u128 << 7);
        let mut needs = Vec::new();
        store
            .file_io(&fork_digest, custody_columns, &mut producer, &mut |io| {
                if let IoEvent::PeerEvent(PeerEvent::ColumnNeed { block_root, missing, .. }) = io {
                    needs.push((missing, block_root));
                }
            })
            .unwrap();

        // Storage reports the need; the SyncEngine schedules the by-root fetch.
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].0, custody_columns);
        assert_eq!(needs[0].1, block_root);
        assert_eq!(store.root_index.get(&block_root), Some(&slot));

        let _ = std::fs::remove_dir_all(&store_path);
    }

    // Set 1: a block already on disk (from sync, columns skipped) with missing
    // columns must be picked up by the column-backfill disk scan and requested
    // — block backfill is never triggered for it (the block is present).
    #[test]
    fn column_scan_requests_missing_columns_for_persisted_block() {
        use silver_common::{PeerEvent, TCache};

        use crate::tile::IoEvent;

        let store_path = format!("/tmp/test_store_column_scan_{}", rand::random::<u32>());
        let mut store = super::Store::load(store_path.clone()).unwrap();

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
        let block_root = util::block_root_fulu(&block);

        // Block on disk, no columns — exactly the post-sync state.
        let dir = store.block_slot_dir(slot);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{slot}_block.ssz")), &block).unwrap();

        // Trigger the scan (as sync_update(Following) would) and run file_io.
        store.finalized_slot = slot;
        store.write_queue.push_back(super::PendingWrite::ColumnBackfillScan {
            finalized_slot: slot,
            finalized_root: [0u8; 32],
        });

        let fork_digest = [0u8; 4];
        let producer_cache = TCache::multi_producer("column_scan_rpc", 1 << 20);
        let mut producer = producer_cache.clone();
        let custody_columns = (1u128 << 3) | (1u128 << 7);
        let mut needs = Vec::new();
        store
            .file_io(&fork_digest, custody_columns, &mut producer, &mut |io| {
                if let IoEvent::PeerEvent(PeerEvent::ColumnNeed { block_root, missing, .. }) = io {
                    needs.push((missing, block_root));
                }
            })
            .unwrap();

        assert_eq!(needs.len(), 1, "scan should report the persisted block's missing columns");
        assert_eq!(needs[0].0, custody_columns);
        assert_eq!(needs[0].1, block_root);

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
        let mut store = super::Store::load(store_path.clone()).unwrap();

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
        store.file_io(&fork_digest, 0, &mut producer, &mut |_| {}).unwrap(); // flush block writes

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
            .file_io(&fork_digest, 0, &mut producer, &mut |s| match s {
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
