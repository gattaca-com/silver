use std::{
    collections::VecDeque,
    ops::Range,
    time::{Duration, Instant},
};

use fxhash::FxHashMap;
use silver_common::{
    BACKFILL_REQUEST_ID, COLUMN_BACKFILL_REQUEST_ID, PeerEvent,
    RpcRequest::BlocksByRange,
    TRead, Wheel,
    ssz_hash::B256,
    ssz_view::{BLOCKS_BY_RANGE_REQ_SIZE, DataColumnSidecarView, SignedBeaconBlockView},
};

use crate::{
    store::{MAX_REQUEST_BLOCKS, PendingWrite},
    util,
};

/// Max column-backfill `DataColumnSidecarsByRoot` requests in flight at once.
/// The seeded backlog is drained a few blocks at a time rather than flooding
/// the network tile / peers with the whole retention window.
pub(super) const MAX_COLUMN_REQUESTS_IN_FLIGHT: usize = 4;
/// In-flight retry timer: an entry sits a full wheel revolution
/// (`BUCKETS × INTERVAL` ≈ 3s) before its bucket comes back around and it's
/// re-requested. Each received column re-buckets it to the head (resets the
/// timer), so an actively-delivering request is never retried mid-stream.
const COLUMN_REQUEST_WHEEL_BUCKETS: usize = 4;
const COLUMN_REQUEST_WHEEL_INTERVAL: Duration = Duration::from_millis(750);

/// Block-history backfill. Blocks only — data-column backfill is a separate,
/// disk-scan-driven concern (`ColumnBackfill`) that runs to completion *before*
/// block backfill starts. Block backfill therefore emits no `EarliestSlot`:
/// the advertised earliest-available slot tracks data columns, not blocks.
pub(super) struct Backfill {
    range: Range<u64>,
    // buffered blocks keyed by block root
    buffered_blocks: FxHashMap<B256, (u64, B256, TRead)>,
    next_parent: B256,
    request_id: u64,
    in_flight: Option<(Range<u64>, u64)>,
    earliest_written: u64,
    blocks_complete: bool,
}

pub(super) struct AcceptedColumn {
    pub(super) block_root: B256,
    pub(super) slot: u64,
    pub(super) column_index: u64,
}

impl Backfill {
    pub(super) fn new(range: Range<u64>, next_parent: B256) -> Self {
        let range_end = range.end;
        Self {
            range,
            buffered_blocks: FxHashMap::with_capacity_and_hasher(
                MAX_REQUEST_BLOCKS as usize,
                Default::default(),
            ),
            next_parent,
            request_id: BACKFILL_REQUEST_ID,
            in_flight: None,
            earliest_written: range_end + 1,
            blocks_complete: false,
        }
    }

    pub(super) fn start<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        self.range_request(emit);
    }

    pub(super) fn add_block(&mut self, ssz: TRead, write_queue: &mut VecDeque<PendingWrite>) {
        // is this the next parent block we are waiting for?
        let buffer = match ssz.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, "failed to read backfill beacon block cache buffer");
                return;
            }
        };

        let new_block_root = util::block_root(buffer);
        let slot = SignedBeaconBlockView::slot(buffer);
        let new_parent_root = *SignedBeaconBlockView::parent_root(buffer);

        self.buffered_blocks.insert(new_block_root, (slot, new_parent_root, ssz));

        while let Some((slot, parent_root, ssz)) = self.buffered_blocks.remove(&self.next_parent) {
            let block_root = self.next_parent;
            write_queue.push_back(PendingWrite::BackfillBlock { block_root, slot, ssz });
            self.earliest_written = self.earliest_written.min(slot);
            self.next_parent = parent_root;
        }
    }

    /// Returns `true` if backfilling is complete.
    pub(super) fn query_complete<F>(&mut self, id: u64, emit: &mut F) -> bool
    where
        F: FnMut(PeerEvent),
    {
        if self.in_flight.as_ref().map(|(_, request_id)| *request_id != id).unwrap_or_default() {
            return false;
        }
        if let Some((in_flight, _)) = self.in_flight.take() {
            if self.earliest_written < in_flight.end {
                // the previous request returned something,
                self.range.end = self.earliest_written.max(in_flight.start);
            }
        }
        if self.range.end == self.range.start {
            tracing::info!("backfill blocks complete");
            self.blocks_complete = true;
            return self.is_complete();
        }
        self.buffered_blocks.clear();
        self.range_request(emit);
        false
    }

    pub(super) fn tick<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let _ = emit;
        // The peer manager owns retry timing for outbound BlocksByRange
        // attempts. Storage only advances the backfill range when the
        // network delivers a terminal Complete for the active request id.
    }

    pub(super) fn is_complete(&self) -> bool {
        self.blocks_complete
    }

    fn range_request<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let next_start_slot =
            (self.range.end.saturating_sub(MAX_REQUEST_BLOCKS)).max(self.range.start);
        let count = self.range.end - next_start_slot;
        let request_id = self.request_id;
        self.request_id += 1;

        tracing::debug!(next_start_slot, count, "backfill blocks by range");

        let mut request = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        request[..8].copy_from_slice(&next_start_slot.to_le_bytes());
        request[8..16].copy_from_slice(&count.to_le_bytes());
        request[16..].copy_from_slice(&1u64.to_le_bytes());

        emit(PeerEvent::SendRpcRequest { request_id, rpc: BlocksByRange(request) });
        self.in_flight = Some((next_start_slot..next_start_slot + count, request_id));
    }
}

/// Data-column backfill, independent of block backfill. Seeded by an on-disk
/// scan of persisted blocks in the column-retention window (`io::file_io`):
/// for each block carrying blob commitments whose custody columns aren't all
/// present on disk, the missing columns are requested by root. Sync skips
/// columns for blocks below the finalized epoch, so a fully block-synced node
/// still needs this to fetch their columns — block backfill alone won't.
pub(super) struct ColumnBackfill {
    range: Range<u64>,
    // Every block awaiting columns (queued or in flight), keyed by block root.
    pending: FxHashMap<B256, PendingColumnBlock>,
    // Roots seeded but not yet requested — FIFO backlog.
    queue: VecDeque<B256>,
    // Roots with a request in flight. A timing wheel doubles as the retry
    // timer: rotation expires idle requests (event-driven, no per-tick scan),
    // and `len()` bounds concurrency. `queue` and `in_flight` are disjoint.
    in_flight: Wheel<B256, (), COLUMN_REQUEST_WHEEL_BUCKETS>,
    request_id: u64,
    scan_complete: bool,
}

struct PendingColumnBlock {
    slot: u64,
    proposer_index: u64,
    parent_root: B256,
    state_root: B256,
    body_root: B256,
    signature: [u8; 96],
    requested: u128,
    received: u128,
}

impl ColumnBackfill {
    pub(super) fn new(range: Range<u64>) -> Self {
        Self {
            range,
            pending: FxHashMap::default(),
            queue: VecDeque::new(),
            in_flight: Wheel::new(COLUMN_REQUEST_WHEEL_INTERVAL),
            request_id: COLUMN_BACKFILL_REQUEST_ID,
            scan_complete: false,
        }
    }

    /// Seed a block found by the disk scan. `missing` is the set of custody
    /// columns not already on disk for this block (computed by the scanner);
    /// callers must pass a non-zero `missing` for a block carrying columns.
    pub(super) fn seed_block<F>(
        &mut self,
        block_root: B256,
        slot: u64,
        block: &[u8],
        missing: u128,
        emit: &mut F,
    ) where
        F: FnMut(PeerEvent),
    {
        if missing == 0 || !self.range.contains(&slot) || self.pending.contains_key(&block_root) {
            return;
        }

        let pending = PendingColumnBlock {
            slot,
            proposer_index: SignedBeaconBlockView::proposer_index(block),
            parent_root: *SignedBeaconBlockView::parent_root(block),
            state_root: *SignedBeaconBlockView::state_root(block),
            body_root: util::body_root(SignedBeaconBlockView::body(block)),
            signature: *SignedBeaconBlockView::signature(block),
            requested: missing,
            received: 0,
        };
        self.pending.insert(block_root, pending);
        self.queue.push_back(block_root);
        // Only fires if under the in-flight cap; otherwise the block waits in
        // the backlog and is drained by `tick`/`pump` as slots free up.
        self.pump(emit);
    }

    pub(super) fn add_sidecar(&mut self, sidecar: &TRead) -> Option<AcceptedColumn> {
        let buffer = match sidecar.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, "failed to read backfill data column sidecar cache buffer");
                return None;
            }
        };

        if !util::verify_data_column_sidecar(buffer) {
            tracing::warn!("badly formed backfill data column sidecar");
            return None;
        }
        if !util::verify_data_column_sidecar_kzg_proofs(buffer) {
            tracing::warn!("failed to verify backfill sidecar kzg proof");
            return None;
        }
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!("failed to verify backfill sidecar inclusion proof");
            return None;
        }

        let block_root = util::block_root_from_sidecar(buffer);
        let column_index = DataColumnSidecarView::index(buffer);
        let column_bitmask = 1u128 << column_index;
        let (slot, complete) = {
            let expected = match self.pending.get_mut(&block_root) {
                Some(expected) => expected,
                None => {
                    tracing::warn!(
                        block_root = hex::encode(block_root),
                        "unrequested backfill data column sidecar"
                    );
                    return None;
                }
            };
            if expected.requested & column_bitmask == 0 {
                tracing::warn!(column_index, "backfill sidecar column was not requested");
                return None;
            }
            if expected.received & column_bitmask != 0 {
                return None;
            }
            if DataColumnSidecarView::slot(buffer) != expected.slot ||
                DataColumnSidecarView::proposer_index(buffer) != expected.proposer_index ||
                DataColumnSidecarView::parent_root(buffer) != &expected.parent_root ||
                DataColumnSidecarView::state_root(buffer) != &expected.state_root ||
                DataColumnSidecarView::body_root(buffer) != &expected.body_root ||
                DataColumnSidecarView::block_signature(buffer) != &expected.signature
            {
                tracing::warn!(
                    block_root = hex::encode(block_root),
                    column_index,
                    "backfill sidecar header does not match block"
                );
                return None;
            }

            expected.received |= column_bitmask;
            let complete = expected.received & expected.requested == expected.requested;
            (expected.slot, complete)
        };

        if complete {
            // Frees an in-flight slot; `tick`/`pump` requests the next backlog
            // block on the following loop.
            self.pending.remove(&block_root);
            self.in_flight.remove(&block_root);
        } else if self.in_flight.remove(&block_root).is_some() {
            // Progress: re-bucket to the head so the retry timer resets and an
            // actively-delivering request isn't retried mid-stream.
            self.in_flight.insert(block_root, ());
        }

        Some(AcceptedColumn { block_root, slot, column_index })
    }

    pub(super) fn tick<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        // Expire in-flight requests idle for a full wheel revolution. The
        // rotation closure only collects roots (it can't borrow `self.pending`
        // / `emit`); re-request + reset happens below where borrows are free.
        Self::rotate(&mut self.in_flight, &self.pending, &mut self.request_id, emit);
        self.pump(emit);
    }

    fn rotate<F>(
        wheel: &mut Wheel<B256, (), COLUMN_REQUEST_WHEEL_BUCKETS>,
        pending: &FxHashMap<B256, PendingColumnBlock>,
        request_id: &mut u64,
        emit: &mut F,
    ) where
        F: FnMut(PeerEvent),
    {
        wheel.maybe_rotate(Instant::now(), &mut |root, _| {
            if let Some(p) = pending.get(root) {
                let columns = p.requested & !p.received;
                if columns != 0 {
                    emit(PeerEvent::SendDataColumnsByRootRequest {
                        request_id: *request_id,
                        columns,
                        block_root: *root,
                    });
                    *request_id += 1;
                    return false; // re-bucket to head = reset
                }
            }
            true
        });
    }

    /// Complete = disk scan finished AND no block awaiting columns. Both the
    /// scan (set 1) and block-backfill `seed_block` calls (set 2) feed
    /// `pending`, so this only holds once every column in the window is on
    /// disk.
    pub(super) fn is_complete(&self) -> bool {
        self.scan_complete && self.pending.is_empty()
    }

    pub(super) fn mark_scan_complete(&mut self) {
        self.scan_complete = true;
    }

    /// Promote backlog roots to in-flight requests up to the concurrency cap.
    fn pump<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        while self.in_flight.len() < MAX_COLUMN_REQUESTS_IN_FLIGHT {
            let Some(root) = self.queue.pop_front() else {
                break; // backlog drained
            };
            // May have completed (and been removed) since it was queued.
            let Some(p) = self.pending.get(&root) else {
                continue;
            };
            let columns = p.requested & !p.received;
            self.emit_request(root, columns, emit);
            self.in_flight.insert(root, ());
        }
    }

    fn emit_request<F>(&mut self, block_root: B256, columns: u128, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let request_id = self.request_id;
        self.request_id += 1;
        emit(PeerEvent::SendDataColumnsByRootRequest { request_id, columns, block_root });
    }
}
