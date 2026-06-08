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
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, BLOCKS_BY_RANGE_REQ_SIZE, DataColumnSidecarView,
        SignedBeaconBlockView,
    },
};

use crate::{
    store::{COLUMN_SLOTS_RETAINED, MAX_REQUEST_BLOCKS, PendingWrite},
    // common::{BACKFILL_REQUEST_ID, COLUMN_BACKFILL_REQUEST_ID},
    util,
};

const COLUMN_BACKFILL_WHEEL_BUCKETS: usize = 16;
const COLUMN_BACKFILL_WHEEL_INTERVAL: Duration = Duration::from_millis(625);

pub(super) struct Backfill {
    range: Range<u64>,
    // buffered blocks keyed by block root
    buffered_blocks: FxHashMap<B256, (u64, B256, TRead)>,
    next_parent: B256,
    request_id: u64,
    in_flight: Option<(Range<u64>, u64, Instant)>,
    earliest_written: u64,
    blocks_complete: bool,
    columns: Option<ColumnBackfill>,
}

pub(super) struct AcceptedColumn {
    pub(super) block_root: B256,
    pub(super) slot: u64,
    pub(super) column_index: u64,
}

impl Backfill {
    pub(super) fn new(range: Range<u64>, next_parent: B256) -> Self {
        let range_end = range.end;
        let column_start = range_end.saturating_sub(COLUMN_SLOTS_RETAINED).max(range.start);
        let columns =
            (column_start < range_end).then(|| ColumnBackfill::new(column_start..range_end));
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
            columns,
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

    pub(super) fn block_persisted<F>(
        &mut self,
        block_root: B256,
        slot: u64,
        block: &[u8],
        custody_columns: u128,
        emit: &mut F,
    ) where
        F: FnMut(PeerEvent),
    {
        if let Some(columns) = self.columns.as_mut() {
            columns.block_persisted(block_root, slot, block, custody_columns, emit);
        }
    }

    pub(super) fn add_data_column<F>(
        &mut self,
        sidecar: &TRead,
        emit: &mut F,
    ) -> Option<AcceptedColumn>
    where
        F: FnMut(PeerEvent),
    {
        let accepted = self.columns.as_mut()?.add_sidecar(sidecar)?;
        self.maybe_emit_earliest(emit);
        Some(accepted)
    }

    /// Returns `true` if backfilling is complete.
    pub(super) fn query_complete<F>(&mut self, id: u64, emit: &mut F) -> bool
    where
        F: FnMut(PeerEvent),
    {
        if self.in_flight.as_ref().map(|(_, request_id, _)| *request_id != id).unwrap_or_default() {
            return false;
        }
        if let Some((in_flight, _, _)) = self.in_flight.take() {
            if self.earliest_written < in_flight.end {
                // the previous request returned something,
                self.range.end = self.earliest_written.max(in_flight.start);
                self.update_column_scan();
                self.maybe_emit_earliest(emit);
            }
        }
        if self.range.end == self.range.start {
            tracing::info!("backfill blocks complete");
            self.blocks_complete = true;
            self.update_column_scan();
            self.maybe_emit_earliest(emit);
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
        if !self.blocks_complete &&
            let Some((_, request_id, start)) = self.in_flight.as_ref() &&
            start.elapsed() > Duration::from_secs(10)
        {
            self.query_complete(*request_id, emit);
        }
        if let Some(columns) = self.columns.as_mut() {
            columns.tick(emit);
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.blocks_complete &&
            self.columns.as_ref().map(ColumnBackfill::is_complete).unwrap_or(true)
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

        let mut request = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        request[..8].copy_from_slice(&next_start_slot.to_le_bytes());
        request[8..16].copy_from_slice(&count.to_le_bytes());
        request[16..].copy_from_slice(&1u64.to_le_bytes());

        emit(PeerEvent::SendRpcRequest { request_id, rpc: BlocksByRange(request) });
        self.in_flight =
            Some((next_start_slot..next_start_slot + count, request_id, Instant::now()));
    }

    fn update_column_scan(&mut self) {
        if let Some(columns) = self.columns.as_mut() &&
            (self.blocks_complete || self.range.end <= columns.range.start)
        {
            columns.mark_scan_complete();
        }
    }

    fn maybe_emit_earliest<F>(&self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let earliest = if let Some(columns) = self.columns.as_ref() &&
            !columns.is_complete()
        {
            columns.range.end
        } else {
            self.earliest_written
        };
        emit(PeerEvent::EarliestSlot(earliest));
    }
}

struct ColumnBackfill {
    range: Range<u64>,
    pending: Wheel<B256, PendingColumnBlock, COLUMN_BACKFILL_WHEEL_BUCKETS>,
    pending_count: usize,
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
    fn new(range: Range<u64>) -> Self {
        Self {
            range,
            pending: Wheel::new(COLUMN_BACKFILL_WHEEL_INTERVAL),
            pending_count: 0,
            request_id: COLUMN_BACKFILL_REQUEST_ID,
            scan_complete: false,
        }
    }

    fn block_persisted<F>(
        &mut self,
        block_root: B256,
        slot: u64,
        block: &[u8],
        custody_columns: u128,
        emit: &mut F,
    ) where
        F: FnMut(PeerEvent),
    {
        if custody_columns == 0 || !self.range.contains(&slot) {
            return;
        }
        if block.len() < 184 + BEACON_BLOCK_BODY_FIXED || !util::has_data_columns(block) {
            return;
        }
        if self.pending.contains(&block_root) {
            return;
        }

        let pending = PendingColumnBlock {
            slot,
            proposer_index: SignedBeaconBlockView::proposer_index(block),
            parent_root: *SignedBeaconBlockView::parent_root(block),
            state_root: *SignedBeaconBlockView::state_root(block),
            body_root: util::body_root(SignedBeaconBlockView::body(block)),
            signature: *SignedBeaconBlockView::signature(block),
            requested: custody_columns,
            received: 0,
        };
        self.pending.insert(block_root, pending);
        self.pending_count += 1;
        self.emit_request(block_root, custody_columns, emit);
    }

    fn add_sidecar(&mut self, sidecar: &TRead) -> Option<AcceptedColumn> {
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
            self.pending.remove(&block_root);
            self.pending_count = self.pending_count.saturating_sub(1);
        }

        Some(AcceptedColumn { block_root, slot, column_index })
    }

    fn tick<F>(&mut self, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let now = Instant::now();
        let mut request_id = self.request_id;
        let mut complete = 0;
        self.pending.maybe_rotate(now, &mut |block_root, pending| {
            let columns = pending.requested & !pending.received;
            if columns == 0 {
                complete += 1;
                true
            } else {
                request_id += 1;
                emit(PeerEvent::SendDataColumnsByRootRequest {
                    request_id,
                    columns,
                    block_root: *block_root,
                });
                false
            }
        });
        self.pending_count = self.pending_count.saturating_sub(complete);
        self.request_id = request_id;
    }

    fn is_complete(&self) -> bool {
        self.scan_complete && self.pending_count == 0
    }

    fn mark_scan_complete(&mut self) {
        self.scan_complete = true;
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
