use std::{collections::VecDeque, ops::Range};

use fxhash::FxHashMap;
use silver_common::{
    PeerEvent, TRead,
    ssz_hash::B256,
    ssz_view::{DataColumnSidecarView, SignedBeaconBlockView},
};

use crate::{store::PendingWrite, util};

/// Block-history backfill **tracker**. Issuance moved to the control-tile
/// `SyncEngine`; storage reports the gap via `PeerEvent::BackfillState` and
/// here only links + writes arriving blocks and detects completion (the chain
/// has been filled down to the gap floor). Block backfill emits no
/// `EarliestSlot`: the advertised earliest-available slot tracks data columns,
/// not blocks.
pub(super) struct Backfill {
    range: Range<u64>,
    // buffered blocks keyed by block root
    buffered_blocks: FxHashMap<B256, (u64, B256, TRead)>,
    next_parent: B256,
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
            buffered_blocks: FxHashMap::default(),
            next_parent,
            earliest_written: range_end + 1,
            blocks_complete: false,
        }
    }

    /// Link an arriving backfill block to the chain and queue it for write.
    /// Blocks arrive child-first; each links to `next_parent` and drains the
    /// buffer downward. Complete once the chain reaches the gap floor.
    pub(super) fn add_block(&mut self, ssz: TRead, write_queue: &mut VecDeque<PendingWrite>) {
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

        if self.earliest_written <= self.range.start {
            self.blocks_complete = true;
        }
    }

    pub(super) fn is_complete(&self) -> bool {
        self.blocks_complete
    }
}

/// Data-column backfill **tracker**, independent of block backfill. Seeded by
/// an on-disk scan of persisted blocks in the column-retention window (set 1)
/// and by block backfill pulling blob-carrying blocks in (set 2). For each such
/// block it reports the missing custody columns via `PeerEvent::ColumnNeed`;
/// the `SyncEngine` fetches them by-root. Storage tracks per-block completeness
/// (it sees the sidecars) and clears the need (`ColumnNeed { missing: 0 }`)
/// once a block's columns are all on disk.
pub(super) struct ColumnBackfill {
    range: Range<u64>,
    // Every block awaiting columns, keyed by block root.
    pending: FxHashMap<B256, PendingColumnBlock>,
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
        Self { range, pending: FxHashMap::default(), scan_complete: false }
    }

    /// Seed a block found by the disk scan / block backfill. `missing` is the
    /// custody columns not already on disk; reports the need to the engine.
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

        self.pending.insert(block_root, PendingColumnBlock {
            slot,
            proposer_index: SignedBeaconBlockView::proposer_index(block),
            parent_root: *SignedBeaconBlockView::parent_root(block),
            state_root: *SignedBeaconBlockView::state_root(block),
            body_root: util::body_root(SignedBeaconBlockView::body(block)),
            signature: *SignedBeaconBlockView::signature(block),
            requested: missing,
            received: 0,
        });
        emit(PeerEvent::ColumnNeed { block_root, slot, missing });
    }

    /// Validate + record a received backfill sidecar. On the block's final
    /// column, clears the need (`ColumnNeed { missing: 0 }`).
    pub(super) fn add_sidecar<F>(&mut self, sidecar: &TRead, emit: &mut F) -> Option<AcceptedColumn>
    where
        F: FnMut(PeerEvent),
    {
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
            emit(PeerEvent::ColumnNeed { block_root, slot, missing: 0 });
        }

        Some(AcceptedColumn { block_root, slot, column_index })
    }

    /// Complete = disk scan finished AND no block awaiting columns.
    pub(super) fn is_complete(&self) -> bool {
        self.scan_complete && self.pending.is_empty()
    }

    pub(super) fn mark_scan_complete(&mut self) {
        self.scan_complete = true;
    }
}
