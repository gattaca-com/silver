use std::{collections::VecDeque, ops::Range, sync::Arc, time::Instant};

use fxhash::FxHashMap;
use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig};
use silver_common::{DataKind, SyncNeed, TRead, merkle::B256};

use super::{
    COLUMN_SLOTS_RETAINED, Payload, PendingWrite,
    backfill::{Backfill, ColumnBackfill, EnvelopeBackfill, RejectedSidecar, VerifiedColumns},
};

/// Sequences the two backfill phases. Column backfill runs first (disk scan of
/// present blocks = set 1, plus the columns of blocks fetched by block backfill
/// = set 2); block backfill is queued only once the scan + its set-1 requests
/// drain.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(super) enum BlockBackfillStage {
    #[default]
    Idle,
    AwaitingColumns {
        finalized_slot: u64,
        finalized_root: B256,
    },
    Queued,
    Running,
    Done,
}

/// The descending disk scan that seeds set 1. `floor` is inclusive.
pub(super) struct ColumnScan {
    pub(super) cursor: u64,
    pub(super) floor: u64,
}

#[derive(Default)]
pub(super) struct HistoryBackfill {
    pub(super) blocks: Option<Backfill>,
    pub(super) columns: Option<ColumnBackfill>,
    pub(super) envelopes: Option<EnvelopeBackfill>,
    pub(super) scan: Option<ColumnScan>,
    pub(super) stage: BlockBackfillStage,
    /// The floor the retired walks reached. `None` until one retires: before
    /// that nothing below the anchor is held.
    pub(super) retired_floor: Option<u64>,
    /// The claim last published from that floor.
    pub(super) claimed_earliest: Option<u64>,
    /// The span last published for each kind, indexed by [`DataKind::index`].
    /// Empty to start with: nothing is owed until a walk says so.
    published_spans: [(u64, u64); 3],
    checked: bool,
}

impl HistoryBackfill {
    pub(super) fn check_disk_once(&mut self) -> bool {
        let first = !self.checked;
        self.checked = true;
        first
    }

    /// Arm the column and envelope walks over the window each retains, and the
    /// scan that seeds them. Block backfill waits for that scan to drain.
    pub(super) fn start(&mut self, finalized_slot: u64, finalized_root: B256, spec: &SpecConfig) {
        let floor = finalized_slot.saturating_sub(COLUMN_SLOTS_RETAINED).max(1);
        self.columns = Some(ColumnBackfill::new(floor..finalized_slot + 1));
        self.scan = Some(ColumnScan { cursor: finalized_slot, floor });
        self.stage = BlockBackfillStage::AwaitingColumns { finalized_slot, finalized_root };
        self.envelopes = (spec.gloas_fork_slot() <= finalized_slot).then(|| {
            let to_retain =
                Payload::Envelope.slots_retained(spec, finalized_slot / SLOTS_PER_EPOCH);
            let floor = finalized_slot.saturating_sub(to_retain).max(spec.gloas_fork_slot());
            tracing::info!(
                finalized_slot,
                to_retain,
                gloas_fork_slot = spec.gloas_fork_slot(),
                floor,
                "envelope backfill armed"
            );
            EnvelopeBackfill::new(floor..finalized_slot + 1)
        });
    }

    pub(super) fn start_blocks(&mut self, range: Range<u64>, parent: B256, spec: Arc<SpecConfig>) {
        self.blocks = Some(Backfill::new(range, parent, spec));
        self.stage = BlockBackfillStage::Running;
    }

    pub(super) fn no_block_gap(&mut self) {
        self.stage = BlockBackfillStage::Done;
    }

    pub(super) fn step(&mut self, write_queue: &mut VecDeque<PendingWrite>) {
        if let BlockBackfillStage::AwaitingColumns { finalized_slot, finalized_root } = self.stage &&
            self.scan.is_none() &&
            self.columns_drained()
        {
            // Queued rather than sized here: `earliest_block` lists every group
            // directory in the retention window, which belongs in the budgeted
            // drain and not on top of the caller's scan step. `Queued` keeps the
            // push one-shot.
            write_queue
                .push_back(PendingWrite::StartBlockBackfill { finalized_slot, finalized_root });
            self.stage = BlockBackfillStage::Queued;
        }

        if self.blocks.as_ref().is_some_and(Backfill::is_complete) {
            let floor = self.blocks.take().expect("just checked").earliest_written();
            self.retire_floor(floor);
            self.stage = BlockBackfillStage::Done;
        }

        let blocks_unwritten =
            write_queue.iter().any(|w| matches!(w, PendingWrite::BackfillBlock { .. }));
        if self.stage == BlockBackfillStage::Done &&
            !blocks_unwritten &&
            self.columns_drained() &&
            self.envelopes_drained()
        {
            if let Some(columns) = self.columns.take() {
                self.retire_floor(columns.servable_floor());
            }
            if let Some(envelopes) = self.envelopes.take() {
                self.retire_floor(envelopes.servable_floor());
            }
            self.stage = BlockBackfillStage::Idle;
        }
    }

    fn columns_drained(&self) -> bool {
        self.columns.as_ref().is_none_or(ColumnBackfill::is_complete)
    }

    fn envelopes_drained(&self) -> bool {
        self.envelopes.as_ref().is_none_or(EnvelopeBackfill::is_complete)
    }

    pub(super) fn take_scan_if_ready(&mut self, backlog_cap: usize) -> Option<ColumnScan> {
        if self.columns.as_ref().is_some_and(|c| c.pending_len() >= backlog_cap) {
            return None;
        }
        self.scan.take()
    }

    pub(super) fn resume_scan(&mut self, scan: ColumnScan) {
        self.scan = Some(scan);
    }

    pub(super) fn finish_scan(&mut self) {
        if let Some(columns) = self.columns.as_mut() {
            columns.mark_scan_complete();
        }
        if let Some(envelopes) = self.envelopes.as_mut() {
            envelopes.mark_scan_complete();
        }
    }

    pub(super) fn wants_envelopes(&self) -> bool {
        self.envelopes.is_some()
    }

    pub(super) fn seed(
        &mut self,
        block_root: B256,
        slot: u64,
        block: &[u8],
        missing_columns: u128,
        needs_envelope: bool,
        spec: &SpecConfig,
    ) {
        if needs_envelope && let Some(envelopes) = self.envelopes.as_mut() {
            envelopes.seed_block(block_root, slot, block);
        }
        if missing_columns != 0 &&
            let Some(columns) = self.columns.as_mut()
        {
            columns.seed_block(block_root, slot, block, missing_columns, spec);
        }
    }

    pub(super) fn add_block(&mut self, ssz: TRead, write_queue: &mut VecDeque<PendingWrite>) {
        match self.blocks.as_mut() {
            Some(blocks) => blocks.add_block(ssz, write_queue),
            None => tracing::error!("received backfill block with no active backfill!"),
        }
    }

    pub(super) fn add_envelope(
        &mut self,
        signed: &TRead,
        root_index: &FxHashMap<B256, u64>,
    ) -> Option<(B256, u64)> {
        match self.envelopes.as_mut() {
            Some(envelopes) => envelopes.add_envelope(signed, root_index),
            None => {
                tracing::error!("received backfill envelope with no active envelope backfill!");
                None
            }
        }
    }

    pub(super) fn add_sidecar(
        &mut self,
        sidecar: TRead,
        peer: usize,
        now: Instant,
    ) -> (Option<VerifiedColumns>, Vec<RejectedSidecar>) {
        match self.columns.as_mut() {
            Some(columns) => columns.add_sidecar(sidecar, peer, now),
            None => {
                tracing::error!("received backfill data column with no active column backfill!");
                (None, Vec::new())
            }
        }
    }

    pub(super) fn expire_incomplete_columns(&mut self, now: Instant) {
        if let Some(columns) = self.columns.as_mut() {
            columns.expire_incomplete(now);
        }
    }

    fn owed_span(&self, kind: DataKind) -> (u64, u64) {
        match kind {
            DataKind::Block => {
                self.blocks.as_ref().map_or((0, 0), |b| (b.floor(), b.earliest_written()))
            }
            DataKind::Columns => self.columns.as_ref().map_or((0, 0), ColumnBackfill::owed_span),
            DataKind::Envelope => {
                self.envelopes.as_ref().and_then(EnvelopeBackfill::owed_span).unwrap_or((0, 0))
            }
        }
    }

    pub(super) fn publish_owed_spans(&mut self, emit: &mut impl FnMut(SyncNeed)) {
        for kind in DataKind::ALL {
            let (floor, next) = self.owed_span(kind);
            if self.published_spans[kind.index()] != (floor, next) {
                self.published_spans[kind.index()] = (floor, next);
                emit(SyncNeed::BackfillGap { kind, floor, next });
            }
        }
    }

    pub(super) fn retire_floor(&mut self, floor: u64) {
        self.retired_floor = Some(self.retired_floor.unwrap_or(0).max(floor));
    }

    pub(super) fn note_truncation(&mut self, earliest_slot: u64) {
        if let Some(floor) = self.retired_floor.as_mut() {
            *floor = (*floor).max(earliest_slot);
        }
    }

    pub(super) fn earliest_servable(
        &self,
        custody_columns: u128,
        spec: &SpecConfig,
        finalized_slot: u64,
    ) -> u64 {
        let unwalked = self.retired_floor.unwrap_or(finalized_slot);

        let mut earliest = self.blocks.as_ref().map_or(unwalked, Backfill::earliest_written);
        if custody_columns != 0 {
            earliest = earliest
                .max(self.columns.as_ref().map_or(unwalked, ColumnBackfill::servable_floor));
        }
        if spec.gloas_fork_slot() <= finalized_slot {
            earliest = earliest
                .max(self.envelopes.as_ref().map_or(unwalked, EnvelopeBackfill::servable_floor));
        }
        earliest
    }

    pub(super) fn take_claim(
        &mut self,
        custody_columns: u128,
        spec: &SpecConfig,
        finalized_slot: u64,
    ) -> Option<u64> {
        let earliest = self.earliest_servable(custody_columns, spec, finalized_slot);
        if self.claimed_earliest == Some(earliest) {
            return None;
        }
        self.claimed_earliest = Some(earliest);
        Some(earliest)
    }
}
