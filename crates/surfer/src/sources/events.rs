//! Per-block pipeline timeline, read from the node's own spine queues. Surfer
//! joins the spine as a broadcast consumer (its own cursor; the tiles are
//! untouched); stage decoding lives in [`StageReader`], and this module only
//! folds the events into per-block rows.

use std::{collections::VecDeque, ops::Deref, path::Path};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{BlockSource, ColumnSource, Nanos, PayloadValidationStatus, SilverSpine};
use silver_stages::{SlotClock, Stage, StageEvent, StageReader};

pub const MAINNET_GENESIS_UNIX_SECS: u64 = 1_606_824_023;
pub const MAINNET_SLOT_MS: u64 = 12_000;

const ROWS_CAP: usize = 64;

pub struct ColumnRow {
    pub index: u64,
    pub source: ColumnSource,
    pub recv: Nanos,
    pub validated: Option<Nanos>,
}

pub struct BlockRow {
    pub slot: u64,
    pub block_root: [u8; 32],
    /// `None` until the block itself arrives — its columns may come first.
    pub source: Option<BlockSource>,
    /// Absolute arrival, for correlating with logs and as the bar's left edge.
    received_at: Option<Nanos>,
    el_sent: Option<Nanos>,
    applied: Option<Nanos>,
    verdict: Option<(PayloadValidationStatus, Nanos)>,
    da_available: Option<Nanos>,
    /// One entry per data-column sidecar, in arrival order.
    pub columns: Vec<ColumnRow>,
}

/// One lane of the block's dependency graph, as drawn by the waterfall: the
/// whole strip, the data side (`Cols → Kzg → Da`) and the execution side
/// (`Validate → Stf ‖ El`), joining at attestable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Strip,
    Data,
    Cols,
    Kzg,
    Da,
    Exec,
    Validate,
    Stf,
    El,
}

impl BlockRow {
    fn new(slot: u64, block_root: [u8; 32]) -> Self {
        Self {
            slot,
            block_root,
            source: None,
            received_at: None,
            el_sent: None,
            applied: None,
            verdict: None,
            da_available: None,
            columns: Vec::new(),
        }
    }

    /// When the DA gate opened; columns arriving after it are custody duty,
    /// not what this block waited for.
    pub fn da_available(&self) -> Option<Nanos> {
        self.da_available
    }

    /// The last event on the block's own path — column custody traffic
    /// excluded, so an applied block's extent ends at attestable, not at the
    /// custody tail.
    fn last_event(&self) -> Option<Nanos> {
        self.applied
            .into_iter()
            .chain(self.verdict.map(|(_, ts)| ts))
            .chain(self.el_sent)
            .chain(self.da_available)
            .max()
    }

    /// Where CL validation starts: the DA gate when it held the block (the
    /// gate precedes dispatch), else arrival.
    fn validate_from(&self) -> Option<Nanos> {
        self.received_at.map(|at| match self.da_available {
            Some(gate) if self.el_sent.is_some_and(|sent| gate < sent) => at.max(gate),
            _ => at,
        })
    }

    /// Wall-clock extent of one lane; `None` while it has no events. An
    /// instant lane (`Da`) is a zero-length span.
    pub fn span(&self, lane: Lane) -> Option<(Nanos, Nanos)> {
        let cols_first = self.columns.iter().map(|c| c.recv).min();
        match lane {
            Lane::Strip => {
                let start = self.received_at.or(cols_first)?;
                let end = self.applied.or_else(|| self.last_event()).unwrap_or(start);
                Some((start, end.max(start)))
            }
            Lane::Data => {
                let start = cols_first.or(self.da_available)?;
                let end = self
                    .da_available
                    .or_else(|| self.span(Lane::Kzg).map(|(_, last)| last))
                    .unwrap_or(start);
                Some((start, end))
            }
            Lane::Cols => Some((cols_first?, self.columns.iter().map(|c| c.recv).max()?)),
            Lane::Kzg => {
                let first = self.columns.iter().filter_map(|c| c.validated).min()?;
                let last = self.columns.iter().filter_map(|c| c.validated).max()?;
                Some((first, last))
            }
            Lane::Da => self.da_available.map(|gate| (gate, gate)),
            Lane::Exec => {
                let start = self.validate_from().or(self.el_sent)?;
                let end = self
                    .applied
                    .into_iter()
                    .chain(self.verdict.map(|(_, ts)| ts))
                    .chain(self.el_sent)
                    .max()?;
                Some((start, end))
            }
            Lane::Validate => Some((self.validate_from()?, self.el_sent?)),
            Lane::Stf => Some((self.el_sent?, self.applied?)),
            Lane::El => self.verdict.map(|(_, ts)| (self.el_sent.unwrap_or(ts), ts)),
        }
    }

    /// When the block was applied, i.e. became attestable.
    pub fn applied_at(&self) -> Option<Nanos> {
        self.applied
    }

    pub fn verdict(&self) -> Option<PayloadValidationStatus> {
        self.verdict.map(|(status, _)| status)
    }
}

/// Joined per-block rows, newest at the back.
pub struct BlockRows(VecDeque<BlockRow>);

impl Deref for BlockRows {
    type Target = VecDeque<BlockRow>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BlockRows {
    fn fold(&mut self, clock: &SlotClock, event: StageEvent) {
        let row = match self.0.iter_mut().rev().find(|r| r.block_root == event.block_root) {
            Some(row) => row,
            // An announcement always opens the block's row; other events
            // only while live, so early columns land but backfill's
            // historical-slot events cannot churn the pane.
            None => {
                let Some(slot) = event.slot else {
                    return;
                };
                let live = matches!(event.stage, Stage::Received { .. }) ||
                    clock.offset_in_slot(event.ts, slot).is_some();
                if !live {
                    return;
                }
                if self.0.len() == ROWS_CAP {
                    self.0.pop_front();
                }
                self.0.push_back(BlockRow::new(slot, event.block_root));
                self.0.back_mut().expect("just pushed")
            }
        };
        match event.stage {
            // The replay admitting a parked block re-announces it; only the
            // first announcement is the arrival.
            Stage::Received { source } => {
                if row.received_at.is_none() {
                    row.source = Some(source);
                    row.received_at = Some(event.ts);
                }
            }
            Stage::ElSent { .. } => row.el_sent = Some(event.ts),
            // Repeat-head and tick FCUs re-emit `Applied`; the first is the
            // apply.
            Stage::Applied => {
                row.applied.get_or_insert(event.ts);
            }
            Stage::ElVerdict { verdict } => row.verdict = Some((verdict, event.ts)),
            // Duplicate arrivals re-emit `Persist`; one subrow per index,
            // keeping the first arrival and validation.
            Stage::ColumnRecv { index, source } => {
                if row.columns.iter().all(|c| c.index != index) {
                    row.columns.push(ColumnRow { index, source, recv: event.ts, validated: None });
                }
            }
            Stage::ColumnValidated { index, .. } => {
                if let Some(col) = row.columns.iter_mut().find(|c| c.index == index) {
                    col.validated.get_or_insert(event.ts);
                }
            }
            Stage::DaAvailable => row.da_available = Some(event.ts),
        }
    }
}

/// Folds stage events into per-block rows; as the tile, it names the
/// broadcast cursors.
struct EventsTile {
    clock: SlotClock,
    reader: StageReader,
    rows: BlockRows,
}

impl Tile<SilverSpine> for EventsTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        for event in self.reader.consume(adapter) {
            self.rows.fold(&self.clock, event);
        }
    }
}

/// The node's spine, read-only. Everything flux-coupled lives here; the rest
/// of surfer sees only `sample()` / `rows()`.
pub struct Events {
    tile: EventsTile,
    adapter: SpineAdapter<SilverSpine>,
}

impl Events {
    pub fn open(base_dir: &Path, genesis_unix_secs: u64, slot_ms: u64) -> Self {
        let tile = EventsTile {
            clock: SlotClock::new(genesis_unix_secs, slot_ms),
            reader: StageReader::default(),
            rows: BlockRows(VecDeque::with_capacity(ROWS_CAP)),
        };
        // Queue handles are `Copy` and live in shmem, so the spine can drop
        // once the adapter has attached.
        let mut spine = SilverSpine::new_with_base_dir(base_dir, None);
        let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        Self { tile, adapter }
    }

    pub fn sample(&mut self) {
        self.tile.loop_body(&mut self.adapter);
    }

    pub fn rows(&self) -> &BlockRows {
        &self.tile.rows
    }

    pub fn clock(&self) -> &SlotClock {
        &self.tile.clock
    }

    /// Offset into the slot by which validators are expected to have attested.
    /// Assumes the pre-Gloas fraction.
    pub fn attestation_deadline(&self) -> Nanos {
        self.tile.clock.slot_duration() / 3u64
    }
}

#[cfg(test)]
mod tests {
    use silver_common::ColumnSource;

    use super::*;

    const GENESIS_SECS: u64 = 1_000;
    const SLOT_MS: u64 = 12_000;
    const MS: u64 = 1_000_000;

    /// Wall time at `ms_into_slot` of `slot`.
    fn at(slot: u64, ms_into_slot: u64) -> Nanos {
        Nanos((GENESIS_SECS * 1_000 + slot * SLOT_MS + ms_into_slot) * MS)
    }

    fn event(stage: Stage, ts: Nanos, slot: Option<u64>) -> StageEvent {
        StageEvent { stage, ts, block_root: [1u8; 32], slot }
    }

    fn received() -> Stage {
        Stage::Received { source: BlockSource::Gossip }
    }

    fn fold_all(events: Vec<StageEvent>) -> BlockRows {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        let mut rows = BlockRows(VecDeque::new());
        for o in events {
            rows.fold(&clock, o);
        }
        rows
    }

    #[test]
    fn block_lane_spans() {
        let el_sent = Stage::ElSent { source: BlockSource::Gossip };
        let verdict = Stage::ElVerdict { verdict: PayloadValidationStatus::Valid };
        let rows = fold_all(vec![
            event(received(), at(2, 300), Some(2)),
            event(el_sent, at(2, 300), Some(2)),
            event(Stage::Applied, at(2, 460), Some(2)),
            event(verdict, at(2, 520), Some(2)),
            event(Stage::DaAvailable, at(2, 350), Some(2)),
        ]);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].slot, 2);
        let r = &rows[0];
        assert_eq!(r.span(Lane::Strip), Some((at(2, 300), at(2, 460))), "arrival → attestable");
        // The gate fired after dispatch, so it never held the block.
        assert_eq!(r.span(Lane::Validate), Some((at(2, 300), at(2, 300))));
        assert_eq!(r.span(Lane::Stf), Some((at(2, 300), at(2, 460))));
        assert_eq!(r.span(Lane::El), Some((at(2, 300), at(2, 520))));
        assert_eq!(r.span(Lane::Da), Some((at(2, 350), at(2, 350))));
        assert_eq!(r.span(Lane::Cols), None, "no sidecars observed");
        assert_eq!(r.applied_at(), Some(at(2, 460)));
        assert_eq!(r.verdict(), Some(PayloadValidationStatus::Valid));
    }

    /// The DA gate precedes `newPayload` dispatch, so a gated block's
    /// `validate` starts at the gate — the data wait must not be counted as
    /// validation.
    #[test]
    fn gated_block_measures_validate_from_the_gate() {
        let el_sent = Stage::ElSent { source: BlockSource::Gossip };
        let rows = fold_all(vec![
            event(received(), at(2, 300), Some(2)),
            event(Stage::DaAvailable, at(2, 410), Some(2)),
            event(el_sent, at(2, 413), Some(2)),
            event(Stage::Applied, at(2, 422), Some(2)),
        ]);

        let r = &rows[0];
        assert_eq!(r.span(Lane::Da), Some((at(2, 410), at(2, 410))));
        assert_eq!(
            r.span(Lane::Validate),
            Some((at(2, 410), at(2, 413))),
            "gate → dispatch, not arrival → dispatch"
        );
        assert_eq!(r.span(Lane::Stf), Some((at(2, 413), at(2, 422))));
        assert_eq!(r.span(Lane::Exec), Some((at(2, 410), at(2, 422))));
    }

    /// Columns often beat the block itself; the row opens on the first of them
    /// and the arrival fills in when the block lands.
    #[test]
    fn columns_ahead_of_the_block_open_its_row() {
        let recv = Stage::ColumnRecv { index: 48, source: ColumnSource::Gossip };
        let validated = Stage::ColumnValidated { index: 48, source: ColumnSource::Gossip };
        let rows = fold_all(vec![
            event(recv, at(4, 200), Some(4)),
            event(validated, at(4, 210), Some(4)),
            event(received(), at(4, 300), Some(4)),
        ]);

        assert_eq!(rows.len(), 1, "the column and the block joined one row");
        let row = &rows[0];
        assert_eq!(row.columns.len(), 1);
        assert_eq!(row.columns[0].index, 48);
        assert_eq!(row.columns[0].recv, at(4, 200));
        assert_eq!(row.columns[0].validated, Some(at(4, 210)));
        assert_eq!(row.span(Lane::Strip).map(|(start, _)| start), Some(at(4, 300)));
        assert_eq!(row.span(Lane::Cols), Some((at(4, 200), at(4, 200))));
        assert_eq!(row.span(Lane::Kzg), Some((at(4, 210), at(4, 210))));
    }

    /// A slotless event (an FCU for a root from before attach) has no
    /// row to join and opens none.
    #[test]
    fn slotless_events_open_no_row() {
        let rows = fold_all(vec![event(Stage::Applied, at(2, 460), None)]);
        assert!(rows.is_empty());
    }

    /// Backfill persists columns for historical slots at the current wall
    /// clock; they must not churn live rows out of the pane.
    #[test]
    fn backfill_columns_open_no_row() {
        let recv = Stage::ColumnRecv { index: 3, source: ColumnSource::Rpc };
        let rows = fold_all(vec![event(recv, at(900, 0), Some(7))]);
        assert!(rows.is_empty());
    }

    /// The reader emits every FCU; the row keeps the first as the apply.
    #[test]
    fn repeat_fcus_keep_the_first_apply() {
        let el_sent = Stage::ElSent { source: BlockSource::Gossip };
        let rows = fold_all(vec![
            event(received(), at(2, 300), Some(2)),
            event(el_sent, at(2, 320), Some(2)),
            event(Stage::Applied, at(2, 460), Some(2)),
            event(Stage::Applied, at(2, 900), Some(2)),
        ]);
        assert_eq!(rows[0].span(Lane::Stf), Some((at(2, 320), at(2, 460))));
    }

    /// A re-announcement past the reader's dedup window must not restamp
    /// the arrival.
    #[test]
    fn repeated_announcement_keeps_the_first_arrival() {
        let rows = fold_all(vec![
            event(received(), at(4, 300), Some(4)),
            event(received(), at(4, 3_100), Some(4)),
        ]);
        assert_eq!(rows[0].span(Lane::Strip).map(|(start, _)| start), Some(at(4, 300)));
    }

    /// Duplicate `Persist` events (an already-held column re-arriving) fold
    /// into one subrow with the first timestamps.
    #[test]
    fn duplicate_column_events_fold_into_one_subrow() {
        let recv = Stage::ColumnRecv { index: 48, source: ColumnSource::Gossip };
        let validated = Stage::ColumnValidated { index: 48, source: ColumnSource::Gossip };
        let rows = fold_all(vec![
            event(recv, at(4, 200), Some(4)),
            event(validated, at(4, 210), Some(4)),
            event(recv, at(4, 500), Some(4)),
            event(validated, at(4, 510), Some(4)),
        ]);

        assert_eq!(rows[0].columns.len(), 1);
        assert_eq!(rows[0].columns[0].recv, at(4, 200));
        assert_eq!(rows[0].columns[0].validated, Some(at(4, 210)));
    }
}
