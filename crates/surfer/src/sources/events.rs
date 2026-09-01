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
    /// Absolute arrival, for correlating with logs and as the delta baseline.
    received_at: Option<Nanos>,
    /// Arrival offset into the block's own slot.
    received: Option<Nanos>,
    el_sent: Option<Nanos>,
    applied: Option<Nanos>,
    verdict: Option<(PayloadValidationStatus, Nanos)>,
    da_available: Option<Nanos>,
    /// One entry per data-column sidecar, in arrival order.
    pub columns: Vec<ColumnRow>,
}

/// `stf` and `el` both begin at EL-sent and run concurrently, so they overlap
/// rather than sum into `total`.
pub struct Timeline {
    /// Absolute wall-clock arrival (unix epoch); `None` when only the block's
    /// columns have been seen so far.
    pub received_at: Option<Nanos>,
    /// Slot start → block arrival; `None` once the arrival clock no longer
    /// belongs to the block's slot.
    pub received: Option<Nanos>,
    /// arrival → EL-sent: CL validation, plus any wait on missing data, up to
    /// dispatching `newPayload`.
    pub validate: Option<Nanos>,
    /// EL-sent → applied: state transition + commit.
    pub stf: Option<Nanos>,
    /// EL-sent → verdict: `newPayload` round-trip (concurrent with stf).
    pub el: Option<Nanos>,
    /// arrival → DA gate open.
    pub da: Option<Nanos>,
    pub verdict: Option<PayloadValidationStatus>,
    /// arrival → last observed event.
    pub total: Option<Nanos>,
}

impl BlockRow {
    fn new(slot: u64, block_root: [u8; 32]) -> Self {
        Self {
            slot,
            block_root,
            source: None,
            received_at: None,
            received: None,
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

    /// First arrival → last validation across the block's column sidecars.
    pub fn columns_span(&self) -> Option<(Nanos, Nanos)> {
        let first = self.columns.iter().map(|c| c.recv).min()?;
        let last = self.columns.iter().map(|c| c.validated.unwrap_or(c.recv)).max()?;
        Some((first, last))
    }

    pub fn timeline(&self) -> Timeline {
        let last = self
            .applied
            .into_iter()
            .chain(self.verdict.map(|(_, ts)| ts))
            .chain(self.el_sent)
            .chain(self.da_available)
            .max();
        let since_arrival =
            |ts: Option<Nanos>| ts.zip(self.received_at).map(|(ts, at)| ts.saturating_sub(at));
        Timeline {
            received_at: self.received_at,
            received: self.received,
            validate: since_arrival(self.el_sent),
            stf: self.applied.zip(self.el_sent).map(|(ts, sent)| ts.saturating_sub(sent)),
            el: self.verdict.zip(self.el_sent).map(|((_, ts), sent)| ts.saturating_sub(sent)),
            da: since_arrival(self.da_available),
            verdict: self.verdict.map(|(status, _)| status),
            total: since_arrival(last),
        }
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
                    row.received = clock.offset_in_slot(event.ts, row.slot);
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
    fn block_timeline() {
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
        let t = rows[0].timeline();
        assert_eq!(t.received_at, Some(at(2, 300)));
        assert_eq!(t.received, Some(Nanos(300 * MS)));
        assert_eq!(t.validate, Some(Nanos(0)));
        assert_eq!(t.stf, Some(Nanos(160 * MS)));
        assert_eq!(t.el, Some(Nanos(220 * MS)));
        assert_eq!(t.da, Some(Nanos(50 * MS)));
        assert_eq!(t.total, Some(Nanos(220 * MS)));
        assert_eq!(t.verdict, Some(PayloadValidationStatus::Valid));
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
        assert_eq!(row.timeline().received_at, Some(at(4, 300)));
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
        assert_eq!(rows[0].timeline().stf, Some(Nanos(140 * MS)));
    }

    /// A re-announcement past the reader's dedup window must not restamp
    /// the arrival.
    #[test]
    fn repeated_announcement_keeps_the_first_arrival() {
        let rows = fold_all(vec![
            event(received(), at(4, 300), Some(4)),
            event(received(), at(4, 3_100), Some(4)),
        ]);
        assert_eq!(rows[0].timeline().received_at, Some(at(4, 300)));
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
