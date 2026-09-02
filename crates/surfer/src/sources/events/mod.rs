//! Per-block pipeline timeline, read from the node's own spine queues. Surfer
//! joins the spine as a broadcast consumer (its own cursor; the tiles are
//! untouched).

use std::{collections::VecDeque, ops::Deref, path::Path};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{Nanos, SilverSpine};
use silver_stages::{SlotClock, Stage, StageEvent, StageReader};

mod da;
mod el;
mod stf;
mod trace;

pub use da::DaSpan;
pub use stf::StfSpan;
#[cfg(test)]
pub use trace::tests as trace_tests;
pub use trace::{BlockTrace, Interval, Margin, Span};

pub const MAINNET_GENESIS_UNIX_SECS: u64 = 1_606_824_023;
pub const MAINNET_SLOT_MS: u64 = 12_000;

const TRACES_CAP: usize = 64;

/// Joined per-block traces, newest at the back.
pub struct BlockTraces(VecDeque<BlockTrace>);

impl Deref for BlockTraces {
    type Target = VecDeque<BlockTrace>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
impl FromIterator<BlockTrace> for BlockTraces {
    fn from_iter<I: IntoIterator<Item = BlockTrace>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl BlockTraces {
    pub fn by_root(&self, root: [u8; 32]) -> Option<&BlockTrace> {
        self.0.iter().find(|t| t.block_root == root)
    }

    fn fold(&mut self, clock: &SlotClock, event: StageEvent) {
        let trace = match self.0.iter_mut().rev().find(|t| t.block_root == event.block_root) {
            Some(trace) => trace,
            // An announcement always opens the block's trace; other events
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
                if self.0.len() == TRACES_CAP {
                    self.0.pop_front();
                }
                self.0.push_back(BlockTrace::new(slot, event.block_root));
                self.0.back_mut().expect("just pushed")
            }
        };
        trace.apply(event);
    }

    pub fn max_strip_offset(&self, clock: &SlotClock) -> Nanos {
        self.0
            .iter()
            .filter_map(|t| t.offset_in_slot(clock, t.interval(Span::Strip)?.end))
            .max()
            .unwrap_or(Nanos(0))
    }
}

/// Folds stage events into per-block traces; as the tile, it names the
/// broadcast cursors.
struct EventsTile {
    clock: SlotClock,
    reader: StageReader,
    traces: BlockTraces,
}

impl Tile<SilverSpine> for EventsTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        for event in self.reader.consume(adapter) {
            self.traces.fold(&self.clock, event);
        }
    }
}

/// The node's spine, read-only. Everything flux-coupled lives here; the rest
/// of surfer sees only `sample()` / `traces()`.
pub struct Events {
    tile: EventsTile,
    adapter: SpineAdapter<SilverSpine>,
}

impl Events {
    pub fn open(base_dir: &Path, clock: SlotClock) -> Self {
        let tile = EventsTile {
            clock,
            reader: StageReader::default(),
            traces: BlockTraces(VecDeque::with_capacity(TRACES_CAP)),
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

    pub fn traces(&self) -> &BlockTraces {
        &self.tile.traces
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

    use super::{
        trace::tests::{GENESIS_SECS, SLOT_MS, at, event, received},
        *,
    };

    fn fold_all(events: Vec<StageEvent>) -> BlockTraces {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        let mut traces = BlockTraces(VecDeque::new());
        for o in events {
            traces.fold(&clock, o);
        }
        traces
    }

    fn strip_start(trace: &BlockTrace) -> Option<Nanos> {
        trace.interval(Span::Strip).map(|iv| iv.start)
    }

    /// Columns often beat the block itself; the trace opens on the first of
    /// them and the arrival fills in when the block lands.
    #[test]
    fn columns_ahead_of_the_block_open_its_trace() {
        let recv = Stage::ColumnRecv { index: 48, source: ColumnSource::Gossip };
        let validated = Stage::ColumnValidated { index: 48, source: ColumnSource::Gossip };
        let traces = fold_all(vec![
            event(recv, at(4, 200), Some(4)),
            event(validated, at(4, 210), Some(4)),
            event(received(), at(4, 300), Some(4)),
        ]);

        assert_eq!(traces.len(), 1, "the column and the block joined one trace");
        let trace = &traces[0];
        assert_eq!(trace.slot, 4);
        assert_eq!(trace.da.columns.len(), 1);
        assert_eq!(trace.da.columns[0].index, 48);
        assert_eq!(trace.da.columns[0].interval(), Interval { start: at(4, 200), end: at(4, 210) });
        assert_eq!(strip_start(trace), Some(at(4, 300)));
    }

    /// A slotless event (an FCU for a root from before attach) has no
    /// trace to join and opens none.
    #[test]
    fn slotless_events_open_no_trace() {
        let traces = fold_all(vec![event(Stage::Applied, at(2, 460), None)]);
        assert!(traces.is_empty());
    }

    /// Backfill persists columns for historical slots at the current wall
    /// clock; they must not churn live traces out of the pane.
    #[test]
    fn backfill_columns_open_no_trace() {
        let recv = Stage::ColumnRecv { index: 3, source: ColumnSource::Rpc };
        let traces = fold_all(vec![event(recv, at(900, 0), Some(7))]);
        assert!(traces.is_empty());
    }

    /// A re-announcement past the reader's dedup window must not restamp
    /// the arrival.
    #[test]
    fn repeated_announcement_keeps_the_first_arrival() {
        let traces = fold_all(vec![
            event(received(), at(4, 300), Some(4)),
            event(received(), at(4, 3_100), Some(4)),
        ]);
        assert_eq!(strip_start(&traces[0]), Some(at(4, 300)));
    }

    #[test]
    fn max_strip_offset_covers_the_latest_end() {
        let clock = SlotClock::new(GENESIS_SECS, SLOT_MS);
        let mut traces = fold_all(vec![
            event(received(), at(4, 300), Some(4)),
            event(Stage::StfImported, at(4, 900), Some(4)),
        ]);
        assert_eq!(traces.max_strip_offset(&clock), Nanos::from_millis(900));

        traces.fold(&clock, StageEvent {
            stage: received(),
            ts: at(5, 1_200),
            block_root: [2u8; 32],
            slot: Some(5),
        });
        assert_eq!(traces.max_strip_offset(&clock), Nanos::from_millis(1_200));
    }
}
