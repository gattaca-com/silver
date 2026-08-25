use std::time::Instant;

use silver_common::{DataKind, Origin, PREFILL_SLOTS, Prefill};

use super::{
    BACKFILL_BATCH, BACKFILL_SETTLE_TIMEOUT, SyncAction,
    peers::PeerView,
    ranges::Ranges,
    sync_window::{BlockState, Coverage, Needs, Slot, SyncWindow},
};

pub(super) struct Backfill {
    window: SyncWindow,
    ranges: Ranges,
    start: Option<Slot>,
}

impl Backfill {
    pub(super) fn new() -> Self {
        Self {
            window: SyncWindow::new(),
            ranges: Ranges::new(Origin::Backfill, BACKFILL_BATCH, 0, BACKFILL_SETTLE_TIMEOUT),
            start: None,
        }
    }

    /// Everything below finality is fetchable, and the prefill already carries
    /// the retention floors as coverage, so nothing here gates a kind.
    fn needs(custody: u128) -> Needs {
        Needs { data_availability_floor: 0, custodies_columns: custody != 0, gloas_fork_slot: 0 }
    }

    pub(super) fn on_prefill(&mut self, prefill: Prefill) {
        let tail = prefill.start.saturating_sub(1);
        if self.start != Some(prefill.start) {
            // A new range. The ring keeps nothing from the last one, and the
            // requests that were out for it name slots no longer owed.
            self.window.drop_above(tail);
            self.ranges.reset();
            self.start = Some(prefill.start);
        }

        self.window.set_tail(tail);
        self.ranges.set_columns(prefill.columns_missing);

        for offset in 0..PREFILL_SLOTS {
            let slot = prefill.start + offset;
            let bit = 1u32 << offset;
            let block = if prefill.have_block & bit != 0 {
                BlockState::Applied
            } else if prefill.known_empty & bit != 0 {
                BlockState::Empty
            } else {
                BlockState::Unknown
            };
            self.window.reseed(slot, Coverage {
                block,
                columns_covered: prefill.columns_covered & bit != 0,
                envelope_covered: prefill.envelopes & bit != 0,
            });
        }
    }

    pub(super) fn on_persisted(
        &mut self,
        kind: DataKind,
        slot: Slot,
        columns: u128,
        parent_slot: Option<Slot>,
        custody: u128,
    ) {
        match kind {
            DataKind::Block => self.window.block_received(slot, [0u8; 32], parent_slot, true),
            DataKind::Columns if columns & custody == custody => self.window.columns_covered(slot),
            DataKind::Columns => {}
            DataKind::Envelope => self.window.envelope_covered(slot),
        }
        self.ranges.note_report(kind, slot);
    }

    pub(super) fn on_msg_served(&mut self, request_id: u64) {
        self.ranges.on_msg_served(request_id);
    }

    pub(super) fn on_terminator(
        &mut self,
        peers: &PeerView,
        request_id: u64,
        peer: usize,
        delivered: bool,
        now: Instant,
    ) {
        let Some(d) = self.ranges.on_terminator(request_id, delivered, now) else { return };
        // The one emptiness storage cannot prove: a run with no block above it
        // has no link over it. As on the live chase, a peer that holds the span
        // and served nothing is the proof.
        if d.kind == DataKind::Block &&
            d.served == 0 &&
            peers.claims_span(peer, d.span.0..=d.span.1)
        {
            for slot in d.span.0..=d.span.1 {
                self.window.mark_empty(slot);
            }
        }
    }

    pub(super) fn drive(
        &mut self,
        custody: u128,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        let Some(start) = self.start else { return };
        let end = start + PREFILL_SLOTS - 1;
        let needs = Self::needs(custody);
        self.ranges.reoffer_unplaced(now, emit);
        self.window.advance_tail(end, needs);
        self.ranges.retire_overtaken(self.window.tail());
        self.ranges.issue(&self.window, end, needs, next_id, now, emit);
    }
}
