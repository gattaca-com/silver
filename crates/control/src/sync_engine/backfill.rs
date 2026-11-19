use std::time::Instant;

use silver_common::{DataKind, Origin, PREFILL_SLOTS, Prefill};

use super::{
    BACKFILL_BATCH, BACKFILL_SETTLE_TIMEOUT, SyncAction,
    by_root::ByRootRequests,
    peers::PeerView,
    ranges::Ranges,
    sync_window::{BlockState, Coverage, Needs, Slot, SyncWindow},
};

pub(super) struct Backfill {
    window: SyncWindow,
    ranges: Ranges,
    prefill: Option<Prefill>,
    // When the range last had nothing left to ask.
    finished_at: Option<Instant>,
    chased: Option<[u8; 32]>,
}

impl Backfill {
    pub(super) fn new() -> Self {
        Self {
            window: SyncWindow::new(),
            ranges: Ranges::new(Origin::Backfill, BACKFILL_BATCH, 0, BACKFILL_SETTLE_TIMEOUT),
            prefill: None,
            finished_at: None,
            chased: None,
        }
    }

    /// Everything below finality is fetchable, and the prefill already carries
    /// the retention floors as coverage, so nothing here gates a kind.
    fn needs(custody: u128) -> Needs {
        Needs { data_availability_floor: 0, custodies_columns: custody != 0, gloas_fork_slot: 0 }
    }

    pub(super) fn on_prefill(&mut self, prefill: Prefill, root_requests: &mut ByRootRequests) {
        // Storage wants another root once the chased one landed.
        if let Some(root) = self.chased.take_if(|root| *root != prefill.wanted_parent) {
            root_requests.retire(&root, DataKind::Block);
        }
        let new_range = self.prefill.is_none_or(|last| last.start != prefill.start);
        self.seed(prefill, new_range);
    }

    fn seed(&mut self, prefill: Prefill, new_range: bool) {
        let tail = prefill.start.saturating_sub(1);
        if new_range {
            // The ring keeps nothing from the last range, and the requests
            // that were out for it name slots no longer owed.
            self.window.drop_above(tail);
            self.ranges.reset();
        }
        self.prefill = Some(prefill);
        self.finished_at = None;

        self.window.set_tail(tail);
        self.ranges.set_columns(prefill.columns_missing);

        for offset in 0..PREFILL_SLOTS {
            let slot = prefill.start.saturating_add(offset);
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
        root_requests: &mut ByRootRequests,
        request_id: u64,
        peer: usize,
        delivered: bool,
        now: Instant,
    ) {
        // The one emptiness storage cannot prove: a run with no block above it
        // has no link over it. As on the live chase, peers that hold the span
        // and served nothing are the proof.
        let Some(span) = self.ranges.on_terminator(peers, request_id, peer, delivered, now) else {
            return;
        };
        for slot in span.0..=span.1 {
            self.window.mark_empty(slot);
        }
        // Storage links only from a block, so a range holding none can
        // move it only through the block below, reached by root.
        if let Some(prefill) = self.prefill {
            let root = prefill.wanted_parent;
            root_requests.want(root, DataKind::Block, 0, Origin::Backfill, prefill.start, now);
            self.chased = Some(root);
        }
    }

    pub(super) fn drive(
        &mut self,
        custody: u128,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) {
        let Some(prefill) = self.prefill else { return };
        let end = prefill.start.saturating_add(PREFILL_SLOTS - 1);
        let needs = Self::needs(custody);
        self.ranges.reoffer_unplaced(now, emit);
        self.window.advance_tail(end, needs);
        if self.window.tail() >= end {
            // Storage moves on once the range is on disk. Standing still
            // means what this side took as done never reached it, such as a
            // peer's silence: start the range over.
            let finished_at = *self.finished_at.get_or_insert(now);
            if now.saturating_duration_since(finished_at) >= BACKFILL_SETTLE_TIMEOUT {
                self.seed(prefill, true);
            }
        }
        self.ranges.retire_overtaken(self.window.tail());
        self.ranges.issue(&self.window, end, needs, next_id, now, emit);
    }
}
