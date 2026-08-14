//! Historical backfill (policy, authoritative). Storage scans + reports what
//! history is missing; the engine schedules the fetches, owned by the
//! `Following` phase. The *durable plan* ([`BackfillPlan`]) lives in `Ctx` and
//! is updated by `BackfillState` / `ColumnNeed` events regardless of phase; the
//! *active driver* ([`Backfill`]) lives in `Phase::Following` and holds the
//! in-flight requests — dropping it (leaving `Following`) releases them while
//! the plan persists, so the next `Following` resumes.
//!
//! Blocks: `BlocksByRange` backward over `[block_floor, earliest_present)`,
//! response-driven. Columns: `DataColumnsByRoot` per `ColumnNeed`, bounded
//! concurrency + per-root retry. Requests carry the `BACKFILL_REQUEST_ID` /
//! `COLUMN_BACKFILL_REQUEST_ID` prefix so storage routes the payloads + clears
//! satisfied needs via `ColumnNeed { missing: 0 }`. Peer selection stays in PM
//! (history-/custody-aware), reached via the control tile.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use silver_common::{BACKFILL_REQUEST_ID, COLUMN_BACKFILL_REQUEST_ID};

use super::event::SyncAction;

const MAX_COLUMN_REQUESTS_IN_FLIGHT: usize = 4;
const COLUMN_RETRY: Duration = Duration::from_millis(3000);
const BLOCK_RETRY: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(super) struct BackfillPlan {
    block_floor: u64,
    block_next: u64,
    /// Outstanding per-block column needs (block_root → missing custody mask),
    /// set by `ColumnNeed { missing != 0 }` and cleared by `{ missing: 0 }`.
    col_needs: HashMap<[u8; 32], u128>,
}

impl BackfillPlan {
    pub(super) fn set_block_gap(&mut self, block_floor: u64, earliest_present: u64) {
        self.block_floor = block_floor;
        self.block_next = earliest_present;
    }

    pub(super) fn set_column_need(&mut self, block_root: [u8; 32], missing: u128) {
        if missing == 0 {
            self.col_needs.remove(&block_root);
        } else {
            self.col_needs.insert(block_root, missing);
        }
    }

    fn blocks_done(&self) -> bool {
        self.block_next <= self.block_floor
    }
}

struct BlockReq {
    request_id: u64,
    start: u64,
    issued_at: Instant,
}

#[derive(Default)]
pub(super) struct Backfill {
    block: Option<BlockReq>,
    /// In-flight column requests: request_id → block_root.
    col_in_flight: HashMap<u64, [u8; 32]>,
    /// Per-root retry gate: earliest instant the root may be (re)issued.
    col_next_eligible: HashMap<[u8; 32], Instant>,
}

impl Backfill {
    pub(super) fn on_block_complete(&mut self, request_id: u64, plan: &mut BackfillPlan) {
        if let Some(req) = self.block.as_ref().filter(|r| r.request_id == request_id) {
            plan.block_next = req.start;
            self.block = None;
        }
    }

    pub(super) fn on_block_failed(&mut self, request_id: u64) {
        if self.block.as_ref().is_some_and(|r| r.request_id == request_id) {
            self.block = None;
        }
    }

    pub(super) fn on_column_done(&mut self, request_id: u64) {
        self.col_in_flight.remove(&request_id);
    }

    pub(super) fn on_column_chunk(&mut self, request_id: u64, now: Instant) {
        if let Some(root) = self.col_in_flight.get(&request_id).copied() {
            self.col_next_eligible.insert(root, now + COLUMN_RETRY);
        }
    }

    pub(super) fn drive(
        &mut self,
        plan: &BackfillPlan,
        batch: u64,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction),
    ) {
        self.drive_blocks(plan, batch, next_id, now, emit);
        self.drive_columns(plan, next_id, now, emit);
    }

    fn drive_blocks(
        &mut self,
        plan: &BackfillPlan,
        batch: u64,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction),
    ) {
        // Re-issue a range that stalled without a terminator (e.g. no history
        // peer was available when it was emitted).
        if self
            .block
            .as_ref()
            .is_some_and(|r| now.saturating_duration_since(r.issued_at) >= BLOCK_RETRY)
        {
            self.block = None;
        }
        if self.block.is_some() || plan.blocks_done() {
            return;
        }
        let start = plan.block_floor.max(plan.block_next.saturating_sub(batch));
        let count = plan.block_next - start;
        let request_id = BACKFILL_REQUEST_ID | *next_id;
        *next_id += 1;
        self.block = Some(BlockReq { request_id, start, issued_at: now });
        emit(SyncAction::RequestBlocksByRange { request_id, peer: 0, start, count });
    }

    fn drive_columns(
        &mut self,
        plan: &BackfillPlan,
        next_id: &mut u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction),
    ) {
        for (&root, &missing) in &plan.col_needs {
            if self.col_in_flight.len() >= MAX_COLUMN_REQUESTS_IN_FLIGHT {
                break;
            }
            if self.col_in_flight.values().any(|r| *r == root) {
                continue; // already in flight
            }
            if self.col_next_eligible.get(&root).is_some_and(|&t| now < t) {
                continue; // retry gate
            }
            let request_id = COLUMN_BACKFILL_REQUEST_ID | *next_id;
            *next_id += 1;
            self.col_in_flight.insert(request_id, root);
            self.col_next_eligible.insert(root, now + COLUMN_RETRY);
            emit(SyncAction::RequestColumnsByRoot {
                request_id,
                peer: 0,
                block_root: root,
                columns: missing,
            });
        }
    }
}
