//! Forward range-sync driver shared by data-column and execution-payload-
//! envelope catch-up. Both trail the block watermark with one cycling per-range
//! attempt over `AwaitingPeer → InFlight → Delivered/Errored`.

use std::{
    collections::HashSet,
    marker::PhantomData,
    time::{Duration, Instant},
};

use silver_common::{BASE_REQUEST_ID, ENVELOPE_REQUEST_ID, GLOAS_ERA_FLAG, RpcSeverity};

use super::{Ctx, event::SyncAction, syncing::ISSUE_RETRY_BACKOFF};

#[derive(Clone, Copy)]
struct Attempt {
    request_id: u64,
    state: ReqState,
}

#[derive(Clone, Copy)]
enum ReqState {
    AwaitingPeer { retry_at: Instant },
    InFlight { peer: usize, columns: u128, peer_head_at_issue: u64, last_progress_at: Instant },
    Delivered { columns: u128, peer_head_at_issue: u64 },
    Errored { peer: usize },
}

#[derive(Clone, Copy)]
pub(super) struct Range {
    start_slot: u64,
    count: u64,
    /// Outstanding custody columns for this range (column kind); envelope kind
    /// leaves it 0.
    remaining: u128,
    attempts: u64,
    /// Min serving-peer head across this range's deliveries (column kind); caps
    /// the watermark advance. Envelope kind leaves it `u64::MAX`.
    served_through: u64,
    attempt: Option<Attempt>,
}

pub(super) struct RangeDriver<K> {
    /// Highest slot a peer confirmed-served this catch-up (column kind); the
    /// envelope kind never advances it.
    synced_through: u64,
    range: Option<Range>,
    /// Peers that failed the active range; the picker skips them (column kind).
    tried: HashSet<usize>,
    _kind: PhantomData<K>,
}

impl<K> Default for RangeDriver<K> {
    fn default() -> Self {
        Self { synced_through: 0, range: None, tried: HashSet::new(), _kind: PhantomData }
    }
}

pub(super) trait RangeKind {
    const PREFIX: u64;

    /// Whether the driver runs this tick (column kind gates on custody).
    fn is_enabled(_ctx: &Ctx) -> bool {
        true
    }

    /// Pre-resolve watermark adjustment (column kind pegs to the applied head
    /// under Gloas, where delivery != verification).
    fn pre_drive(_driver: &mut RangeDriver<Self>, _ctx: &Ctx)
    where
        Self: Sized,
    {
    }

    /// Exclusive base slot (the range starts at `base + 1`) and the initial
    /// custody mask (0 for the envelope kind).
    fn open(driver: &RangeDriver<Self>, ctx: &Ctx, local_head: u64) -> (u64, u128)
    where
        Self: Sized;

    fn request(request_id: u64, range: &Range, tried: &HashSet<usize>) -> SyncAction;

    /// Consume a `Delivered` attempt; return `true` when the range is complete
    /// and should be retired.
    fn on_delivered(
        driver: &mut RangeDriver<Self>,
        ctx: &Ctx,
        columns: u128,
        peer_head_at_issue: u64,
    ) -> bool
    where
        Self: Sized;

    /// Called from `issue` when no attempt is in flight: given the range's
    /// issued-attempt count, return `true` to give up and drop the range.
    /// Default: never — for kinds with no by-root fallback (e.g. envelopes).
    fn on_attempts_exhausted(_driver: &mut RangeDriver<Self>, _ctx: &Ctx, _attempts: u64) -> bool
    where
        Self: Sized,
    {
        false
    }
}

impl<K: RangeKind> RangeDriver<K> {
    pub(super) fn synced_through(&self) -> u64 {
        self.synced_through
    }

    /// Seed the watermark to the applied head when catch-up first turns on at
    /// the finalized→head edge (data isn't fetched during `SyncingFinalized`).
    pub(super) fn seed(&mut self, head: u64) {
        *self = Self::default();
        self.synced_through = head;
    }

    pub(super) fn on_chunk(&mut self, request_id: u64, now: Instant) {
        if let Some(range) = self.range.as_mut() &&
            let Some(att) = range.attempt.as_mut() &&
            att.request_id == request_id &&
            let ReqState::InFlight { last_progress_at, .. } = &mut att.state
        {
            *last_progress_at = now;
        }
    }

    pub(super) fn on_terminator(&mut self, request_id: u64, delivered: bool) {
        if let Some(range) = self.range.as_mut() &&
            let Some(att) = range.attempt.as_mut() &&
            att.request_id == request_id &&
            let ReqState::InFlight { peer, columns, peer_head_at_issue, .. } = att.state
        {
            att.state = if delivered {
                ReqState::Delivered { columns, peer_head_at_issue }
            } else {
                ReqState::Errored { peer }
            };
        }
    }

    pub(super) fn on_request_issued(
        &mut self,
        ctx: &Ctx,
        request_id: u64,
        peer: Option<(usize, u128)>,
        now: Instant,
    ) {
        let Some(range) = self.range.as_mut() else { return };
        let state = match peer {
            Some((peer, columns)) => {
                range.attempts += 1;
                ReqState::InFlight {
                    peer,
                    columns,
                    peer_head_at_issue: ctx.peers.head_slot_of(peer).unwrap_or(0),
                    last_progress_at: now,
                }
            }
            None => ReqState::AwaitingPeer { retry_at: now + ISSUE_RETRY_BACKOFF },
        };
        range.attempt = Some(Attempt { request_id, state });
    }

    pub(super) fn drive(
        &mut self,
        ctx: &mut Ctx,
        block_synced_through: u64,
        block_inflight_end: u64,
        now: Instant,
        emit: &mut impl FnMut(SyncAction),
    ) {
        if !K::is_enabled(ctx) {
            return;
        }
        K::pre_drive(self, ctx);
        self.resolve(ctx, now, Duration::from_millis(ctx.cfg.inflight_progress_timeout_ms), emit);
        self.open_range(
            ctx,
            block_synced_through,
            block_inflight_end,
            ctx.local.head_imported_slot,
            ctx.cfg.max_blocks_by_range_batch,
        );
        self.issue(ctx, emit);
    }

    fn resolve(
        &mut self,
        ctx: &Ctx,
        now: Instant,
        timeout: Duration,
        emit: &mut impl FnMut(SyncAction),
    ) {
        let Some((request_id, state)) =
            self.range.as_ref().and_then(|r| r.attempt.map(|a| (a.request_id, a.state)))
        else {
            return;
        };

        match state {
            ReqState::AwaitingPeer { retry_at } => {
                if now >= retry_at &&
                    let Some(range) = self.range.as_ref()
                {
                    emit(K::request(request_id, range, &self.tried));
                }
            }
            ReqState::InFlight { peer, last_progress_at, .. } => {
                if now.saturating_duration_since(last_progress_at) >= timeout {
                    // No terminator / no chunk for a full window: peer stall.
                    self.tried.insert(peer);
                    if let Some(r) = self.range.as_mut() {
                        r.attempt = None;
                    }
                    emit(SyncAction::ScorePeer { peer, severity: RpcSeverity::HighTolerance });
                }
            }
            ReqState::Delivered { columns, peer_head_at_issue } => {
                if K::on_delivered(self, ctx, columns, peer_head_at_issue) {
                    self.tried.clear();
                    self.range = None;
                }
            }
            // Error terminator (peer already scored at the RPC layer): re-issue
            // elsewhere — `peer` is added to `tried`.
            ReqState::Errored { peer } => {
                self.tried.insert(peer);
                if let Some(r) = self.range.as_mut() {
                    r.attempt = None;
                }
            }
        }
    }

    fn open_range(
        &mut self,
        ctx: &Ctx,
        block_synced_through: u64,
        block_inflight_end: u64,
        local_head: u64,
        batch: u64,
    ) {
        if self.range.is_some() {
            return;
        }
        let (base, remaining) = K::open(self, ctx, local_head);
        let cap = block_synced_through.max(block_inflight_end);
        if base >= cap {
            return;
        }
        let mut count = (cap - base).min(batch);
        // Keep the range fork-homogeneous: never span the Gloas boundary, so the
        // whole range shares one sidecar layout (routed via `GLOAS_ERA_FLAG`).
        let fork = ctx.spec.gloas_fork_slot();
        if base + 1 < fork {
            count = count.min(fork - 1 - base);
        }
        self.tried.clear();
        self.range = Some(Range {
            start_slot: base + 1,
            count,
            remaining,
            attempts: 0,
            served_through: u64::MAX,
            attempt: None,
        });
    }

    fn issue(&mut self, ctx: &mut Ctx, emit: &mut impl FnMut(SyncAction)) {
        let Some((attempt_present, attempts)) =
            self.range.as_ref().map(|r| (r.attempt.is_some(), r.attempts))
        else {
            return;
        };
        if attempt_present {
            return;
        }
        if K::on_attempts_exhausted(self, ctx, attempts) {
            self.range = None;
            return;
        }
        let id = ctx.next_request_id;
        ctx.next_request_id += 1;
        let Some(range) = self.range.as_ref() else { return };
        let mut request_id = K::PREFIX | id;
        if ctx.spec.is_gloas_at_slot(range.start_slot) {
            request_id |= GLOAS_ERA_FLAG;
        }
        emit(K::request(request_id, range, &self.tried));
    }
}

pub(super) type ColumnSync = RangeDriver<ColumnKind>;
pub(super) type EnvelopeSync = RangeDriver<EnvelopeKind>;

pub(super) struct ColumnKind;

impl RangeKind for ColumnKind {
    const PREFIX: u64 = BASE_REQUEST_ID;

    fn is_enabled(ctx: &Ctx) -> bool {
        ctx.custody_columns != 0
    }

    fn pre_drive(driver: &mut RangeDriver<Self>, ctx: &Ctx) {
        // Gloas columns verify only once their block's bid commitments are
        // cached, so the applied head is the truthful column watermark.
        if ctx.head_is_gloas() {
            driver.synced_through = ctx.local.head_imported_slot;
        }
    }

    fn open(driver: &RangeDriver<Self>, ctx: &Ctx, local_head: u64) -> (u64, u128) {
        (driver.synced_through.max(local_head), ctx.custody_columns)
    }

    fn request(request_id: u64, range: &Range, tried: &HashSet<usize>) -> SyncAction {
        SyncAction::RequestColumnsByRange {
            request_id,
            peer: 0,
            start: range.start_slot,
            count: range.count,
            columns: range.remaining,
            tried_peers: tried.iter().copied().collect(),
        }
    }

    fn on_delivered(
        driver: &mut RangeDriver<Self>,
        ctx: &Ctx,
        columns: u128,
        peer_head_at_issue: u64,
    ) -> bool {
        let Some(range) = driver.range.as_mut() else { return true };
        range.served_through = range.served_through.min(peer_head_at_issue);
        range.remaining &= !columns;
        range.attempts = 0;
        range.attempt = None;
        if range.remaining != 0 {
            return false;
        }
        // Fulu: delivery == verification, so advance the watermark (capped at
        // the serving peer's head). Gloas leaves it pegged to the applied head.
        if !ctx.head_is_gloas() {
            let end = (range.start_slot + range.count - 1).min(range.served_through);
            driver.synced_through = driver.synced_through.max(end);
        }
        true
    }

    fn on_attempts_exhausted(driver: &mut RangeDriver<Self>, ctx: &Ctx, attempts: u64) -> bool {
        if attempts < ctx.cfg.max_colreq_attempts {
            return false;
        }
        driver.tried.clear();
        if ctx.head_is_gloas() {
            // Never concede a Gloas column slot to a by-root straggler — reset
            // the attempt budget and re-fetch the frontier.
            if let Some(r) = driver.range.as_mut() {
                r.attempts = 0;
            }
            false
        } else {
            if let Some(r) = driver.range.as_ref() {
                driver.synced_through = driver.synced_through.max(r.start_slot + r.count - 1);
            }
            true
        }
    }
}

pub(super) struct EnvelopeKind;

impl RangeKind for EnvelopeKind {
    const PREFIX: u64 = ENVELOPE_REQUEST_ID;

    fn is_enabled(ctx: &Ctx) -> bool {
        // Envelopes exist only from the Gloas fork.
        ctx.head_is_gloas()
    }

    fn open(_driver: &RangeDriver<Self>, ctx: &Ctx, local_head: u64) -> (u64, u128) {
        // Start at the applied head (base = head - 1), not head + 1: the head
        // slot's own payload is still unverified and blocks its child.
        let base = local_head.saturating_sub(1).max(ctx.spec.gloas_fork_slot().saturating_sub(1));
        (base, 0)
    }

    fn request(request_id: u64, range: &Range, _tried: &HashSet<usize>) -> SyncAction {
        SyncAction::RequestEnvelopesByRange {
            request_id,
            peer: 0,
            start: range.start_slot,
            count: range.count,
        }
    }

    fn on_delivered(
        _driver: &mut RangeDriver<Self>,
        _ctx: &Ctx,
        _columns: u128,
        _peer_head_at_issue: u64,
    ) -> bool {
        // Delivery only means "buffered / pending block"; the applied head
        // (pegged in `open`) is the real watermark. Retire and reopen there.
        true
    }
}
