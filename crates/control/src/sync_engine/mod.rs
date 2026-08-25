mod backfill;
mod by_root;
mod peers;
mod select;
mod sync_window;
mod syncing;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use backfill::BackfillPlan;
use by_root::ByRootRequests;
use peers::PeerView;
use silver_chain_spec::SpecConfig;
use silver_common::{
    BeaconStateEvent, BlockSource, DataKind, PeerEvent, PeerStatus, RpcInbound, RpcRequest,
    RpcRequestInbound, RpcResponse, RpcResponseInbound, SLOTS_PER_EPOCH, SyncNeed, SyncRequest,
    SyncUpdate, SyncingStrategy, ssz_view::StatusView,
};
use silver_peer::SyncingConfig;
use sync_window::{FETCH_CEILING, SyncWindow};
use syncing::Syncing;

use crate::ControlCounters;

pub const BATCH: u64 = 64;
pub(super) const BACKFILL_BATCH: u64 = 32;

const SYNCING_STRATEGY_TIMEOUT_WINDOW: Duration = Duration::from_secs(15);

const ISSUE_RETRY_BACKOFF: Duration = Duration::from_millis(250);

/// How long to wait for a report of data being settled on the interested tile
/// before refetching it.
pub(super) const SETTLE_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) const BACKFILL_SETTLE_TIMEOUT: Duration = Duration::from_secs(4);

pub enum SyncAction {
    /// Ask the peer manager to place this. It answers whether any peer took it.
    Request { request_id: u64, request: SyncRequest },
    /// Nobody can serve what we need; go looking for peers who can.
    DiscoverPeers,
}

#[derive(Clone, Copy)]
pub(super) enum Placement {
    WithPeer,
    AwaitingPeer { retry_at: Instant },
}

impl Placement {
    pub(super) fn after_emit(placed: bool, now: Instant) -> Self {
        match placed {
            true => Self::WithPeer,
            false => Self::AwaitingPeer { retry_at: now + ISSUE_RETRY_BACKOFF },
        }
    }

    pub(super) fn needs_reoffer(self, now: Instant) -> bool {
        matches!(self, Self::AwaitingPeer { retry_at } if now >= retry_at)
    }
}

enum ReplayGate {
    Open,
    AwaitingStatus,
    Deciding { since: Instant },
    Decided,
}

impl ReplayGate {
    fn new(awaiting_local_replay: bool) -> Self {
        match awaiting_local_replay {
            true => Self::AwaitingStatus,
            false => Self::Open,
        }
    }

    fn blocks_requests(&self) -> bool {
        !matches!(self, Self::Open)
    }

    fn open(&mut self) {
        *self = Self::Open;
    }

    fn deciding_for(&mut self, now: Instant) -> Option<Duration> {
        match *self {
            Self::Open | Self::Decided => None,
            Self::AwaitingStatus => {
                *self = Self::Deciding { since: now };
                Some(Duration::ZERO)
            }
            Self::Deciding { since } => Some(now.saturating_duration_since(since)),
        }
    }

    fn decided(&mut self) {
        *self = Self::Decided;
    }
}

#[derive(Default)]
struct LocalView {
    have_status: bool,
    finalized_epoch: u64,
    finalized_root: [u8; 32],
    head_imported_slot: u64,
    wall_slot: u64,
}

impl LocalView {
    fn update(
        &mut self,
        head_slot: u64,
        finalized_epoch: u64,
        finalized_root: [u8; 32],
        wall_slot: u64,
    ) {
        self.have_status = true;
        self.finalized_epoch = finalized_epoch;
        self.finalized_root = finalized_root;
        self.head_imported_slot = head_slot;
        self.wall_slot = wall_slot;
    }

    fn finalized_slot(&self) -> u64 {
        self.finalized_epoch * SLOTS_PER_EPOCH
    }
}

struct Ctx {
    cfg: SyncingConfig,
    custody_columns: u128,
    spec: Arc<SpecConfig>,
    next_request_id: u64,
    local: LocalView,
    peers: PeerView,
    backfill: BackfillPlan,
    root_requests: ByRootRequests,
}

#[allow(clippy::large_enum_variant)]
enum Phase {
    Idle,
    Syncing(Syncing),
    Following,
}

impl Phase {
    fn target(&self) -> Option<SyncUpdate> {
        match self {
            Self::Idle => None,
            Self::Syncing(s) => Some(s.target()),
            Self::Following => Some(SyncUpdate::Following),
        }
    }

    fn is_following(&self) -> bool {
        matches!(self, Self::Following)
    }

    fn column_claim(&self) -> Option<(u64, u64)> {
        match self {
            Self::Syncing(s) => s.inflight_span(DataKind::Columns),
            Self::Idle | Self::Following => None,
        }
    }

    fn on_terminator(
        &mut self,
        ctx: &mut Ctx,
        window: &mut SyncWindow,
        request_id: u64,
        peer: usize,
        delivered: bool,
        now: Instant,
    ) {
        if let Self::Syncing(s) = self {
            s.on_terminator(ctx, window, request_id, peer, delivered, now);
        }
    }

    fn on_reorg(&mut self) {
        if let Self::Syncing(s) = self {
            s.restart();
        }
    }

    fn note_report(&mut self, kind: DataKind, slot: u64) {
        if let Self::Syncing(s) = self {
            s.note_report(kind, slot);
        }
    }

    fn on_block_rejected(&mut self, ctx: &mut Ctx, source: BlockSource) {
        let Self::Syncing(s) = self else { return };
        s.restart();
        if matches!(source, BlockSource::Rpc) &&
            let SyncUpdate::SyncingFinalized { target_root, .. } = s.target()
        {
            ctx.peers.mark_rejected(target_root);
        }
    }

    /// Returns true when the chain was marked unavailable, so the caller
    /// re-runs target selection.
    fn drive(
        &mut self,
        ctx: &mut Ctx,
        window: &mut SyncWindow,
        now: Instant,
        emit: &mut impl FnMut(SyncAction) -> bool,
    ) -> bool {
        match self {
            Self::Syncing(s) => s.drive(ctx, window, now, emit),
            Self::Following => {
                ctx.backfill.drive(
                    ctx.custody_columns,
                    BACKFILL_BATCH,
                    &mut ctx.next_request_id,
                    now,
                    emit,
                );
                false
            }
            Self::Idle => false,
        }
    }
}

pub struct SyncEngine {
    ctx: Ctx,
    window: SyncWindow,
    phase: Phase,
    published: Option<SyncUpdate>,
    dirty: bool,
    /// `has_block_gap()` is the only `select_target` input no event owns.
    prev_has_block_gap: bool,
    just_synced: bool,
    replay: ReplayGate,
}

impl SyncEngine {
    pub fn new(
        cfg: SyncingConfig,
        awaiting_local_replay: bool,
        custody_columns: u128,
        spec: Arc<SpecConfig>,
    ) -> Self {
        // Buffer discipline: coverage is only durable if every block we fetch
        // ahead can be parked.
        assert!(
            FETCH_CEILING <= cfg.pending.max_dc as u64,
            "fetch ceiling {FETCH_CEILING} exceeds max_dc {}",
            cfg.pending.max_dc
        );

        let by_root_cap = cfg.pending.max_parents + cfg.pending.max_dc;
        Self {
            ctx: Ctx {
                custody_columns,
                spec,
                next_request_id: 0,
                local: LocalView::default(),
                peers: PeerView::new(cfg.rejected_cap),
                cfg,
                backfill: BackfillPlan::default(),
                root_requests: ByRootRequests::new(by_root_cap),
            },
            window: SyncWindow::new(),
            phase: Phase::Idle,
            published: None,
            dirty: false,
            prev_has_block_gap: false,
            just_synced: false,
            replay: ReplayGate::new(awaiting_local_replay),
        }
    }

    pub fn maybe_choose_syncing_strategy(&mut self, now: Instant) -> Option<SyncingStrategy> {
        if !self.ctx.local.have_status {
            return None;
        }
        let deciding_for = self.replay.deciding_for(now)?;
        let strategy =
            match select::select_target(&self.ctx, self.has_block_gap(), self.phase.target()) {
                SyncUpdate::SyncingFinalized { .. } => SyncingStrategy::SyncFromPeers,
                _ if deciding_for >= SYNCING_STRATEGY_TIMEOUT_WINDOW => SyncingStrategy::ReplayDisk,
                _ => return None,
            };
        self.replay.decided();
        Some(strategy)
    }

    pub fn current_target(&self) -> Option<SyncUpdate> {
        self.phase.target()
    }

    fn has_block_gap(&self) -> bool {
        self.window.unknown_blocks_up_to_slot(self.ctx.local.wall_slot) >=
            self.ctx.cfg.head_lag_threshold_slots
    }

    pub fn fell_behind(&self) -> bool {
        self.phase.is_following() && self.ctx.local.have_status && self.has_block_gap()
    }

    pub fn take_just_synced(&mut self) -> bool {
        std::mem::take(&mut self.just_synced)
    }

    pub fn on_peer_event(&mut self, event: PeerEvent, fork_digest: Option<[u8; 4]>) {
        match &event {
            PeerEvent::P2pPeerStatus { p2p_peer, status_ssz } => {
                if let Some(status) = checked_status(status_ssz, fork_digest) {
                    self.on_peer_status(*p2p_peer, status);
                }
            }
            PeerEvent::P2pDisconnect { p2p_peer, .. } => self.on_peer_disconnected(*p2p_peer),
            _ => {}
        }
    }

    pub fn rpc_event(&mut self, rpc: &RpcInbound, fork_digest: Option<[u8; 4]>) {
        match rpc {
            RpcInbound::Request(RpcRequestInbound {
                stream_id,
                request: RpcRequest::StatusV2(status),
            }) |
            RpcInbound::Response(RpcResponseInbound {
                stream_id,
                response: RpcResponse::StatusV2(status),
                ..
            }) => {
                let status_ssz = PeerStatus::V2(*status);
                if let Some(status) = checked_status(&status_ssz, fork_digest) {
                    self.on_peer_status(stream_id.peer(), status);
                }
            }
            RpcInbound::Request(RpcRequestInbound {
                stream_id,
                request: RpcRequest::StatusV1(status),
            }) |
            RpcInbound::Response(RpcResponseInbound {
                stream_id,
                response: RpcResponse::StatusV1(status),
                ..
            }) => {
                let status_ssz = PeerStatus::V1(*status);
                if let Some(status) = checked_status(&status_ssz, fork_digest) {
                    self.on_peer_status(stream_id.peer(), status);
                }
            }
            _ => {}
        }
    }

    pub fn on_sync_need(&mut self, need: SyncNeed, now: Instant) {
        match need {
            SyncNeed::Missing { root, slot, kind, columns, origin } => {
                self.ctx.root_requests.want(root, kind, columns, origin, slot, now);
            }
            SyncNeed::Arrived { root, kind, .. } => {
                self.ctx.root_requests.retire(&root);
                self.ctx.backfill.on_arrived(kind);
            }
            SyncNeed::BackfillGap { kind, floor, next } => {
                self.ctx.backfill.set_owed(kind, floor, next)
            }
        }
    }

    /// Status is handled separately - to only consume the latest one and in
    /// sync with the other part of the Control tile.
    pub fn on_beacon_state_event(&mut self, event: &BeaconStateEvent) {
        match *event {
            BeaconStateEvent::BlockRejected { block_root, source } => {
                self.on_block_rejected(block_root, source)
            }
            BeaconStateEvent::ReplayComplete => self.on_replay_complete(),
            BeaconStateEvent::BlockReceived { slot, block_root, parent_slot, applied } => {
                self.on_block_received(slot, block_root, parent_slot, applied)
            }
            BeaconStateEvent::EnvelopeAvailable { slot, block_root, .. } => {
                self.on_envelope_covered(slot, block_root)
            }
            BeaconStateEvent::Reorg { lca_slot } => self.on_reorg(lca_slot),
            _ => {}
        }
    }

    fn on_peer_status(&mut self, peer: usize, status: &[u8]) {
        let finalized_root = *StatusView::finalized_root(status);
        let (head_slot, finalized_epoch) =
            (StatusView::head_slot(status), StatusView::finalized_epoch(status));
        tracing::debug!(peer, head_slot, finalized_epoch, "sync: peer status");
        if self.ctx.peers.is_rejected(&finalized_root) {
            return;
        }
        if self.ctx.peers.upsert(peer, status) {
            self.ctx.peers.retry_chains_backed_by(peer);
        }
        self.mark_dirty();
    }

    fn on_peer_disconnected(&mut self, peer: usize) {
        self.dirty |= self.ctx.peers.remove(peer);
    }

    pub fn on_local_status(
        &mut self,
        head_slot: u64,
        finalized_epoch: u64,
        finalized_root: [u8; 32],
        wall_slot: u64,
    ) {
        tracing::debug!(head_slot, finalized_epoch, wall_slot, "sync: local status updated");
        self.ctx.local.update(head_slot, finalized_epoch, finalized_root, wall_slot);
        self.window.record_status(head_slot, self.ctx.local.finalized_slot());
        self.ctx.root_requests.prune_finalized(self.ctx.local.finalized_slot());
        self.mark_dirty();
    }

    fn on_block_rejected(&mut self, block_root: [u8; 32], source: BlockSource) {
        self.ctx.peers.mark_rejected(block_root);
        self.phase.on_block_rejected(&mut self.ctx, source);
        self.mark_dirty();
    }

    fn on_replay_complete(&mut self) {
        self.replay.open();
        self.window.restart_at_next_status();
    }

    pub fn on_terminator(&mut self, request_id: u64, peer: usize, delivered: bool, now: Instant) {
        self.ctx.backfill.on_terminator(request_id, delivered, now);
        self.phase.on_terminator(&mut self.ctx, &mut self.window, request_id, peer, delivered, now);
    }

    pub fn on_msg_served(&mut self, request_id: u64) {
        if let Phase::Syncing(s) = &mut self.phase {
            s.on_msg_served(request_id);
        }
    }

    fn on_block_received(
        &mut self,
        slot: u64,
        block_root: [u8; 32],
        parent_slot: Option<u64>,
        applied: bool,
    ) {
        self.window.block_received(slot, block_root, parent_slot, applied);
        self.phase.note_report(DataKind::Block, slot);
        self.ctx.root_requests.retire(&block_root);
    }

    fn on_envelope_covered(&mut self, slot: u64, block_root: [u8; 32]) {
        self.ctx.root_requests.retire(&block_root);
        self.window.envelope_covered(slot);
        self.phase.note_report(DataKind::Envelope, slot);
    }

    pub fn on_columns_covered(&mut self, slot: u64, block_root: [u8; 32]) {
        self.ctx.root_requests.retire(&block_root);
        self.window.columns_covered(slot);
        self.phase.note_report(DataKind::Columns, slot);
    }

    fn on_reorg(&mut self, lca_slot: u64) {
        tracing::info!(lca_slot, "sync: reorg, dropping coverage above the ancestor");
        self.window.on_reorg(lca_slot);
        self.phase.on_reorg();
    }

    fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn advance(&mut self) -> Option<SyncUpdate> {
        let has_block_gap = self.has_block_gap();
        let dirty = std::mem::take(&mut self.dirty);
        if !dirty && has_block_gap == self.prev_has_block_gap {
            return None;
        }

        self.prev_has_block_gap = has_block_gap;
        self.enter_phase_for(select::select_target(&self.ctx, has_block_gap, self.phase.target()));

        let target = self.phase.target()?;
        if self.published.is_some_and(|p| p.same_target_as(target)) {
            return None;
        }
        let previous = self.published.replace(target);
        tracing::info!("Sync target updated from: {previous:?} to {target:?}");
        Some(target)
    }

    fn enter_phase_for(&mut self, chosen: SyncUpdate) {
        let resolved = self.resolve(chosen);

        if let Phase::Syncing(s) = &mut self.phase &&
            let Some(target) = resolved &&
            s.target().same_target_as(target)
        {
            s.repin(target);
            return;
        }

        self.just_synced |=
            matches!(resolved, Some(SyncUpdate::Following)) && !self.phase.is_following();
        self.phase = match resolved {
            None => Phase::Idle,
            Some(SyncUpdate::Following) => Phase::Following,
            Some(target) => {
                self.window.reseed_for_new_target();
                Phase::Syncing(Syncing::new(target))
            }
        };
    }

    fn resolve(&self, chosen: SyncUpdate) -> Option<SyncUpdate> {
        if !chosen.is_following() {
            return Some(chosen);
        }
        let comparable = self.ctx.local.have_status &&
            (self.phase.target().is_some() || self.ctx.peers.received_statuses());
        comparable.then_some(SyncUpdate::Following)
    }

    pub fn drive_requests(&mut self, now: Instant, emit: &mut impl FnMut(SyncAction) -> bool) {
        if self.replay.blocks_requests() {
            return;
        }

        let claim = self.phase.column_claim();
        self.ctx.root_requests.drive(
            &mut self.ctx.next_request_id,
            now,
            |slot| claim.is_some_and(|(start, end)| (start..=end).contains(&slot)),
            emit,
        );

        self.dirty |= self.phase.drive(&mut self.ctx, &mut self.window, now, emit);
    }
}

/// A peer `Status` worth aggregating: `None` for a malformed payload or a
/// wrong-fork-digest peer (which PM evicts before aggregating).
fn checked_status(status_ssz: &PeerStatus, our_fork_digest: Option<[u8; 4]>) -> Option<&[u8]> {
    let buf: &[u8] = match status_ssz {
        PeerStatus::V1(b) => b,
        PeerStatus::V2(b) => b,
    };
    if !StatusView::check_size(buf) {
        return None;
    }
    if let Some(fd) = our_fork_digest &&
        *StatusView::fork_digest(buf) != fd
    {
        tracing::info!("peer status fork digest mismatch");
        return None;
    }
    Some(buf)
}

#[cfg(test)]
mod tests;
