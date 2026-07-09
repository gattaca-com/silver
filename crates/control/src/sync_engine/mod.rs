mod backfill;
mod event;
mod peers;
mod range_driver;
mod select;
mod syncing;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use backfill::{Backfill, BackfillPlan};
pub use event::{SyncAction, SyncEvent};
use peers::PeerView;
use silver_chain_spec::SpecConfig;
use silver_common::{
    BlockSource, PeerEvent, PeerStatus, RpcInbound, RpcRequest, RpcRequestInbound, RpcResponse,
    RpcResponseInbound, StreamProtocol, SyncUpdate, SyncingStrategy, ssz_view::StatusView,
};
use silver_peer::SyncingConfig;
use syncing::Syncing;

const SLOTS_PER_EPOCH: u64 = 32;
const SYNCING_STRATEGY_TIMEOUT_WINDOW: Duration = Duration::from_secs(15);
const REPLAY_GATE_TIMEOUT: Duration = Duration::from_secs(300);

fn same_target_identity(a: SyncUpdate, b: SyncUpdate) -> bool {
    match (a, b) {
        (SyncUpdate::Following, SyncUpdate::Following) => true,
        (
            SyncUpdate::SyncingFinalized { target_epoch: e1, target_root: r1 },
            SyncUpdate::SyncingFinalized { target_epoch: e2, target_root: r2 },
        ) => e1 == e2 && r1 == r2,
        (
            SyncUpdate::SyncingHead { head_root: r1, .. },
            SyncUpdate::SyncingHead { head_root: r2, .. },
        ) => r1 == r2,
        _ => false,
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
    ) -> bool {
        let advanced = head_slot > self.head_imported_slot;
        self.have_status = true;
        self.finalized_epoch = finalized_epoch;
        self.finalized_root = finalized_root;
        self.head_imported_slot = head_slot;
        self.wall_slot = wall_slot;
        advanced
    }
}

struct Ctx {
    cfg: SyncingConfig,
    custody_columns: u128,
    spec: Arc<SpecConfig>,
    awaiting_local_replay: bool,
    next_request_id: u64,
    local: LocalView,
    peers: PeerView,
    backfill: BackfillPlan,
}

impl Ctx {
    fn behind_wall(&self) -> bool {
        self.local.wall_slot >
            self.local.head_imported_slot.saturating_add(self.cfg.head_lag_threshold_slots)
    }

    fn head_is_gloas(&self) -> bool {
        self.spec.is_gloas_at_slot(self.local.head_imported_slot + 1)
    }
}

#[allow(clippy::large_enum_variant)]
enum Phase {
    Idle,
    Syncing(Syncing),
    Following(Backfill),
}

pub struct SyncEngine {
    ctx: Ctx,
    phase: Phase,
    dirty: bool,
    was_ever_synced: bool,
    just_synced: bool,
    force_resync: bool,
    syncing_strategy_chosen: bool,
    awaiting_replay_since: Option<Instant>,
}

impl SyncEngine {
    pub fn new(
        cfg: SyncingConfig,
        awaiting_local_replay: bool,
        custody_columns: u128,
        spec: Arc<SpecConfig>,
    ) -> Self {
        Self {
            ctx: Ctx {
                cfg,
                custody_columns,
                spec,
                awaiting_local_replay,
                next_request_id: 0,
                local: LocalView::default(),
                peers: PeerView::default(),
                backfill: BackfillPlan::default(),
            },
            phase: Phase::Idle,
            dirty: false,
            was_ever_synced: false,
            just_synced: false,
            force_resync: false,
            syncing_strategy_chosen: false,
            awaiting_replay_since: None,
        }
    }

    pub fn maybe_choose_syncing_strategy(&mut self, now: Instant) -> Option<SyncingStrategy> {
        if !self.ctx.awaiting_local_replay ||
            self.syncing_strategy_chosen ||
            !self.ctx.local.have_status
        {
            return None;
        }
        let since = *self.awaiting_replay_since.get_or_insert(now);
        if matches!(
            select::select_target(&self.ctx, self.current_target(), self.force_resync),
            SyncUpdate::SyncingFinalized { .. }
        ) {
            self.syncing_strategy_chosen = true;
            return Some(SyncingStrategy::SyncFromPeers);
        }
        if now.saturating_duration_since(since) >= SYNCING_STRATEGY_TIMEOUT_WINDOW {
            self.syncing_strategy_chosen = true;
            return Some(SyncingStrategy::ReplayDisk);
        }
        None
    }

    pub fn current_target(&self) -> SyncUpdate {
        match &self.phase {
            Phase::Syncing(s) => s.target(),
            _ => SyncUpdate::Following,
        }
    }

    pub fn is_synced(&self) -> bool {
        matches!(self.phase, Phase::Following(_))
    }

    pub fn fell_behind(&self) -> bool {
        matches!(self.phase, Phase::Following(_)) &&
            self.ctx.local.have_status &&
            self.ctx.behind_wall()
    }

    pub fn take_just_synced(&mut self) -> bool {
        std::mem::take(&mut self.just_synced)
    }

    pub fn block_synced_through(&self) -> u64 {
        match &self.phase {
            Phase::Syncing(s) => s.synced_through(),
            _ => 0,
        }
    }

    pub fn inflight_block_range_end(&self) -> u64 {
        match &self.phase {
            Phase::Syncing(s) => s.inflight_end(),
            _ => 0,
        }
    }

    pub fn request_resync(&mut self) {
        self.force_resync = true;
        self.dirty = true;
    }

    pub fn peer_event(&mut self, event: PeerEvent, now: Instant, fork_digest: Option<[u8; 4]>) {
        match &event {
            PeerEvent::P2pPeerStatus { p2p_peer, status_ssz } => {
                if let Some(ev) = parse_peer_status(*p2p_peer, status_ssz, fork_digest) {
                    self.on_event(ev, now);
                }
            }
            PeerEvent::P2pDisconnect { p2p_peer, .. } => {
                self.on_event(SyncEvent::PeerDisconnected { peer: *p2p_peer }, now);
            }
            // Storage's backfill scan reports → engine (it schedules).
            PeerEvent::BackfillState { block_floor, earliest_present, .. } => {
                self.on_event(
                    SyncEvent::BackfillState {
                        block_floor: *block_floor,
                        earliest_present: *earliest_present,
                    },
                    now,
                );
            }
            PeerEvent::ColumnNeed { block_root, missing, .. } => {
                self.on_event(
                    SyncEvent::ColumnNeed { block_root: *block_root, missing: *missing },
                    now,
                );
            }
            _ => {}
        }
    }

    pub fn rpc_event(&mut self, now: Instant, rpc: &RpcInbound, fork_digest: Option<[u8; 4]>) {
        match rpc {
            RpcInbound::Response(RpcResponseInbound { application_id, stream_id, response })
                if matches!(
                    stream_id.protocol(),
                    StreamProtocol::BeaconBlocksByRange |
                        StreamProtocol::DataColumnSidecarsByRange |
                        StreamProtocol::DataColumnSidecarsByRoot |
                        StreamProtocol::ExecutionPayloadEnvelopesByRange
                ) =>
            {
                let peer = stream_id.peer();
                let request_id = *application_id;
                let ev = match response {
                    RpcResponse::Complete => Some(SyncEvent::RpcComplete { request_id, peer }),
                    RpcResponse::Error { .. } => Some(SyncEvent::RpcFailed { request_id, peer }),
                    RpcResponse::BeaconBlock { .. } |
                    RpcResponse::DataColumnSidecar { .. } |
                    RpcResponse::ExecutionPayloadEnvelope { .. } => {
                        Some(SyncEvent::RpcChunk { request_id, peer })
                    }
                    _ => None,
                };
                if let Some(ev) = ev {
                    self.on_event(ev, now);
                }
            }
            RpcInbound::Request(RpcRequestInbound {
                stream_id,
                request: RpcRequest::StatusV2(status),
            }) => {
                if let Some(ev) =
                    parse_peer_status(stream_id.peer(), &PeerStatus::V2(*status), fork_digest)
                {
                    self.on_event(ev, now);
                }
            }
            RpcInbound::Request(RpcRequestInbound {
                stream_id,
                request: RpcRequest::StatusV1(status),
            }) => {
                if let Some(ev) =
                    parse_peer_status(stream_id.peer(), &PeerStatus::V1(*status), fork_digest)
                {
                    self.on_event(ev, now);
                }
            }
            RpcInbound::Response(RpcResponseInbound {
                application_id: _,
                stream_id,
                response: RpcResponse::StatusV2(status),
            }) => {
                if let Some(ev) =
                    parse_peer_status(stream_id.peer(), &PeerStatus::V2(*status), fork_digest)
                {
                    self.on_event(ev, now);
                }
            }
            RpcInbound::Response(RpcResponseInbound {
                application_id: _,
                stream_id,
                response: RpcResponse::StatusV1(status),
            }) => {
                if let Some(ev) =
                    parse_peer_status(stream_id.peer(), &PeerStatus::V1(*status), fork_digest)
                {
                    self.on_event(ev, now);
                }
            }
            _ => {}
        }
    }

    pub fn on_event(&mut self, event: SyncEvent, now: Instant) {
        match event {
            SyncEvent::PeerStatus {
                peer,
                head_slot,
                head_root,
                finalized_epoch,
                finalized_root,
                ..
            } => {
                tracing::debug!(peer, head_slot, finalized_epoch, "sync: peer status");
                if self.ctx.peers.is_rejected(&finalized_root) {
                    return;
                }
                self.ctx.peers.upsert(peer, finalized_epoch, finalized_root, head_root, head_slot);
                self.dirty = true;
            }
            SyncEvent::PeerDisconnected { peer } => {
                if self.ctx.peers.remove(peer) {
                    self.dirty = true;
                }
            }
            SyncEvent::LocalStatus { head_slot, finalized_epoch, finalized_root, wall_slot } => {
                tracing::debug!(
                    head_slot,
                    finalized_epoch,
                    wall_slot,
                    "sync: local status updated"
                );
                if self.ctx.local.update(head_slot, finalized_epoch, finalized_root, wall_slot) &&
                    let Phase::Syncing(s) = &mut self.phase
                {
                    s.on_head_advance();
                }
                self.dirty = true;
            }
            SyncEvent::BlockRejected { block_root, source } => {
                self.ctx.peers.mark_rejected(block_root);
                let mut poisoned = None;
                if let Phase::Syncing(s) = &mut self.phase {
                    s.on_block_rejected();
                    if matches!(source, BlockSource::Rpc) &&
                        let SyncUpdate::SyncingFinalized { target_root, .. } = s.target()
                    {
                        poisoned = Some(target_root);
                    }
                }
                if let Some(root) = poisoned {
                    self.ctx.peers.mark_rejected(root);
                }
                self.dirty = true;
            }
            SyncEvent::ReplayComplete => {
                self.ctx.awaiting_local_replay = false;
                self.dirty = true;
            }
            SyncEvent::RpcComplete { request_id, peer } => match &mut self.phase {
                Phase::Syncing(s) => s.on_terminator(request_id, peer, true),
                Phase::Following(bf) => {
                    bf.on_block_complete(request_id, &mut self.ctx.backfill);
                    bf.on_column_done(request_id);
                }
                Phase::Idle => {}
            },
            SyncEvent::RpcFailed { request_id, peer } => match &mut self.phase {
                Phase::Syncing(s) => s.on_terminator(request_id, peer, false),
                Phase::Following(bf) => {
                    bf.on_block_failed(request_id);
                    bf.on_column_done(request_id);
                }
                Phase::Idle => {}
            },
            SyncEvent::RpcChunk { request_id, .. } => match &mut self.phase {
                Phase::Syncing(s) => s.on_chunk(request_id, now),
                Phase::Following(bf) => bf.on_column_chunk(request_id, now),
                Phase::Idle => {}
            },
            SyncEvent::BackfillState { block_floor, earliest_present } => {
                tracing::info!(block_floor, earliest_present, "set backfill state");
                self.ctx.backfill.set_block_gap(block_floor, earliest_present);
            }
            SyncEvent::ColumnNeed { block_root, missing } => {
                self.ctx.backfill.set_column_need(block_root, missing);
            }
        }
    }

    pub fn advance(&mut self, _now: Instant, emit: &mut impl FnMut(SyncAction)) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        let prev_target = self.current_target();
        let new_target = select::select_target(&self.ctx, prev_target, self.force_resync);
        self.force_resync = false;

        let phase = std::mem::replace(&mut self.phase, Phase::Idle);
        self.phase = self.transition(phase, new_target);

        let now_target = self.current_target();
        if !same_target_identity(prev_target, now_target) {
            tracing::info!("Sync target updated from: {prev_target:?} to {now_target:?}");
            emit(SyncAction::SetSyncTarget(now_target));
        }
    }

    fn transition(&mut self, phase: Phase, new_target: SyncUpdate) -> Phase {
        match new_target {
            SyncUpdate::Following => {
                if self.ctx.local.have_status && !self.was_ever_synced && self.ctx.behind_wall() {
                    return phase; // stays Idle
                }
                if self.ctx.local.have_status {
                    self.was_ever_synced = true;
                    match phase {
                        Phase::Following(bf) => Phase::Following(bf),
                        _ => {
                            self.just_synced = true;
                            Phase::Following(Backfill::default())
                        }
                    }
                } else {
                    Phase::Idle
                }
            }
            target => match phase {
                Phase::Syncing(mut s) => {
                    s.retarget(
                        target,
                        self.ctx.cfg.head_lag_threshold_slots,
                        self.ctx.local.head_imported_slot,
                    );
                    Phase::Syncing(s)
                }
                _ => Phase::Syncing(Syncing::new(target)),
            },
        }
    }

    /// Drive the forward block + column lifecycle when `Syncing`.
    pub fn drive_forward_sync(&mut self, now: Instant, emit: &mut impl FnMut(SyncAction)) {
        // Replay-gate watchdog: ungate issuance if `ReplayComplete` was lost.
        if self.ctx.awaiting_local_replay {
            let since = *self.awaiting_replay_since.get_or_insert(now);
            if now.saturating_duration_since(since) >= REPLAY_GATE_TIMEOUT {
                tracing::warn!("local-replay gate timed out without ReplayComplete; unblocking");
                self.ctx.awaiting_local_replay = false;
            }
        }
        match &mut self.phase {
            Phase::Syncing(s) => s.drive(&mut self.ctx, now, emit),
            Phase::Following(bf) => bf.drive(
                &self.ctx.backfill,
                self.ctx.cfg.max_blocks_by_range_batch,
                &mut self.ctx.next_request_id,
                now,
                emit,
            ),
            Phase::Idle => {}
        }
    }

    pub fn on_request_issued(
        &mut self,
        request_id: u64,
        start: u64,
        count: u64,
        peer: Option<usize>,
        now: Instant,
    ) {
        if let Phase::Syncing(s) = &mut self.phase {
            s.on_request_issued(&self.ctx, request_id, start, count, peer, now);
        }
    }

    pub fn on_range_request_issued(
        &mut self,
        request_id: u64,
        peer: Option<(usize, u128)>,
        now: Instant,
    ) {
        if let Phase::Syncing(s) = &mut self.phase {
            s.on_range_request_issued(&self.ctx, request_id, peer, now);
        }
    }
}

/// Parse a peer `Status` into a `PeerStatus` sync event, dropping malformed
/// payloads and wrong-fork-digest peers (which PM evicts before aggregating).
/// `custody` is unused by target selection and left zero.
fn parse_peer_status(
    peer: usize,
    status_ssz: &PeerStatus,
    our_fork_digest: Option<[u8; 4]>,
) -> Option<SyncEvent> {
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
    Some(SyncEvent::PeerStatus {
        peer,
        head_slot: StatusView::head_slot(buf),
        head_root: *StatusView::head_root(buf),
        finalized_epoch: StatusView::finalized_epoch(buf),
        finalized_root: *StatusView::finalized_root(buf),
        earliest_available_slot: StatusView::earliest_available_slot(buf).unwrap_or(0),
        custody: 0,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        time::{Duration, Instant},
    };

    use silver_chain_spec::SpecConfig;
    use silver_common::{
        BlockSource, SyncUpdate, msg_is_envelope_request, msg_is_live_column_request,
        msg_is_post_gloas,
    };
    use silver_peer::SyncingConfig;

    use super::{
        SyncAction, SyncEngine, SyncEvent,
        syncing::{IMPORT_STALL_TIMEOUT, ISSUE_RETRY_BACKOFF},
    };

    const PEER: usize = 1;
    const HEAD_ROOT: [u8; 32] = [7; 32];

    fn engine() -> SyncEngine {
        SyncEngine::new(SyncingConfig::default(), false, 0, Arc::new(SpecConfig::mainnet()))
    }

    fn peer_status(peer: usize, head_root: [u8; 32], head_slot: u64) -> SyncEvent {
        SyncEvent::PeerStatus {
            peer,
            head_slot,
            head_root,
            finalized_epoch: 0,
            finalized_root: [0; 32],
            earliest_available_slot: 0,
            custody: 0,
        }
    }

    fn local_status(head_slot: u64, wall_slot: u64) -> SyncEvent {
        SyncEvent::LocalStatus { head_slot, finalized_epoch: 0, finalized_root: [0; 32], wall_slot }
    }

    fn feed(e: &mut SyncEngine, ev: SyncEvent, now: Instant) {
        e.on_event(ev, now);
    }

    /// Drive one issuance: returns the emitted block `(request_id, start,
    /// count)`, if any.
    fn drive(e: &mut SyncEngine, now: Instant) -> Option<(u64, u64, u64)> {
        let mut req = None;
        e.drive_forward_sync(now, &mut |a| {
            if let SyncAction::RequestBlocksByRange { request_id, start, count, .. } = a {
                req = Some((request_id, start, count));
            }
        });
        req
    }

    /// Bring the engine to `Syncing` against a single head peer and issue the
    /// first range, served by `PEER`. Returns `(request_id, start, count)`.
    fn issue_one(
        e: &mut SyncEngine,
        peer_head: u64,
        local_head: u64,
        now: Instant,
    ) -> (u64, u64, u64) {
        feed(e, peer_status(PEER, HEAD_ROOT, peer_head), now);
        feed(e, local_status(local_head, peer_head), now);
        e.advance(now, &mut |_| {});
        assert!(matches!(e.current_target(), SyncUpdate::SyncingHead { .. }), "entered Syncing");
        let (rid, start, count) = drive(e, now).expect("range issued");
        e.on_request_issued(rid, start, count, Some(PEER), now);
        (rid, start, count)
    }

    #[test]
    fn selects_head_target_and_emits() {
        let now = Instant::now();
        let mut e = engine();
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        let mut emitted = None;
        e.advance(now, &mut |a| {
            if let SyncAction::SetSyncTarget(t) = a {
                emitted = Some(t);
            }
        });
        assert_eq!(emitted, Some(SyncUpdate::SyncingHead { head_root: HEAD_ROOT, head_slot: 200 }));
        assert!(!e.is_synced());
    }

    #[test]
    fn caught_up_enters_following_and_latches_just_synced() {
        let now = Instant::now();
        let mut e = engine();
        // First sync to a head, then local head reaches it with no peer ahead.
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});
        assert!(matches!(e.current_target(), SyncUpdate::SyncingHead { .. }));

        feed(&mut e, local_status(200, 200), now);
        e.advance(now, &mut |_| {});
        assert!(e.is_synced());
        assert!(e.take_just_synced());
        assert!(!e.take_just_synced(), "one-shot");
    }

    #[test]
    fn cold_start_stays_idle_until_caught_up() {
        let now = Instant::now();
        let mut e = engine();
        // Status arrives, far behind wall, no peer target → stay Idle (not
        // Following), emit nothing.
        feed(&mut e, local_status(0, 1000), now);
        let mut emitted = None;
        e.advance(now, &mut |a| {
            if let SyncAction::SetSyncTarget(t) = a {
                emitted = Some(t);
            }
        });
        assert_eq!(emitted, None, "Following suppressed at cold start");
        assert!(!e.is_synced());
    }

    #[test]
    fn complete_advances_watermark_without_import() {
        let now = Instant::now();
        let mut e = engine();
        let (rid, _start, count) = issue_one(&mut e, 200, 0, now);
        feed(&mut e, SyncEvent::RpcComplete { request_id: rid, peer: PEER }, now);
        // Local head never advanced (still 0) — completion is response-driven.
        drive(&mut e, now);
        assert_eq!(e.block_synced_through(), count);
        assert_eq!(e.inflight_block_range_end(), 0, "delivered range cleared");
    }

    #[test]
    fn complete_caps_at_serving_peer_head() {
        // Two peers on the same chain: A (head 200) sets the target; B (head 20,
        // behind) serves the head-batch [1, 32] range. `Complete` advances only
        // to 20 — never claims past the serving peer's tip.
        let now = Instant::now();
        let mut e = engine();
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, peer_status(2, HEAD_ROOT, 20), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});
        let (rid, start, count) = drive(&mut e, now).expect("range issued");
        assert_eq!((start, count), (1, 32), "head sync uses the 32-block batch");
        e.on_request_issued(rid, start, count, Some(2), now); // served by B (head 20)
        feed(&mut e, SyncEvent::RpcComplete { request_id: rid, peer: 2 }, now);
        drive(&mut e, now);
        assert_eq!(e.block_synced_through(), 20);
    }

    #[test]
    fn finalized_uses_full_batch_head_uses_smaller() {
        let now = Instant::now();
        let mut e = engine();
        // A finalized target far ahead → full `max_blocks_by_range_batch` (64).
        feed(
            &mut e,
            SyncEvent::PeerStatus {
                peer: PEER,
                head_slot: 4000,
                head_root: [5; 32],
                finalized_epoch: 100,
                finalized_root: [5; 32],
                earliest_available_slot: 0,
                custody: 0,
            },
            now,
        );
        feed(&mut e, local_status(0, 4000), now);
        e.advance(now, &mut |_| {});
        assert!(matches!(e.current_target(), SyncUpdate::SyncingFinalized { .. }));
        let (_, start, count) = drive(&mut e, now).expect("range issued");
        assert_eq!((start, count), (1, 64), "finalized catch-up uses the full batch");

        // A head-only peer → the 32-block head batch.
        let mut e = engine();
        let (_, start, count) = issue_one(&mut e, 200, 0, now);
        assert_eq!((start, count), (1, 32), "head sync uses the 32-block batch");
    }

    #[test]
    fn envelopes_trail_block_progress_in_gloas() {
        let now = Instant::now();
        // Gloas from epoch 0: the whole head-sync window is in gloas.
        let mut e = SyncEngine::new(
            SyncingConfig::default(),
            false,
            0,
            Arc::new(SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() }),
        );
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});

        // First drive issues blocks; envelopes can't open until a block range is
        // in flight (they pace to the block watermark / in-flight end).
        let (brid, bstart, bcount) = drive(&mut e, now).expect("block issued");
        e.on_request_issued(brid, bstart, bcount, Some(PEER), now);

        // Second drive: the envelope range now trails the in-flight block range.
        let mut env = None;
        e.drive_forward_sync(now, &mut |a| {
            if let SyncAction::RequestEnvelopesByRange { request_id, start, count, .. } = a {
                env = Some((request_id, start, count));
            }
        });
        let (erid, estart, ecount) = env.expect("envelope range issued");
        assert_eq!((estart, ecount), (1, 32), "envelopes trail the 32-block head batch");
        assert!(msg_is_envelope_request(erid), "envelope request id");
    }

    #[test]
    fn no_envelopes_below_gloas_fork() {
        let now = Instant::now();
        // Gloas far in the future (epoch 32 = slot 1024): the applied-head
        // frontier stays pre-gloas across the 200-slot window.
        let mut e = SyncEngine::new(
            SyncingConfig::default(),
            false,
            0,
            Arc::new(SpecConfig { gloas_fork_epoch: 32, ..SpecConfig::mainnet() }),
        );
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});

        let (brid, bstart, bcount) = drive(&mut e, now).expect("block issued");
        e.on_request_issued(brid, bstart, bcount, Some(PEER), now);

        let mut env = None;
        e.drive_forward_sync(now, &mut |a| {
            if let SyncAction::RequestEnvelopesByRange { start, count, .. } = a {
                env = Some((start, count));
            }
        });
        assert_eq!(env, None, "no envelope request below the gloas fork slot");
    }

    #[test]
    fn head_sync_lead_hard_capped_at_64() {
        let now = Instant::now();
        let mut e = engine();
        // Head far ahead, local head pinned at 0 (import makes no progress).
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 1000), now);
        feed(&mut e, local_status(0, 1000), now);
        e.advance(now, &mut |_| {});

        // Drive + complete repeatedly; the watermark must stop at head + 64.
        for _ in 0..10 {
            let Some((rid, start, count)) = drive(&mut e, now) else { break };
            e.on_request_issued(rid, start, count, Some(PEER), now);
            feed(&mut e, SyncEvent::RpcComplete { request_id: rid, peer: PEER }, now);
        }
        assert_eq!(e.block_synced_through(), 64, "head lead hard-capped at 64");
    }

    #[test]
    fn unrouted_request_awaits_peer_then_re_emits_after_backoff() {
        let t0 = Instant::now();
        let mut e = engine();
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), t0);
        feed(&mut e, local_status(0, 200), t0);
        e.advance(t0, &mut |_| {});
        let (rid, start, count) = drive(&mut e, t0).expect("range issued");

        // PM found no peer to place it → AwaitingPeer.
        e.on_request_issued(rid, start, count, None, t0);
        assert!(drive(&mut e, t0).is_none(), "awaits peer; no re-emit before backoff");

        // After the backoff: re-emitted with the *same* request id + range.
        let later = t0 + ISSUE_RETRY_BACKOFF;
        assert_eq!(drive(&mut e, later), Some((rid, start, count)), "re-emits same request");

        // A peer is found → InFlight, no further re-emit.
        e.on_request_issued(rid, start, count, Some(PEER), later);
        assert!(drive(&mut e, later).is_none(), "placed; stops re-emitting");
    }

    #[test]
    fn unrouted_column_request_awaits_peer_then_re_emits_after_backoff() {
        let t0 = Instant::now();
        let mut e = SyncEngine::new(
            SyncingConfig::default(),
            false,
            0b1011,
            Arc::new(SpecConfig::mainnet()),
        );
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), t0);
        feed(&mut e, local_status(0, 200), t0);
        e.advance(t0, &mut |_| {});

        // Open a block range so the column driver has something to trail.
        let (brid, bstart, bcount) = drive(&mut e, t0).expect("block issued");
        e.on_request_issued(brid, bstart, bcount, Some(PEER), t0);

        let col = |e: &mut SyncEngine, now| {
            let mut c = None;
            e.drive_forward_sync(now, &mut |a| {
                if let SyncAction::RequestColumnsByRange { request_id, start, count, .. } = a {
                    c = Some((request_id, start, count));
                }
            });
            c
        };
        let (crid, cstart, ccount) = col(&mut e, t0).expect("column range issued");

        // PM found no custody peer → AwaitingPeer.
        e.on_range_request_issued(crid, None, t0);
        assert!(col(&mut e, t0).is_none(), "awaits peer; no re-emit before backoff");

        // After the backoff: re-emitted with the *same* request id + range.
        let later = t0 + ISSUE_RETRY_BACKOFF;
        assert_eq!(col(&mut e, later), Some((crid, cstart, ccount)), "re-emits same request");
    }

    #[test]
    fn error_terminator_retries_without_advancing() {
        let now = Instant::now();
        let mut e = engine();
        let (rid, _start, _count) = issue_one(&mut e, 200, 0, now);
        feed(&mut e, SyncEvent::RpcFailed { request_id: rid, peer: PEER }, now);
        let reissued = drive(&mut e, now).map(|(_, start, _)| start);
        assert_eq!(e.block_synced_through(), 0, "watermark untouched on error");
        assert_eq!(reissued, Some(1), "re-issued from the applied head");
    }

    #[test]
    fn import_stall_backtracks_watermark_to_applied_head() {
        let t0 = Instant::now();
        let mut e = engine();
        let (rid, _start, count) = issue_one(&mut e, 200, 0, t0);
        feed(&mut e, SyncEvent::RpcComplete { request_id: rid, peer: PEER }, t0);
        // Delivered: watermark leads the (still 0) applied head — arms the clock.
        drive(&mut e, t0);
        assert_eq!(e.block_synced_through(), count);

        // Import never advanced past the stall window → backtrack to head (0).
        drive(&mut e, t0 + IMPORT_STALL_TIMEOUT + Duration::from_secs(1));
        assert_eq!(e.block_synced_through(), 0, "watermark reset to applied head");
    }

    #[test]
    fn import_progress_refreshes_stall_clock() {
        let t0 = Instant::now();
        let mut e = engine();
        let (rid, _start, count) = issue_one(&mut e, 400, 0, t0);
        feed(&mut e, SyncEvent::RpcComplete { request_id: rid, peer: PEER }, t0);
        drive(&mut e, t0);
        assert_eq!(e.block_synced_through(), count);

        // Import advances partially just before the window closes — still
        // fetched-ahead (head 16 < watermark 32), but the clock restarts.
        let near = t0 + IMPORT_STALL_TIMEOUT - Duration::from_secs(1);
        feed(&mut e, local_status(16, 400), near);
        // Past the *original* deadline, but the refresh re-armed the clock at
        // `near` — no backtrack, watermark intact.
        drive(&mut e, t0 + IMPORT_STALL_TIMEOUT + Duration::from_secs(1));
        assert_eq!(e.block_synced_through(), count, "no spurious backtrack after import progress");
    }

    #[test]
    fn chain_segment_change_resets_watermark() {
        let now = Instant::now();
        let mut e = engine();
        let (rid, _start, count) = issue_one(&mut e, 200, 0, now);
        feed(&mut e, SyncEvent::RpcComplete { request_id: rid, peer: PEER }, now);
        drive(&mut e, now);
        assert_eq!(e.block_synced_through(), count);

        // The pinned head loses its only backer; a different-fork head appears
        // → re-target to a different chain resets the watermark.
        feed(&mut e, SyncEvent::PeerDisconnected { peer: PEER }, now);
        feed(&mut e, peer_status(2, [9; 32], 300), now);
        feed(&mut e, local_status(0, 300), now);
        e.advance(now, &mut |_| {});
        assert!(
            matches!(e.current_target(), SyncUpdate::SyncingHead { head_root, .. } if head_root == [9; 32]),
        );
        assert_eq!(e.block_synced_through(), 0, "watermark reset on chain change");
    }

    #[test]
    fn columns_trail_block_progress() {
        let now = Instant::now();
        // Custody a few columns so the column driver is live.
        let mut e = SyncEngine::new(
            SyncingConfig::default(),
            false,
            0b1011,
            Arc::new(SpecConfig::mainnet()),
        );
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});

        // First drive issues blocks; columns can't open until a block range is
        // in flight (they pace to the block watermark / in-flight end).
        let (brid, bstart, bcount) = drive(&mut e, now).expect("block issued");
        e.on_request_issued(brid, bstart, bcount, Some(PEER), now);

        // Second drive: the column range now trails the in-flight block range.
        let mut col = None;
        e.drive_forward_sync(now, &mut |a| {
            if let SyncAction::RequestColumnsByRange { request_id, start, count, columns, .. } = a {
                col = Some((request_id, start, count, columns));
            }
        });
        let (crid, cstart, ccount, ccols) = col.expect("column range issued");
        // Columns trail the in-flight block range (head sync's 32-block batch).
        assert_eq!((cstart, ccount), (1, 32));
        assert_eq!(ccols, 0b1011, "requests the full custody mask");
        assert!(msg_is_live_column_request(crid), "live-column request id");
        assert!(!msg_is_post_gloas(crid), "pre-gloas range carries no era flag");
    }

    #[test]
    fn column_range_stops_at_gloas_fork() {
        let now = Instant::now();
        // Gloas at epoch 1 (slot 32). A pre-fork column range must not span the
        // boundary, so the whole range shares one (fulu) sidecar layout.
        let mut e = SyncEngine::new(
            SyncingConfig::default(),
            false,
            0b1011,
            Arc::new(SpecConfig { gloas_fork_epoch: 1, ..SpecConfig::mainnet() }),
        );
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});

        let (brid, bstart, bcount) = drive(&mut e, now).expect("block issued");
        e.on_request_issued(brid, bstart, bcount, Some(PEER), now);

        let mut col = None;
        e.drive_forward_sync(now, &mut |a| {
            if let SyncAction::RequestColumnsByRange { request_id, start, count, .. } = a {
                col = Some((request_id, start, count));
            }
        });
        let (crid, cstart, ccount) = col.expect("column range issued");
        // Clamped to end at slot 31 (fork slot 32) instead of the full 32-batch.
        assert_eq!((cstart, ccount), (1, 31), "range stops just below the fork slot");
        assert!(!msg_is_post_gloas(crid), "fulu-era range: no gloas flag");
    }

    #[test]
    fn gloas_era_column_range_carries_flag() {
        let now = Instant::now();
        // Gloas from epoch 0: the whole window is gloas-era.
        let mut e = SyncEngine::new(
            SyncingConfig::default(),
            false,
            0b1011,
            Arc::new(SpecConfig { gloas_fork_epoch: 0, ..SpecConfig::mainnet() }),
        );
        feed(&mut e, peer_status(PEER, HEAD_ROOT, 200), now);
        feed(&mut e, local_status(0, 200), now);
        e.advance(now, &mut |_| {});

        let (brid, bstart, bcount) = drive(&mut e, now).expect("block issued");
        e.on_request_issued(brid, bstart, bcount, Some(PEER), now);

        let mut col = None;
        e.drive_forward_sync(now, &mut |a| {
            if let SyncAction::RequestColumnsByRange { request_id, start, count, .. } = a {
                col = Some((request_id, start, count));
            }
        });
        let (crid, cstart, ccount) = col.expect("column range issued");
        assert_eq!((cstart, ccount), (1, 32), "gloas columns trail the block batch");
        assert!(msg_is_post_gloas(crid), "gloas-era range carries the flag");
        assert!(msg_is_live_column_request(crid), "live-column request id");
    }

    #[test]
    fn rpc_block_reject_blacklists_finalized_target() {
        let now = Instant::now();
        let mut e = engine();
        // Sync to a finalized target.
        feed(
            &mut e,
            SyncEvent::PeerStatus {
                peer: PEER,
                head_slot: 4000,
                head_root: HEAD_ROOT,
                finalized_epoch: 100,
                finalized_root: [5; 32],
                earliest_available_slot: 0,
                custody: 0,
            },
            now,
        );
        feed(&mut e, local_status(0, 4000), now);
        e.advance(now, &mut |_| {});
        let target = e.current_target();
        assert!(
            matches!(target, SyncUpdate::SyncingFinalized { target_root, .. } if target_root == [5; 32])
        );

        // Rpc-sourced reject blacklists the target root → can't re-pin it.
        feed(
            &mut e,
            SyncEvent::BlockRejected { block_root: [1; 32], source: BlockSource::Rpc },
            now,
        );
        e.advance(now, &mut |_| {});
        assert!(
            !matches!(e.current_target(), SyncUpdate::SyncingFinalized { target_root, .. } if target_root == [5; 32]),
            "poisoned finalized target not re-pinned",
        );
    }
}
