//! Peer manager: consumes `PeerEvent`, maintains per-peer state + scoring,
//! emits `PeerControl`. Counters-only on the hot path; all score math +
//! mesh decisions live in `tick`.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use flux_profiler::timed;
use fxhash::FxHashSet;
use silver_common::{
    BlockSource, Enr, GossipMsgOut, GossipTopic, IpBytes, MessageId, P2pSend, PeerControl,
    PeerEvent, PeerId, PeerStatus, RpcRequest, RpcRequestOutbound, RpcSeverity, StreamProtocol,
    SyncUpdate, TCacheRead,
    rpc_rate_limit::RpcRateLimit,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE, StatusView},
};
use silver_config::{ScoreParams, SyncingConfig};

use crate::{
    database::{PeerDatabase, PeerRecord},
    scoring,
    state::{ArchivedState, IpPrefix, MsgIdMap, PeerState, TopicScore},
};

pub(crate) mod rpc;

/// Initial capacity hints — chosen so normal steady-state activity doesn't
/// rehash. Undersizing is fine correctness-wise; this is a perf nudge.
const PEERS_CAP: usize = 256;
const IP_COLOC_CAP: usize = 128;
const ARCHIVE_CAP: usize = 512;

pub struct PeerManager {
    /// Live peers keyed by connection handle.
    peers: HashMap<usize, PeerState>,

    /// In-progress dials, mapping PeerId to when the dial was initiated.
    dialing: HashMap<PeerId, Instant>,

    /// Counters persisted across reconnect by PeerId. GC'd on tick.
    archived: HashMap<PeerId, ArchivedState>,

    /// IP colocation index for P6. Prefix → list of live connection handles.
    ip_colocations: HashMap<IpPrefix, Vec<usize>>,

    /// Topics we subscribe to ourselves. Drives SUBSCRIBE emission on new
    /// peers and mesh-management decisions.
    our_topics: Vec<GossipTopic>,

    /// Our mesh per topic: connections we've grafted onto. Bounded by d_high.
    mesh: HashMap<GossipTopic, Vec<usize>>,

    /// Outstanding IHAVE→IWANT promises, keyed by `MessageId`. Each entry
    /// holds every (conn, deadline) that has promised that id. Any one
    /// peer's delivery via `PeerEvent::NewGossip` clears the entry for all
    /// of them — broken-promise penalty only applies if the message never
    /// arrives from anyone by `iwant_followup`.
    promises: MsgIdMap<Vec<(usize, Instant)>>,

    /// Our current fork digest, set by the consumer at startup and rotated
    /// across hard-fork boundaries. `None` disables the fork-digest filter
    /// on `DiscNodeFound` (useful for tests; production should always set
    /// it). Compared against the leading 4 bytes of an ENR's `eth2` field.
    our_fork_digest: Option<[u8; 4]>,

    /// Session-level blacklist of rejected block + finalized roots. Inserted
    /// from beacon-state's `BlockRejected`; queried by Status validation
    /// and target selection.
    rejected: RejectedRoots,

    /// Tunables for target selection + blacklist caps.
    pub(crate) syncing: SyncingConfig,

    /// The `SyncEngine`-selected sync target, fed in via `set_sync_target`.
    /// Read by `pick_sync_peer` to match candidate peers; `Following` until the
    /// engine selects one.
    current_target: SyncUpdate,

    /// SSZ Bitvector[64] of attestation subnets we subscribe to, derived
    /// once from `our_topics`. Bit N set ↔ `BeaconAttestation(N) ∈
    /// our_topics`. Matched bitwise against an ENR's `attnets` to detect
    /// peers that can fill our attnet mesh.
    required_attnets: [u8; 8],
    /// SSZ Bitvector[N] of sync-committee subnets we subscribe to (same
    /// scheme as `required_attnets`). N is small — the eth2 spec uses 4 —
    /// and the wire encoding is one byte; we keep that one byte here too.
    required_syncnets: u8,

    /// IPs of peers we've graylisted out, keyed by ban time. Discovery hits
    /// matching one of these IPs are dropped before we issue a dial. Entries
    /// expire after `params.banned_ip_ttl` — IP-level bans have higher
    /// false-positive blast radius than PeerId-level archive entries
    /// (NAT/CGN) so this TTL is tuned independently of `archived_ttl`.
    banned_ips: HashMap<IpAddr, Instant>,

    /// Per-IP count of recent peer-level evictions, plus the time of the
    /// most recent bump. When the count crosses `params.ip_ban_threshold`
    /// the IP gets promoted into `banned_ips`. Counts age out with the
    /// same TTL as `banned_ips` (sliding-window).
    ip_eviction_counts: HashMap<IpAddr, (u32, Instant)>,

    /// PeerIds we've graylist-banned, keyed by ban time. Drives discovery
    /// filtering and the `Unban` emission once `banned_peer_ttl` elapses.
    banned_peers: HashMap<PeerId, Instant>,

    params: ScoreParams,

    /// Last heartbeat rollover time. When `now - last_heartbeat >=
    /// heartbeat_interval`, per-heartbeat counters reset + mesh revised.
    last_heartbeat: Instant,

    /// Last score-decay application. Gated to `score_decay_interval` (one
    /// slot) so the gossipsub-canonical `*_decay` constants apply at their
    /// calibrated cadence.
    last_decay: Instant,

    /// Last `DiscoverNodes` emission. Throttles repeat queries while we're
    /// under target.
    last_discovery: Instant,

    /// Database of peers
    pub(crate) database: PeerDatabase,

    /// Our local beacon status and metadata.
    status: Option<[u8; STATUS_V2_SIZE]>,
    metadata: [u8; METADATA_SIZE],
    earliest_available_slot: u64,

    /// Our data-column custody set (bitmask of column indices), derived from
    /// node_id + CGC at startup. Used to fetch columns by range alongside
    /// catch-up `BlocksByRange`.
    pub(crate) custody_columns: u128,

    /// Slot of the highest block BS has imported (`last_applied`), from the
    /// `latest_block_slot` on the Status event. Used by the data-column peer
    /// picker (`best_peer_for_data_columns`) for earliest-available gating.
    pub(crate) local_head_imported_slot: u64,

    /// Seeds the `SyncEngine`'s replay gate at construction; cleared on
    /// `on_local_replay_complete`.
    awaiting_local_replay: bool,

    pub(crate) pending_range_requests: VecDeque<PendingRangeRequest>,
    pub(crate) outbound_range_attempts: Vec<OutboundRangeAttempt>,
    pub(crate) pending_by_root: VecDeque<(RootReqKind, u64, Option<usize>, [u8; 32])>,
    pub(crate) pending_rpc_request: VecDeque<(u64, RpcRequest)>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RangeReqKind {
    Blocks { step: u64 },
    DataColumns { columns: u128 },
    Envelopes,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RootReqKind {
    Block,
    Envelope,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingRangeRequest {
    pub request_id: u64,
    pub start_slot: u64,
    pub count: u64,
    pub kind: RangeReqKind,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OutboundRangeAttempt {
    pub request_id: u64,
    pub peer_id: usize,
    pub start_slot: u64,
    pub count: u64,
    pub kind: RangeReqKind,
    pub last_progress_at: Instant,
    pub responded: bool,
    pub delivered: bool,
}

impl PeerManager {
    pub fn new(
        our_topics: Vec<GossipTopic>,
        params: ScoreParams,
        syncing: SyncingConfig,
        fork_digest: [u8; 4],
        metadata: [u8; METADATA_SIZE],
        custody_columns: u128,
        awaiting_local_replay: bool,
    ) -> Self {
        let now = Instant::now();
        let mesh =
            our_topics.iter().map(|t| (*t, Vec::with_capacity(params.d_high as usize))).collect();
        let (required_attnets, required_syncnets) = build_subnet_masks(&our_topics);
        let rejected = RejectedRoots::new(syncing.rejected_cap);
        Self {
            peers: HashMap::with_capacity(PEERS_CAP),
            dialing: HashMap::with_capacity(64),
            archived: HashMap::with_capacity(ARCHIVE_CAP),
            ip_colocations: HashMap::with_capacity(IP_COLOC_CAP),
            our_topics,
            mesh,
            promises: MsgIdMap::with_capacity_and_hasher(4096, Default::default()),
            banned_ips: HashMap::with_capacity(64),
            ip_eviction_counts: HashMap::with_capacity(64),
            banned_peers: HashMap::with_capacity(128),
            our_fork_digest: Some(fork_digest),
            rejected,
            syncing,
            current_target: SyncUpdate::Following,
            required_attnets,
            required_syncnets,
            params,
            last_heartbeat: now,
            last_decay: now,
            last_discovery: now,
            database: PeerDatabase::default(),
            status: None,
            metadata,
            earliest_available_slot: u64::MAX,
            custody_columns,
            local_head_imported_slot: 0,
            awaiting_local_replay,
            pending_range_requests: VecDeque::with_capacity(PEERS_CAP),
            outbound_range_attempts: Vec::with_capacity(PEERS_CAP),
            pending_by_root: VecDeque::with_capacity(PEERS_CAP),
            pending_rpc_request: VecDeque::with_capacity(PEERS_CAP),
        }
    }

    /// Current cached score. Recomputed on `tick`.
    pub fn score(&self, conn: usize) -> Option<f64> {
        self.peers.get(&conn).map(|p| p.cached_score)
    }

    /// Application-specific score nudge (P5). Negative values penalise.
    pub fn set_application_score(&mut self, conn: usize, delta: f64) {
        if let Some(p) = self.peers.get_mut(&conn) {
            p.application_score += delta;
        }
    }

    /// Set the current fork digest. Call at startup and on every hard-fork
    /// transition. Once set, discovery hits whose ENR doesn't carry the
    /// matching `eth2` field are dropped before dial.
    pub fn set_fork_digest(&mut self, digest: [u8; 4]) {
        self.our_fork_digest = Some(digest);
    }

    pub fn set_status(&mut self, mut ssz: [u8; STATUS_V2_SIZE]) -> bool {
        let new_digest = *StatusView::fork_digest(&ssz);
        let digest_changed = self.our_fork_digest != Some(new_digest);
        self.our_fork_digest = Some(new_digest);

        if self.earliest_available_slot != u64::MAX {
            ssz[84..].copy_from_slice(&self.earliest_available_slot.to_le_bytes());
        }

        tracing::debug!("set status");
        self.status = Some(ssz);
        digest_changed
    }

    pub fn set_local_head_imported(&mut self, slot: u64) {
        self.local_head_imported_slot = slot;
    }

    pub fn on_local_replay_complete(&mut self) {
        if self.awaiting_local_replay {
            tracing::info!("local replay complete; unblocking network sync");
            self.awaiting_local_replay = false;
        }
    }

    /// Consume `BeaconStateEvent::BlockRejected`: blacklist `block_root` so a
    /// peer whose Status backs the rejected chain gets evicted. The sync-target
    /// + watermark invalidation is the `SyncEngine`'s.
    pub fn record_block_rejected(&mut self, block_root: [u8; 32], _source: BlockSource) {
        self.rejected.mark(block_root);
    }

    pub fn record_finalized_rejected(&mut self, root: [u8; 32]) {
        self.rejected.mark(root);
    }

    pub fn rejected(&self) -> &RejectedRoots {
        &self.rejected
    }

    pub fn current_sync_target(&self) -> SyncUpdate {
        self.current_target
    }

    /// Tunables, for the control-tile `SyncEngine` shadow (step 2 migration).
    pub fn syncing_config(&self) -> SyncingConfig {
        self.syncing.clone()
    }

    /// Our fork digest, once a Status has been set. The `SyncEngine` shadow
    /// uses it to drop wrong-network peer Status before aggregation (PM
    /// evicts those peers; the shadow must not count them).
    pub fn our_fork_digest(&self) -> Option<[u8; 4]> {
        self.our_fork_digest
    }

    /// Still replaying disk into fork choice — forward issuance is gated until
    /// this clears. Seeds the `SyncEngine`'s matching gate at construction.
    pub fn awaiting_local_replay(&self) -> bool {
        self.awaiting_local_replay
    }

    pub fn custody_columns(&self) -> u128 {
        self.custody_columns
    }

    /// Track the engine-selected sync target (the engine is authoritative) so
    /// `pick_sync_peer` / `best_peer_for_data_columns` can match peers against
    /// it. Watermark + column resets are the engine's.
    pub fn set_sync_target(&mut self, new_target: SyncUpdate) {
        self.current_target = new_target;
    }

    /// Pick a target-matching peer with capacity (PM keeps ranking + caps) and
    /// issue the engine's forward `BlocksByRange`. Returns the chosen peer, or
    /// `None` if none was eligible / admitted — the engine re-emits next loop.
    pub fn issue_sync_blocks_by_range(
        &mut self,
        request_id: u64,
        start_slot: u64,
        count: u64,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> Option<usize> {
        let peer = self.pick_sync_peer(count, now)?;
        self.issue_range_request(
            peer,
            request_id,
            start_slot,
            count,
            RangeReqKind::Blocks { step: 1 },
            now,
            emit,
        )
        .then_some(peer)
    }

    /// Pick a custody-overlapping peer with capacity (PM keeps the picker +
    /// caps) and issue the engine's forward `DataColumnsByRange`, requesting
    /// only the claimed-custody overlap of `columns`. `tried` peers (failed the
    /// active range) are skipped. Returns `(peer, overlap)` if sent.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_sync_columns_by_range(
        &mut self,
        request_id: u64,
        start_slot: u64,
        count: u64,
        columns: u128,
        tried: &[usize],
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> Option<(usize, u128)> {
        let (peer, overlap, _tokens) = self.best_peer_for_data_columns(
            StreamProtocol::DataColumnSidecarsByRange,
            columns,
            request_id,
            tried,
            start_slot,
            count,
            now,
        )?;
        self.issue_range_request(
            peer,
            request_id,
            start_slot,
            count,
            RangeReqKind::DataColumns { columns: overlap },
            now,
            emit,
        )
        .then_some((peer, overlap))
    }

    /// Score a forward-sync peer that stalled an engine-issued range.
    pub fn score_sync_peer(&mut self, peer: usize, severity: RpcSeverity) {
        self.on_rpc_misbehaviour(peer, severity, "blocks-by-range progress stall");
    }

    pub fn peer_metadata_seq(&self, p2p_peer: usize) -> Option<u64> {
        self.database.p2p_metadata_seq(p2p_peer)
    }

    /// Iterator over live peer connection handles (for tests/introspection).
    pub fn live_peers(&self) -> impl Iterator<Item = usize> + '_ {
        self.peers.keys().copied()
    }

    pub fn live_peers_with_status(&self) -> impl Iterator<Item = &PeerRecord> {
        self.database.live_peers_with_status()
    }

    /// Announce our topic subscriptions to every currently-connected peer.
    pub fn fan_out_subscriptions(&mut self, emit: &mut impl FnMut(PeerControl)) {
        for (&conn, peer) in &self.peers {
            for &topic in &self.our_topics {
                emit(PeerControl::P2pGossipSubscribe {
                    p2p: peer.peer_id,
                    p2p_connection: conn,
                    topic,
                });
            }
        }
    }

    pub fn status(&self) -> Option<&[u8; STATUS_V2_SIZE]> {
        self.status.as_ref()
    }

    pub fn metadata(&self) -> &[u8; METADATA_SIZE] {
        &self.metadata
    }

    pub fn set_metadata(&mut self, metadata: [u8; METADATA_SIZE]) {
        self.metadata = metadata;
    }

    /// Pick the connected, protocol-supporting peer with the highest
    /// cached score that also satisfies the caller-supplied `eligible`
    /// predicate (e.g., "not at outstanding-request cap"). Returns `None`
    /// when no peer matches. Unscored peers (first-heartbeat window) are
    /// treated as -∞ so they lose to any scored peer.
    pub fn best_peer_for(
        &self,
        protocol: StreamProtocol,
        eligible: impl Fn(usize) -> bool,
    ) -> Option<usize> {
        self.database.live_peers_supporting(protocol).filter(|p| eligible(*p)).max_by(|a, b| {
            let sa = self.score(*a).unwrap_or(f64::NEG_INFINITY);
            let sb = self.score(*b).unwrap_or(f64::NEG_INFINITY);
            sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Mesh size for a topic (for tests/introspection).
    #[allow(dead_code)]
    pub(crate) fn mesh_size(&self, topic: GossipTopic) -> usize {
        self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0)
    }

    /// Size of the archive set.
    #[allow(dead_code)]
    pub(crate) fn archived_count(&self) -> usize {
        self.archived.len()
    }

    // ── Hot path: counter updates only ──────────────────────────────────
    #[timed]
    pub fn handle_event(
        &mut self,
        event: PeerEvent,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        match event {
            PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, ip, port, local_dial } => {
                tracing::info!("New p2p peer: {ip:?}:{port}, local dial? {local_dial}");
                self.on_connected(p2p_peer_id, peer_id_full, ip, port, now, emit, local_dial);
            }
            PeerEvent::P2pDisconnect { p2p_peer, peer_id } => {
                self.dialing.remove(&peer_id);
                self.on_disconnected(p2p_peer, now, emit);
            }
            PeerEvent::P2pCannotCreateStream { p2p_peer, .. } => {
                self.add_behaviour_penalty(p2p_peer, 1.0, "cannot create stream");
            }
            PeerEvent::P2pOutboundMessageDropped { p2p_peer, .. } => {
                self.add_behaviour_penalty(p2p_peer, 1.0, "outbound message dropped");
            }
            PeerEvent::P2pStreamClosed { stream_id } => {
                // Premature close on a request-response stream — the
                // peer FIN'd or RST'd before the response terminator
                // (`Complete`/`Error`) was observed. `MidTolerance`
                // accumulates a signal without fast-banning over a
                // single flaky session. Gossip / identity streams don't
                // have the same completion model — no penalty. `Unset`
                // means multistream-select hadn't negotiated yet, also
                // skipped (the close there is a protocol-negotiation
                // failure, distinct from a premature RPC termination).
                let protocol = stream_id.protocol();
                if protocol.is_request_response() && protocol != StreamProtocol::Unset {
                    tracing::warn!(?protocol, "stream close misbehaviour");
                    self.on_rpc_misbehaviour(
                        stream_id.peer(),
                        RpcSeverity::MidTolerance,
                        "premature rpc stream close",
                    );
                    // No terminal response will arrive for this stream —
                    // release the outbound in-flight slot, else each
                    // abnormal close permanently burns one of the peer's
                    // `MAX_RPC_PROTOCOL_IN_FLIGHT` slots and the protocol
                    // goes dark for the connection's lifetime.
                    if !stream_id.is_incoming() &&
                        let Some(peer) = self.peers.get_mut(&stream_id.peer())
                    {
                        peer.outbound_in_flight[protocol.ordinal() as usize] =
                            peer.outbound_in_flight[protocol.ordinal() as usize].saturating_sub(1);
                    }
                    if !stream_id.is_incoming() {
                        self.on_range_stream_closed(stream_id.peer(), protocol, emit);
                    }
                }
            }
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer, topic } => {
                self.on_subscribe(p2p_peer, topic, now, emit);
            }
            PeerEvent::P2pGossipTopicUnsubscribe { p2p_peer, topic } => {
                self.on_unsubscribe(p2p_peer, topic, now, emit);
            }
            PeerEvent::P2pGossipTopicGraft { p2p_peer, topic } => {
                self.on_remote_graft(p2p_peer, topic, now, emit);
            }
            PeerEvent::P2pGossipTopicPrune { p2p_peer, topic } => {
                self.on_remote_prune(p2p_peer, topic, now, emit);
            }
            PeerEvent::P2pGossipHave { p2p_peer, topic: _, hash, already_seen } => {
                self.on_ihave(p2p_peer, hash, already_seen, now);
            }
            PeerEvent::P2pGossipWant { p2p_peer, hash, tcache } => {
                self.on_iwant_received(p2p_peer, hash, tcache, emit);
            }
            PeerEvent::P2pGossipDontWant { p2p_peer, hash } => {
                self.on_idontwant_received(p2p_peer, hash);
            }
            PeerEvent::P2pGossipInvalidMsg { p2p_peer, topic, hash: _ } => {
                crate::PeerCounters::GossipInvalidMsg.inc();
                self.add_invalid_delivery(p2p_peer, topic);
            }
            PeerEvent::P2pGossipInvalidControl { p2p_peer } => {
                crate::PeerCounters::GossipInvalidControl.inc();
                self.add_behaviour_penalty(p2p_peer, 1.0, "invalid gossip control message");
            }
            PeerEvent::P2pGossipInvalidFrame { p2p_peer } => {
                crate::PeerCounters::GossipInvalidFrame.inc();
                self.add_behaviour_penalty(p2p_peer, 1.0, "invalid gossip frame");
            }
            PeerEvent::DiscNodeFound { enr } => {
                self.on_disc_node_found(enr, now, emit);
            }
            PeerEvent::DiscExternalAddress { address: _ } => {
                // Informational — network tile handles advertisement.
            }
            PeerEvent::NewGossip { p2p_peer, topic, msg_hash, idontwant } => {
                self.on_new_gossip(p2p_peer, topic, msg_hash, idontwant, emit);
            }
            PeerEvent::OutboundIHave { topic, msg_count: _, protobuf } => {
                self.on_outbound_ihave(topic, protobuf, emit);
            }
            // Consumed by the control tile (gossip republish); PM sees only
            // the SendGossip it turns into.
            PeerEvent::PublishDataColumn { .. } => {}
            PeerEvent::OutboundIWant { p2p_peer, iwant } => {
                self.on_outbound_iwant(p2p_peer, iwant, emit);
            }
            PeerEvent::SendGossip {
                originator_stream_id,
                topic,
                msg_hash,
                recv_ts: _,
                protobuf,
            } => {
                // TODO recv_ts elapsed metric
                self.on_send_gossip(originator_stream_id.peer(), msg_hash, topic, protobuf, emit);
            }
            PeerEvent::RpcMisbehaviour { p2p_peer, severity } => {
                self.on_rpc_misbehaviour(p2p_peer, severity, "rpc chunk/framing violation");
            }
            PeerEvent::P2pPeerStatus { p2p_peer, status_ssz } => {
                tracing::trace!(p2p_peer, "Got peer status");
                self.on_p2p_peer_status(p2p_peer, status_ssz);
            }
            PeerEvent::P2pPeerMetadata { p2p_peer, metadata_ssz } => {
                tracing::trace!(p2p_peer, "Got peer metadata");
                self.database.p2p_metadata(p2p_peer, metadata_ssz)
            }
            PeerEvent::P2pPeerGoodbye { p2p_peer, status } => {
                self.on_p2p_peer_goodbye(p2p_peer, now, status, emit);
            }
            PeerEvent::P2pPeerIdentity { p2p_peer, identify } => {
                tracing::trace!(p2p_peer, ?identify, "Got peer identify");
                self.database.add_p2p_identify(p2p_peer, identify)
            }
            PeerEvent::SendDataColumnsByRootRequest { request_id, columns, block_root } => {
                self.on_request_data_columns_by_root(request_id, columns, block_root, now, emit);
            }
            PeerEvent::SendBlocksByRootRequest { request_id, p2p_peer, block_root } => {
                self.on_request_by_root(
                    RootReqKind::Block,
                    request_id,
                    p2p_peer,
                    block_root,
                    now,
                    emit,
                );
            }
            PeerEvent::SendEnvelopesByRootRequest { request_id, p2p_peer, block_root } => {
                self.on_request_by_root(
                    RootReqKind::Envelope,
                    request_id,
                    p2p_peer,
                    block_root,
                    now,
                    emit,
                );
            }
            PeerEvent::SendRpcRequest { request_id, rpc } => {
                self.on_rpc_request(request_id, rpc, now, emit);
            }
            PeerEvent::EarliestSlot(slot) => {
                self.earliest_available_slot = slot;
            }
            // Storage backfill reports — consumed by the control tile's
            // `SyncEngine`, not PM.
            PeerEvent::BackfillState { .. } | PeerEvent::ColumnNeed { .. } => {}
        }
    }

    // ── Cold path: tick ─────────────────────────────────────────────────

    pub fn tick(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        // Mesh-size gauges refreshed here rather than at each mutation site —
        // mesh entries persist (empty vecs stay), so this is exact.
        for (topic, mesh_peers) in &self.mesh {
            crate::counters::GossipTopicCounters::mesh(*topic, mesh_peers.len());
        }
        // Peers announce SUBSCRIBE for all their subnets; only count
        // subscribers on topics we participate in ourselves.
        let mut ours = [false; silver_common::GOSSIP_TOPIC_COUNTER_SLOTS];
        for topic in &self.our_topics {
            ours[topic.counter_slot()] = true;
        }
        let mut subs = [0u16; silver_common::GOSSIP_TOPIC_COUNTER_SLOTS];
        for peer in self.peers.values() {
            for topic in &peer.topics {
                let slot = topic.counter_slot();
                if ours[slot] {
                    subs[slot] = subs[slot].saturating_add(1);
                }
            }
        }
        crate::counters::GossipTopicCounters::subscribed(&subs);

        // 1) Heartbeat rollover: reset per-heartbeat counters, sweep broken promises.
        if now.saturating_duration_since(self.last_heartbeat) >= self.params.heartbeat_interval {
            self.heartbeat(now);
            self.last_heartbeat = now;
        }

        // 2) Activate P3 tracking for peers whose grace window has elapsed.
        self.activate_p3_where_due(now);

        // 3) Decay all counters — gated to `score_decay_interval` (one slot), the
        //    cadence the `*_decay` constants are calibrated for.
        if now.saturating_duration_since(self.last_decay) >= self.params.score_decay_interval {
            for p in self.peers.values_mut() {
                scoring::decay(p, &self.params);
            }
            self.last_decay = now;
        }

        // 4) Recompute scores for every peer.
        self.rescore_all(now);

        // 5) Evict peers below the graylist threshold.
        self.evict_graylisted(now, emit);

        // 6) Mesh management: graft under-filled topics, prune over-filled ones.
        self.manage_mesh(now, emit);

        // 7) GC archived state past TTL.
        self.gc_archived(now);
        self.gc_banned_ips(now, emit);
        self.gc_banned_peers(now, emit);

        // 8) Trigger discovery if we're under target.
        self.maybe_request_discovery(now, emit);

        self.sweep_backfill_range_attempts(now, emit);

        // 9) Prune stale dials (older than 15 seconds)
        self.dialing.retain(|_, &mut time| {
            now.saturating_duration_since(time) < std::time::Duration::from_secs(15)
        });

        crate::PeerCounters::PeersConnected.set(self.peers.len() as u64);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn on_connected(
        &mut self,
        conn: usize,
        peer_id: PeerId,
        ip: IpBytes,
        port: u16,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
        local_dialler: bool,
    ) {
        let addr = SocketAddr::new(ip_bytes_to_addr(ip), port);
        let mut state = PeerState::new(peer_id, addr, now);

        self.dialing.remove(&peer_id);

        // Inherit counters if we remember this PeerId.
        if let Some(archive) = self.archived.remove(&peer_id) {
            state.restore_from_archive(archive);
        }

        // Index by /24 or /64 prefix for P6.
        self.ip_colocations
            .entry(state.ip_prefix)
            .or_insert_with(|| Vec::with_capacity(4))
            .push(conn);

        let initial_status = if local_dialler &&
            let Some(status) = self.status &&
            matches!(
                state.outbound_rpc_limits.admit_outbound(StreamProtocol::StatusV2, 1, now),
                RpcRateLimit::Allowed
            ) {
            Some(status)
        } else {
            None
        };

        tracing::info!("adding peer with p2p connection: {conn}");
        self.peers.insert(conn, state);
        self.database.add_peer_id(peer_id, conn);

        emit(PeerControl::P2pSend(P2pSend::Identify(conn)));
        if let Some(status) = initial_status {
            // Send rpc Status
            emit(PeerControl::P2pSend(P2pSend::Rpc(silver_common::RpcOutbound::Request(
                RpcRequestOutbound {
                    application_id: 0,
                    peer: conn,
                    request: silver_common::RpcRequest::StatusV2(status),
                },
            ))));
        }

        // Announce our own topic subscriptions to this peer.
        for &topic in &self.our_topics {
            emit(PeerControl::P2pGossipSubscribe { p2p: peer_id, p2p_connection: conn, topic });
        }
    }

    fn on_disconnected(
        &mut self,
        conn: usize,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) -> Option<&PeerRecord> {
        let mut state = self.peers.remove(&conn)?;

        // De-index IP colocation.
        if let Some(v) = self.ip_colocations.get_mut(&state.ip_prefix) {
            v.retain(|c| *c != conn);
            if v.is_empty() {
                self.ip_colocations.remove(&state.ip_prefix);
            }
        }

        // Remove from mesh + emit PRUNE to whoever else tracks the control.
        let peer_id = state.peer_id;
        for (topic, mesh_peers) in self.mesh.iter_mut() {
            if let Some(idx) = mesh_peers.iter().position(|c| *c == conn) {
                mesh_peers.swap_remove(idx);
                emit(PeerControl::P2pGossipPrune {
                    p2p: peer_id,
                    p2p_connection: conn,
                    topic: *topic,
                });
            }
        }

        // Clear this peer from the global IHAVE-promise index. They can't
        // fulfil anything anymore and shouldn't be re-penalised on sweep.
        self.promises.retain(|_hash, waiters| {
            waiters.retain(|(c, _)| *c != conn);
            !waiters.is_empty()
        });

        // Archive counters for reputation persistence.
        self.archived.insert(peer_id, ArchivedState {
            application_score: state.application_score,
            behaviour_penalty: state.behaviour_penalty,
            topic_stats: std::mem::take(&mut state.topic_stats),
            archived_at: now,
        });

        self.on_range_peer_disconnected(conn, emit);
        self.database.peer_disconnected(conn)
    }

    // ── Gossip event handlers ───────────────────────────────────────────

    fn on_subscribe(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let peer_id = {
            let Some(peer) = self.peers.get_mut(&conn) else {
                return;
            };
            peer.topics.insert(topic);
            peer.peer_id
        };

        let we_want = self.our_topics.contains(&topic);
        let mesh_size = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        tracing::debug!(p2p_peer = conn, ?topic, we_want, mesh_size, "PM peer subscribed");

        // Opportunistic graft: if this is a topic we care about and our mesh
        // is below d_low, pull the peer in.
        if we_want &&
            mesh_size < self.params.d_low as usize &&
            !self.is_backed_off(conn, topic, now)
        {
            self.do_graft(conn, peer_id, topic, now, emit);
        }
    }

    fn on_unsubscribe(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        _now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let peer_id = match self.peers.get_mut(&conn) {
            Some(p) => {
                p.topics.remove(&topic);
                p.topic_stats.remove(&topic);
                p.peer_id
            }
            None => return,
        };
        tracing::debug!(p2p_peer = conn, ?topic, "PM peer unsubscribed");
        // If peer was in our mesh, remove them.
        if let Some(mesh_peers) = self.mesh.get_mut(&topic) &&
            let Some(idx) = mesh_peers.iter().position(|c| *c == conn)
        {
            mesh_peers.swap_remove(idx);
            emit(PeerControl::P2pGossipPrune { p2p: peer_id, p2p_connection: conn, topic });
        }
    }

    fn on_remote_graft(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let Some(peer) = self.peers.get(&conn) else {
            if let Some(record) = self.database.by_p2p_id(conn) &&
                let Some(id) = record.peer_id
            {
                emit(PeerControl::P2pDisconnect { p2p: id, p2p_connection: conn })
            }
            return;
        };
        let peer_id = peer.peer_id;
        let score = peer.cached_score;
        let mesh_size = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        let accept = self.our_topics.contains(&topic) &&
            mesh_size < self.params.d_high as usize &&
            score >= self.params.gossip_threshold &&
            !self.is_backed_off(conn, topic, now);
        if accept {
            self.do_graft(conn, peer_id, topic, now, emit);
            tracing::info!(p2p_peer = conn, ?topic, mesh_size, "PM peer GRAFTed us: accepted");
        } else {
            self.do_prune(conn, peer_id, topic, now, emit);
            tracing::info!(p2p_peer = conn, ?topic, mesh_size, "PM peer GRAFTed us: refused");
        }
    }

    fn on_remote_prune(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let mut mesh_size = 0;
        if let Some(mesh_peers) = self.mesh.get_mut(&topic) &&
            let Some(idx) = mesh_peers.iter().position(|c| *c == conn)
        {
            mesh_peers.swap_remove(idx);
            mesh_size = mesh_peers.len();
        }
        let Some(peer) = self.peers.get_mut(&conn) else {
            if let Some(record) = self.database.by_p2p_id(conn) &&
                let Some(id) = record.peer_id
            {
                emit(PeerControl::P2pDisconnect { p2p: id, p2p_connection: conn })
            }
            return;
        };
        if let Some(t) = peer.topic_stats.get_mut(&topic) {
            // Carry any active deficit into the failure penalty.
            if t.mesh_active && t.mesh_deliveries < self.params.mesh_message_deliveries_threshold {
                t.mesh_failure_penalty +=
                    self.params.mesh_message_deliveries_threshold - t.mesh_deliveries;
            }
            t.meshed_since = None;
            t.mesh_active = false;
        }
        peer.backoffs.insert(topic, now + self.params.prune_backoff);
        tracing::info!(p2p_peer = conn, ?topic, mesh_size, "PM peer PRUNEd us");
    }

    fn on_ihave(&mut self, conn: usize, hash: MessageId, already_seen: bool, now: Instant) {
        // Always count, regardless of dedup state — flood detection treats
        // a peer IHAVEing thousands of ids we already have just as badly as
        // ids we don't.
        let (over_cap, should_iwant) = {
            let Some(peer) = self.peers.get_mut(&conn) else {
                return;
            };
            peer.ihaves_received = peer.ihaves_received.saturating_add(1);
            let over_cap = peer.ihaves_received > self.params.max_ihave_length;
            // Only send an IWANT (and thus track a promise) if:
            //  - we don't already have the message,
            //  - we haven't exceeded the per-heartbeat IWANT budget,
            //  - the peer hasn't saturated the IHAVE rate cap.
            let should_iwant =
                !already_seen && !over_cap && peer.iwant_ids_sent < self.params.max_ihave_length;
            if should_iwant {
                peer.iwant_ids_sent = peer.iwant_ids_sent.saturating_add(1);
            }
            (over_cap, should_iwant)
        };
        if over_cap {
            self.add_behaviour_penalty(conn, 1.0, "ihave rate limit exceeded");
            return;
        }
        if !should_iwant {
            return;
        }
        // Record the promise globally. Dedupe: same peer IHAVEing the same
        // id twice is one outstanding promise, not two.
        let deadline = now + self.params.iwant_followup;
        let entry = self.promises.entry(hash).or_default();
        if !entry.iter().any(|(c, _)| *c == conn) {
            entry.push((conn, deadline));
        }
    }

    /// Peer sent us an IWANT that hit our mcache. Check retransmission
    /// threshold and apply the score gate.
    fn on_iwant_received(
        &mut self,
        conn: usize,
        hash: MessageId,
        tcache: TCacheRead,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let Some(peer) = self.peers.get_mut(&conn) else {
            return;
        };
        if peer.msg_cache_insert(hash) > 2 {
            // exceeds retransmission threshold
            return;
        }
        if peer.cached_score < self.params.gossip_threshold {
            return;
        }
        emit(PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id: conn, tcache })));
    }

    /// Peer sent us an IDONTWANT - store the message id in the peer message
    /// cache.
    fn on_idontwant_received(&mut self, conn: usize, hash: MessageId) {
        let Some(peer) = self.peers.get_mut(&conn) else {
            return;
        };
        peer.msg_cache_insert(hash);
    }

    /// A fully-validated inbound gossip message arrived — this is the first
    /// (dedup-clean) delivery from any peer. Clear all promises for this id
    /// (every peer who IHAVE'd it kept their word, regardless of who
    /// actually reached us first), credit P2/P3 on the delivering peer, and
    /// fan out the pre-encoded IDONTWANT frame to every mesh peer except
    /// the sender so they stop racing this id toward us.
    fn on_new_gossip(
        &mut self,
        sender_conn: usize,
        topic: GossipTopic,
        msg_hash: MessageId,
        idontwant: TCacheRead,
        emit: &mut impl FnMut(PeerControl),
    ) {
        crate::counters::GossipTopicCounters::recv(topic);

        // Any peer who promised this id is released — they did their job;
        // we just got another copy from someone else first.
        self.promises.remove(&msg_hash);

        if let Some(peer) = self.peers.get_mut(&sender_conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            // P2 — first-delivery credit (capped + weighted in `compute_score`).
            t.first_deliveries += 1.0;
            // P3 — mesh-delivery credit only when we've actually grafted them
            // for this topic.
            if t.meshed_since.is_some() {
                t.mesh_deliveries += 1.0;
            }
        }

        // Fan IDONTWANT out to mesh members (except sender) above threshold.
        let Some(mesh_peers) = self.mesh.get(&topic) else {
            return;
        };
        for conn in mesh_peers {
            if *conn == sender_conn {
                continue;
            }
            let Some(peer) = self.peers.get(conn) else {
                continue;
            };
            if peer.cached_score < self.params.gossip_threshold {
                continue;
            }
            emit(PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut {
                peer_id: *conn,
                tcache: idontwant,
            })));
        }
    }

    /// Compression tile has prepared a batched IHAVE frame for `topic`.
    /// Fan it out: one `P2pGossipSend` per non-mesh subscriber whose score
    /// clears `gossip_threshold`, capped at `d_lazy`.
    fn on_outbound_ihave(
        &mut self,
        topic: GossipTopic,
        protobuf: TCacheRead,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let mesh_for_topic = self.mesh.get(&topic);
        let cap = self.params.d_lazy as usize;
        let mut emitted = 0usize;
        for (conn, peer) in &self.peers {
            if emitted >= cap {
                break;
            }
            if !peer.topics.contains(&topic) {
                continue;
            }
            if mesh_for_topic.is_some_and(|m| m.contains(conn)) {
                continue; // mesh peers get full-body forwards, not IHAVE
            }
            if peer.cached_score < self.params.gossip_threshold {
                continue;
            }
            emit(PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut {
                peer_id: *conn,
                tcache: protobuf,
            })));
            emitted += 1;
        }
    }

    /// Compression tile has prepared an IWANT frame for a peer that just
    /// sent us IHAVE. Forward it to the network tile provided the peer is
    /// still live and scoring above `gossip_threshold` (mirrors rust-libp2p,
    /// which ignores IHAVE — and therefore doesn't send the IWANT reply —
    /// for peers below that threshold).
    fn on_outbound_iwant(
        &mut self,
        conn: usize,
        tcache: TCacheRead,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let Some(peer) = self.peers.get(&conn) else {
            return;
        };
        if peer.cached_score < self.params.gossip_threshold {
            return;
        }
        emit(PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id: conn, tcache })));
    }

    fn on_send_gossip(
        &mut self,
        sender: usize,
        msg_hash: MessageId,
        topic: GossipTopic,
        tcache: TCacheRead,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let Some(meshed_peers) = self.mesh.get(&topic) else {
            return;
        };
        for peer in meshed_peers {
            if *peer == sender {
                continue;
            }
            let Some(peer_state) = self.peers.get(peer) else {
                continue;
            };
            if peer_state.cached_score < self.params.gossip_threshold {
                continue;
            }
            if peer_state.msg_cache_contains(&msg_hash) {
                // dontwant
                continue;
            }
            crate::counters::GossipTopicCounters::sent(topic);
            emit(PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id: *peer, tcache })));
        }
    }

    fn ban_disc_peer(&mut self, peer_id: PeerId, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        if self.banned_peers.insert(peer_id, now).is_none() {
            crate::PeerCounters::PeersBanned.inc();
            emit(PeerControl::Ban { p2p: peer_id });
        }
    }

    /// Discovery surfaced a candidate peer. Filter chain:
    /// 1. Fork-digest match (if `our_fork_digest` is set).
    /// 2. IP not in our recent ban set.
    /// 3. Capacity — under `target_peers`, OR the peer covers a subnet we need
    ///    (priority) and we're under `max_priority_peers`.
    ///
    /// Network tile handles in-flight dial / already-connected dedup.
    fn on_disc_node_found(&mut self, enr: Enr, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        // 1. Fork-digest gate. Spec-conformant CL nodes always advertise `eth2`;
        //    missing-or-mismatched is a drop (matches lighthouse).
        if let Some(my_digest) = self.our_fork_digest {
            match enr.eth2() {
                Some(eth2) => {
                    if eth2[..4] != my_digest {
                        crate::PeerCounters::DiscDroppedForkDigest.inc();
                        tracing::warn!(
                            theirs = hex::encode(&eth2[..4]),
                            ours = hex::encode(my_digest),
                            ?enr,
                            "fork digest mismatch"
                        );
                        self.ban_disc_peer(
                            PeerId::from_secp256k1_pubkey(&enr.public_key().serialize()),
                            now,
                            emit,
                        );
                        return;
                    }
                }
                None => {
                    crate::PeerCounters::DiscDroppedForkDigest.inc();
                    tracing::trace!("Not a beacon node, no eth2");
                    self.ban_disc_peer(
                        PeerId::from_secp256k1_pubkey(&enr.public_key().serialize()),
                        now,
                        emit,
                    );
                    return;
                }
            }
        }

        // 2. IP-ban gate.
        let ip = enr.ip4().map(IpAddr::V4).or_else(|| enr.ip6().map(IpAddr::V6));
        if let Some(ip) = ip &&
            self.banned_ips.contains_key(&ip)
        {
            crate::PeerCounters::DiscDroppedBanned.inc();
            tracing::warn!(?ip, "peer with banned ip");
            return;
        }

        // 3. Check if already have this node, or ban applies at PeerId level.
        let compressed = enr.public_key().serialize();
        let peer_id = PeerId::from_secp256k1_pubkey(&compressed);
        if self.banned_peers.contains_key(&peer_id) {
            crate::PeerCounters::DiscDroppedBanned.inc();
            tracing::warn!(?peer_id, "banned peer id");
            return;
        }
        if self.peers.values().any(|p| p.peer_id == peer_id) {
            // Normal high-frequency case: discovery re-surfaces connected peers
            // every poll cycle. trace, not warn — else it floods the log.
            tracing::trace!(?peer_id, "known peer id");
            return;
        }
        if self.dialing.contains_key(&peer_id) {
            tracing::trace!(?peer_id, "already dialing peer id");
            return;
        }

        if enr.quic4_socket().is_none() && enr.quic6_socket().is_none() {
            tracing::debug!(udp4=?enr.udp4(), udp6=enr.udp6(), tcp4=?enr.tcp4(), tcp6=enr.tcp6(), "Peer does not support quic");
            self.ban_disc_peer(peer_id, now, emit);
            return;
        }

        tracing::debug!(id=?enr.node_id(), ?enr, "new node");

        // Add to peer database.
        self.database.add_enr(enr);

        // 4. Capacity gate. Priority match: ENR's attnets/syncnets bitfield intersects
        //    ours, meaning the peer can fill a subnet we care about. Lets us go past
        //    `target_peers` up to `max_priority_peers` for under-meshed validator
        //    subnets.
        let connected = self.peers.len() + self.dialing.len();
        let priority = enr_matches_subnets(
            &enr,
            self.required_attnets,
            self.required_syncnets,
            self.custody_columns,
        );
        let dial = connected < self.params.target_peers ||
            (priority && connected < self.params.max_priority_peers);
        if !dial {
            tracing::debug!(connected, "not dialling");
            return;
        }
        self.dialing.insert(peer_id, now);
        emit(PeerControl::P2pDial { p2p: peer_id, enr });
    }

    /// On every tick, if we're below `target_peers` and the throttle has
    /// elapsed, ask discovery to surface more candidates.
    fn maybe_request_discovery(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        if self.peers.len() >= self.params.target_peers {
            return;
        }
        if now.saturating_duration_since(self.last_discovery) < self.params.discovery_query_interval
        {
            return;
        }
        self.last_discovery = now;
        emit(PeerControl::DiscoverNodes);
    }

    fn add_invalid_delivery(&mut self, conn: usize, topic: GossipTopic) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            t.invalid_deliveries += 1.0;
        }
    }

    fn add_behaviour_penalty(&mut self, conn: usize, delta: f64, offence: &'static str) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            peer.behaviour_penalty += delta;
            tracing::info!(
                p2p_peer = conn,
                offence,
                delta,
                total = peer.behaviour_penalty,
                "P7 behaviour penalty"
            );
        }
    }

    /// Validate an inbound Status RPC payload, then upsert the parsed
    /// fields into the DB.
    ///
    /// 1. `fork_digest` mismatch — peer is on a different chain/fork.
    /// 2. Same `finalized_epoch` as ours but different `finalized_root` — peer
    ///    has finalized a competing branch.
    /// 3. `finalized_root` is in our session blacklist — peer is backing a
    ///    chain we already rejected.
    fn on_p2p_peer_status(&mut self, p2p_peer: usize, status_ssz: PeerStatus) {
        let buf: &[u8] = match &status_ssz {
            PeerStatus::V1(b) => b.as_slice(),
            PeerStatus::V2(b) => b.as_slice(),
        };
        if !StatusView::check_size(buf) {
            self.on_rpc_misbehaviour(
                p2p_peer,
                RpcSeverity::LowTolerance,
                "malformed status payload",
            );
            return;
        }
        let fork_digest = *StatusView::fork_digest(buf);
        let finalized_root = *StatusView::finalized_root(buf);
        let finalized_epoch = StatusView::finalized_epoch(buf);

        if let Some(our_fd) = self.our_fork_digest &&
            fork_digest != our_fd
        {
            self.on_rpc_misbehaviour(p2p_peer, RpcSeverity::Fatal, "status fork_digest mismatch");
            return;
        }

        // Only meaningful once something is actually finalized. At epoch 0 the
        // "finalized root" is a pre-finalization placeholder whose convention
        // differs across clients (zero vs genesis block root), so comparing it
        // would fatally evict every peer on a fresh chain.
        if let Some(local_ssz) = self.status.as_ref() &&
            finalized_epoch > 0 &&
            finalized_epoch == StatusView::finalized_epoch(local_ssz) &&
            finalized_root != *StatusView::finalized_root(local_ssz)
        {
            tracing::warn!("FATAL: finalized root and epoch mismatch");
            self.on_rpc_misbehaviour(
                p2p_peer,
                RpcSeverity::Fatal,
                "status finalized checkpoint mismatch",
            );
            return;
        }

        if self.rejected.is_rejected(&finalized_root) {
            self.on_rpc_misbehaviour(p2p_peer, RpcSeverity::Fatal, "status backs rejected chain");
            return;
        }

        // Upsert the validated Status into the DB; the `SyncEngine` consumes
        // its own copy (`PeerStatus` event) for target selection + aggregates.
        let earliest_slot = StatusView::earliest_available_slot(buf);
        self.database.p2p_status(p2p_peer, status_ssz, earliest_slot);
    }

    pub(crate) fn on_p2p_peer_goodbye(
        &mut self,
        p2p_peer: usize,
        now: Instant,
        code: u64,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if let Some(peer_record) = self.on_disconnected(p2p_peer, now, emit) &&
            let Some(peer_id) = peer_record.peer_id
        {
            let user_agent = peer_record.identify.as_ref().map(|i| i.user_agent());
            tracing::info!(
                p2p_peer,
                code = Self::goodbye_reason(code),
                ?user_agent,
                "received goodbye"
            );
            emit(PeerControl::P2pDisconnect { p2p: peer_id, p2p_connection: p2p_peer })
        }
        self.peers.remove(&p2p_peer);
    }

    /// Translate RPC misbehaviour severity into a P5 application-score
    /// delta. Calibrated so a single `Fatal` report drops the peer below the
    /// default `graylist_threshold = -80`, triggering eviction on the next
    /// `tick`. Lighter severities accumulate over time until decay catches
    /// up — same recovery dynamics as gossipsub-domain behaviour penalty.
    pub(crate) fn on_rpc_misbehaviour(
        &mut self,
        conn: usize,
        severity: RpcSeverity,
        offence: &'static str,
    ) {
        let delta = match severity {
            RpcSeverity::Fatal => -200.0,
            RpcSeverity::LowTolerance => -10.0,
            RpcSeverity::MidTolerance => -5.0,
            RpcSeverity::HighTolerance => -2.0,
        };
        crate::PeerCounters::RpcMisbehaviour.inc();
        if let Some(peer) = self.peers.get_mut(&conn) {
            peer.application_score += delta;
            tracing::info!(
                peer_id = conn,
                offence,
                ?severity,
                delta,
                score = peer.application_score,
                "P5 rpc misbehaviour"
            );
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn is_backed_off(&self, conn: usize, topic: GossipTopic, now: Instant) -> bool {
        self.peers.get(&conn).and_then(|p| p.backoffs.get(&topic)).is_some_and(|d| now < *d)
    }

    fn do_graft(
        &mut self,
        conn: usize,
        peer_id: PeerId,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let mesh = self
            .mesh
            .entry(topic)
            .or_insert_with(|| Vec::with_capacity(self.params.d_high as usize));
        if mesh.contains(&conn) {
            return;
        }
        mesh.push(conn);
        // Seed per-topic state so P3 tracking kicks in after grace window.
        if let Some(peer) = self.peers.get_mut(&conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            t.meshed_since = Some(now);
            t.mesh_active = false;
        }
        tracing::info!(?topic, conn, "GRAFT peer");
        emit(PeerControl::P2pGossipGraft { p2p: peer_id, p2p_connection: conn, topic });
    }

    fn do_prune(
        &mut self,
        conn: usize,
        peer_id: PeerId,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if let Some(mesh) = self.mesh.get_mut(&topic) &&
            let Some(idx) = mesh.iter().position(|c| *c == conn)
        {
            mesh.swap_remove(idx);
        }
        if let Some(peer) = self.peers.get_mut(&conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            if t.mesh_active && t.mesh_deliveries < self.params.mesh_message_deliveries_threshold {
                t.mesh_failure_penalty +=
                    self.params.mesh_message_deliveries_threshold - t.mesh_deliveries;
            }
            t.meshed_since = None;
            t.mesh_active = false;
            peer.backoffs.insert(topic, now + self.params.prune_backoff);
        }
        emit(PeerControl::P2pGossipPrune { p2p: peer_id, p2p_connection: conn, topic });
    }

    fn heartbeat(&mut self, now: Instant) {
        // Reset per-heartbeat rate-limit counters on every live peer.
        for peer in self.peers.values_mut() {
            peer.ihaves_received = 0;
            peer.iwant_ids_sent = 0;
        }

        // Sweep expired promises from the global map. Expired entries
        // credit `behaviour_penalty` to the peer who promised but didn't
        // come through (nor did anyone else for that id).
        let mut penalties: HashMap<usize, u32> = HashMap::new();
        self.promises.retain(|_hash, waiters| {
            waiters.retain(|(conn, deadline)| {
                if now >= *deadline {
                    *penalties.entry(*conn).or_insert(0) += 1;
                    false
                } else {
                    true
                }
            });
            !waiters.is_empty()
        });
        for (conn, _count) in penalties {
            // TODO seem to be over eagerly banning people here
            self.add_behaviour_penalty(conn, 1.0, "broken gossip promises");
        }
    }

    fn activate_p3_where_due(&mut self, now: Instant) {
        let activation = self.params.mesh_message_deliveries_activation_s;
        for peer in self.peers.values_mut() {
            for (topic, t) in peer.topic_stats.iter_mut() {
                if topic.p3_scored() &&
                    !t.mesh_active &&
                    let Some(since) = t.meshed_since &&
                    now.saturating_duration_since(since).as_secs_f64() >= activation
                {
                    t.mesh_active = true;
                }
            }
        }
    }

    fn rescore_all(&mut self, now: Instant) {
        // Snapshot colocation counts so we don't hold borrows across the
        // mutation loop.
        let peers_by_prefix: HashMap<IpPrefix, usize> =
            self.ip_colocations.iter().map(|(k, v)| (*k, v.len())).collect();

        for peer in self.peers.values_mut() {
            let coloc = *peers_by_prefix.get(&peer.ip_prefix).unwrap_or(&1);
            peer.cached_score = scoring::compute_score(peer, &self.params, coloc, now);
            peer.score_valid_at = now;
        }
    }

    fn evict_graylisted(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let threshold = self.params.graylist_threshold;
        // Two-phase: identify + remove (can't mutate self.peers while
        // iterating it); emit is inline in phase 2.
        let mut evict: Vec<(usize, PeerId, IpAddr)> = Vec::new();
        for (conn, peer) in &self.peers {
            if peer.cached_score < threshold {
                let coloc = self.ip_colocations.get(&peer.ip_prefix).map(|v| v.len()).unwrap_or(1);
                let b = scoring::score_breakdown(peer, &self.params, coloc, now);
                tracing::warn!(
                    peer_id = ?peer.peer_id,
                    addr = ?peer.addr,
                    total = b.total,
                    threshold,
                    p1_time_in_mesh = b.p1_time_in_mesh,
                    p2_first_deliveries = b.p2_first_deliveries,
                    p3_mesh_deficit = b.p3_mesh_deficit,
                    p3b_mesh_failure = b.p3b_mesh_failure,
                    p4_invalid = b.p4_invalid,
                    p5_application = b.p5_application,
                    p6_ip_colocation = b.p6_ip_colocation,
                    p7_behaviour = b.p7_behaviour,
                    "evicting greylisted peer: {conn}"
                );
                evict.push((*conn, peer.peer_id, peer.addr.ip()));
            }
        }
        for (conn, peer_id, ip) in evict {
            emit(PeerControl::Ban { p2p: peer_id });
            crate::PeerCounters::PeersEvicted.inc();
            crate::PeerCounters::PeersBanned.inc();
            self.banned_peers.insert(peer_id, now);
            // Bump the per-IP eviction count; only escalate to `BanIp`
            // once we've seen `ip_ban_threshold` peer-level graylists from
            // this IP within the TTL window. Avoids first-strike IP bans
            // for honest NAT/CGN endpoints sharing an address.
            let count = {
                let entry = self.ip_eviction_counts.entry(ip).or_insert((0, now));
                entry.0 += 1;
                entry.1 = now;
                entry.0
            };
            if count >= self.params.ip_ban_threshold {
                tracing::info!(?ip, evictions = count, "banning ip");
                emit(PeerControl::BanIp { ip });
                crate::PeerCounters::IpsBanned.inc();
                self.banned_ips.insert(ip, now);
            }
            // Archived copy is written on the normal disconnect path fired
            // downstream once the Ban takes ffect; here we just drop live.
            self.peers.remove(&conn);
        }
    }

    fn manage_mesh(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        // Iterate over OUR topics (topics we care about). We briefly clone
        // the topic list so `ensure_mesh_*` can take `&mut self`.
        let our_topics = self.our_topics.clone();
        for topic in &our_topics {
            self.ensure_mesh_filled(*topic, now, emit);
            self.ensure_mesh_capped(*topic, now, emit);
        }
    }

    fn ensure_mesh_filled(
        &mut self,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let current = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        let d_low = self.params.d_low as usize;
        let d = self.params.d as usize;
        if current >= d_low {
            return;
        }
        let needed = d - current;
        // Sort requires a buffer; the emit isn't what forces it.
        let mut candidates: Vec<(usize, f64)> = self
            .peers
            .iter()
            .filter_map(|(conn, peer)| {
                if !peer.topics.contains(&topic) {
                    return None;
                }
                if self.mesh.get(&topic).is_some_and(|m| m.contains(conn)) {
                    return None;
                }
                if peer.cached_score < self.params.gossip_threshold {
                    return None;
                }
                if self.is_backed_off(*conn, topic, now) {
                    return None;
                }
                Some((*conn, peer.cached_score))
            })
            .collect();
        candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for (conn, _) in candidates.into_iter().take(needed) {
            let Some(peer_id) = self.peers.get(&conn).map(|p| p.peer_id) else {
                continue;
            };
            self.do_graft(conn, peer_id, topic, now, emit);
        }
    }

    fn ensure_mesh_capped(
        &mut self,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let d_high = self.params.d_high as usize;
        let d = self.params.d as usize;
        let current = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        if current <= d_high {
            return;
        }
        let excess = current - d;
        // Sort requires a buffer; the emit isn't what forces it.
        let mut ranked: Vec<(usize, f64, PeerId)> = self
            .mesh
            .get(&topic)
            .map(|mesh| {
                mesh.iter()
                    .filter_map(|conn| {
                        self.peers.get(conn).map(|p| (*conn, p.cached_score, p.peer_id))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        for (conn, _, peer_id) in ranked.into_iter().take(excess) {
            self.do_prune(conn, peer_id, topic, now, emit);
        }
    }

    fn gc_archived(&mut self, now: Instant) {
        let ttl = self.params.archived_ttl;
        self.archived.retain(|_, a| now.saturating_duration_since(a.archived_at) < ttl);
    }

    /// Sweep expired entries from `banned_ips`, emitting `UnbanIp` for each
    /// expired IP so the network/discovery tile can drop their socket-level
    /// deny entries. Also ages out `ip_eviction_counts` (no emit — purely
    /// internal accounting).
    fn gc_banned_ips(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let ttl = self.params.banned_ip_ttl;
        self.banned_ips.retain(|ip, t| {
            if now.saturating_duration_since(*t) >= ttl {
                emit(PeerControl::UnbanIp { ip: *ip });
                false
            } else {
                true
            }
        });
        self.ip_eviction_counts.retain(|_, (_, t)| now.saturating_duration_since(*t) < ttl);
    }

    /// Sweep expired entries from `banned_peers`, emitting `Unban` per
    /// expired PeerId. Symmetric to `gc_banned_ips` but on a separate TTL.
    fn gc_banned_peers(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let ttl = self.params.banned_peer_ttl;
        self.banned_peers.retain(|p2p, t| {
            if now.saturating_duration_since(*t) >= ttl {
                emit(PeerControl::Unban { p2p: *p2p });
                false
            } else {
                true
            }
        });
    }

    /// Human label for a Goodbye reason code (per eth2 spec).
    fn goodbye_reason(code: u64) -> &'static str {
        match code {
            1 => "ClientShutdown",
            2 => "IrrelevantNetwork",
            3 => "Error",
            128 => "Banned",
            129 => "BannedIP",
            250 => "ScoreTooLow",
            251 => "Fault",
            _ => "Unknown",
        }
    }
}

/// Session-level blacklist. Inserted into by beacon-state's `BlockRejected`
/// emissions by target-rejection propagation. Queried by inbound
/// Status validation by sync target selection. FIFO eviction.
/// Capacity comes from `SyncingConfig`.
#[derive(Debug)]
pub struct RejectedRoots {
    cap: usize,
    order: VecDeque<[u8; 32]>,
    set: FxHashSet<[u8; 32]>,
}

impl RejectedRoots {
    pub fn new(cap: usize) -> Self {
        Self { cap, order: VecDeque::new(), set: FxHashSet::default() }
    }

    pub fn mark(&mut self, root: [u8; 32]) {
        if self.set.insert(root) {
            self.order.push_back(root);
            if self.order.len() > self.cap &&
                let Some(old) = self.order.pop_front()
            {
                self.set.remove(&old);
            }
        }
    }

    pub fn is_rejected(&self, root: &[u8; 32]) -> bool {
        self.set.contains(root)
    }

    pub fn count(&self) -> usize {
        self.set.len()
    }
}

/// Build SSZ Bitvector[64] / Bitvector[N≤8] masks from `our_topics`. Each
/// `BeaconAttestation(N)` flips bit N in the 64-bit attnet mask; each
/// `SyncCommittee(N)` flips bit N in the syncnet byte. Computed once at
/// construction — `our_topics` is immutable for the manager's lifetime.
fn build_subnet_masks(our_topics: &[GossipTopic]) -> ([u8; 8], u8) {
    let mut attnets = [0u8; 8];
    let mut syncnets = 0u8;
    for t in our_topics {
        match t {
            GossipTopic::BeaconAttestation(n) => {
                let n = *n as usize;
                if n < 64 {
                    attnets[n / 8] |= 1 << (n % 8);
                }
            }
            GossipTopic::SyncCommittee(n) => {
                let n = *n;
                if n < 8 {
                    syncnets |= 1 << n;
                }
            }
            _ => {}
        }
    }
    (attnets, syncnets)
}

/// True iff the ENR advertises subscription to at least one attnet/syncnet
/// we also subscribe to. Both bitfields are SSZ Bitvectors so a bytewise
/// AND is sufficient — any non-zero result means at least one shared bit.
fn enr_matches_subnets(
    enr: &Enr,
    attnets_mask: [u8; 8],
    syncnets_mask: u8,
    custody_columns: u128,
) -> bool {
    if let Some(enr_attnets) = enr.attnets() {
        for i in 0..8 {
            if enr_attnets[i] & attnets_mask[i] != 0 {
                return true;
            }
        }
    }
    if let Some(enr_syncnets) = enr.syncnets() &&
        enr_syncnets & syncnets_mask != 0
    {
        return true;
    }
    if let Some(cgc) = enr.cgc() {
        return enr.node_id().custody_groups(cgc as u8) & custody_columns != 0
    }
    false
}

fn ip_bytes_to_addr(ip: IpBytes) -> IpAddr {
    match ip {
        IpBytes::V4(o) => IpAddr::V4(std::net::Ipv4Addr::from(o)),
        IpBytes::V6(o) => IpAddr::V6(std::net::Ipv6Addr::from(o)),
    }
}

// Suppress "unused" on HashSet pulled through the re-export graph.
#[allow(dead_code)]
type _TopicSet = HashSet<GossipTopic>;
#[allow(dead_code)]
type _TopicScoreAlias = TopicScore;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use silver_common::{
        BACKFILL_REQUEST_ID, BASE_REQUEST_ID, COLUMN_BACKFILL_REQUEST_ID, Enr, Identify, Keypair,
        P2pStreamId, RpcInbound, RpcResponse, RpcResponseInbound, TCacheProducer,
        ssz_view::BLOCKS_BY_RANGE_REQ_SIZE,
    };

    use super::*;

    /// Owns the captured `PeerControl` stream for a test. Tests push into
    /// `cap.0` via an ad-hoc `|c| cap.0.push(c)` closure passed to
    /// `handle_event`/`tick`.
    #[derive(Default)]
    struct Captured(Vec<PeerControl>);

    fn fixture(
        our_topics: Vec<GossipTopic>,
        params: ScoreParams,
        awaiting_replay: bool,
    ) -> (PeerManager, Captured) {
        (
            PeerManager::new(
                our_topics,
                params,
                SyncingConfig::default(),
                [0u8; 4],
                [0u8; METADATA_SIZE],
                0,
                awaiting_replay,
            ),
            Captured::default(),
        )
    }

    fn peer_id(seed: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 1;
        Keypair::from_secret(&bytes).unwrap().peer_id()
    }

    fn connect(mgr: &mut PeerManager, cap: &mut Captured, conn: usize, seed: u8, now: Instant) {
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: conn,
                peer_id_full: peer_id(seed),
                ip: IpBytes::V4([10, 0, 0, seed]),
                port: 4000 + seed as u16,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
    }

    /// `on_connected` always emits a `P2pSend::Identify` event; filter
    /// it out so subscribe-focused tests can assert on subscribe counts.
    fn subscribe_events(cap: &Captured) -> Vec<&PeerControl> {
        cap.0.iter().filter(|c| !matches!(c, PeerControl::P2pSend(P2pSend::Identify(_)))).collect()
    }

    #[test]
    fn connect_with_no_topics_emits_nothing() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        assert!(subscribe_events(&cap).is_empty());
    }

    #[test]
    fn connect_emits_subscribe_per_our_topic() {
        let now = Instant::now();
        let topics = vec![GossipTopic::BeaconBlock, GossipTopic::VoluntaryExit];
        let (mut mgr, mut cap) = fixture(topics.clone(), ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        let subs = subscribe_events(&cap);
        assert_eq!(subs.len(), 2);
        for e in &subs {
            assert!(matches!(e, PeerControl::P2pGossipSubscribe { .. }));
        }
    }

    #[test]
    fn peer_subscribes_and_we_graft_when_mesh_under_d_low() {
        let now = Instant::now();
        let topics = vec![GossipTopic::BeaconBlock];
        let (mut mgr, mut cap) = fixture(topics, ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        cap.0.clear();

        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic: GossipTopic::BeaconBlock },
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(
            cap.0.iter().any(|e| matches!(
                e,
                PeerControl::P2pGossipGraft { topic, .. } if *topic == GossipTopic::BeaconBlock
            )),
            "expected a GRAFT, got {:?}",
            cap.0
        );
        assert_eq!(mgr.mesh_size(GossipTopic::BeaconBlock), 1);
    }

    #[test]
    fn invalid_frames_increment_behaviour_penalty_and_tick_bans() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0; // excess^2 * -10
        params.graylist_threshold = -80.0; // behaviour_penalty=3 → score=-90
        params.ip_ban_threshold = 1; // single eviction → BanIp for this test
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        assert!(mgr.score(1).is_some());
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "expected Ban, got {:?}",
            cap.0
        );
        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })),
            "expected BanIp, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none(), "banned peer should be gone");
    }

    #[test]
    fn broken_promise_sweep_adds_penalty() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.iwant_followup = Duration::from_secs(3);
        params.heartbeat_interval = Duration::from_millis(100);
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        let hash = silver_common::MessageId { id: [7u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                hash,
                already_seen: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );

        now += Duration::from_secs(4);
        mgr.tick(now, &mut |c| cap.0.push(c));

        let s = mgr.score(1).unwrap();
        assert!(s <= 0.0, "expected non-positive score after broken promise, got {s}");
    }

    #[test]
    fn ihave_flood_over_heartbeat_cap_penalises() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.max_ihave_length = 3;
        params.graylist_threshold = -100_000.0;
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        let hash = silver_common::MessageId { id: [9u8; 20] };
        for _ in 0..8 {
            mgr.handle_event(
                PeerEvent::P2pGossipHave {
                    p2p_peer: 1,
                    topic: GossipTopic::BeaconBlock,
                    hash,
                    already_seen: false,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        let s = mgr.score(1).unwrap();
        assert!(s < 0.0, "expected negative score after flood, got {s}");
    }

    #[test]
    fn already_seen_ihave_tracks_no_promise() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.iwant_followup = Duration::from_secs(3);
        params.heartbeat_interval = Duration::from_millis(100);
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        let hash = silver_common::MessageId { id: [77u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                hash,
                already_seen: true,
            },
            now,
            &mut |c| cap.0.push(c),
        );

        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let s = mgr.score(1).unwrap();
        assert_eq!(s, 0.0, "no IWANT was issued → no promise → no broken-promise penalty, got {s}");
    }

    #[test]
    fn ip_colocation_penalty_applies() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.ip_colocation_threshold = 2;
        params.ip_colocation_weight = -5.0;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        for i in 1..=5u8 {
            mgr.handle_event(
                PeerEvent::P2pNewConnection {
                    p2p_peer_id: i as usize,
                    peer_id_full: peer_id(i),
                    ip: IpBytes::V4([10, 0, 0, i]),
                    port: 4000 + i as u16,
                    local_dial: false,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        let s = mgr.score(1).unwrap();
        assert!((s - -45.0).abs() < 1e-9, "expected -45, got {s}");
    }

    #[test]
    fn disconnect_archives_and_reconnect_restores() {
        let now = Instant::now();
        let params = ScoreParams::default();
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: peer_id(1) },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.archived_count(), 1);

        connect(&mut mgr, &mut cap, 99, 1, now);
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        let s = mgr.score(99).unwrap();
        assert!(s < 0.0, "expected restored penalty score, got {s}");
        assert_eq!(mgr.archived_count(), 0);
    }

    #[test]
    fn archived_state_dropped_past_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.archived_ttl = Duration::from_secs(10);
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: peer_id(1) },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.archived_count(), 1);

        now += Duration::from_secs(11);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert_eq!(mgr.archived_count(), 0);
    }

    fn mk_tcache_read() -> silver_common::TCacheRead {
        let mut producer = silver_common::TCache::producer("test_peer", 1 << 14);
        let mut reservation = producer.reserve(64, true).unwrap();
        use std::io::Write as _;
        reservation.write_all(&[0u8; 64]).unwrap();
        reservation.read()
    }

    #[test]
    fn new_inbound_fulfils_promise_and_credits_p2() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.iwant_followup = Duration::from_secs(3);
        params.heartbeat_interval = Duration::from_millis(100);
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        let hash = silver_common::MessageId { id: [7u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                hash,
                already_seen: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );

        now += Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::NewGossip {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                msg_hash: hash,
                idontwant: mk_tcache_read(),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let score_delivered = mgr.score(1).unwrap();

        connect(&mut mgr, &mut cap, 2, 2, now);
        let other = silver_common::MessageId { id: [8u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 2,
                topic: GossipTopic::BeaconBlock,
                hash: other,
                already_seen: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let score_broken = mgr.score(2).unwrap();

        assert!(
            score_delivered > score_broken,
            "delivered peer must score above broken-promise peer: \
             delivered={score_delivered}, broken={score_broken}"
        );
    }

    #[test]
    fn delivery_from_one_peer_fulfils_all_peers_promises_for_that_id() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.iwant_followup = Duration::from_secs(3);
        params.heartbeat_interval = Duration::from_millis(100);
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);

        let hash = silver_common::MessageId { id: [42u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                hash,
                already_seen: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 2,
                topic: GossipTopic::BeaconBlock,
                hash,
                already_seen: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );

        now += Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::NewGossip {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                msg_hash: hash,
                idontwant: mk_tcache_read(),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));

        connect(&mut mgr, &mut cap, 3, 3, now);
        let other = silver_common::MessageId { id: [99u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipHave {
                p2p_peer: 3,
                topic: GossipTopic::BeaconBlock,
                hash: other,
                already_seen: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));

        let s1 = mgr.score(1).unwrap();
        let s2 = mgr.score(2).unwrap();
        let s3 = mgr.score(3).unwrap();
        assert!(s1 > s3, "delivering peer must out-score broken-promise peer: {s1} vs {s3}");
        assert!(
            s2 > s3,
            "promise-fulfilled-by-other-peer must out-score broken-promise peer: {s2} vs {s3}"
        );
    }

    #[test]
    fn new_outbound_ihave_fans_out_to_non_mesh_subscribers() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.d_lazy = 3;
        params.d_low = 1; // so the first subscriber grafts into mesh, rest stay non-mesh
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params, false);

        for i in 1..=4u8 {
            connect(&mut mgr, &mut cap, i as usize, i, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe {
                    p2p_peer: i as usize,
                    topic: GossipTopic::BeaconBlock,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        assert_eq!(mgr.mesh_size(GossipTopic::BeaconBlock), 1);
        cap.0.clear();

        mgr.handle_event(
            PeerEvent::OutboundIHave {
                topic: GossipTopic::BeaconBlock,
                msg_count: 2,
                protobuf: mk_tcache_read(),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        let send_ihaves: Vec<_> = cap
            .0
            .iter()
            .filter_map(|e| {
                if let PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id, .. })) = e {
                    Some(*peer_id)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            send_ihaves.len(),
            3,
            "expected 3 IHAVE emissions (d_lazy=3, 3 non-mesh subscribers), got {:?}",
            cap.0
        );
        assert!(
            send_ihaves.iter().all(|c| !matches!(c, &1)),
            "mesh peer (conn=1) must not receive IHAVE, got {send_ihaves:?}"
        );
    }

    #[test]
    fn new_outbound_ihave_skips_below_threshold_peers() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.gossip_threshold = -1.0;
        params.graylist_threshold = -1_000_000.0;
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic: GossipTopic::BeaconBlock },
            now,
            &mut |c| cap.0.push(c),
        );
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(10), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).unwrap() < -1.0);

        cap.0.clear();
        mgr.handle_event(
            PeerEvent::OutboundIHave {
                topic: GossipTopic::BeaconBlock,
                msg_count: 1,
                protobuf: mk_tcache_read(),
            },
            now + Duration::from_millis(20),
            &mut |c| cap.0.push(c),
        );
        assert!(
            !cap.0
                .iter()
                .any(|e| matches!(e, PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { .. })))),
            "below-threshold peer should not receive IHAVE, got {:?}",
            cap.0
        );
    }

    #[test]
    fn iwant_request_above_threshold_emits_forward() {
        use silver_common::{TCache, TCacheRead};
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        let mut producer = TCache::producer("test_peer", 1 << 14);
        let mut reservation = producer.reserve(64, true).unwrap();
        use std::io::Write as _;
        reservation.write_all(&[0u8; 64]).unwrap();
        let tcache: TCacheRead = reservation.read();

        cap.0.clear();
        let hash = silver_common::MessageId { id: [3u8; 20] };
        mgr.handle_event(PeerEvent::P2pGossipWant { p2p_peer: 1, hash, tcache }, now, &mut |c| {
            cap.0.push(c)
        });

        assert!(
            cap.0.iter().any(|e| matches!(
                e,
                PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id: 1, .. }))
            )),
            "expected ForwardMsg emission, got {:?}",
            cap.0
        );
    }

    #[test]
    fn iwant_request_below_threshold_drops() {
        use silver_common::{TCache, TCacheRead};
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.gossip_threshold = -1.0;
        params.graylist_threshold = -1_000_000.0;
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(10), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).unwrap() < -1.0);

        let mut producer = TCache::producer("test_peer", 1 << 14);
        let mut reservation = producer.reserve(64, true).unwrap();
        use std::io::Write as _;
        reservation.write_all(&[0u8; 64]).unwrap();
        let tcache: TCacheRead = reservation.read();

        cap.0.clear();
        let hash = silver_common::MessageId { id: [4u8; 20] };
        mgr.handle_event(
            PeerEvent::P2pGossipWant { p2p_peer: 1, hash, tcache },
            now + Duration::from_millis(20),
            &mut |c| cap.0.push(c),
        );

        assert!(
            !cap.0
                .iter()
                .any(|e| matches!(e, PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { .. })))),
            "expected no ForwardMsg for below-threshold peer, got {:?}",
            cap.0
        );
    }

    #[test]
    fn new_inbound_fans_out_dontwant_to_mesh_excluding_sender() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.d_low = 0;
        params.d = 0;
        params.d_high = 8;
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params, false);

        for i in 1..=4u8 {
            connect(&mut mgr, &mut cap, i as usize, i, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe {
                    p2p_peer: i as usize,
                    topic: GossipTopic::BeaconBlock,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        for i in 1..=4usize {
            mgr.mesh.entry(GossipTopic::BeaconBlock).or_default().push(i);
        }
        cap.0.clear();

        let hash = silver_common::MessageId { id: [55u8; 20] };
        mgr.handle_event(
            PeerEvent::NewGossip {
                p2p_peer: 2,
                topic: GossipTopic::BeaconBlock,
                msg_hash: hash,
                idontwant: mk_tcache_read(),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        let dontwants: Vec<usize> = cap
            .0
            .iter()
            .filter_map(|e| match e {
                PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id, .. })) => {
                    Some(*peer_id)
                }
                _ => None,
            })
            .collect();

        assert_eq!(
            dontwants.len(),
            3,
            "expected IDONTWANT to 3 non-sender mesh peers, got {:?}",
            cap.0
        );
        assert!(
            !dontwants.contains(&2),
            "sender (conn=2) must not receive IDONTWANT for its own delivery: {dontwants:?}"
        );
        for conn in [1usize, 3, 4] {
            assert!(
                dontwants.contains(&conn),
                "expected IDONTWANT to mesh peer {conn}, got {dontwants:?}"
            );
        }
    }

    #[test]
    fn new_inbound_skips_dontwant_for_below_threshold_peer() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.gossip_threshold = -1.0;
        params.graylist_threshold = -1_000_000.0;
        params.d_high = 8;
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params, false);

        for i in 1..=2u8 {
            connect(&mut mgr, &mut cap, i as usize, i, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe {
                    p2p_peer: i as usize,
                    topic: GossipTopic::BeaconBlock,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        for i in 1..=2usize {
            mgr.mesh.entry(GossipTopic::BeaconBlock).or_default().push(i);
        }
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 2 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(10), &mut |c| cap.0.push(c));
        assert!(mgr.score(2).unwrap() < -1.0);
        cap.0.clear();

        let hash = silver_common::MessageId { id: [66u8; 20] };
        mgr.handle_event(
            PeerEvent::NewGossip {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                msg_hash: hash,
                idontwant: mk_tcache_read(),
            },
            now + Duration::from_millis(20),
            &mut |c| cap.0.push(c),
        );

        assert!(
            !cap.0
                .iter()
                .any(|e| matches!(e, PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { .. })))),
            "below-threshold mesh peer should not receive IDONTWANT, got {:?}",
            cap.0
        );
    }

    #[test]
    fn send_gossip_skips_mesh_peer_with_idontwant() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        // d_low=0 disables the auto-graft on subscribe so manual mesh seeding
        // is the only thing populating the mesh map.
        params.d_low = 0;
        params.d = 0;
        params.d_high = 8;
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params, false);

        for i in 1..=3u8 {
            connect(&mut mgr, &mut cap, i as usize, i, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe {
                    p2p_peer: i as usize,
                    topic: GossipTopic::BeaconBlock,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        for i in 1..=3usize {
            mgr.mesh.entry(GossipTopic::BeaconBlock).or_default().push(i);
        }

        let hash = silver_common::MessageId { id: [0xAB; 20] };

        // Peer 2 says "don't send me this id".
        mgr.handle_event(PeerEvent::P2pGossipDontWant { p2p_peer: 2, hash }, now, &mut |c| {
            cap.0.push(c)
        });

        cap.0.clear();

        // Internal SendGossip with originator stream from peer 1.
        let stream_id =
            silver_common::P2pStreamId::new(1, 0, silver_common::StreamProtocol::GossipSub, false);
        mgr.handle_event(
            PeerEvent::SendGossip {
                originator_stream_id: stream_id,
                topic: GossipTopic::BeaconBlock,
                msg_hash: hash,
                recv_ts: silver_common::Nanos::now(),
                protobuf: mk_tcache_read(),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        let recipients: Vec<usize> = cap
            .0
            .iter()
            .filter_map(|e| match e {
                PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id, .. })) => {
                    Some(*peer_id)
                }
                _ => None,
            })
            .collect();
        // Peer 1 = sender (skipped), peer 2 = IDONTWANT (skipped), peer 3 = served.
        assert_eq!(
            recipients,
            vec![3],
            "expected only peer 3 to receive the broadcast, got {recipients:?}"
        );
    }

    /// Same key derivation as `peer_id(seed)` so an ENR built with this
    /// helper has a `public_key()` whose derived `PeerId` matches what
    /// `connect(...)` registers. Critical for `banned_peers` /
    /// `archived` filter tests.
    fn test_enr(seed: u8, ip: std::net::Ipv4Addr) -> silver_common::Enr {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 1;
        let kp = Keypair::from_secret(&bytes).unwrap();
        // QUIC port required — `on_disc_node_found` drops ENRs that don't
        // advertise a quic4/quic6 socket.
        silver_common::Enr::builder().ip4(ip).udp4(9000).quic4(9000).build(kp.secret_key()).unwrap()
    }

    /// Builder variant for fork-digest / subnet-bitfield tests. `eth2` is
    /// the full ENRForkID (16 bytes — fork_digest first 4, then next-fork-
    /// version 4, then next-fork-epoch 8); only the leading 4 are matched
    /// against `set_fork_digest`.
    fn test_enr_with(
        seed: u8,
        ip: std::net::Ipv4Addr,
        eth2: Option<[u8; 16]>,
        attnets: Option<[u8; 8]>,
        syncnets: Option<u8>,
    ) -> silver_common::Enr {
        // Match `peer_id(seed)`'s derivation for cross-test consistency.
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 1;
        let kp = Keypair::from_secret(&bytes).unwrap();
        let mut b = silver_common::Enr::builder();
        b.ip4(ip).udp4(9000).quic4(9000);
        if let Some(e) = eth2 {
            b.eth2(e);
        }
        if let Some(a) = attnets {
            b.attnets(a);
        }
        if let Some(s) = syncnets {
            b.syncnets(s);
        }
        b.build(kp.secret_key()).unwrap()
    }

    #[test]
    fn disc_node_found_below_target_emits_dial() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        // ENR must carry an `eth2` field matching the fixture's [0u8;4]
        // fork digest now that `our_fork_digest` is always set.
        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some([0u8; 16]), None, None);

        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "expected P2pDial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_redials_archived_peer() {
        // Archive persists reputation but must not veto redial: a benign
        // disconnect (not a ban) has to be re-dialable or we strand ourselves.
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        connect(&mut mgr, &mut cap, 1, 7, now);
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: peer_id(7) },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.archived_count(), 1);
        cap.0.clear();

        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some([0u8; 16]), None, None);
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "archived (non-banned) peer must be redialed, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_at_target_does_not_dial() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 2;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        cap.0.clear();

        let enr = test_enr(99, std::net::Ipv4Addr::new(10, 0, 0, 99));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));

        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "at-target manager must not dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_skips_banned_ip() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.ip_ban_threshold = 1; // single eviction → BanIp for this test
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        // Connect a peer on 10.0.0.42, drive their score below graylist, tick
        // to evict — that should record 10.0.0.42 in `banned_ips`.
        connect(&mut mgr, &mut cap, 42, 42, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 42 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));
        cap.0.clear();

        // Same /32 reappears via discovery — must be dropped.
        let enr = test_enr(42, std::net::Ipv4Addr::new(10, 0, 0, 42));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));

        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "banned-IP discovery hit must not dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn banned_ip_clears_after_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.banned_ip_ttl = Duration::from_secs(10);
        // Match peer-TTL so both filters expire on the same tick — this
        // test exercises the IP-level filter; without aligning these
        // we'd still be blocked at the PeerId-level filter post-TTL.
        params.banned_peer_ttl = Duration::from_secs(10);
        params.ip_ban_threshold = 1; // single eviction → BanIp for this test
        // Decay must be slow enough that "5 invalid frames -> tick -> ban"
        // still trips the gate after the test's first tick.
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        connect(&mut mgr, &mut cap, 42, 42, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 42 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));

        // Pre-TTL: discovery hit on banned IP is dropped.
        cap.0.clear();
        // ENR must carry an `eth2` field matching the fixture's [0u8;4]
        // fork digest (always-on filter since `our_fork_digest` is set).
        let enr =
            test_enr_with(42, std::net::Ipv4Addr::new(10, 0, 0, 42), Some([0u8; 16]), None, None);
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })));

        // Advance past banned_ip_ttl + tick to GC the ban entry.
        now += Duration::from_secs(11);
        mgr.tick(now, &mut |c| cap.0.push(c));

        // Same IP via discovery now dials.
        cap.0.clear();
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));
        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "post-TTL discovery hit must dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn ip_ban_threshold_gates_ban_ip_emission() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 16;
        params.ip_ban_threshold = 3;
        // Slow decay so we don't flap above threshold between iterations.
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 99);

        // Evict 3 distinct peers from the same IP. The first two should
        // emit `Ban` only; the third should also emit `BanIp` (threshold).
        for seed in 1..=3u8 {
            mgr.handle_event(
                PeerEvent::P2pNewConnection {
                    p2p_peer_id: seed as usize,
                    peer_id_full: peer_id(seed),
                    ip: IpBytes::V4(ip.octets()),
                    port: 4000 + seed as u16,
                    local_dial: false,
                },
                now,
                &mut |c| cap.0.push(c),
            );
            for _ in 0..5 {
                mgr.handle_event(
                    PeerEvent::P2pGossipInvalidFrame { p2p_peer: seed as usize },
                    now,
                    &mut |c| cap.0.push(c),
                );
            }
            cap.0.clear();
            mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

            let banned = cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. }));
            let banned_peer = cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. }));
            assert!(banned_peer, "every eviction should emit Ban (seed {seed})");
            if seed < 3 {
                assert!(!banned, "below-threshold eviction must not emit BanIp (seed {seed})");
            } else {
                assert!(banned, "threshold-reaching eviction must emit BanIp (seed {seed})");
            }
        }
    }

    #[test]
    fn ip_ban_count_decays_with_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 16;
        params.ip_ban_threshold = 2;
        params.banned_ip_ttl = Duration::from_secs(10);
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 88);
        // First eviction: bumps count to 1. No BanIp yet (threshold=2).
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 1,
                peer_id_full: peer_id(1),
                ip: IpBytes::V4(ip.octets()),
                port: 4001,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));
        cap.0.clear();

        // Past the TTL — gc clears the eviction-count entry.
        now += Duration::from_secs(11);
        mgr.tick(now, &mut |c| cap.0.push(c));

        // Fresh eviction post-TTL: count starts at 0 again, single eviction
        // bumps to 1 (still under threshold=2) → no BanIp.
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 2,
                peer_id_full: peer_id(2),
                ip: IpBytes::V4(ip.octets()),
                port: 4002,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 2 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        cap.0.clear();
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })),
            "post-TTL fresh count must not BanIp on first eviction, got {:?}",
            cap.0
        );
    }

    #[test]
    fn banned_ip_emits_unban_after_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.ip_ban_threshold = 1;
        params.banned_ip_ttl = Duration::from_secs(10);
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        connect(&mut mgr, &mut cap, 42, 42, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 42 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));
        cap.0.clear();

        // Pre-TTL: no UnbanIp.
        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::UnbanIp { .. })));

        // Past TTL: gc fires → UnbanIp emitted exactly once.
        now += Duration::from_secs(6);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let unban_count = cap.0.iter().filter(|e| matches!(e, PeerControl::UnbanIp { .. })).count();
        assert_eq!(unban_count, 1, "expected one UnbanIp after TTL, got {:?}", cap.0);

        // Subsequent tick: nothing more — entry already gc'd.
        cap.0.clear();
        now += Duration::from_secs(1);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::UnbanIp { .. })));
    }

    #[test]
    fn banned_peer_emits_unban_after_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.banned_peer_ttl = Duration::from_secs(10);
        // Decouple peer-TTL from IP-TTL so the IP ban doesn't gc + emit
        // UnbanIp at the same tick and confuse the assertion. Also keep
        // ip_ban_threshold=2 so this single eviction stays peer-only.
        params.banned_ip_ttl = Duration::from_secs(60);
        params.ip_ban_threshold = 2;
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        connect(&mut mgr, &mut cap, 1, 1, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })));
        cap.0.clear();

        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::Unban { .. })));

        now += Duration::from_secs(6);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let unban_count = cap.0.iter().filter(|e| matches!(e, PeerControl::Unban { .. })).count();
        assert_eq!(unban_count, 1, "expected one Unban after TTL, got {:?}", cap.0);
    }

    #[test]
    fn disc_node_found_skips_banned_peer_id() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        // Long peer TTL, never expires during this test. Keep the IP ban
        // threshold high so we test PeerId-only filter (not IP).
        params.banned_peer_ttl = Duration::from_secs(3600);
        params.ip_ban_threshold = 100;
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        // Connect peer with seed=7 on 10.0.0.7 → drive below graylist → tick.
        connect(&mut mgr, &mut cap, 1, 7, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        cap.0.clear();

        // ENR re-presents the same PeerId (same seed → same secp256k1 key).
        // Even from a different IP, it must drop on banned-peer-id filter.
        now += Duration::from_secs(1);
        let enr = test_enr(7, std::net::Ipv4Addr::new(10, 0, 0, 200));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "banned PeerId discovery hit must not dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn tick_under_target_emits_discover_nodes_throttled() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        params.discovery_query_interval = Duration::from_secs(5);
        params.heartbeat_interval = Duration::from_millis(10);
        let (mut mgr, mut cap) = fixture(vec![], params, false);

        // First tick after construction: under target, throttle has elapsed
        // (last_discovery was set to construction time, query_interval=5s).
        now += Duration::from_secs(6);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let first_count = cap.0.iter().filter(|e| matches!(e, PeerControl::DiscoverNodes)).count();
        assert_eq!(first_count, 1, "first tick should fire one DiscoverNodes, got {:?}", cap.0);

        // Immediate second tick should be throttled.
        cap.0.clear();
        now += Duration::from_millis(50);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::DiscoverNodes)),
            "throttle should suppress second emission, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_drops_mismatched_fork_digest() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        mgr.set_fork_digest([0xAA, 0xBB, 0xCC, 0xDD]);

        let mut wrong_eth2 = [0u8; 16];
        wrong_eth2[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some(wrong_eth2), None, None);

        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "wrong-fork ENR must be dropped, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_drops_missing_eth2_when_filter_set() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        mgr.set_fork_digest([0xAA, 0xBB, 0xCC, 0xDD]);

        // ENR with no eth2 field — same drop policy as lighthouse.
        let enr = test_enr(7, std::net::Ipv4Addr::new(10, 0, 0, 7));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "ENR without eth2 must be dropped when filter set, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_priority_subnet_dials_past_target() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 2;
        params.max_priority_peers = 4;
        // Subscribe to attnet 5 — our required mask flips bit 5.
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconAttestation(5)], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        cap.0.clear();

        // ENR advertises attnet 5 (byte 0, bit 5 = 0x20). Also include an
        // `eth2` matching the fixture's [0u8;4] fork digest — that filter
        // is always on now.
        let mut attnets = [0u8; 8];
        attnets[0] = 0x20;
        let enr = test_enr_with(
            99,
            std::net::Ipv4Addr::new(10, 0, 0, 99),
            Some([0u8; 16]),
            Some(attnets),
            None,
        );
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "priority subnet match should dial past target, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_priority_capped_at_max_priority() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 2;
        params.max_priority_peers = 2; // already at the priority cap
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconAttestation(5)], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        cap.0.clear();

        let mut attnets = [0u8; 8];
        attnets[0] = 0x20;
        let enr =
            test_enr_with(99, std::net::Ipv4Addr::new(10, 0, 0, 99), None, Some(attnets), None);
        mgr.handle_event(PeerEvent::DiscNodeFound { enr }, now, &mut |c| cap.0.push(c));

        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "priority dial must respect max_priority_peers cap, got {:?}",
            cap.0
        );
    }

    #[test]
    fn rpc_fatal_misbehaviour_evicts_on_tick() {
        let now = Instant::now();
        // Defaults: graylist_threshold = -80, Fatal delta = -200.
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        cap.0.clear();

        mgr.handle_event(
            PeerEvent::RpcMisbehaviour { p2p_peer: 1, severity: silver_common::RpcSeverity::Fatal },
            now,
            &mut |c| cap.0.push(c),
        );
        // Score is recomputed in tick — only then does the eviction fire.
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "Fatal severity must trigger eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none(), "evicted peer should be gone");
    }

    #[test]
    fn rpc_low_tolerance_penalises_but_keeps_peer() {
        let now = Instant::now();
        // Defaults: graylist_threshold = -80, Low delta = -10.
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        mgr.handle_event(
            PeerEvent::RpcMisbehaviour {
                p2p_peer: 1,
                severity: silver_common::RpcSeverity::LowTolerance,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        let s = mgr.score(1).expect("peer still alive after a single Low report");
        assert!(s < 0.0 && s > -80.0, "expected mild negative score in (-80, 0), got {s}");
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "single Low report must not evict, got {:?}",
            cap.0
        );
    }

    #[test]
    fn rpc_low_tolerance_accumulates_to_eviction() {
        let now = Instant::now();
        // Eight Low reports at -10 each = -80, exactly at graylist (strict <
        // check, so push to nine to trip).
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        for _ in 0..9 {
            mgr.handle_event(
                PeerEvent::RpcMisbehaviour {
                    p2p_peer: 1,
                    severity: silver_common::RpcSeverity::LowTolerance,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "9× Low reports should accumulate past graylist, got {:?}",
            cap.0
        );
    }

    #[test]
    fn decay_drives_honest_peer_to_zero() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_decay = 0.5;
        params.decay_to_zero = 0.01;
        let (mut mgr, mut cap) = fixture(vec![], params, false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
            cap.0.push(c)
        });

        for _ in 0..30 {
            now += Duration::from_secs(12);
            mgr.tick(now, &mut |c| cap.0.push(c));
        }
        let s = mgr.score(1).unwrap();
        assert!(s.abs() < 1e-6, "expected score ≈ 0 after decay, got {s}");
    }

    fn status_v2_ssz(
        fork_digest: [u8; 4],
        finalized_root: [u8; 32],
        finalized_epoch: u64,
        head_root: [u8; 32],
        head_slot: u64,
    ) -> [u8; silver_common::ssz_view::STATUS_V2_SIZE] {
        let mut b = [0u8; silver_common::ssz_view::STATUS_V2_SIZE];
        b[0..4].copy_from_slice(&fork_digest);
        b[4..36].copy_from_slice(&finalized_root);
        b[36..44].copy_from_slice(&finalized_epoch.to_le_bytes());
        b[44..76].copy_from_slice(&head_root);
        b[76..84].copy_from_slice(&head_slot.to_le_bytes());
        b
    }

    fn make_status_v2(
        fork_digest: [u8; 4],
        finalized_root: [u8; 32],
        finalized_epoch: u64,
        head_root: [u8; 32],
        head_slot: u64,
    ) -> PeerStatus {
        PeerStatus::V2(status_v2_ssz(
            fork_digest,
            finalized_root,
            finalized_epoch,
            head_root,
            head_slot,
        ))
    }

    fn fork_a() -> [u8; 4] {
        [0x01, 0x02, 0x03, 0x04]
    }
    fn fork_b() -> [u8; 4] {
        [0x05, 0x06, 0x07, 0x08]
    }

    fn send_status(mgr: &mut PeerManager, cap: &mut Captured, peer: usize, status: PeerStatus) {
        let now = Instant::now();
        mgr.handle_event(
            PeerEvent::P2pPeerStatus { p2p_peer: peer, status_ssz: status },
            now,
            &mut |c| cap.0.push(c),
        );
    }

    #[test]
    fn p2p_status_fork_digest_mismatch_evicts() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.set_fork_digest(fork_a());
        cap.0.clear();

        send_status(&mut mgr, &mut cap, 1, make_status_v2(fork_b(), [0u8; 32], 0, [0u8; 32], 0));
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "fork_digest mismatch must trigger Fatal eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none());
    }

    #[test]
    fn p2p_status_matching_fork_digest_keeps_peer_and_parses_db() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.set_fork_digest(fork_a());

        send_status(&mut mgr, &mut cap, 1, make_status_v2(fork_a(), [0u8; 32], 10, [0u8; 32], 320));
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(mgr.score(1).is_some(), "valid Status must not evict");
        let ssz = mgr.database.peer_status_bytes(1).expect("status present");
        assert_eq!(StatusView::fork_digest(ssz), &fork_a());
        assert_eq!(StatusView::finalized_epoch(ssz), 10);
        assert_eq!(StatusView::head_slot(ssz), 320);
    }

    #[test]
    fn p2p_status_divergent_finalized_root_evicts() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        set_local(&mut mgr, status_v2_ssz(fork_a(), [0xAA; 32], 42, [0xCC; 32], 42 * 32 + 5));
        cap.0.clear();

        // Same epoch, DIFFERENT finalized root → permanent fork divergence.
        send_status(
            &mut mgr,
            &mut cap,
            1,
            make_status_v2(fork_a(), [0xBB; 32], 42, [0xDD; 32], 42 * 32 + 5),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "divergent finalized root must trigger Fatal eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none());
    }

    #[test]
    fn p2p_status_same_finalized_root_accepted() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        set_local(&mut mgr, status_v2_ssz(fork_a(), [0xAA; 32], 42, [0xCC; 32], 42 * 32 + 5));

        send_status(
            &mut mgr,
            &mut cap,
            1,
            make_status_v2(fork_a(), [0xAA; 32], 42, [0xEE; 32], 42 * 32 + 9),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).is_some());
    }

    #[test]
    fn p2p_status_rejected_finalized_root_evicts() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        set_local(&mut mgr, status_v2_ssz(fork_a(), [0xAA; 32], 42, [0xCC; 32], 42 * 32 + 5));
        // Mark a competing finalized root as rejected. Any peer reporting
        // it must be evicted on next inbound Status.
        mgr.record_finalized_rejected([0xBB; 32]);
        cap.0.clear();

        // Peer is ahead in finality (so divergence rule doesn't fire), but
        // their finalized_root is the blacklisted one.
        send_status(
            &mut mgr,
            &mut cap,
            1,
            make_status_v2(fork_a(), [0xBB; 32], 50, [0xDD; 32], 50 * 32 + 1),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "blacklisted finalized_root must trigger Fatal eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none());
    }

    #[test]
    fn set_status_syncs_fork_digest() {
        // When BS publishes LocalStateUpdate, our_fork_digest moves in
        // lockstep so ENR-discovery filter and inbound Status check never
        // diverge.
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);

        set_local(&mut mgr, status_v2_ssz(fork_b(), [0; 32], 0, [0; 32], 0));
        send_status(&mut mgr, &mut cap, 1, make_status_v2(fork_b(), [0u8; 32], 0, [0u8; 32], 0));
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).is_some());
    }

    #[test]
    fn set_status_reports_fork_digest_change() {
        let (mut mgr, _cap) = fixture(vec![], ScoreParams::default(), false);
        // First set (None -> Some) is a change.
        assert!(mgr.set_status(status_v2_ssz(fork_a(), [0; 32], 0, [0; 32], 0)));
        // Same digest, other fields differ -> not a change (only the digest matters).
        assert!(!mgr.set_status(status_v2_ssz(fork_a(), [0; 32], 0, [1; 32], 5)));
        // Fork flip -> change (triggers subscription re-announce).
        assert!(mgr.set_status(status_v2_ssz(fork_b(), [0; 32], 0, [0; 32], 0)));
    }

    /// Set local status + imported tip together, as the controller does from a
    /// real Status event.
    fn set_local(mgr: &mut PeerManager, ssz: [u8; STATUS_V2_SIZE]) {
        mgr.set_local_head_imported(StatusView::head_slot(&ssz));
        mgr.set_status(ssz);
    }

    #[test]
    fn peer_data_columns_prioritization_and_slot_reservation() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);

        // Connect and identify Peer 1
        let kp1 = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr1 = Enr::builder().cgc(4).build(kp1.secret_key()).unwrap();
        mgr.database.add_enr(enr1);
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 1,
                peer_id_full: kp1.peer_id(),
                ip: IpBytes::V4([10, 0, 0, 1]),
                port: 4001,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        let mut identify1 = Identify::default();
        identify1.protocols |= 1 << StreamProtocol::DataColumnSidecarsByRoot.ordinal();
        mgr.handle_event(
            PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify: identify1 },
            now,
            &mut |c| cap.0.push(c),
        );

        // Connect and identify Peer 2
        let kp2 = Keypair::from_secret(&[2u8; 32]).unwrap();
        let enr2 = Enr::builder().cgc(4).build(kp2.secret_key()).unwrap();
        mgr.database.add_enr(enr2);
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 2,
                peer_id_full: kp2.peer_id(),
                ip: IpBytes::V4([10, 0, 0, 2]),
                port: 4002,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        let mut identify2 = Identify::default();
        identify2.protocols |= 1 << StreamProtocol::DataColumnSidecarsByRoot.ordinal();
        mgr.handle_event(
            PeerEvent::P2pPeerIdentity { p2p_peer: 2, identify: identify2 },
            now,
            &mut |c| cap.0.push(c),
        );

        let custody_mask1 = mgr.database.data_column_custody_groups_intersection(1, u128::MAX);
        let custody_mask2 = mgr.database.data_column_custody_groups_intersection(2, u128::MAX);
        assert!(custody_mask1 != 0);
        assert!(custody_mask2 != 0);

        let block_root = [0xAA; 32];

        // Peer-exclusive custody columns so a request can split cleanly: peer 1
        // covers `m1`, peer 2 covers `m2`, no overlap. A request for `m1 | m2`
        // sent while one peer is at capacity yields partial coverage: the
        // covered part is placed, while the unsent remainder is left for the
        // storage live/backfill wheels to retry.
        let m1 = custody_mask1 & !custody_mask2;
        let m2 = custody_mask2 & !custody_mask1;
        assert!(m1 != 0 && m2 != 0, "test needs peer-exclusive custody columns");
        let both = m1 | m2;
        let dcbr = StreamProtocol::DataColumnSidecarsByRoot.ordinal() as usize;

        // Per-peer caps: backfill = MAX_RPC_PROTOCOL_IN_FLIGHT / 2 = 1, live = 2.

        // 1) Backfill `m1` → peer 1 (sole custodian), filling its one backfill slot.
        mgr.handle_event(
            PeerEvent::SendDataColumnsByRootRequest {
                request_id: COLUMN_BACKFILL_REQUEST_ID | 1,
                columns: m1,
                block_root,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.peers.get(&1).unwrap().outbound_in_flight[dcbr], 1);
        assert_eq!(mgr.peers.get(&2).unwrap().outbound_in_flight[dcbr], 0);

        // 2) Backfill `both`: peer 1 is at its backfill cap, so only peer 2's `m2` is
        //    placed; peer 1's `m1` can't be sent and — being backfill — is dropped, not
        //    queued (the storage ColumnBackfill wheel re-emits it).
        mgr.handle_event(
            PeerEvent::SendDataColumnsByRootRequest {
                request_id: COLUMN_BACKFILL_REQUEST_ID | 2,
                columns: both,
                block_root,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.peers.get(&1).unwrap().outbound_in_flight[dcbr], 1);
        assert_eq!(mgr.peers.get(&2).unwrap().outbound_in_flight[dcbr], 1);

        // 3) Live `m1` → peer 1: backfill used 1 of its 2 live slots, so this fits.
        mgr.handle_event(
            PeerEvent::SendDataColumnsByRootRequest {
                request_id: BASE_REQUEST_ID | 3,
                columns: m1,
                block_root,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.peers.get(&1).unwrap().outbound_in_flight[dcbr], 2);

        // 4) Live `both`: peer 1 is at its live cap (2), so peer 2 takes `m2` and `m1`
        //    is left for storage's live wheel to retry.
        mgr.handle_event(
            PeerEvent::SendDataColumnsByRootRequest {
                request_id: BASE_REQUEST_ID | 4,
                columns: both,
                block_root,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.peers.get(&1).unwrap().outbound_in_flight[dcbr], 2);
        assert_eq!(mgr.peers.get(&2).unwrap().outbound_in_flight[dcbr], 2);
    }

    #[test]
    fn block_backfill_range_attempt_is_tracked_until_complete() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        let mut identify = Identify::default();
        identify.protocols |= 1 << StreamProtocol::BeaconBlocksByRange.ordinal();
        mgr.handle_event(PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify }, now, &mut |c| {
            cap.0.push(c)
        });

        let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        ssz[0..8].copy_from_slice(&20u64.to_le_bytes());
        ssz[8..16].copy_from_slice(&3u64.to_le_bytes());
        ssz[16..24].copy_from_slice(&1u64.to_le_bytes());
        mgr.handle_event(
            PeerEvent::SendRpcRequest {
                request_id: BACKFILL_REQUEST_ID | 7,
                rpc: RpcRequest::BlocksByRange(ssz),
            },
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(mgr.pending_range_requests.is_empty());
        assert_eq!(mgr.outbound_range_attempts.len(), 1);
        assert_eq!(mgr.outbound_range_attempts[0].request_id, BACKFILL_REQUEST_ID | 7);

        mgr.on_rpc_inbound(
            RpcInbound::Response(RpcResponseInbound {
                application_id: BACKFILL_REQUEST_ID | 7,
                stream_id: P2pStreamId::new(1, 11, StreamProtocol::BeaconBlocksByRange, false),
                response: RpcResponse::Complete,
            }),
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(mgr.outbound_range_attempts.is_empty());
    }

    #[test]
    fn block_backfill_range_error_is_retried_by_peer_manager() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        let mut identify = Identify::default();
        identify.protocols |= 1 << StreamProtocol::BeaconBlocksByRange.ordinal();
        mgr.handle_event(PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify }, now, &mut |c| {
            cap.0.push(c)
        });

        let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        ssz[0..8].copy_from_slice(&20u64.to_le_bytes());
        ssz[8..16].copy_from_slice(&3u64.to_le_bytes());
        ssz[16..24].copy_from_slice(&1u64.to_le_bytes());
        mgr.handle_event(
            PeerEvent::SendRpcRequest {
                request_id: BACKFILL_REQUEST_ID | 8,
                rpc: RpcRequest::BlocksByRange(ssz),
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.outbound_range_attempts.len(), 1);

        mgr.on_rpc_inbound(
            RpcInbound::Response(RpcResponseInbound {
                application_id: BACKFILL_REQUEST_ID | 8,
                stream_id: P2pStreamId::new(1, 12, StreamProtocol::BeaconBlocksByRange, false),
                response: RpcResponse::Error { error: 2, msg: [0; 256], len: 0 },
            }),
            now,
            &mut |c| cap.0.push(c),
        );

        assert!(mgr.outbound_range_attempts.is_empty());
        assert_eq!(mgr.pending_range_requests.len(), 1);
        let req = mgr.pending_range_requests.front().copied().unwrap();
        let RangeReqKind::Blocks { step } = req.kind else {
            panic!("expected pending BlocksByRange retry");
        };
        assert_eq!(req.request_id, BACKFILL_REQUEST_ID | 8);
        assert_eq!((req.start_slot, req.count, step), (20, 3, 1));
    }

    #[test]
    fn block_backfill_range_timeout_is_retried_by_peer_manager() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default(), false);
        connect(&mut mgr, &mut cap, 1, 1, now);
        let mut identify = Identify::default();
        identify.protocols |= 1 << StreamProtocol::BeaconBlocksByRange.ordinal();
        mgr.handle_event(PeerEvent::P2pPeerIdentity { p2p_peer: 1, identify }, now, &mut |c| {
            cap.0.push(c)
        });

        let mut ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
        ssz[0..8].copy_from_slice(&30u64.to_le_bytes());
        ssz[8..16].copy_from_slice(&2u64.to_le_bytes());
        ssz[16..24].copy_from_slice(&1u64.to_le_bytes());
        mgr.handle_event(
            PeerEvent::SendRpcRequest {
                request_id: BACKFILL_REQUEST_ID | 9,
                rpc: RpcRequest::BlocksByRange(ssz),
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.outbound_range_attempts.len(), 1);

        let later = now +
            Duration::from_millis(mgr.syncing.inflight_progress_timeout_ms) +
            Duration::from_millis(1);
        mgr.tick(later, &mut |c| cap.0.push(c));

        assert!(mgr.outbound_range_attempts.is_empty());
        assert_eq!(
            mgr.peers.get(&1).unwrap().outbound_in_flight
                [StreamProtocol::BeaconBlocksByRange.ordinal() as usize],
            0
        );
        assert_eq!(mgr.pending_range_requests.len(), 1);
        let req = mgr.pending_range_requests.front().copied().unwrap();
        let RangeReqKind::Blocks { step } = req.kind else {
            panic!("expected pending BlocksByRange retry");
        };
        assert_eq!(req.request_id, BACKFILL_REQUEST_ID | 9);
        assert_eq!((req.start_slot, req.count, step), (30, 2, 1));
    }
}
