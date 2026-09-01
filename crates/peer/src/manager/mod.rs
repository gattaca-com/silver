//! Peer manager: consumes `PeerEvent`, maintains per-peer state + scoring,
//! emits `PeerControl`. Counters-only on the hot path; all score math +
//! mesh decisions live in `tick`.

use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

use silver_common::{
    AgentString, Enr, GossipTopic, PeerControl, PeerEvent, PeerId, RpcSeverity, StreamProtocol,
    SyncUpdate,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE},
};
use silver_config::{ScoreParams, SyncingConfig};

use crate::{
    database::{PeerDatabase, PeerRecord},
    scoring,
    state::{ArchivedState, IpPrefix, MsgIdMap, PeerState},
};

pub(crate) mod admission;
pub(crate) mod attempts;
pub(crate) mod peers;
pub(crate) mod promises;
pub(crate) mod rpc;
pub(crate) mod sync;

pub use sync::RejectedRoots;

/// Initial capacity hints — chosen so normal steady-state activity doesn't
/// rehash. Undersizing is fine correctness-wise; this is a perf nudge.
const PEERS_CAP: usize = 256;

const IP_COLOC_CAP: usize = 128;

const ARCHIVE_CAP: usize = 512;

const DIAL_FAILURE_BACKOFF: Duration = Duration::from_secs(3600);

/// Disconnect reason for a QUIC-level close with no Goodbye received.
const TRANSPORT_DISCONNECT: &str = "transport";

const SHORT_LIVED_CONNECTION: Duration = Duration::from_secs(30);

const SHORT_LIVED_DIAL_BACKOFF: Duration = Duration::from_secs(15 * 60);

/// Goodbye reason shared with lighthouse/prysm: routine excess-peer shed,
/// and the remote is expected back.
const GOODBYE_TOO_MANY_PEERS: u64 = 129;
/// Deadweight shed: at most this many idle peers per tick, collected during
/// the rescore pass so no extra walk of the population is needed.
const MAX_IDLE_GOODBYES: usize = 32;
/// A connection has to be around this long before "no mesh, no score" reads
/// as deadweight rather than a peer we simply haven't grafted yet.
const IDLE_PEER_MIN_AGE: Duration = Duration::from_secs(30 * 60);
/// Scores at or below this value are indistinguishable from idle noise.
const IDLE_PEER_MAX_SCORE: f64 = 0.1;

pub struct PeerManager {
    local_peer_id: PeerId,

    /// Live peers keyed by connection handle.
    peers: HashMap<usize, PeerState>,

    /// Live-connection index: `PeerId` → connection handle. Mirrors `peers`
    /// exactly (unlike the database's `by_peer_id`, which maps to persistent
    /// records that outlive the connection).
    peers_by_id: HashMap<PeerId, usize>,

    /// In-progress dials, mapping PeerId to when the dial was initiated.
    dialing: HashMap<PeerId, Instant>,

    /// Counters persisted across reconnect by PeerId. GC'd on tick.
    archived: HashMap<PeerId, ArchivedState>,

    /// IP colocation index for P6. Prefix → list of live connection handles.
    ip_colocations: HashMap<IpPrefix, Vec<usize>>,

    /// Topics we subscribe to ourselves. Drives SUBSCRIBE emission on new
    /// peers and mesh-management decisions.
    our_topics: Vec<GossipTopic>,

    /// Our mesh per topic: connections we've grafted onto. May exceed d_high
    /// between heartbeats; trimmed back to d by `ensure_mesh_capped`.
    mesh: HashMap<GossipTopic, Vec<usize>>,

    /// Outstanding IHAVE→IWANT promises, keyed by `MessageId`. Each entry
    /// holds every (conn, deadline) that has promised that id. Any one
    /// peer's delivery via `PeerEvent::NewGossip` clears the entry for all
    /// of them — broken-promise penalty only applies if the message never
    /// arrives from anyone by `iwant_followup`.
    promises: MsgIdMap<Vec<(usize, Instant)>>,

    recent_deliveries: MsgIdMap<promises::RecentDelivery>,

    /// Our current fork digest, set by the consumer at startup and rotated
    /// across hard-fork boundaries. `None` disables the fork-digest filter
    /// on `DiscNodeFound` (useful for tests; production should always set
    /// it). Compared against the leading 4 bytes of an ENR's `eth2` field.
    our_fork_digest: Option<[u8; 4]>,

    /// The digest we advertised before the last fork.
    previous_fork_digest: Option<[u8; 4]>,

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
    /// Subnets whose mesh was still short of `d` after the last sweep —
    /// i.e. we ran out of connected subscribers, not out of graft slots.
    /// Same bit layout as `required_*`; peers covering one of these dial
    /// past the ordinary caps.
    deficit_attnets: [u8; 8],
    deficit_syncnets: u8,
    deficit_columns: u128,

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

    /// Dial backoff from a received Goodbye, keyed to the expiry instant;
    /// tier per code via `goodbye_dial_backoff`. Their inbound stays welcome.
    remote_banned_peers: HashMap<PeerId, Instant>,

    params: ScoreParams,

    /// Last heartbeat rollover time. When `now - last_heartbeat >=
    /// heartbeat_interval`, per-heartbeat counters reset + mesh revised.
    last_heartbeat: Instant,

    last_opportunistic_graft: Instant,

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
    /// syncing `BlocksByRange`.
    pub(crate) custody_columns: u128,

    /// Slot of the highest block BS has imported (`last_applied`), from the
    /// `latest_block_slot` on the Status event. Used by the data-column peer
    /// picker (`best_peer_for_data_columns`) for earliest-available gating.
    pub(crate) local_head_imported_slot: u64,

    pub(crate) outbound_attempts: Vec<attempts::OutboundAttempt>,
    /// `(request_id, peer, delivered)` per *logical* request that has ended —
    /// drained by the control tile into the sync engine.
    pub(crate) finished_requests: Vec<(u64, usize, bool)>,
    /// Peers already served from during one column fan-out.
    column_fanout_tried: Vec<usize>,
}

impl PeerManager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_peer_id: PeerId,
        mut trusted_peers: Vec<Enr>,
        our_topics: Vec<GossipTopic>,
        params: ScoreParams,
        syncing: SyncingConfig,
        fork_digest: [u8; 4],
        metadata: [u8; METADATA_SIZE],
        custody_columns: u128,
    ) -> Self {
        let now = Instant::now();
        let mesh =
            our_topics.iter().map(|t| (*t, Vec::with_capacity(params.d_high as usize))).collect();
        let (required_attnets, required_syncnets) = build_subnet_masks(&our_topics);
        let rejected = RejectedRoots::new(syncing.rejected_cap);

        let mut database = PeerDatabase::default();
        trusted_peers.drain(..).for_each(|enr| {
            tracing::info!(quic=?enr.quic4_socket(), "adding trusted peer");
            database.add_trusted_peer(enr);
        });

        Self {
            peers: HashMap::with_capacity(PEERS_CAP),
            peers_by_id: HashMap::with_capacity(PEERS_CAP),
            dialing: HashMap::with_capacity(64),
            archived: HashMap::with_capacity(ARCHIVE_CAP),
            ip_colocations: HashMap::with_capacity(IP_COLOC_CAP),
            local_peer_id,
            our_topics,
            mesh,
            promises: MsgIdMap::with_capacity_and_hasher(4096, Default::default()),
            recent_deliveries: MsgIdMap::with_capacity_and_hasher(4096, Default::default()),
            banned_ips: HashMap::with_capacity(64),
            ip_eviction_counts: HashMap::with_capacity(64),
            banned_peers: HashMap::with_capacity(128),
            remote_banned_peers: HashMap::with_capacity(128),
            our_fork_digest: Some(fork_digest),
            previous_fork_digest: None,
            rejected,
            syncing,
            current_target: SyncUpdate::Following,
            required_attnets,
            required_syncnets,
            deficit_attnets: [0u8; 8],
            deficit_syncnets: 0,
            deficit_columns: 0,
            params,
            last_heartbeat: now,
            last_opportunistic_graft: now,
            last_decay: now,
            last_discovery: now,
            database,
            status: None,
            metadata,
            earliest_available_slot: u64::MAX,
            custody_columns,
            local_head_imported_slot: 0,
            outbound_attempts: Vec::with_capacity(PEERS_CAP),
            finished_requests: Vec::with_capacity(PEERS_CAP),
            column_fanout_tried: Vec::with_capacity(PEERS_CAP),
        }
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

    pub fn handle_event(
        &mut self,
        event: PeerEvent,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        match event {
            PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, ip, port, local_dial } => {
                self.on_connected(p2p_peer_id, peer_id_full, ip, port, now, emit, local_dial);
            }
            PeerEvent::P2pDisconnect { p2p_peer, peer_id } => {
                let was_dialing = self.dialing.remove(&peer_id).is_some();
                let was_connected =
                    self.on_disconnected(p2p_peer, now, TRANSPORT_DISCONNECT, emit).is_some();
                // Dial died pre-handshake (zombie): the sweep won't see the
                // removed `dialing` entry, so arm the failure backoff here.
                if was_dialing && !was_connected {
                    self.database.dial_failed(&peer_id, now + DIAL_FAILURE_BACKOFF);
                }
            }
            PeerEvent::P2pCannotCreateStream { p2p_peer, protocol, rpc_request, stream_gone } => {
                if rpc_request {
                    self.release_outbound_in_flight(p2p_peer, protocol);
                }
                if stream_gone {
                    // Their teardown raced our (possibly late) response —
                    // not peer misbehaviour. Counted, not penalised.
                    crate::PeerCounters::ResponseStreamGone.inc();
                } else {
                    crate::PeerCounters::StreamCreditExhausted.inc();
                    self.add_behaviour_penalty(p2p_peer, 1.0, "stream credit exhausted");
                }
                self.disconnect_after_failed_goodbye(p2p_peer, protocol, emit);
            }
            PeerEvent::P2pOutboundMessageDropped { p2p_peer, protocol, rpc_request } => {
                // Local outbound-ring overflow — a backpressure signal, often
                // ours (blocked socket), not peer misbehaviour. No P7: a
                // stalled connection drops in bursts and the squared penalty
                // would graylist the whole mesh on a local uplink stall.
                if rpc_request {
                    self.release_outbound_in_flight(p2p_peer, protocol);
                }
                tracing::debug!(p2p_peer, ?protocol, rpc_request, "outbound message dropped");
                self.disconnect_after_failed_goodbye(p2p_peer, protocol, emit);
            }
            PeerEvent::P2pStreamClosed { stream_id } => {
                // Premature close on an outgoing request-response stream —
                // the peer FIN'd or RST'd before the response terminator
                // (`Complete`/`Error`) was observed. `MidTolerance`
                // accumulates a signal without fast-banning over a
                // single flaky session. Gossip / identity streams don't
                // have the same completion model — no penalty. `Unset`
                // means multistream-select hadn't negotiated yet, also
                // skipped (the close there is a protocol-negotiation
                // failure, distinct from a premature RPC termination).
                // Incoming closes are exempt: that's the requester's
                // read-timeout giving up on our slow response — penalising
                // it blames the wrong side.
                let protocol = stream_id.protocol();
                if protocol.is_request_response() && protocol != StreamProtocol::Unset {
                    tracing::warn!(
                        ?protocol,
                        incoming = stream_id.is_incoming(),
                        "stream close misbehaviour"
                    );
                    if !stream_id.is_incoming() {
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
                        if let Some(peer) = self.peers.get_mut(&stream_id.peer()) {
                            peer.outbound_in_flight[protocol.ordinal() as usize] = peer
                                .outbound_in_flight[protocol.ordinal() as usize]
                                .saturating_sub(1);
                        }
                        self.fail_attempt_on_stream_close(stream_id.peer(), protocol);
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
            PeerEvent::P2pGossipTopicPrune { p2p_peer, topic, backoff_seconds } => {
                self.on_remote_prune(p2p_peer, topic, now, backoff_seconds, emit);
            }
            PeerEvent::P2pGossipHave { p2p_peer, topic: _, hash, already_seen } => {
                self.on_ihave(p2p_peer, hash, already_seen, now);
            }
            PeerEvent::GossipDuplicate { p2p_peer, topic, hash, recv_ts } => {
                self.on_gossip_duplicate(p2p_peer, topic, hash, recv_ts);
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
            PeerEvent::DiscNodeFound { enr, reload: _ } => {
                self.on_disc_node_found(enr, now, emit);
            }
            PeerEvent::DiscExternalAddress { address: _, seq } => {
                // update metadata seq number so that it matches ENR
                self.metadata[..8].copy_from_slice(&seq.to_le_bytes());
            }
            PeerEvent::NewGossip { p2p_peer, topic, msg_hash, recv_ts, idontwant } => {
                self.on_new_gossip(p2p_peer, topic, msg_hash, recv_ts, idontwant, emit);
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
            PeerEvent::RpcServeOutcome {
                p2p_peer,
                protocol,
                units_total,
                units_sent,
                missing,
                first_chunk_ms,
                elapsed_ms,
            } => {
                let user_agent =
                    self.peers.get(&p2p_peer).map(|p| p.user_agent).unwrap_or_default();
                tracing::info!(
                    p2p_peer,
                    ?protocol,
                    units_total,
                    units_sent,
                    missing,
                    first_chunk_ms,
                    elapsed_ms,
                    user_agent = user_agent.as_str(),
                    "rpc serve outcome"
                );
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
                if let Some(peer) = self.peers.get_mut(&p2p_peer) {
                    peer.user_agent = AgentString::new(identify.user_agent());
                }
                self.database.add_p2p_identify(p2p_peer, identify)
            }
            PeerEvent::EarliestSlot(slot) => {
                self.earliest_available_slot = slot;
            }
        }
    }

    /// The periodic sweep: gauges, scoring decay, redials, stalled attempts.
    /// Off the per-event path, so walking every peer is affordable here.
    pub fn tick(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        // Mesh-size gauges refreshed here rather than at each mutation site —
        // mesh entries persist (empty vecs stay), so this is exact.
        for (topic, mesh_peers) in &self.mesh {
            crate::counters::GossipTopicCounters::mesh(*topic, mesh_peers.len());
        }
        // 1) Heartbeat rollover: reset per-heartbeat counters, sweep broken promises.
        if now.saturating_duration_since(self.last_heartbeat) >= self.params.heartbeat_interval {
            self.heartbeat(now);
            self.last_heartbeat = now;
        }

        // 2) Decay all counters — gated to `score_decay_interval` (one slot), the
        //    cadence the `*_decay` constants are calibrated for.
        if now.saturating_duration_since(self.last_decay) >= self.params.score_decay_interval {
            for p in self.peers.values_mut() {
                scoring::decay(p, &self.params);
            }
            self.last_decay = now;
        }

        // 3) One walk of the population doing everything that needs a per-peer (and
        //    per-topic) visit: the subscriber census, the score recompute — which also
        //    flips P3 activation, see `scoring::score_breakdown` — and collection of
        //    deadweight to shed. Peers announce SUBSCRIBE for all their subnets; only
        //    count subscribers on topics we participate in ourselves.
        let mut ours = [false; silver_common::GOSSIP_TOPIC_COUNTER_SLOTS];
        for topic in &self.our_topics {
            ours[topic.counter_slot()] = true;
        }
        let mut subs = [0u16; silver_common::GOSSIP_TOPIC_COUNTER_SLOTS];
        let peers_by_prefix: HashMap<IpPrefix, usize> =
            self.ip_colocations.iter().map(|(k, v)| (*k, v.len())).collect();

        let mut idle = [0usize; MAX_IDLE_GOODBYES];
        let mut idle_len = 0;
        let mut negative = [(0usize, 0.0f64); 256];
        let mut negative_len = 0;
        let mut pending_goodbyes = 0;

        for (&conn, peer) in self.peers.iter_mut() {
            for topic in &peer.topics {
                let slot = topic.counter_slot();
                if ours[slot] {
                    subs[slot] = subs[slot].saturating_add(1);
                }
            }

            let coloc = *peers_by_prefix.get(&peer.ip_prefix).unwrap_or(&1);
            peer.last_breakdown = scoring::score_breakdown(peer, &self.params, coloc, now);
            peer.cached_score = peer.last_breakdown.total;
            peer.score_valid_at = now;

            // Deadweight: long-connected, in no mesh, nothing scored either
            // way — it has had every chance to be grafted. Negative scorers
            // are `manage_peers`' business.
            if peer.goodbye_sent {
                pending_goodbyes += 1;
                continue;
            }
            if !peer.is_trusted && peer.cached_score < 0.0 && negative_len < negative.len() {
                negative[negative_len] = (conn, peer.cached_score);
                negative_len += 1;
            } else if !peer.is_trusted &&
                peer.cached_score <= IDLE_PEER_MAX_SCORE &&
                idle_len < idle.len() &&
                now.saturating_duration_since(peer.connected_at) > IDLE_PEER_MIN_AGE &&
                peer.topic_stats.values().all(|s| s.meshed_since.is_none())
            {
                idle[idle_len] = conn;
                idle_len += 1;
            }
        }
        crate::counters::GossipTopicCounters::subscribed(&subs);

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

        self.sweep_stalled_attempts(now);

        // 9) Prune stale dials (older than 15 seconds); an entry expiring here means
        //    the dial failed or timed out (successful connects leave `dialing` in
        //    `on_connected`) — back the peer off.
        let database = &mut self.database;
        self.dialing.retain(|peer_id, &mut time| {
            if now.saturating_duration_since(time) < std::time::Duration::from_secs(15) {
                true
            } else {
                database.dial_failed(peer_id, now + DIAL_FAILURE_BACKOFF);
                false
            }
        });

        // 10) manage over population
        self.manage_peers(now, negative, negative_len, idle, idle_len, pending_goodbyes, emit);

        crate::PeerCounters::PeersConnected.set(self.peers.len() as u64);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────
}

/// Build SSZ Bitvector[64] / Bitvector[N≤8] masks from `our_topics`. Each
/// `BeaconAttestation(N)` flips bit N in the 64-bit attnet mask; each
/// `SyncCommittee(N)` flips bit N in the syncnet byte. Computed at
/// construction and recomputed by `activate_topics`.
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

/// Shared test harness for the `manager` submodules: a manager wired to
/// defaults, the `PeerControl` sink every handler emits into, and the two
/// events (`connect`, local status) that most tests open with.
#[cfg(test)]
pub(crate) mod fixture {
    use silver_common::{IpBytes, Keypair, PeerStatus, ssz_view::StatusView};

    use super::*;

    /// Owns the captured `PeerControl` stream for a test. Tests push into
    /// `cap.0` via an ad-hoc `|c| cap.0.push(c)` closure passed to
    /// `handle_event`/`tick`.
    #[derive(Default)]
    pub(crate) struct Captured(pub(crate) Vec<PeerControl>);

    pub(crate) fn fixture(
        our_topics: Vec<GossipTopic>,
        params: ScoreParams,
    ) -> (PeerManager, Captured) {
        (
            PeerManager::new(
                peer_id(99),
                vec![],
                our_topics,
                params,
                SyncingConfig::default(),
                [0u8; 4],
                [0u8; METADATA_SIZE],
                0,
            ),
            Captured::default(),
        )
    }

    pub(crate) fn peer_id(seed: u8) -> PeerId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 1;
        Keypair::from_secret(&bytes).unwrap().peer_id()
    }

    pub(crate) fn connect(
        mgr: &mut PeerManager,
        cap: &mut Captured,
        conn: usize,
        seed: u8,
        now: Instant,
    ) {
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

    pub(crate) fn status_v2_ssz(
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

    pub(crate) fn make_status_v2(
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

    pub(crate) fn send_status(
        mgr: &mut PeerManager,
        cap: &mut Captured,
        peer: usize,
        status: PeerStatus,
    ) {
        let now = Instant::now();
        mgr.handle_event(
            PeerEvent::P2pPeerStatus { p2p_peer: peer, status_ssz: status },
            now,
            &mut |c| cap.0.push(c),
        );
    }

    /// Set local status + imported tip together, as the controller does from a
    /// real Status event.
    pub(crate) fn set_local(mgr: &mut PeerManager, ssz: [u8; STATUS_V2_SIZE]) {
        mgr.set_local_head_imported(StatusView::head_slot(&ssz));
        mgr.set_status(ssz);
    }
}
