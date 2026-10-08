//! Per-peer state: identity, subscriptions, and scoring counters. All heap
//! allocations are one-shot at construction.
//!
//! IHAVE→IWANT promise tracking lives in the manager, keyed by `MessageId`
//! globally — one message arrival fulfils every promise for that id
//! regardless of which peer delivered it.

use std::{
    collections::HashMap,
    hash::BuildHasherDefault,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Instant,
};

use fxhash::FxHashMap;
use silver_common::{
    AgentString, CountingWitherFilter, GossipTopic, MessageId, MessageIdHasher, PeerId, PeerScores,
    StreamProtocol,
    rpc_rate_limit::{N_STREAM_PROTOCOLS, RpcRateLimit, RpcRateLimitSet},
};

use crate::scoring::ScoreBreakdown;

/// Initial capacity hint; peers with larger custody sets may grow beyond it.
pub(crate) const TOPICS_PER_PEER_CAP: usize = 96;

pub(crate) type MsgIdBuild = BuildHasherDefault<MessageIdHasher>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PartialCapabilities {
    pub requests: bool,
    pub supports_sending: bool,
}

/// One live peer's state.
pub(crate) struct PeerState {
    // Identity — `PeerId` + connection handle are both needed to emit any
    // `PeerControl` targeting this peer.
    pub peer_id: PeerId,
    pub addr: SocketAddr,
    pub ip_prefix: IpPrefix,
    pub connected_at: Instant,
    pub local_dialler: bool,
    // From the identify exchange; default-empty until it completes.
    pub user_agent: AgentString,

    // Subscriptions observed from the peer's SUBSCRIBE frames.
    pub subscriptions: FxHashMap<([u8; 4], GossipTopic), PartialCapabilities>,

    // Stream-wide gossipsub 1.3 extension announcement.
    pub partial_extensions: bool,

    // Per-topic scoring. Sparse — entry created on first meshed activity.
    pub topic_stats: FxHashMap<GossipTopic, TopicScore>,

    // WANT/ DONTWANT message id cache. For mesh peers this cache contains DONTWANT msg ids
    // and for non-mesh peers it tracks WANT requests.
    // This filter may return false negatives which will have the effect of:
    // - replying to an IWANT in excess of retransmission limit (non-mesh)
    // - broadcasting a gossip message for which we had IDNOTWANT
    // Note that this struct is NOT cleared or rotated. This means message ids may persist
    // longer than specced timeouts (4.2s for IWANT limits and 3s for IDONTWANT) - but would
    // argue that this is irrelevent - msg ids naturally age out.
    pub msg_cache: CountingWitherFilter<MessageId, MessageIdHasher, 4096>,

    // Global score components.
    pub application_score: f64, // P5
    pub behaviour_penalty: f64, // P7, quadratic over threshold

    // Per-heartbeat rate-limit counters; reset every `heartbeat_interval`.
    pub ihaves_received: u16, // caps IWANT issuance via max_ihave_length
    pub iwant_ids_sent: u16,  // caps the per-heartbeat IWANT budget

    // Outbound protocol rate-limit state.
    pub outbound_rpc_limits: RpcRateLimitSet,

    // Outbound requests in flight count per protocol
    pub outbound_in_flight: [u32; N_STREAM_PROTOCOLS],

    // Prune backoff deadlines per topic
    pub backoffs: FxHashMap<GossipTopic, Instant>,

    // Backoff deadlines we sent this peer in our PRUNEs. Only a GRAFT before
    // one of these breaks the protocol; `backoffs` also holds our own,
    // escalated waits after the peer pruned us.
    pub advertised_backoffs: FxHashMap<GossipTopic, Instant>,

    // Cached score value + recomputation timestamp. `last_breakdown.total ==
    // cached_score`; both refreshed together by `rescore_all` so decisions
    // and the emitted `PeerScores` read the same numbers.
    pub cached_score: f64,
    pub score_valid_at: Instant,
    pub last_breakdown: ScoreBreakdown,
    /// TooManyPeers goodbye emitted; the connection is on its way down —
    /// keeps `manage_peers` from re-selecting it while the flush + shutdown
    /// completes.
    pub goodbye_sent: bool,

    // Graylisted but kept for data-column coverage; dedups the spare log.
    pub evict_spared: bool,
    /// Whether peer is trusted.
    pub is_trusted: bool,
}

impl Default for PeerState {
    fn default() -> Self {
        let now = Instant::now();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        Self {
            peer_id: PeerId::default(),
            addr,
            ip_prefix: IpPrefix::from(addr.ip()),
            connected_at: now,
            local_dialler: false,
            user_agent: AgentString::default(),
            subscriptions: FxHashMap::with_capacity_and_hasher(
                TOPICS_PER_PEER_CAP * 2,
                Default::default(),
            ),
            partial_extensions: false,
            topic_stats: FxHashMap::with_capacity_and_hasher(
                TOPICS_PER_PEER_CAP,
                Default::default(),
            ),
            msg_cache: CountingWitherFilter::default(),
            application_score: 0.0,
            behaviour_penalty: 0.0,
            ihaves_received: 0,
            iwant_ids_sent: 0,
            outbound_rpc_limits: RpcRateLimitSet::default(),
            outbound_in_flight: [0; N_STREAM_PROTOCOLS],
            backoffs: FxHashMap::default(),
            advertised_backoffs: FxHashMap::default(),
            cached_score: 0.0,
            score_valid_at: now,
            last_breakdown: ScoreBreakdown::default(),
            goodbye_sent: false,
            evict_spared: false,
            is_trusted: false,
        }
    }
}

impl PeerState {
    /// Readies a recycled slot for a new connection.
    pub fn connect(&mut self, peer_id: PeerId, addr: SocketAddr, now: Instant) {
        self.clear();
        self.peer_id = peer_id;
        self.addr = addr;
        self.ip_prefix = IpPrefix::from(addr.ip());
        self.connected_at = now;
        self.score_valid_at = now;
    }

    /// Defaults every field, keeping map capacity. `msg_cache` is kept as is:
    /// a previous connection's ids age out like any other.
    fn clear(&mut self) {
        let Self {
            peer_id,
            addr,
            ip_prefix,
            connected_at: _,
            local_dialler,
            user_agent,
            subscriptions,
            partial_extensions,
            topic_stats,
            msg_cache: _,
            application_score,
            behaviour_penalty,
            ihaves_received,
            iwant_ids_sent,
            outbound_rpc_limits,
            outbound_in_flight,
            backoffs,
            advertised_backoffs,
            cached_score,
            score_valid_at: _,
            last_breakdown,
            goodbye_sent,
            evict_spared,
            is_trusted,
        } = self;
        *peer_id = PeerId::default();
        *addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        *ip_prefix = IpPrefix::from(addr.ip());
        *local_dialler = false;
        *user_agent = AgentString::default();
        subscriptions.clear();
        *partial_extensions = false;
        topic_stats.clear();
        *application_score = 0.0;
        *behaviour_penalty = 0.0;
        *ihaves_received = 0;
        *iwant_ids_sent = 0;
        *outbound_rpc_limits = RpcRateLimitSet::default();
        *outbound_in_flight = [0; N_STREAM_PROTOCOLS];
        backoffs.clear();
        advertised_backoffs.clear();
        *cached_score = 0.0;
        *last_breakdown = ScoreBreakdown::default();
        *goodbye_sent = false;
        *evict_spared = false;
        *is_trusted = false;
    }

    /// The breakdown as of the last rescore.
    pub(crate) fn scores(&self, mesh_count: u32) -> PeerScores {
        let b = self.last_breakdown;
        PeerScores {
            id: self.peer_id,
            user_agent: self.user_agent,
            mesh_count,
            p1_time_in_mesh: b.p1_time_in_mesh,
            p2_first_deliveries: b.p2_first_deliveries,
            p3_mesh_deficit: b.p3_mesh_deficit,
            p3b_mesh_failure: b.p3b_mesh_failure,
            p4_invalid: b.p4_invalid,
            p5_application: b.p5_application,
            p6_ip_colocation: b.p6_ip_colocation,
            p7_behaviour: b.p7_behaviour,
            total: b.total,
        }
    }

    pub(crate) fn outbound_has_capacity(
        &self,
        conn: usize,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
        max_in_flight: u32,
    ) -> bool {
        if self.outbound_in_flight[protocol.ordinal() as usize] >= max_in_flight {
            return false;
        }
        match self.outbound_rpc_limits.peek_outbound(protocol, tokens, now) {
            RpcRateLimit::Allowed => true,
            denied => {
                silver_log::debug!(
                    peer = conn,
                    ?protocol,
                    tokens,
                    ?denied,
                    "outbound rpc request rate limited"
                );
                false
            }
        }
    }

    pub(crate) fn try_admit_outbound(
        &mut self,
        conn: usize,
        protocol: StreamProtocol,
        tokens: u64,
        now: Instant,
        claim_in_flight: bool,
    ) -> bool {
        match self.outbound_rpc_limits.admit_outbound(protocol, tokens, now) {
            RpcRateLimit::Allowed => {
                if claim_in_flight {
                    self.outbound_in_flight[protocol.ordinal() as usize] += 1;
                }
                true
            }
            denied => {
                silver_log::debug!(
                    peer = conn,
                    ?protocol,
                    tokens,
                    ?denied,
                    "outbound rpc rate limited"
                );
                false
            }
        }
    }

    /// Restore counters from a previously-archived entry. Identity/address
    /// fields are NOT touched — they come from the fresh connection.
    pub fn restore_from_archive(&mut self, archive: ArchivedState) {
        self.application_score = archive.application_score;
        self.behaviour_penalty = archive.behaviour_penalty;
        self.topic_stats.extend(archive.topic_stats);
        for t in self.topic_stats.values_mut() {
            t.fanout_total = 0;
            t.fanout_sent = 0;
        }
    }

    /// Inserts or updates msg cache entry, returning previous count
    /// Score for gossip-domain gates (`gossip_threshold` comparisons):
    /// excludes P5 — an RPC-domain penalty must not silence our gossip
    /// toward the peer, which starves their P3 view of us and gets us
    /// pruned/disconnected in return. Gossip-domain offences (P4, P7)
    /// still count.
    pub fn gossip_gate_score(&self) -> f64 {
        self.cached_score - self.last_breakdown.p5_application
    }

    pub fn msg_cache_insert(&mut self, msg_id: MessageId) -> u32 {
        self.msg_cache.upsert(msg_id)
    }

    pub fn msg_cache_contains(&self, msg_id: &MessageId) -> bool {
        self.msg_cache.contains(msg_id)
    }
}

/// Per-topic scoring counters. One per (peer, topic) pair the peer has
/// interacted with on a topic we care about.
#[derive(Debug, Default)]
pub(crate) struct TopicScore {
    // P1
    pub meshed_since: Option<Instant>,
    // P2
    pub first_deliveries: f64,
    // P3
    pub mesh_deliveries: f64,
    /// True once `mesh_message_deliveries_activation_s` has elapsed since
    /// graft — deficit scoring only applies after this.
    pub mesh_active: bool,
    /// Grafted by `opportunistic_graft` into a sub-median mesh. Exempt from
    /// mesh-capped eviction until the activation window elapses, so the
    /// trim falls on the poor performers the graft targets.
    pub opportunistic: bool,
    /// Consecutive remote prunes arriving within `QUICK_PRUNE_WINDOW` of
    /// graft — the signature of a saturated remote mesh trimming us at its
    /// heartbeat. Scales our re-graft backoff; reset by any prune after a
    /// longer residency.
    pub quick_prunes: u8,
    // P3b
    pub mesh_failure_penalty: f64,
    // P4
    pub invalid_deliveries: f64,
    // Fan-out ledger: every message we gossiped on the topic while this
    // peer was meshed, and how many were actually forwarded to it (the
    // rest: it was the originator, sent IDONTWANT, or is score-gated).
    // Not decayed; zeroed on reconnect so the ratio is per-connection.
    pub fanout_total: u64,
    pub fanout_sent: u64,
}

/// Archived counters kept for `archived_ttl` after a peer disconnects. Lets
/// a reconnecting peer inherit their prior reputation.
pub(crate) struct ArchivedState {
    pub application_score: f64,
    pub behaviour_penalty: f64,
    pub topic_stats: FxHashMap<GossipTopic, TopicScore>,
    pub archived_at: Instant,
}

/// IPv4 /24 or IPv6 /64 prefix. Packed into 8 bytes so it's a cheap
/// `HashMap` key. For IPv4 the upper 5 bytes are zeroed.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) struct IpPrefix([u8; 8]);

impl IpPrefix {
    pub fn from(ip: IpAddr) -> Self {
        let mut out = [0u8; 8];
        match ip {
            IpAddr::V4(v4) => {
                // /24 — first three octets.
                let o = v4.octets();
                out[0] = o[0];
                out[1] = o[1];
                out[2] = o[2];
            }
            IpAddr::V6(v6) => {
                // /64 — first eight bytes.
                out.copy_from_slice(&v6.octets()[..8]);
            }
        }
        Self(out)
    }
}

/// Type alias for a hashmap keyed by MessageId using the identity-hasher
/// (MessageId is already a SHA-256 truncation — skip re-hashing).
pub(crate) type MsgIdMap<V> = HashMap<MessageId, V, MsgIdBuild>;
