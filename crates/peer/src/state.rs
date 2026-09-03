//! Per-peer state: identity, subscriptions, and scoring counters. All heap
//! allocations are one-shot at construction.
//!
//! IHAVE→IWANT promise tracking lives in the manager, keyed by `MessageId`
//! globally — one message arrival fulfils every promise for that id
//! regardless of which peer delivered it.

use std::{
    collections::{HashMap, HashSet},
    hash::BuildHasherDefault,
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use silver_common::{
    AgentString, CountingWitherFilter, GossipTopic, MessageId, MessageIdHasher, PeerId,
    rpc_rate_limit::{N_STREAM_PROTOCOLS, RpcRateLimitSet},
};

use crate::scoring::ScoreBreakdown;

/// Max topics an honest eth2 peer can reasonably subscribe to (64 attnets +
/// 4 syncnets + 6 blobs + aggregates + blocks + slashings + exits + bls-
/// change + lc updates ≈ 80). Cap capacity so inserts don't rehash in steady
/// state.
pub(crate) const TOPICS_PER_PEER_CAP: usize = 96;

pub(crate) type MsgIdBuild = BuildHasherDefault<MessageIdHasher>;

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
    pub topics: HashSet<GossipTopic>,

    // Per-topic scoring. Sparse — entry created on first meshed activity.
    pub topic_stats: HashMap<GossipTopic, TopicScore>,

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
    pub backoffs: HashMap<GossipTopic, Instant>,

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

impl PeerState {
    pub fn new(peer_id: PeerId, addr: SocketAddr, now: Instant) -> Self {
        Self {
            peer_id,
            addr,
            ip_prefix: IpPrefix::from(addr.ip()),
            connected_at: now,
            local_dialler: false,
            user_agent: AgentString::default(),
            topics: HashSet::with_capacity(TOPICS_PER_PEER_CAP),
            topic_stats: HashMap::with_capacity(TOPICS_PER_PEER_CAP),
            msg_cache: CountingWitherFilter::default(),
            application_score: 0.0,
            behaviour_penalty: 0.0,
            ihaves_received: 0,
            iwant_ids_sent: 0,
            outbound_rpc_limits: RpcRateLimitSet::default(),
            outbound_in_flight: [0; N_STREAM_PROTOCOLS],
            backoffs: HashMap::new(),
            cached_score: 0.0,
            score_valid_at: now,
            last_breakdown: ScoreBreakdown::default(),
            goodbye_sent: false,
            evict_spared: false,
            is_trusted: false,
        }
    }

    /// Restore counters from a previously-archived entry. Identity/address
    /// fields are NOT touched — they come from the fresh connection.
    pub fn restore_from_archive(&mut self, archive: ArchivedState) {
        self.application_score = archive.application_score;
        self.behaviour_penalty = archive.behaviour_penalty;
        self.topic_stats = archive.topic_stats;
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
    pub topic_stats: HashMap<GossipTopic, TopicScore>,
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
