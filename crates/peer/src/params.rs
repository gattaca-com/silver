//! Peer-scoring tuning parameters. Defaults match gossipsub v1.1 canonical
//! values (eth2 consensus layer inherits these unchanged).

use std::time::Duration;

#[derive(Clone, Debug)]
pub struct ScoreParams {
    // ── Action thresholds ────────────────────────────────────────────────
    /// Below this score, peer is fully graylisted — all inbound messages
    /// including control frames ignored, and Ban is emitted.
    pub graylist_threshold: f64,
    /// Below this score we don't publish to this peer.
    pub publish_threshold: f64,
    /// Below this score we ignore IHAVE/IWANT gossip.
    pub gossip_threshold: f64,
    /// Below this score we don't accept PX peer-exchange lists in PRUNE.
    pub accept_px_threshold: f64,
    /// Above this score a peer is eligible for opportunistic mesh graft.
    pub opportunistic_graft_threshold: f64,

    // ── P1: time in mesh ────────────────────────────────────────────────
    pub time_in_mesh_cap_s: f64,
    pub time_in_mesh_weight: f64,

    // ── P2: first-message deliveries ────────────────────────────────────
    pub first_message_deliveries_cap: f64,
    pub first_message_deliveries_weight: f64,
    pub first_message_deliveries_decay: f64,

    // ── P3: mesh-message deliveries (rate threshold) ────────────────────
    pub mesh_message_deliveries_threshold: f64,
    pub mesh_message_deliveries_weight: f64,
    pub mesh_message_deliveries_decay: f64,
    /// Seconds after graft before P3 tracking becomes active.
    pub mesh_message_deliveries_activation_s: f64,

    // ── P3b: mesh failure penalty ───────────────────────────────────────
    pub mesh_failure_penalty_weight: f64,
    pub mesh_failure_penalty_decay: f64,

    // ── P4: invalid-message deliveries (per topic) ──────────────────────
    pub invalid_message_deliveries_weight: f64,
    pub invalid_message_deliveries_decay: f64,

    // ── P6: IP colocation ───────────────────────────────────────────────
    /// Peers sharing a /24 (v4) or /64 (v6) beyond this count → penalty.
    pub ip_colocation_threshold: usize,
    pub ip_colocation_weight: f64,

    // ── P7: behaviour penalty ───────────────────────────────────────────
    pub behaviour_penalty_threshold: f64,
    pub behaviour_penalty_weight: f64,
    pub behaviour_penalty_decay: f64,

    // ── Misc ────────────────────────────────────────────────────────────
    /// Counter values below this clamp to 0 after decay.
    pub decay_to_zero: f64,
    /// How long to retain an archived peer's counters after disconnect.
    pub archived_ttl: Duration,
    /// Re-score cache TTL. Scores older than this get recomputed.
    pub score_cache_ttl: Duration,

    // ── Heartbeat / rate limits ─────────────────────────────────────────
    pub heartbeat_interval: Duration,
    pub max_ihave_messages: u16,
    pub max_ihave_length: u16,
    /// Deadline for an IWANT reply after we send it. Past this, the IHAVE
    /// sender gets a broken-promise penalty.
    pub iwant_followup: Duration,

    // ── Mesh sizing (gossipsub D parameters) ────────────────────────────
    pub d: u8,
    pub d_low: u8,
    pub d_high: u8,
    pub d_lazy: u8,

    /// Backoff applied after a PRUNE before re-grafting the same peer.
    pub prune_backoff: Duration,

    // ── Peer pool sizing ─────────────────────────────────────────────────
    /// Desired live-peer count. Below this, discovery hits trigger a dial
    /// and `tick` periodically emits `DiscoverNodes` to refill.
    pub target_peers: usize,
    /// Hard ceiling on dials when a discovery hit advertises a subnet we
    /// need (`attnets`/`syncnets` ∩ our subscribed subnets ≠ 0). Lets us
    /// stay slightly above `target_peers` to fill mesh gaps on validator-
    /// critical subnets without unbounded growth.
    pub max_priority_peers: usize,
    /// Minimum gap between `DiscoverNodes` emissions while under-target.
    pub discovery_query_interval: Duration,
    /// How long to keep an IP in the ban-set after we graylisted the peer
    /// behind it. Tuned independently of `archived_ttl` because IP-level
    /// bans have higher false-positive blast radius (NAT/CGN) than the
    /// PeerId-level reputation archive.
    pub banned_ip_ttl: Duration,
    /// Number of recent peer-level graylist evictions from a single IP
    /// before we escalate to an IP-level ban. Mirrors lighthouse's
    /// `BANNED_PEERS_PER_IP_THRESHOLD`. Higher → more tolerant of NAT/CGN
    /// where multiple honest peers share an IP. Lower → faster lockout of
    /// PeerId-rotation sybils.
    pub ip_ban_threshold: u32,
    /// How long a peer-level ban (the `PeerId`) is held before it auto-
    /// expires and the manager emits `Unban`. Independent of
    /// `banned_ip_ttl` — peer-level granularity is finer (one PeerId is
    /// one entity), so this can run on a different cadence to the
    /// IP-level lockout.
    pub banned_peer_ttl: Duration,
}

impl Default for ScoreParams {
    fn default() -> Self {
        Self {
            // Thresholds
            graylist_threshold: -80.0,
            publish_threshold: -50.0,
            gossip_threshold: -10.0,
            accept_px_threshold: 10.0,
            opportunistic_graft_threshold: 5.0,

            // P1 — small positive reward, capped
            time_in_mesh_cap_s: 3600.0,
            time_in_mesh_weight: 0.00027, // ~1.0 per hour in mesh

            // P2 — larger positive reward for low-latency relaying
            first_message_deliveries_cap: 1000.0,
            first_message_deliveries_weight: 1.0,
            first_message_deliveries_decay: 0.998,

            // P3 — deficit below expected delivery rate, squared
            mesh_message_deliveries_threshold: 20.0,
            mesh_message_deliveries_weight: -1.0,
            mesh_message_deliveries_decay: 0.971,
            mesh_message_deliveries_activation_s: 30.0,

            // P3b — carries deficit forward across re-graft
            mesh_failure_penalty_weight: -1.0,
            mesh_failure_penalty_decay: 0.971,

            // P4 — invalid-message deliveries, squared
            invalid_message_deliveries_weight: -100.0,
            invalid_message_deliveries_decay: 0.9994,

            // P6 — IP colocation
            ip_colocation_threshold: 10,
            ip_colocation_weight: -1.0,

            // P7 — behaviour penalty
            behaviour_penalty_threshold: 0.0,
            behaviour_penalty_weight: -10.0,
            behaviour_penalty_decay: 0.999,

            decay_to_zero: 0.01,
            archived_ttl: Duration::from_secs(384), // 1 eth2 epoch
            score_cache_ttl: Duration::from_millis(700),

            // Heartbeat / rate limits
            heartbeat_interval: Duration::from_millis(700),
            max_ihave_messages: 10,
            max_ihave_length: 5000,
            iwant_followup: Duration::from_secs(3),

            // Mesh
            d: 8,
            d_low: 6,
            d_high: 12,
            d_lazy: 6,

            prune_backoff: Duration::from_secs(60),

            target_peers: 100,
            max_priority_peers: 130, // ~30% headroom, matches lighthouse PRIORITY_PEER_EXCESS
            discovery_query_interval: Duration::from_secs(5),
            banned_ip_ttl: Duration::from_secs(3600),
            ip_ban_threshold: 5,
            banned_peer_ttl: Duration::from_secs(3600),
        }
    }
}
