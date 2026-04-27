//! Peer manager: consumes `PeerEvent`, maintains per-peer state + scoring,
//! emits `PeerControl`. Counters-only on the hot path; all score math +
//! mesh decisions live in `tick`.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::Instant,
};

use silver_common::{
    GossipTopic, IpBytes, MessageId, NodeId, PeerControl, PeerEvent, PeerId, TCacheRead,
};

use crate::{
    params::ScoreParams,
    scoring,
    state::{ArchivedState, IpPrefix, MsgIdMap, PeerState, TopicScore},
};

/// Initial capacity hints — chosen so normal steady-state activity doesn't
/// rehash. Undersizing is fine correctness-wise; this is a perf nudge.
const PEERS_CAP: usize = 256;
const MESH_CAP: usize = 96;
const IP_COLOC_CAP: usize = 128;
const ARCHIVE_CAP: usize = 512;

pub struct PeerManager {
    /// Live peers keyed by connection handle.
    peers: HashMap<usize, PeerState>,

    /// Counters persisted across reconnect by PeerId. GC'd on tick.
    archived: HashMap<PeerId, ArchivedState>,

    /// IP colocation index for P6. Prefix → list of live connection handles.
    ip_colocations: HashMap<IpPrefix, Vec<usize>>,

    /// Topics we subscribe to ourselves. Drives SUBSCRIBE emission on new
    /// peers and mesh-management decisions.
    our_topics: Vec<GossipTopic>,

    /// Our mesh per topic: connections we've grafted onto. Bounded by d_high.
    mesh: HashMap<GossipTopic, Vec<usize>>,

    /// Backoff after PRUNE — don't re-graft same (peer, topic) until deadline.
    backoffs: HashMap<(usize, GossipTopic), Instant>,

    /// Outstanding IHAVE→IWANT promises, keyed by `MessageId`. Each entry
    /// holds every (conn, deadline) that has promised that id. Any one
    /// peer's delivery via `PeerEvent::NewGossip` clears the entry for all
    /// of them — broken-promise penalty only applies if the message never
    /// arrives from anyone by `iwant_followup`.
    promises: MsgIdMap<Vec<(usize, Instant)>>,
    params: ScoreParams,

    /// Last heartbeat rollover time. When `now - last_heartbeat >=
    /// heartbeat_interval`, per-heartbeat counters reset + mesh revised.
    last_heartbeat: Instant,
}

impl PeerManager {
    pub fn new(our_topics: Vec<GossipTopic>, params: ScoreParams) -> Self {
        let now = Instant::now();
        let mesh =
            our_topics.iter().map(|t| (*t, Vec::with_capacity(params.d_high as usize))).collect();
        Self {
            peers: HashMap::with_capacity(PEERS_CAP),
            archived: HashMap::with_capacity(ARCHIVE_CAP),
            ip_colocations: HashMap::with_capacity(IP_COLOC_CAP),
            our_topics,
            mesh,
            backoffs: HashMap::with_capacity(MESH_CAP),
            promises: MsgIdMap::with_capacity_and_hasher(4096, Default::default()),
            params,
            last_heartbeat: now,
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

    /// Iterator over live peer connection handles (for tests/introspection).
    #[allow(dead_code)]
    pub(crate) fn live_peers(&self) -> impl Iterator<Item = usize> + '_ {
        self.peers.keys().copied()
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

    pub fn handle_event(
        &mut self,
        event: PeerEvent,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        match event {
            PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, ip, port } => {
                self.on_connected(p2p_peer_id, peer_id_full, ip, port, now, emit);
            }
            PeerEvent::P2pDisconnect { p2p_peer } => {
                self.on_disconnected(p2p_peer, now, emit);
            }
            PeerEvent::P2pCannotCreateStream { p2p_peer, .. } |
            PeerEvent::P2pOutboundMessageDropped { p2p_peer, .. } => {
                self.add_behaviour_penalty(p2p_peer, 1.0);
            }
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer, topic } => {
                self.on_subscribe(p2p_peer, topic, now, emit);
            }
            PeerEvent::P2pGossipTopicUnsubscribe { p2p_peer, topic } => {
                self.on_unsubscribe(p2p_peer, topic, now, emit);
            }
            PeerEvent::P2pGossipTopicGraft { p2p_peer, topic } => {
                self.on_remote_graft(p2p_peer, topic, now);
            }
            PeerEvent::P2pGossipTopicPrune { p2p_peer, topic } => {
                self.on_remote_prune(p2p_peer, topic, now);
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
                self.add_invalid_delivery(p2p_peer, topic);
            }
            PeerEvent::P2pGossipInvalidControl { p2p_peer } |
            PeerEvent::P2pGossipInvalidFrame { p2p_peer } => {
                self.add_behaviour_penalty(p2p_peer, 1.0);
            }
            PeerEvent::DiscNodeFound { enr: _ } => {
                // TODO init p2p connection? determine if we need more p2p
                // peers? TODO init status rpc
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
                // TODO recv_ts elpased metric
                self.on_send_gossip(originator_stream_id.peer(), msg_hash, topic, protobuf, emit);
            }
        }
    }

    // ── Cold path: tick ─────────────────────────────────────────────────

    pub fn tick(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        // 1) Heartbeat rollover: reset per-heartbeat counters, sweep broken promises.
        if now.saturating_duration_since(self.last_heartbeat) >= self.params.heartbeat_interval {
            self.heartbeat(now);
            self.last_heartbeat = now;
        }

        // 2) Activate P3 tracking for peers whose grace window has elapsed.
        self.activate_p3_where_due(now);

        // 3) Decay all counters.
        for p in self.peers.values_mut() {
            scoring::decay(p, &self.params);
        }

        // 4) Recompute scores for every peer.
        self.rescore_all(now);

        // 5) Evict peers below the graylist threshold.
        self.evict_graylisted(emit);

        // 6) Mesh management: graft under-filled topics, prune over-filled ones.
        self.manage_mesh(now, emit);

        // 7) GC archived state past TTL.
        self.gc_archived(now);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    fn on_connected(
        &mut self,
        conn: usize,
        peer_id: PeerId,
        ip: IpBytes,
        port: u16,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let addr = SocketAddr::new(ip_bytes_to_addr(ip), port);
        let mut state = PeerState::new(peer_id, addr, now);

        // Inherit counters if we remember this PeerId.
        if let Some(archive) = self.archived.remove(&peer_id) {
            state.restore_from_archive(archive);
        }

        // Index by /24 or /64 prefix for P6.
        self.ip_colocations
            .entry(state.ip_prefix)
            .or_insert_with(|| Vec::with_capacity(4))
            .push(conn);

        self.peers.insert(conn, state);

        // Announce our own topic subscriptions to this peer.
        for &topic in &self.our_topics {
            emit(PeerControl::P2pGossipSubscribe { p2p: peer_id, p2p_connection: conn, topic });
        }
    }

    fn on_disconnected(&mut self, conn: usize, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let Some(mut state) = self.peers.remove(&conn) else {
            return;
        };

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

        // Drop any outstanding backoffs referencing this conn.
        self.backoffs.retain(|(c, _), _| *c != conn);

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

        // Opportunistic graft: if this is a topic we care about and our mesh
        // is below d_low, pull the peer in.
        if we_want &&
            self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0) < self.params.d_low as usize &&
            !self.is_backed_off((conn, topic), now)
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
        // If peer was in our mesh, remove them.
        if let Some(mesh_peers) = self.mesh.get_mut(&topic) &&
            let Some(idx) = mesh_peers.iter().position(|c| *c == conn)
        {
            mesh_peers.swap_remove(idx);
            emit(PeerControl::P2pGossipPrune { p2p: peer_id, p2p_connection: conn, topic });
        }
    }

    /// Peer grafted us — they consider us in their mesh. From our side this
    /// just means subsequent deliveries from them will count as mesh
    /// deliveries (P3 tracking), which needs a timestamp.
    fn on_remote_graft(&mut self, conn: usize, topic: GossipTopic, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            t.meshed_since = Some(now);
            t.mesh_active = false; // activates after grace window
        }
    }

    /// Peer pruned us. Record a backoff so we don't re-graft immediately,
    /// and mark their P3b penalty so the deficit carries forward.
    fn on_remote_prune(&mut self, conn: usize, topic: GossipTopic, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&conn) &&
            let Some(t) = peer.topic_stats.get_mut(&topic)
        {
            // Carry any active deficit into the failure penalty.
            if t.mesh_active && t.mesh_deliveries < self.params.mesh_message_deliveries_threshold {
                t.mesh_failure_penalty +=
                    self.params.mesh_message_deliveries_threshold - t.mesh_deliveries;
            }
            t.meshed_since = None;
            t.mesh_active = false;
        }
        self.backoffs.insert((conn, topic), now + self.params.prune_backoff);
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
            self.add_behaviour_penalty(conn, 1.0);
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
        emit(PeerControl::P2pGossipSend { p2p: peer.peer_id, p2p_connection: conn, tcache });
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
            emit(PeerControl::P2pGossipSend {
                p2p: peer.peer_id,
                p2p_connection: *conn,
                tcache: idontwant,
            });
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
            emit(PeerControl::P2pGossipSend {
                p2p: peer.peer_id,
                p2p_connection: *conn,
                tcache: protobuf,
            });
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
        emit(PeerControl::P2pGossipSend { p2p: peer.peer_id, p2p_connection: conn, tcache });
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
            emit(PeerControl::P2pGossipSend {
                p2p: peer_state.peer_id,
                p2p_connection: *peer,
                tcache,
            });
        }
    }

    fn add_invalid_delivery(&mut self, conn: usize, topic: GossipTopic) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            t.invalid_deliveries += 1.0;
        }
    }

    fn add_behaviour_penalty(&mut self, conn: usize, delta: f64) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            peer.behaviour_penalty += delta;
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn is_backed_off(&self, key: (usize, GossipTopic), now: Instant) -> bool {
        self.backoffs.get(&key).is_some_and(|d| now < *d)
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
        }
        self.backoffs.insert((conn, topic), now + self.params.prune_backoff);
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
        for (conn, count) in penalties {
            if let Some(peer) = self.peers.get_mut(&conn) {
                peer.behaviour_penalty += count as f64;
            }
        }
    }

    fn activate_p3_where_due(&mut self, now: Instant) {
        let activation = self.params.mesh_message_deliveries_activation_s;
        for peer in self.peers.values_mut() {
            for t in peer.topic_stats.values_mut() {
                if !t.mesh_active &&
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

    fn evict_graylisted(&mut self, emit: &mut impl FnMut(PeerControl)) {
        let threshold = self.params.graylist_threshold;
        // Two-phase: identify + remove (can't mutate self.peers while
        // iterating it); emit is inline in phase 2.
        let mut evict: Vec<(usize, PeerId, IpAddr)> = Vec::new();
        for (conn, peer) in &self.peers {
            if peer.cached_score < threshold {
                evict.push((*conn, peer.peer_id, peer.addr.ip()));
            }
        }
        for (conn, peer_id, ip) in evict {
            // NodeId is populated downstream where the Discovery tile can
            // resolve it from the PeerId's secp256k1 pubkey.
            emit(PeerControl::Ban {
                p2p: peer_id,
                p2p_connection: conn,
                disc: NodeId::new(&[0u8; 32]),
            });
            emit(PeerControl::BanIp { ip });
            // Archived copy is written on the normal disconnect path fired
            // downstream once the Ban takes effect; here we just drop live.
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
                if self.is_backed_off((*conn, topic), now) {
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

    use silver_common::Keypair;

    use super::*;

    /// Owns the captured `PeerControl` stream for a test. Tests push into
    /// `cap.0` via an ad-hoc `|c| cap.0.push(c)` closure passed to
    /// `handle_event`/`tick`.
    #[derive(Default)]
    struct Captured(Vec<PeerControl>);

    fn fixture(our_topics: Vec<GossipTopic>, params: ScoreParams) -> (PeerManager, Captured) {
        (PeerManager::new(our_topics, params), Captured::default())
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
            },
            now,
            &mut |c| cap.0.push(c),
        );
    }

    #[test]
    fn connect_with_no_topics_emits_nothing() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        assert!(cap.0.is_empty());
    }

    #[test]
    fn connect_emits_subscribe_per_our_topic() {
        let now = Instant::now();
        let topics = vec![GossipTopic::BeaconBlock, GossipTopic::VoluntaryExit];
        let (mut mgr, mut cap) = fixture(topics.clone(), ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        assert_eq!(cap.0.len(), 2);
        for e in &cap.0 {
            assert!(matches!(e, PeerControl::P2pGossipSubscribe { .. }));
        }
    }

    #[test]
    fn peer_subscribes_and_we_graft_when_mesh_under_d_low() {
        let now = Instant::now();
        let topics = vec![GossipTopic::BeaconBlock];
        let (mut mgr, mut cap) = fixture(topics, ScoreParams::default());
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![], params);

        for i in 1..=5u8 {
            mgr.handle_event(
                PeerEvent::P2pNewConnection {
                    p2p_peer_id: i as usize,
                    peer_id_full: peer_id(i),
                    ip: IpBytes::V4([10, 0, 0, i]),
                    port: 4000 + i as u16,
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
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, 1, 1, now);

        mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.handle_event(PeerEvent::P2pDisconnect { p2p_peer: 1 }, now, &mut |c| cap.0.push(c));
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
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(PeerEvent::P2pDisconnect { p2p_peer: 1 }, now, &mut |c| cap.0.push(c));
        assert_eq!(mgr.archived_count(), 1);

        now += Duration::from_secs(11);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert_eq!(mgr.archived_count(), 0);
    }

    fn mk_tcache_read() -> silver_common::TCacheRead {
        let mut producer = silver_common::TCache::producer(1 << 14);
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params);

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
                if let PeerControl::P2pGossipSend { p2p_connection, .. } = e {
                    Some(*p2p_connection)
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
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params);
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
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pGossipSend { .. })),
            "below-threshold peer should not receive IHAVE, got {:?}",
            cap.0
        );
    }

    #[test]
    fn iwant_request_above_threshold_emits_forward() {
        use silver_common::{TCache, TCacheRead};
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        let mut producer = TCache::producer(1 << 14);
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
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pGossipSend { p2p_connection: 1, .. })),
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
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, 1, 1, now);

        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(10), &mut |c| cap.0.push(c));
        assert!(mgr.score(1).unwrap() < -1.0);

        let mut producer = TCache::producer(1 << 14);
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
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pGossipSend { .. })),
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
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params);

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
                PeerControl::P2pGossipSend { p2p_connection, .. } => Some(*p2p_connection),
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
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params);

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
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pGossipSend { .. })),
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
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconBlock], params);

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
            silver_common::P2pStreamId::new(1, 0, silver_common::StreamProtocol::GossipSub);
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
                PeerControl::P2pGossipSend { p2p_connection, .. } => Some(*p2p_connection),
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

    #[test]
    fn decay_drives_honest_peer_to_zero() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_decay = 0.5;
        params.decay_to_zero = 0.01;
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, 1, 1, now);

        mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
            cap.0.push(c)
        });

        for _ in 0..30 {
            now += Duration::from_secs(1);
            mgr.tick(now, &mut |c| cap.0.push(c));
        }
        let s = mgr.score(1).unwrap();
        assert!(s.abs() < 1e-6, "expected score ≈ 0 after decay, got {s}");
    }
}
