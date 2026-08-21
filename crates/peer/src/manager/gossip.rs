//! Gossipsub domain: topic subscriptions, mesh membership
//! (graft/prune/backoff, fill/cap/opportunistic maintenance), IHAVE/IWANT
//! promise tracking, delivery crediting, and the heartbeat sweeps.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use flux_profiler::timed;
use rand::seq::SliceRandom;
use silver_common::{
    GossipMsgOut, GossipTopic, MessageId, Nanos, P2pSend, PeerControl, PeerId, TCacheRead,
};

use super::{PeerManager, build_subnet_masks};
use crate::scoring;

const MESH_MESSAGE_DELIVERIES_WINDOW_NS: u64 = 2_000_000_000;
/// Remote prune this soon after graft = their heartbeat trimming an
/// oversubscribed mesh; re-grafting on the base backoff is futile.
const QUICK_PRUNE_WINDOW: Duration = Duration::from_secs(5);
/// Caps futility escalation at `prune_backoff << 4` (60s → 960s).
const QUICK_PRUNE_MAX_SHIFT: u8 = 4;
const OPPORTUNISTIC_GRAFT_INTERVAL: Duration = Duration::from_secs(60);
const OPPORTUNISTIC_GRAFT_PEERS: usize = 2;

pub(super) struct RecentDelivery {
    pub(super) topic: GossipTopic,
    pub(super) received_at: Nanos,
    pub(super) first_credited_peer: Option<PeerId>,
    pub(super) additional_credited_peers: Vec<PeerId>,
}

impl RecentDelivery {
    fn new(topic: GossipTopic, received_at: Nanos, credited_peer: Option<PeerId>) -> Self {
        Self {
            topic,
            received_at,
            first_credited_peer: credited_peer,
            additional_credited_peers: Vec::new(),
        }
    }

    fn credit(&mut self, peer_id: PeerId) -> bool {
        if self.first_credited_peer == Some(peer_id) ||
            self.additional_credited_peers.contains(&peer_id)
        {
            return false;
        }
        if self.first_credited_peer.is_none() {
            self.first_credited_peer = Some(peer_id);
        } else {
            self.additional_credited_peers.push(peer_id);
        }
        true
    }
}

impl PeerManager {
    /// Announce our topic subscriptions to every currently-connected peer.
    /// Add topics at runtime (deferred long-lived subnets): extends
    /// `our_topics` + mesh bookkeeping + subnet masks, and announces
    /// SUBSCRIBE to every connected peer. New connections pick the
    /// topics up via the normal `on_connected` fan-out.
    pub fn activate_topics(&mut self, topics: &[GossipTopic], emit: &mut impl FnMut(PeerControl)) {
        for &topic in topics {
            if self.our_topics.contains(&topic) {
                continue;
            }
            self.our_topics.push(topic);
            self.mesh.insert(topic, Vec::with_capacity(self.params.d_high as usize));
            for (&conn, peer) in &self.peers {
                emit(PeerControl::P2pGossipSubscribe {
                    p2p: peer.peer_id,
                    p2p_connection: conn,
                    topic,
                });
            }
        }
        let (attnets, syncnets) = build_subnet_masks(&self.our_topics);
        self.required_attnets = attnets;
        self.required_syncnets = syncnets;
    }

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

    /// Mesh size for a topic (for tests/introspection).
    #[allow(dead_code)]
    pub(crate) fn mesh_size(&self, topic: GossipTopic) -> usize {
        self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0)
    }

    #[timed]
    pub(super) fn on_subscribe(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let (peer_id, score) = {
            let Some(peer) = self.peers.get_mut(&conn) else {
                return;
            };
            peer.topics.insert(topic);
            (peer.peer_id, peer.cached_score)
        };

        let we_want = self.our_topics.contains(&topic);
        let mesh_size = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        tracing::debug!(p2p_peer = conn, ?topic, we_want, mesh_size, "PM peer subscribed");

        // Opportunistic graft: if this is a topic we care about and our mesh
        // is below d_low, pull the peer in.
        if we_want &&
            mesh_size < self.params.d_low as usize &&
            score >= 0.0 &&
            !self.is_backed_off(conn, topic, now)
        {
            self.do_graft(conn, peer_id, topic, now, false, emit);
        }
    }

    #[timed]
    pub(super) fn on_unsubscribe(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        _now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let peer_id = match self.peers.get_mut(&conn) {
            Some(p) => {
                p.topics.remove(&topic);
                p.peer_id
            }
            None => return,
        };
        tracing::debug!(p2p_peer = conn, ?topic, "PM peer unsubscribed");
        // If peer was in our mesh, remove them.
        if self.leave_mesh(conn, topic) {
            emit(PeerControl::P2pGossipPrune { p2p: peer_id, p2p_connection: conn, topic });
        }
    }

    #[timed]
    pub(super) fn on_remote_graft(
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
        // No mesh-size gate: refusing at the cap makes well-behaved remotes
        // retry on a 60s backoff loop forever and keeps us out of their
        // meshes (no first-delivery score → pruned as excess). Reference
        // gossipsub accepts and lets the heartbeat trim past d_high.
        let accept = self.our_topics.contains(&topic) &&
            score >= 0.0 &&
            !self.is_backed_off(conn, topic, now);
        if accept {
            crate::PeerCounters::MeshGraftAcceptedByUs.inc();
            self.do_graft(conn, peer_id, topic, now, false, emit);
            tracing::debug!(p2p_peer = conn, ?topic, mesh_size, "PM peer GRAFTed us: accepted");
        } else {
            crate::PeerCounters::MeshGraftRefusedByUs.inc();
            self.do_prune(conn, peer_id, topic, now, "graft refused", emit);
            tracing::debug!(p2p_peer = conn, ?topic, mesh_size, "PM peer GRAFTed us: refused");
        }
    }

    #[timed]
    pub(super) fn on_remote_prune(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        now: Instant,
        backoff_seconds: Option<u64>,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let meshed_since = self
            .peers
            .get(&conn)
            .and_then(|p| p.topic_stats.get(&topic))
            .and_then(|t| t.meshed_since);
        let was_in_mesh = self.leave_mesh(conn, topic);
        let mesh_size = self.mesh.get(&topic).map(|peers| peers.len()).unwrap_or(0);
        if !self.peers.contains_key(&conn) {
            if let Some(record) = self.database.by_p2p_id(conn) &&
                let Some(id) = record.peer_id
            {
                emit(PeerControl::P2pDisconnect { p2p: id, p2p_connection: conn })
            }
            return;
        }
        let quick = was_in_mesh &&
            meshed_since.is_some_and(|s| now.saturating_duration_since(s) < QUICK_PRUNE_WINDOW);
        let quick_prunes = self
            .peers
            .get_mut(&conn)
            .and_then(|p| p.topic_stats.get_mut(&topic))
            .map(|t| {
                if quick {
                    t.quick_prunes = (t.quick_prunes + 1).min(QUICK_PRUNE_MAX_SHIFT);
                } else if was_in_mesh {
                    t.quick_prunes = 0;
                }
                t.quick_prunes
            })
            .unwrap_or(0);
        let backoff = backoff_seconds.map(Duration::from_secs).unwrap_or(self.params.prune_backoff);
        // Futility escalation — longer-than-requested backoff is spec-legal
        // and stops the 61s graft/trim cycle against saturated meshes.
        let backoff = backoff.checked_mul(1 << quick_prunes).unwrap_or(backoff);
        self.set_backoff(conn, topic, now, backoff);
        if was_in_mesh {
            crate::PeerCounters::MeshPrunedByRemote.inc();
        }
        let user_agent = self.peers.get(&conn).map(|p| p.user_agent).unwrap_or_default();
        tracing::debug!(
            p2p_peer = conn,
            ?topic,
            mesh_size,
            user_agent = user_agent.as_str(),
            was_in_mesh,
            meshed_for_ms =
                ?meshed_since.map(|s| now.saturating_duration_since(s).as_millis() as u64),
            backoff_s = backoff.as_secs(),
            quick_prunes,
            "PM peer PRUNEd us"
        );
    }

    pub(super) fn on_ihave(
        &mut self,
        conn: usize,
        hash: MessageId,
        already_seen: bool,
        now: Instant,
    ) {
        // Always count, regardless of dedup state — the rate cap treats
        // a peer IHAVEing thousands of ids we already have just as badly as
        // ids we don't.
        let should_iwant = {
            let Some(peer) = self.peers.get_mut(&conn) else {
                return;
            };
            peer.ihaves_received = peer.ihaves_received.saturating_add(1);
            // Only send an IWANT (and thus track a promise) if:
            //  - we don't already have the message,
            //  - we haven't exceeded the per-heartbeat IWANT budget,
            //  - the peer hasn't saturated the IHAVE rate cap — excess ids are ignored
            //    without penalty (matching reference gossipsub; P7 for gossip abuse comes
            //    from broken promises),
            //  - the peer clears the gossip threshold (`on_outbound_iwant` drops the frame
            //    below it — a promise without a sent IWANT can only ever expire).
            let should_iwant = !already_seen &&
                peer.ihaves_received <= self.params.max_ihave_length &&
                peer.cached_score >= self.params.gossip_threshold &&
                peer.iwant_ids_sent < self.params.max_ihave_length;
            if should_iwant {
                peer.iwant_ids_sent = peer.iwant_ids_sent.saturating_add(1);
            }
            should_iwant
        };
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
    #[timed]
    pub(super) fn on_iwant_received(
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
    pub(super) fn on_idontwant_received(&mut self, conn: usize, hash: MessageId) {
        let Some(peer) = self.peers.get_mut(&conn) else {
            return;
        };
        peer.msg_cache_insert(hash);
    }

    fn credit_mesh_delivery(&mut self, conn: usize, topic: GossipTopic) -> Option<PeerId> {
        if !self.mesh.get(&topic).is_some_and(|mesh| mesh.contains(&conn)) {
            return None;
        }
        let peer = self.peers.get_mut(&conn)?;
        peer.topic_stats.entry(topic).or_default().mesh_deliveries += 1.0;
        Some(peer.peer_id)
    }

    pub(super) fn on_gossip_duplicate(
        &mut self,
        conn: usize,
        topic: GossipTopic,
        hash: MessageId,
        recv_ts: Nanos,
    ) {
        self.promises.remove(&hash);
        if !self.mesh.get(&topic).is_some_and(|mesh| mesh.contains(&conn)) {
            return;
        }
        let Some(peer_id) = self.peers.get(&conn).map(|peer| peer.peer_id) else {
            return;
        };
        let Some(delivery) = self.recent_deliveries.get_mut(&hash) else {
            return;
        };
        if delivery.topic != topic ||
            recv_ts.0.saturating_sub(delivery.received_at.0) > MESH_MESSAGE_DELIVERIES_WINDOW_NS ||
            !delivery.credit(peer_id)
        {
            return;
        }
        if let Some(peer) = self.peers.get_mut(&conn) {
            peer.topic_stats.entry(topic).or_default().mesh_deliveries += 1.0;
        }
    }

    /// A fully-validated inbound gossip message arrived — this is the first
    /// (dedup-clean) delivery from any peer. Clear all promises for this id
    /// (every peer who IHAVE'd it kept their word, regardless of who
    /// actually reached us first), credit P2/P3 on the delivering peer, and
    /// fan out the pre-encoded IDONTWANT frame to every mesh peer except
    /// the sender so they stop racing this id toward us.
    #[timed]
    pub(super) fn on_new_gossip(
        &mut self,
        sender_conn: usize,
        topic: GossipTopic,
        msg_hash: MessageId,
        recv_ts: Nanos,
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
        }

        let credited_peer = self.credit_mesh_delivery(sender_conn, topic);
        if scoring::p3_scored(&topic) {
            self.recent_deliveries
                .insert(msg_hash, RecentDelivery::new(topic, recv_ts, credited_peer));
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
    #[timed]
    pub(super) fn on_outbound_ihave(
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
    #[timed]
    pub(super) fn on_outbound_iwant(
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

    #[timed]
    pub(super) fn on_send_gossip(
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
            let Some(peer_state) = self.peers.get_mut(peer) else {
                continue;
            };
            peer_state.topic_stats.entry(topic).or_default().fanout_total += 1;
            if *peer == sender {
                continue;
            }
            if peer_state.cached_score < self.params.gossip_threshold {
                continue;
            }
            if peer_state.msg_cache_contains(&msg_hash) {
                // dontwant
                continue;
            }
            peer_state.topic_stats.entry(topic).or_default().fanout_sent += 1;
            crate::counters::GossipTopicCounters::sent(topic);
            emit(PeerControl::P2pSend(P2pSend::Gossip(GossipMsgOut { peer_id: *peer, tcache })));
        }
    }

    pub(super) fn add_invalid_delivery(&mut self, conn: usize, topic: GossipTopic) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            let t = peer.topic_stats.entry(topic).or_default();
            t.invalid_deliveries += 1.0;
        }
    }

    /// Unexpired opportunistic graft: still inside the activation window,
    /// so its score is structurally ~0 and proves nothing yet.
    fn in_opportunistic_grace(&self, conn: usize, topic: GossipTopic, now: Instant) -> bool {
        let activation = self.params.mesh_message_deliveries_activation_s;
        self.peers.get(&conn).and_then(|p| p.topic_stats.get(&topic)).is_some_and(|t| {
            t.opportunistic &&
                t.meshed_since
                    .is_some_and(|s| now.saturating_duration_since(s).as_secs_f64() < activation)
        })
    }

    pub(super) fn is_backed_off(&self, conn: usize, topic: GossipTopic, now: Instant) -> bool {
        let Some(deadline) = self.peers.get(&conn).and_then(|p| p.backoffs.get(&topic)) else {
            return false;
        };
        deadline
            .checked_add(self.params.heartbeat_interval)
            .map_or(now < *deadline, |deadline_with_slack| now < deadline_with_slack)
    }

    fn set_backoff(&mut self, conn: usize, topic: GossipTopic, now: Instant, backoff: Duration) {
        let Some(deadline) = now.checked_add(backoff) else {
            tracing::warn!(p2p_peer = conn, ?topic, ?backoff, "ignoring oversized prune backoff");
            return;
        };
        let Some(peer) = self.peers.get_mut(&conn) else { return };
        peer.backoffs
            .entry(topic)
            .and_modify(|current| *current = (*current).max(deadline))
            .or_insert(deadline);
    }

    fn do_graft(
        &mut self,
        conn: usize,
        peer_id: PeerId,
        topic: GossipTopic,
        now: Instant,
        opportunistic: bool,
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
            t.opportunistic = opportunistic;
        }
        tracing::debug!(?topic, conn, "GRAFT peer");
        emit(PeerControl::P2pGossipGraft { p2p: peer_id, p2p_connection: conn, topic });
    }

    fn do_prune(
        &mut self,
        conn: usize,
        peer_id: PeerId,
        topic: GossipTopic,
        now: Instant,
        reason: &'static str,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let meshed_since = self
            .peers
            .get(&conn)
            .and_then(|p| p.topic_stats.get(&topic))
            .and_then(|t| t.meshed_since);
        let was_in_mesh = self.leave_mesh(conn, topic);
        self.set_backoff(conn, topic, now, self.params.prune_backoff);
        if was_in_mesh {
            crate::PeerCounters::MeshPrunedByUs.inc();
        }
        let user_agent = self.peers.get(&conn).map(|p| p.user_agent).unwrap_or_default();
        tracing::debug!(
            p2p_peer = conn,
            ?topic,
            reason,
            user_agent = user_agent.as_str(),
            was_in_mesh,
            meshed_for_ms =
                ?meshed_since.map(|s| now.saturating_duration_since(s).as_millis() as u64),
            "PRUNE peer"
        );
        emit(PeerControl::P2pGossipPrune { p2p: peer_id, p2p_connection: conn, topic });
    }

    pub(super) fn leave_mesh(&mut self, conn: usize, topic: GossipTopic) -> bool {
        let removed = if let Some(mesh) = self.mesh.get_mut(&topic) &&
            let Some(index) = mesh.iter().position(|peer| *peer == conn)
        {
            mesh.swap_remove(index);
            true
        } else {
            false
        };

        if let Some(topic_score) =
            self.peers.get_mut(&conn).and_then(|peer| peer.topic_stats.get_mut(&topic))
        {
            let threshold = scoring::topic_params(&topic).p3_threshold;
            if topic_score.mesh_active && topic_score.mesh_deliveries < threshold {
                let deficit = threshold - topic_score.mesh_deliveries;
                topic_score.mesh_failure_penalty += deficit * deficit;
            }
            topic_score.meshed_since = None;
            topic_score.mesh_active = false;
        }

        removed
    }

    pub(super) fn heartbeat(&mut self, now: Instant) {
        // Reset per-heartbeat rate-limit counters on every live peer.
        for peer in self.peers.values_mut() {
            peer.ihaves_received = 0;
            peer.iwant_ids_sent = 0;
        }

        let recv_now = Nanos::now();
        self.recent_deliveries.retain(|_, delivery| {
            recv_now.0.saturating_sub(delivery.received_at.0) <= MESH_MESSAGE_DELIVERIES_WINDOW_NS
        });

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

    pub(super) fn activate_p3_where_due(&mut self, now: Instant) {
        let activation = self.params.mesh_message_deliveries_activation_s;
        for peer in self.peers.values_mut() {
            for (topic, t) in peer.topic_stats.iter_mut() {
                if scoring::p3_scored(topic) &&
                    !t.mesh_active &&
                    let Some(since) = t.meshed_since &&
                    now.saturating_duration_since(since).as_secs_f64() >= activation
                {
                    t.mesh_active = true;
                }
            }
        }
    }

    pub(super) fn manage_mesh(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        // Self-heal: a mesh entry with no live PeerState means a removal
        // path skipped the mesh sweep (see the graylist-evict leak). It
        // suppresses grafting via a phantom degree and, once quinn recycles
        // the handle, mesh-pushes to a peer that never grafted.
        let peers = &self.peers;
        for (topic, mesh_peers) in self.mesh.iter_mut() {
            mesh_peers.retain(|conn| {
                let live = peers.contains_key(conn);
                if !live {
                    tracing::warn!(conn, ?topic, "dropping mesh entry with no peer state");
                }
                live
            });
        }

        // Iterate over OUR topics (topics we care about). We briefly take
        // the topic list so `ensure_mesh_*` can take `&mut self`.
        let our_topics = std::mem::take(&mut self.our_topics);
        let opportunistic_graft_due = now.saturating_duration_since(self.last_opportunistic_graft) >=
            OPPORTUNISTIC_GRAFT_INTERVAL;
        for topic in &our_topics {
            self.prune_negative_mesh_peers(*topic, now, emit);
            self.ensure_mesh_filled(*topic, now, emit);
            self.ensure_mesh_capped(*topic, now, emit);
            if opportunistic_graft_due {
                self.opportunistic_graft(*topic, now, emit);
            }
        }
        self.our_topics = our_topics;
        if opportunistic_graft_due {
            self.last_opportunistic_graft = now;
        }
    }

    fn prune_negative_mesh_peers(
        &mut self,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let peers: Vec<_> = self
            .mesh
            .get(&topic)
            .into_iter()
            .flatten()
            .filter_map(|conn| {
                self.peers
                    .get(conn)
                    .filter(|peer| peer.cached_score < 0.0)
                    .map(|peer| (*conn, peer.peer_id))
            })
            .collect();
        for (conn, peer_id) in peers {
            self.do_prune(conn, peer_id, topic, now, "negative score", emit);
        }
    }

    fn ensure_mesh_filled(
        &mut self,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let current = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        let d = self.params.d as usize;
        if current >= d {
            return;
        }
        let needed = d - current;
        // Sort requires a buffer; the emit isn't what forces it.
        let mut candidates: Vec<usize> = self
            .peers
            .iter()
            .filter_map(|(conn, peer)| {
                if !peer.topics.contains(&topic) {
                    return None;
                }
                if self.mesh.get(&topic).is_some_and(|m| m.contains(conn)) {
                    return None;
                }
                if peer.cached_score < 0.0 {
                    return None;
                }
                if self.is_backed_off(*conn, topic, now) {
                    return None;
                }
                Some(*conn)
            })
            .collect();
        candidates.shuffle(&mut rand::thread_rng());
        for conn in candidates.into_iter().take(needed) {
            let Some(peer_id) = self.peers.get(&conn).map(|p| p.peer_id) else {
                continue;
            };
            self.do_graft(conn, peer_id, topic, now, false, emit);
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
        // Strictly above d_high (spec heartbeat rule): remote grafts can
        // push the mesh past the cap between heartbeats; a mesh sitting at
        // exactly d_high is steady state, not a prune trigger.
        if current <= d_high {
            return;
        }
        let excess = current.saturating_sub(d);
        if excess == 0 {
            return;
        }
        // Lowest selection score evicted first — no random component
        // (deliberate spec deviation: proven deliverers are never displaced
        // by unproven newcomers). Grace-window members rank ~0 (P3 not yet
        // active), below any positive-scoring incumbent a remote-graft
        // flood would otherwise displace. Unexpired opportunistic grafts
        // are exempt outright — a >median-at-selection score does not
        // guarantee surviving a deep trim — and are bounded (≤
        // OPPORTUNISTIC_GRAFT_PEERS per activation window), so the exempt
        // set can never dominate the mesh the way blanket grace exemption
        // did.
        // Sort requires a buffer; the emit isn't what forces it.
        let mut ranked: Vec<(usize, f64, PeerId)> = self
            .mesh
            .get(&topic)
            .map(|mesh| {
                mesh.iter()
                    .filter_map(|conn| {
                        if self.in_opportunistic_grace(*conn, topic, now) {
                            return None;
                        }
                        let p = self.peers.get(conn)?;
                        Some((
                            *conn,
                            scoring::selection_score(p, &topic, &self.params, now),
                            p.peer_id,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        for (conn, _, peer_id) in ranked.into_iter().take(excess) {
            self.do_prune(conn, peer_id, topic, now, "mesh capped", emit);
        }
    }

    fn opportunistic_graft(
        &mut self,
        topic: GossipTopic,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        let Some(mesh) = self.mesh.get(&topic) else { return };
        if mesh.len() <= 1 {
            return;
        }
        // One round per activation window: stacking exempt grafts while the
        // last batch is still unproven would shrink the evictable pool.
        if mesh.iter().any(|&conn| self.in_opportunistic_grace(conn, topic, now)) {
            return;
        }
        // Median over established members only: peers meshed for less than
        // the P3 activation window score near zero structurally, so counting
        // them reads a freshly-built mesh as underperforming and re-grafts
        // (then prunes) before anyone has a chance to establish.
        let activation = self.params.mesh_message_deliveries_activation_s;
        let mut mesh_scores: Vec<_> = mesh
            .iter()
            .filter_map(|conn| {
                let peer = self.peers.get(conn)?;
                let since = peer.topic_stats.get(&topic)?.meshed_since?;
                (now.saturating_duration_since(since).as_secs_f64() >= activation)
                    .then_some(scoring::selection_score(peer, &topic, &self.params, now))
            })
            .collect();
        if mesh_scores.len() <= 1 {
            return;
        }
        mesh_scores.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let middle = mesh_scores.len() / 2;
        let median = if mesh_scores.len().is_multiple_of(2) {
            (mesh_scores[middle - 1] + mesh_scores[middle]) * 0.5
        } else {
            mesh_scores[middle]
        };
        if median >= self.params.opportunistic_graft_threshold {
            return;
        }

        let mut candidates: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(conn, peer)| {
                if !peer.topics.contains(&topic) ||
                    mesh.contains(conn) ||
                    scoring::selection_score(peer, &topic, &self.params, now) <= median ||
                    self.is_backed_off(*conn, topic, now)
                {
                    return None;
                }
                Some(*conn)
            })
            .collect();
        candidates.shuffle(&mut rand::thread_rng());
        for conn in candidates.into_iter().take(OPPORTUNISTIC_GRAFT_PEERS) {
            let Some(peer_id) = self.peers.get(&conn).map(|peer| peer.peer_id) else {
                continue;
            };
            self.do_graft(conn, peer_id, topic, now, true, emit);
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{PeerEvent, TCacheProducer};
    use silver_config::ScoreParams;

    use super::{
        super::tests::{Captured, connect, fixture, peer_id},
        *,
    };

    /// `on_connected` always emits a `P2pSend::Identify` event; filter
    /// it out so subscribe-focused tests can assert on subscribe counts.
    fn subscribe_events(cap: &Captured) -> Vec<&PeerControl> {
        cap.0.iter().filter(|c| !matches!(c, PeerControl::P2pSend(P2pSend::Identify(_)))).collect()
    }

    #[test]
    fn connect_with_no_topics_emits_nothing() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        assert!(subscribe_events(&cap).is_empty());
    }

    #[test]
    fn connect_emits_subscribe_per_our_topic() {
        let now = Instant::now();
        let topics = vec![GossipTopic::BeaconBlock, GossipTopic::VoluntaryExit];
        let (mut mgr, mut cap) = fixture(topics.clone(), ScoreParams::default());
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
    fn negative_score_subscriber_is_not_grafted() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.peers.get_mut(&1).unwrap().cached_score = -0.1;
        cap.0.clear();

        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );

        assert_eq!(mgr.mesh_size(topic), 0);
        assert!(!cap.0.iter().any(|event| matches!(event, PeerControl::P2pGossipGraft { .. })));

        mgr.handle_event(
            PeerEvent::P2pGossipTopicGraft { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );

        assert_eq!(mgr.mesh_size(topic), 0);
        assert!(cap.0.iter().any(|event| matches!(
            event,
            PeerControl::P2pGossipPrune { p2p_connection: 1, topic: pruned, .. }
                if *pruned == topic
        )));
    }

    #[test]
    fn remote_graft_accepted_past_d_high() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d_low = 0;
        params.d = 0;
        params.d_high = 2;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for i in 1..=3u8 {
            connect(&mut mgr, &mut cap, i as usize, i, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe { p2p_peer: i as usize, topic },
                now,
                &mut |event| cap.0.push(event),
            );
        }
        mgr.mesh.entry(topic).or_default().extend([1, 2]);
        cap.0.clear();

        mgr.handle_event(
            PeerEvent::P2pGossipTopicGraft { p2p_peer: 3, topic },
            now,
            &mut |event| cap.0.push(event),
        );

        assert_eq!(mgr.mesh_size(topic), 3);
        assert!(
            !cap.0.iter().any(|event| matches!(event, PeerControl::P2pGossipPrune {
                p2p_connection: 3,
                ..
            }))
        );
    }

    #[test]
    fn negative_mesh_peer_is_pruned_before_refill() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );
        assert_eq!(mgr.mesh_size(topic), 1);
        mgr.peers.get_mut(&1).unwrap().application_score = -1.0;
        cap.0.clear();

        mgr.tick(now + Duration::from_secs(1), &mut |event| cap.0.push(event));

        assert_eq!(mgr.mesh_size(topic), 0);
        assert!(cap.0.iter().any(|event| matches!(
            event,
            PeerControl::P2pGossipPrune { p2p_connection: 1, topic: pruned, .. }
                if *pruned == topic
        )));
    }

    #[test]
    fn randomized_refill_uses_only_eligible_peers() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d = 4;
        params.d_low = 0;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=6 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe { p2p_peer: conn, topic },
                now,
                &mut |event| cap.0.push(event),
            );
            mgr.peers.get_mut(&conn).unwrap().cached_score = conn as f64;
        }
        mgr.peers.get_mut(&1).unwrap().cached_score = -0.1;
        mgr.set_backoff(2, topic, now, Duration::from_secs(60));

        mgr.ensure_mesh_filled(topic, now, &mut |event| cap.0.push(event));

        let mesh = &mgr.mesh[&topic];
        assert_eq!(mesh.len(), 4);
        assert!(!mesh.contains(&1));
        assert!(!mesh.contains(&2));
        assert!(mesh.iter().all(|conn| (3..=6).contains(conn)));
    }

    #[test]
    fn capping_spares_opportunistic_grafts_within_window() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d = 2;
        params.d_low = 0;
        params.d_high = 3;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=4 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.peers.get_mut(&conn).unwrap().cached_score = conn as f64;
        }
        // 1..=3 are incumbents; 4 is an opportunistic graft with the lowest
        // effective score — exempt, so the trim falls on incumbent 1.
        for conn in 1..=3 {
            mgr.do_graft(conn, peer_id(conn as u8), topic, now, false, &mut |event| {
                cap.0.push(event)
            });
        }
        mgr.do_graft(4, peer_id(4), topic, now, true, &mut |event| cap.0.push(event));
        mgr.peers.get_mut(&4).unwrap().cached_score = 0.0;
        cap.0.clear();

        mgr.ensure_mesh_capped(topic, now, &mut |event| cap.0.push(event));
        let mesh = &mgr.mesh[&topic];
        assert!(mesh.contains(&4));
        assert!(!mesh.contains(&1));

        // Past the activation window the exemption lapses: lowest score
        // (still peer 4) is evicted like anyone else.
        mgr.do_graft(1, peer_id(1), topic, now, false, &mut |event| cap.0.push(event));
        mgr.do_graft(2, peer_id(2), topic, now, false, &mut |event| cap.0.push(event));
        let settled =
            now + Duration::from_secs_f64(mgr.params.mesh_message_deliveries_activation_s);
        mgr.ensure_mesh_capped(topic, settled, &mut |event| cap.0.push(event));
        assert!(!mgr.mesh[&topic].contains(&4));
    }

    #[test]
    fn capping_evicts_lowest_scores_first() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d = 8;
        params.d_low = 0;
        params.d_high = 12;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=12 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.do_graft(conn, peer_id(conn as u8), topic, now, false, &mut |event| {
                cap.0.push(event)
            });
            mgr.peers.get_mut(&conn).unwrap().cached_score = conn as f64;
        }
        cap.0.clear();

        mgr.ensure_mesh_capped(topic, now, &mut |event| cap.0.push(event));
        assert_eq!(mgr.mesh[&topic].len(), 12);
        assert!(cap.0.is_empty());

        connect(&mut mgr, &mut cap, 13, 13, now);
        mgr.do_graft(13, peer_id(13), topic, now, false, &mut |event| cap.0.push(event));
        mgr.peers.get_mut(&13).unwrap().cached_score = 13.0;
        cap.0.clear();

        // Over cap: trims to d immediately — grace-window members are
        // eligible victims, top scorers retained.
        mgr.ensure_mesh_capped(topic, now, &mut |event| cap.0.push(event));

        let mesh = &mgr.mesh[&topic];
        assert_eq!(mesh.len(), 8);
        assert!((6..=13).all(|conn| mesh.contains(&conn)));
        assert_eq!(
            cap.0
                .iter()
                .filter(|event| matches!(event, PeerControl::P2pGossipPrune { .. }))
                .count(),
            5
        );
    }

    #[test]
    fn opportunistic_graft_runs_on_duration_and_selects_above_median() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d = 2;
        params.d_low = 0;
        params.d_high = 8;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=5 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe { p2p_peer: conn, topic },
                now,
                &mut |event| cap.0.push(event),
            );
        }
        mgr.do_graft(1, peer_id(1), topic, now, false, &mut |event| cap.0.push(event));
        mgr.do_graft(2, peer_id(2), topic, now, false, &mut |event| cap.0.push(event));
        for (conn, score) in [(1, 1.0), (2, 2.0), (3, 3.0), (4, 4.0), (5, 1.4)] {
            mgr.peers.get_mut(&conn).unwrap().cached_score = score;
        }
        let due = mgr.last_opportunistic_graft + OPPORTUNISTIC_GRAFT_INTERVAL;

        mgr.manage_mesh(due - Duration::from_nanos(1), &mut |event| cap.0.push(event));
        assert_eq!(mgr.mesh_size(topic), 2);

        // Due, but both members are inside the activation window: no median,
        // no graft.
        mgr.manage_mesh(due, &mut |event| cap.0.push(event));
        assert_eq!(mgr.mesh_size(topic), 2);
        assert_eq!(mgr.last_opportunistic_graft, due);

        // Past the activation window the members' scores count.
        let established =
            due + Duration::from_secs_f64(mgr.params.mesh_message_deliveries_activation_s);
        mgr.manage_mesh(established, &mut |event| cap.0.push(event));

        let mesh = &mgr.mesh[&topic];
        assert_eq!(mesh.len(), 4);
        assert!(mesh.contains(&3));
        assert!(mesh.contains(&4));
        assert!(!mesh.contains(&5));
    }

    #[test]
    fn quick_prune_escalates_backoff_and_long_residency_resets() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        // Graft, then pruned 1s later (their heartbeat trim): base backoff
        // doubles.
        mgr.do_graft(1, peer_id(1), topic, now, false, &mut |event| cap.0.push(event));
        let pruned_at = now + Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 1, topic, backoff_seconds: Some(60) },
            pruned_at,
            &mut |event| cap.0.push(event),
        );
        assert_eq!(mgr.peers[&1].topic_stats[&topic].quick_prunes, 1);
        assert_eq!(mgr.peers[&1].backoffs[&topic], pruned_at + Duration::from_secs(120));

        // Second quick trim: ×4.
        mgr.peers.get_mut(&1).unwrap().backoffs.clear();
        mgr.do_graft(1, peer_id(1), topic, pruned_at, false, &mut |event| cap.0.push(event));
        let pruned_again = pruned_at + Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 1, topic, backoff_seconds: Some(60) },
            pruned_again,
            &mut |event| cap.0.push(event),
        );
        assert_eq!(mgr.peers[&1].topic_stats[&topic].quick_prunes, 2);
        assert_eq!(mgr.peers[&1].backoffs[&topic], pruned_again + Duration::from_secs(240));

        // A graft that outlives the window resets the escalation.
        mgr.peers.get_mut(&1).unwrap().backoffs.clear();
        mgr.do_graft(1, peer_id(1), topic, pruned_again, false, &mut |event| cap.0.push(event));
        let pruned_late = pruned_again + QUICK_PRUNE_WINDOW + Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 1, topic, backoff_seconds: Some(60) },
            pruned_late,
            &mut |event| cap.0.push(event),
        );
        assert_eq!(mgr.peers[&1].topic_stats[&topic].quick_prunes, 0);
        assert_eq!(mgr.peers[&1].backoffs[&topic], pruned_late + Duration::from_secs(60));
    }

    #[test]
    fn received_prune_honors_full_backoff_and_heartbeat_slack() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let params = ScoreParams::default();
        let heartbeat = params.heartbeat_interval;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 1, topic, backoff_seconds: Some(7200) },
            now,
            &mut |event| cap.0.push(event),
        );
        let original_deadline = mgr.peers[&1].backoffs[&topic];

        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 1, topic, backoff_seconds: Some(60) },
            now + Duration::from_secs(1),
            &mut |event| cap.0.push(event),
        );

        assert_eq!(mgr.peers[&1].backoffs[&topic], original_deadline);
        let end_with_slack = now + Duration::from_secs(7200) + heartbeat;
        assert!(mgr.is_backed_off(1, topic, end_with_slack - Duration::from_nanos(1)));
        assert!(!mgr.is_backed_off(1, topic, end_with_slack));

        connect(&mut mgr, &mut cap, 2, 2, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 2, topic, backoff_seconds: Some(u64::MAX) },
            now,
            &mut |event| cap.0.push(event),
        );
        assert!(!mgr.peers[&2].backoffs.contains_key(&topic));
    }

    #[test]
    fn unsubscribe_preserves_reputation_and_squares_mesh_failure() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );
        let topic_score = mgr.peers.get_mut(&1).unwrap().topic_stats.get_mut(&topic).unwrap();
        topic_score.first_deliveries = 2.0;
        topic_score.mesh_deliveries = 0.2;
        topic_score.mesh_active = true;
        topic_score.invalid_deliveries = 3.0;

        mgr.handle_event(
            PeerEvent::P2pGossipTopicUnsubscribe { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );

        let topic_score = &mgr.peers[&1].topic_stats[&topic];
        let deficit = scoring::topic_params(&topic).p3_threshold - 0.2;
        assert_eq!(mgr.mesh_size(topic), 0);
        assert_eq!(topic_score.first_deliveries, 2.0);
        assert_eq!(topic_score.invalid_deliveries, 3.0);
        assert_eq!(topic_score.mesh_failure_penalty, deficit * deficit);
        assert!(topic_score.meshed_since.is_none());
        assert!(!topic_score.mesh_active);
    }

    #[test]
    fn remote_prune_squares_mesh_failure() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );
        let topic_score = mgr.peers.get_mut(&1).unwrap().topic_stats.get_mut(&topic).unwrap();
        topic_score.mesh_deliveries = 0.1;
        topic_score.mesh_active = true;

        mgr.handle_event(
            PeerEvent::P2pGossipTopicPrune { p2p_peer: 1, topic, backoff_seconds: Some(60) },
            now,
            &mut |event| cap.0.push(event),
        );

        let topic_score = &mgr.peers[&1].topic_stats[&topic];
        let deficit = scoring::topic_params(&topic).p3_threshold - 0.1;
        assert_eq!(topic_score.mesh_failure_penalty, deficit * deficit);
        assert!(topic_score.meshed_since.is_none());
        assert!(!topic_score.mesh_active);
    }

    #[test]
    fn disconnect_squares_mesh_failure_before_archiving() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let id = peer_id(1);
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.handle_event(
            PeerEvent::P2pGossipTopicSubscribe { p2p_peer: 1, topic },
            now,
            &mut |event| cap.0.push(event),
        );
        let topic_score = mgr.peers.get_mut(&1).unwrap().topic_stats.get_mut(&topic).unwrap();
        topic_score.mesh_deliveries = 0.3;
        topic_score.mesh_active = true;

        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: id },
            now,
            &mut |event| cap.0.push(event),
        );

        let topic_score = &mgr.archived[&id].topic_stats[&topic];
        let deficit = scoring::topic_params(&topic).p3_threshold - 0.3;
        assert_eq!(mgr.mesh_size(topic), 0);
        assert_eq!(topic_score.mesh_failure_penalty, deficit * deficit);
        assert!(topic_score.meshed_since.is_none());
        assert!(!topic_score.mesh_active);
    }

    #[test]
    fn ihave_below_gossip_threshold_records_no_promise() {
        let now = Instant::now();
        let params = ScoreParams::default();
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, 1, 1, now);
        mgr.peers.get_mut(&1).unwrap().cached_score = mgr.params.gossip_threshold - 1.0;

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
        assert!(mgr.promises.is_empty());
    }

    #[test]
    fn duplicate_delivery_clears_promise() {
        let now = Instant::now();
        let params = ScoreParams::default();
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
        assert_eq!(mgr.promises.len(), 1);

        mgr.handle_event(
            PeerEvent::GossipDuplicate {
                p2p_peer: 1,
                topic: GossipTopic::BeaconBlock,
                hash,
                recv_ts: Nanos::now(),
            },
            now,
            &mut |c| cap.0.push(c),
        );
        assert!(mgr.promises.is_empty());
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

    /// Over-cap IHAVEs are ignored without penalty — no P7, and no promise
    /// (an unfulfillable promise would surface later as a broken-promise
    /// penalty instead).
    #[test]
    fn ihave_flood_over_heartbeat_cap_ignored() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.max_ihave_length = 3;
        params.graylist_threshold = -100_000.0;
        let (mut mgr, mut cap) = fixture(vec![], params);
        connect(&mut mgr, &mut cap, 1, 1, now);

        for i in 0..8u8 {
            mgr.handle_event(
                PeerEvent::P2pGossipHave {
                    p2p_peer: 1,
                    topic: GossipTopic::BeaconBlock,
                    hash: silver_common::MessageId { id: [i; 20] },
                    already_seen: true,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        let s = mgr.score(1).unwrap();
        assert!(s >= 0.0, "expected no penalty for over-cap IHAVEs, got {s}");
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

    fn mk_tcache_read() -> silver_common::TCacheRead {
        let mut producer = silver_common::TCache::producer("test_peer", 1 << 14);
        let mut reservation = producer.reserve(64, true).unwrap();
        use std::io::Write as _;
        reservation.write_all(&[0u8; 64]).unwrap();
        reservation.read()
    }

    #[test]
    fn near_first_mesh_deliveries_credit_each_peer_once() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d_low = 0;
        params.d = 0;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=3 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.do_graft(conn, peer_id(conn as u8), topic, now, false, &mut |event| {
                cap.0.push(event)
            });
        }
        let hash = MessageId { id: [11u8; 20] };
        let first_seen = Nanos::from_secs(10);

        mgr.handle_event(
            PeerEvent::NewGossip {
                p2p_peer: 1,
                topic,
                msg_hash: hash,
                recv_ts: first_seen,
                idontwant: mk_tcache_read(),
            },
            now,
            &mut |event| cap.0.push(event),
        );
        mgr.handle_event(
            PeerEvent::GossipDuplicate {
                p2p_peer: 2,
                topic,
                hash,
                recv_ts: Nanos(first_seen.0 + 1_000_000_000),
            },
            now,
            &mut |event| cap.0.push(event),
        );
        mgr.handle_event(
            PeerEvent::GossipDuplicate {
                p2p_peer: 2,
                topic,
                hash,
                recv_ts: Nanos(first_seen.0 + 1_500_000_000),
            },
            now,
            &mut |event| cap.0.push(event),
        );
        mgr.handle_event(
            PeerEvent::GossipDuplicate {
                p2p_peer: 3,
                topic,
                hash,
                recv_ts: Nanos(first_seen.0 + 2_000_000_001),
            },
            now,
            &mut |event| cap.0.push(event),
        );

        assert_eq!(mgr.peers[&1].topic_stats[&topic].mesh_deliveries, 1.0);
        assert_eq!(mgr.peers[&2].topic_stats[&topic].mesh_deliveries, 1.0);
        assert_eq!(mgr.peers[&3].topic_stats[&topic].mesh_deliveries, 0.0);
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
                recv_ts: Nanos::now(),
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
                recv_ts: Nanos::now(),
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
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
                recv_ts: Nanos::now(),
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
                recv_ts: Nanos::now(),
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
}
