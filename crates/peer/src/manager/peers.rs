//! The live peer set and the gossip mesh grafted onto it: connections in
//! and out, subscriptions, GRAFT/PRUNE both ways, and the scoring that
//! decides which peers the mesh keeps.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use flux_profiler::timed;
use rand::seq::SliceRandom;
use silver_common::{
    GossipTopic, IpBytes, P2pSend, PeerControl, PeerId, PeerScores, PeerTopicScores,
    RpcRequestOutbound, StreamProtocol, rpc_rate_limit::RpcRateLimit,
};

use super::{
    PeerManager, SHORT_LIVED_CONNECTION, SHORT_LIVED_DIAL_BACKOFF, TRANSPORT_DISCONNECT,
    build_subnet_masks,
};
use crate::{
    database::PeerRecord,
    scoring,
    state::{ArchivedState, PeerState},
};

/// Remote prune this soon after graft = their heartbeat trimming an
/// oversubscribed mesh; re-grafting on the base backoff is futile.
const QUICK_PRUNE_WINDOW: Duration = Duration::from_secs(5);

/// Caps futility escalation at `prune_backoff << 4` (60s → 960s).
const QUICK_PRUNE_MAX_SHIFT: u8 = 4;

const OPPORTUNISTIC_GRAFT_INTERVAL: Duration = Duration::from_secs(60);

const OPPORTUNISTIC_GRAFT_PEERS: usize = 2;

impl PeerManager {
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

    /// Size of the archive set.
    #[allow(dead_code)]
    pub(crate) fn archived_count(&self) -> usize {
        self.archived.len()
    }

    #[allow(clippy::too_many_arguments)]
    #[timed]
    pub(super) fn on_connected(
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
        state.local_dialler = local_dialler;

        self.dialing.remove(&peer_id);

        let duplicate = self
            .peers_by_id
            .get(&peer_id)
            .and_then(|c| self.peers.get(c).map(|p| (*c, p.local_dialler)));
        if let Some((existing_conn, existing_dialler)) = duplicate {
            let keep_new = existing_dialler == local_dialler ||
                (self.local_peer_id.as_bytes() < peer_id.as_bytes()) == local_dialler;
            if keep_new {
                tracing::info!(
                    ?peer_id,
                    old = existing_conn,
                    new = conn,
                    "duplicate connection: replacing existing"
                );
                self.on_disconnected(existing_conn, now, "duplicate connection", emit);
                emit(PeerControl::P2pDisconnect { p2p: peer_id, p2p_connection: existing_conn });
            } else {
                tracing::info!(
                    ?peer_id,
                    existing = existing_conn,
                    refused = conn,
                    "duplicate connection: refusing new"
                );
                emit(PeerControl::P2pDisconnect { p2p: peer_id, p2p_connection: conn });
                return;
            }
        }

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

        if let Some(record) = self.database.by_peer_id(&peer_id) {
            tracing::info!(conn, ?addr, "trusted peer connected");
            state.is_trusted = record.is_trusted;
        }

        self.peers.insert(conn, state);
        self.peers_by_id.insert(peer_id, conn);
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

    #[timed]
    pub(super) fn on_disconnected(
        &mut self,
        conn: usize,
        now: Instant,
        reason: &'static str,
        emit: &mut impl FnMut(PeerControl),
    ) -> Option<&PeerRecord> {
        let peer_id = self.peers.get(&conn)?.peer_id;
        let mesh_topics: Vec<_> = self
            .mesh
            .iter()
            .filter_map(|(topic, peers)| peers.contains(&conn).then_some(*topic))
            .collect();
        for topic in mesh_topics {
            self.leave_mesh(conn, topic);
            // Connection is going away; no backoff to honour or advertise.
            emit(PeerControl::P2pGossipPrune {
                p2p: peer_id,
                p2p_connection: conn,
                topic,
                backoff_seconds: None,
            });
        }

        let mut state = self.peers.remove(&conn).unwrap();
        if self.peers_by_id.get(&state.peer_id) == Some(&conn) {
            self.peers_by_id.remove(&state.peer_id);
        }

        let age = now.saturating_duration_since(state.connected_at);
        let (dc_subscribed, dc_advertised) = self.data_column_overlap(conn, &state);
        let user_agent =
            self.database.by_p2p_id(conn).and_then(|r| r.identify.as_ref()).map(|i| i.user_agent());
        tracing::info!(
            p2p_peer = conn,
            peer_id = ?state.peer_id,
            addr = ?state.addr,
            reason,
            ?user_agent,
            age_ms = age.as_millis(),
            score = state.cached_score,
            dc_subscribed,
            dc_advertised,
            "peer disconnected"
        );

        // A connection dying young without a Goodbye is a failed dial in
        // all but name (remote gater denial, instant crash). The completed
        // handshake cleared any dial backoff, so re-arm a short one or the
        // redial loop re-knocks every tick.
        if reason == TRANSPORT_DISCONNECT && age < SHORT_LIVED_CONNECTION {
            self.database.dial_failed(&state.peer_id, now + SHORT_LIVED_DIAL_BACKOFF);
        }

        // De-index IP colocation.
        if let Some(v) = self.ip_colocations.get_mut(&state.ip_prefix) {
            v.retain(|c| *c != conn);
            if v.is_empty() {
                self.ip_colocations.remove(&state.ip_prefix);
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

        self.fail_attempts_on_disconnect(conn);
        self.database.peer_disconnected(conn)
    }

    pub(super) fn add_behaviour_penalty(&mut self, conn: usize, delta: f64, offence: &'static str) {
        if let Some(peer) = self.peers.get_mut(&conn) {
            peer.behaviour_penalty += delta;
            tracing::info!(
                p2p_peer = conn,
                offence,
                delta,
                total = peer.behaviour_penalty,
                user_agent = peer.user_agent.as_str(),
                "P7 behaviour penalty"
            );
        }
    }

    /// Raw per-topic gossipsub counters for every meshed (peer, topic) pair.
    pub fn peer_topic_scores(&self, now: Instant, emit: &mut impl FnMut(PeerTopicScores)) {
        for (topic, mesh_peers) in &self.mesh {
            for conn in mesh_peers {
                let Some(peer) = self.peers.get(conn) else { continue };
                let Some(t) = peer.topic_stats.get(topic) else { continue };
                emit(PeerTopicScores {
                    id: peer.peer_id,
                    topic: *topic,
                    meshed_secs: t
                        .meshed_since
                        .map(|s| now.saturating_duration_since(s).as_secs())
                        .unwrap_or(0),
                    first_deliveries: t.first_deliveries,
                    mesh_deliveries: t.mesh_deliveries,
                    p3_scored: scoring::p3_scored(topic),
                    mesh_active: t.mesh_active,
                    fanout_total: t.fanout_total,
                    fanout_sent: t.fanout_sent,
                    mesh_failure_penalty: t.mesh_failure_penalty,
                    invalid_deliveries: t.invalid_deliveries,
                });
            }
        }
    }

    /// Score breakdown for every live peer, as of the last `rescore_all`.
    pub fn peer_scores(&self, emit: &mut impl FnMut(PeerScores)) {
        let mut mesh_counts: HashMap<usize, u32> = HashMap::with_capacity(self.peers.len());
        for mesh_peers in self.mesh.values() {
            for conn in mesh_peers {
                *mesh_counts.entry(*conn).or_insert(0) += 1;
            }
        }

        for (conn, peer) in &self.peers {
            let b = peer.last_breakdown;
            emit(PeerScores {
                id: peer.peer_id,
                user_agent: peer.user_agent,
                mesh_count: mesh_counts.get(conn).copied().unwrap_or(0),
                p1_time_in_mesh: b.p1_time_in_mesh,
                p2_first_deliveries: b.p2_first_deliveries,
                p3_mesh_deficit: b.p3_mesh_deficit,
                p3b_mesh_failure: b.p3b_mesh_failure,
                p4_invalid: b.p4_invalid,
                p5_application: b.p5_application,
                p6_ip_colocation: b.p6_ip_colocation,
                p7_behaviour: b.p7_behaviour,
                total: b.total,
            });
        }
    }

    pub(super) fn gc_archived(&mut self, now: Instant) {
        let ttl = self.params.archived_ttl;
        self.archived.retain(|_, a| now.saturating_duration_since(a.archived_at) < ttl);
    }

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
        let (peer_id, score, is_trusted) = {
            let Some(peer) = self.peers.get_mut(&conn) else {
                return;
            };
            peer.topics.insert(topic);
            (peer.peer_id, peer.cached_score, peer.is_trusted)
        };

        let we_want = self.our_topics.contains(&topic);
        let mesh_size = self.mesh.get(&topic).map(|m| m.len()).unwrap_or(0);
        tracing::debug!(p2p_peer = conn, ?topic, we_want, mesh_size, "PM peer subscribed");

        // Opportunistic graft: if this is a topic we care about and our mesh
        // is below d_low, pull the peer in.
        if we_want &&
            (is_trusted ||
                (mesh_size < self.params.d_low as usize &&
                    score >= 0.0 &&
                    !self.is_backed_off(conn, topic, now)))
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
            emit(PeerControl::P2pGossipPrune {
                p2p: peer_id,
                p2p_connection: conn,
                topic,
                backoff_seconds: None,
            });
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
            (peer.is_trusted || (score >= 0.0 && !self.is_backed_off(conn, topic, now)));
        if accept {
            crate::PeerCounters::MeshGraftAcceptedByUs.inc();
            self.do_graft(conn, peer_id, topic, now, false, emit);
            tracing::debug!(p2p_peer = conn, ?topic, mesh_size, "PM peer GRAFTed us: accepted");
        } else {
            crate::PeerCounters::MeshGraftRefusedByUs.inc();
            // Violation is judged against the advertised deadline, not
            // `is_backed_off`'s slack: a peer that waits exactly as long as
            // we asked must not be penalised for our own grace window.
            if self.backoff_deadline(conn, topic).is_some_and(|deadline| now < deadline) {
                crate::PeerCounters::MeshGraftBackoffViolation.inc();
                self.add_behaviour_penalty(conn, 1.0, "graft during prune backoff");
            }
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

    /// Instant our backoff for this topic expires, if one is recorded. This
    /// is the value we advertise; `is_backed_off` enforces it with a
    /// heartbeat of slack on top.
    fn backoff_deadline(&self, conn: usize, topic: GossipTopic) -> Option<Instant> {
        self.peers.get(&conn).and_then(|p| p.backoffs.get(&topic)).copied()
    }

    pub(crate) fn is_backed_off(&self, conn: usize, topic: GossipTopic, now: Instant) -> bool {
        let Some(deadline) = self.backoff_deadline(conn, topic) else {
            return false;
        };
        deadline
            .checked_add(self.params.heartbeat_interval)
            .map_or(now < deadline, |deadline_with_slack| now < deadline_with_slack)
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

    pub(super) fn do_graft(
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
        // Advertise what we will actually enforce, not the nominal param:
        // `set_backoff` keeps any longer deadline already recorded, and a
        // shorter advertisement would invite a re-GRAFT we then penalise.
        // Round up so the advertised instant never precedes ours.
        let backoff_seconds = self
            .backoff_deadline(conn, topic)
            .map(|deadline| deadline.saturating_duration_since(now).as_secs_f64().ceil() as u64);
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
        emit(PeerControl::P2pGossipPrune {
            p2p: peer_id,
            p2p_connection: conn,
            topic,
            backoff_seconds,
        });
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
        let mut deficit_attnets = [0u8; 8];
        let mut deficit_syncnets = 0u8;
        let mut deficit_columns = 0u128;
        let mut deficits = 0u64;
        for topic in &our_topics {
            self.prune_negative_mesh_peers(*topic, now, emit);
            self.ensure_mesh_filled(*topic, now, emit);
            self.ensure_mesh_capped(*topic, now, emit);
            if opportunistic_graft_due {
                self.opportunistic_graft(*topic, now, emit);
            }
            // Measured after the fill: still short of `d` means we ran out
            // of connected subscribers to graft, so the shortfall can only
            // be closed by acquiring peers that serve this subnet.
            if self.mesh.get(topic).map_or(0, |mesh| mesh.len()) >= self.params.d as usize {
                continue;
            }
            deficits += 1;
            match topic {
                GossipTopic::BeaconAttestation(n) if *n < 64 => {
                    deficit_attnets[(*n / 8) as usize] |= 1 << (*n % 8);
                }
                GossipTopic::SyncCommittee(n) if *n < 8 => deficit_syncnets |= 1 << *n,
                GossipTopic::DataColumnSidecar(n) if *n < 128 => deficit_columns |= 1u128 << *n,
                _ => {}
            }
        }
        self.deficit_attnets = deficit_attnets;
        self.deficit_syncnets = deficit_syncnets;
        self.deficit_columns = deficit_columns;
        crate::PeerCounters::MeshSubnetDeficits.set(deficits);
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
                    .filter(|peer| !peer.is_trusted && peer.cached_score < 0.0)
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
                        if p.is_trusted {
                            return None;
                        }
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
        // Established members only: peers meshed for less than the P3
        // activation window score near zero structurally, so counting them
        // reads a freshly-built mesh as underperforming and re-grafts (then
        // prunes) before anyone has a chance to establish.
        let activation = self.params.mesh_message_deliveries_activation_s;
        let mut local_scores = Vec::with_capacity(mesh.len());
        let mut global_scores = Vec::with_capacity(mesh.len());
        for conn in mesh {
            let Some(peer) = self.peers.get(conn) else { continue };
            let Some(since) = peer.topic_stats.get(&topic).and_then(|t| t.meshed_since) else {
                continue;
            };
            if now.saturating_duration_since(since).as_secs_f64() < activation {
                continue;
            }
            local_scores.push(scoring::selection_score(peer, &topic, &self.params, now));
            global_scores.push(scoring::candidate_score(peer));
        }
        if local_scores.len() <= 1 {
            return;
        }

        // Trigger on topic-local merit: is *this* mesh underperforming?
        let saturation = scoring::topic_local_saturation(&topic, &self.params);
        if median(&mut local_scores) >= self.params.opportunistic_graft_fraction * saturation {
            return;
        }

        // Candidates have no topic-local record, so they are ranked — and
        // the members they must beat are measured — on global merit. The two
        // scales differ by the number of meshes a peer holds; comparing
        // across them would admit every candidate.
        let bar = median(&mut global_scores);
        let mut candidates: Vec<_> = self
            .peers
            .iter()
            .filter_map(|(conn, peer)| {
                if !peer.topics.contains(&topic) ||
                    mesh.contains(conn) ||
                    scoring::candidate_score(peer) <= bar ||
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

fn ip_bytes_to_addr(ip: IpBytes) -> IpAddr {
    match ip {
        IpBytes::V4(o) => IpAddr::V4(std::net::Ipv4Addr::from(o)),
        IpBytes::V6(o) => IpAddr::V6(std::net::Ipv6Addr::from(o)),
    }
}

/// Median of `values`, sorting it in place. Empty yields 0.0.
fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_unstable_by(|a, b| a.total_cmp(b));
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) * 0.5
    } else {
        values[middle]
    }
}

#[cfg(test)]
mod tests {
    use silver_common::PeerEvent;
    use silver_config::ScoreParams;

    use super::*;
    use crate::manager::fixture::*;

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
    /// A remote that re-GRAFTs inside the backoff we advertised earns P7;
    /// one that waits the advertised window out lands in `is_backed_off`'s
    /// heartbeat slack — still refused, but not penalised for our own grace.
    fn regraft_inside_advertised_backoff_earns_p7() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let (mut mgr, mut cap) = fixture(vec![topic], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        let backoff = mgr.params.prune_backoff;
        for conn in [1, 2] {
            mgr.do_prune(conn, peer_id(conn as u8), topic, now, "test", &mut |event| {
                cap.0.push(event)
            });
        }

        mgr.handle_event(
            PeerEvent::P2pGossipTopicGraft { p2p_peer: 1, topic },
            now + Duration::from_secs(1),
            &mut |event| cap.0.push(event),
        );
        assert_eq!(mgr.peers[&1].behaviour_penalty, 1.0, "early re-GRAFT must earn P7");

        mgr.handle_event(
            PeerEvent::P2pGossipTopicGraft { p2p_peer: 2, topic },
            now + backoff,
            &mut |event| cap.0.push(event),
        );
        assert_eq!(mgr.peers[&2].behaviour_penalty, 0.0, "honoured backoff must not earn P7");
        assert!(!mgr.mesh[&topic].contains(&2), "slack window still refuses the graft");
    }

    #[test]
    /// The trigger is a fraction of the class's saturation, not an absolute:
    /// an attestation subnet saturates near 2.0, so a healthy attnet mesh
    /// must not read as underperforming the way a fixed threshold made it.
    fn opportunistic_graft_threshold_scales_with_topic_class() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconAttestation(0);
        let mut params = ScoreParams::default();
        params.d = 2;
        params.d_low = 0;
        params.d_high = 8;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=4 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe { p2p_peer: conn, topic },
                now,
                &mut |event| cap.0.push(event),
            );
        }
        for conn in [1, 2] {
            mgr.do_graft(conn, peer_id(conn as u8), topic, now, false, &mut |event| {
                cap.0.push(event)
            });
            // Saturate this topic's P2 (cap 1000 × weight 0.001 = 1.0).
            mgr.peers
                .get_mut(&conn)
                .unwrap()
                .topic_stats
                .get_mut(&topic)
                .unwrap()
                .first_deliveries = 1000.0;
        }
        for conn in [3, 4] {
            mgr.peers.get_mut(&conn).unwrap().cached_score = 5.0;
        }

        let established = mgr.last_opportunistic_graft +
            OPPORTUNISTIC_GRAFT_INTERVAL +
            Duration::from_secs_f64(mgr.params.mesh_message_deliveries_activation_s);
        mgr.manage_mesh(established, &mut |event| cap.0.push(event));
        assert_eq!(mgr.mesh_size(topic), 2, "saturated attnet mesh must not graft");

        // Same mesh with no deliveries falls under the fractional bar.
        for conn in [1, 2] {
            mgr.peers
                .get_mut(&conn)
                .unwrap()
                .topic_stats
                .get_mut(&topic)
                .unwrap()
                .first_deliveries = 0.0;
        }
        mgr.manage_mesh(established + OPPORTUNISTIC_GRAFT_INTERVAL, &mut |event| cap.0.push(event));
        assert_eq!(mgr.mesh_size(topic), 4, "starved attnet mesh must graft");
    }

    #[test]
    /// Candidates hold no topic-local record, so they are ranked on global
    /// merit against the members' global median — scoring them on the
    /// topic-local scale would zero out delivery credit earned elsewhere.
    fn opportunistic_graft_ranks_candidates_on_global_merit() {
        let now = Instant::now();
        let topic = GossipTopic::BeaconBlock;
        let mut params = ScoreParams::default();
        params.d = 2;
        params.d_low = 0;
        params.d_high = 8;
        let (mut mgr, mut cap) = fixture(vec![topic], params);
        for conn in 1..=4 {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
            mgr.handle_event(
                PeerEvent::P2pGossipTopicSubscribe { p2p_peer: conn, topic },
                now,
                &mut |event| cap.0.push(event),
            );
        }
        for conn in [1, 2] {
            mgr.do_graft(conn, peer_id(conn as u8), topic, now, false, &mut |event| {
                cap.0.push(event)
            });
            mgr.peers.get_mut(&conn).unwrap().cached_score = 1.0;
        }
        // Candidate 3's merit is entirely P2 earned on other topics; 4 sits
        // below the members' global median.
        let three = mgr.peers.get_mut(&3).unwrap();
        three.cached_score = 10.0;
        three.last_breakdown.p2_first_deliveries = 10.0;
        mgr.peers.get_mut(&4).unwrap().cached_score = 0.5;

        let established = mgr.last_opportunistic_graft +
            OPPORTUNISTIC_GRAFT_INTERVAL +
            Duration::from_secs_f64(mgr.params.mesh_message_deliveries_activation_s);
        mgr.manage_mesh(established, &mut |event| cap.0.push(event));

        let mesh = &mgr.mesh[&topic];
        assert!(mesh.contains(&3), "candidate with global delivery merit must be grafted");
        assert!(!mesh.contains(&4), "candidate below the members' global median must not be");
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
    fn invalid_frames_increment_behaviour_penalty_and_tick_bans() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0; // excess^2 * -10
        params.graylist_threshold = -80.0; // behaviour_penalty=3 → score=-90
        params.ip_ban_threshold = 1; // single eviction → BanIp for this test
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

    fn connect_dialler(
        mgr: &mut PeerManager,
        cap: &mut Captured,
        conn: usize,
        seed: u8,
        local_dial: bool,
        now: Instant,
    ) {
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: conn,
                peer_id_full: peer_id(seed),
                ip: IpBytes::V4([10, 0, 0, seed]),
                port: 4000 + seed as u16,
                local_dial,
            },
            now,
            &mut |c| cap.0.push(c),
        );
    }

    #[test]
    fn duplicate_crossing_connections_keep_deterministic_survivor() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect_dialler(&mut mgr, &mut cap, 1, 1, true, now);
        connect_dialler(&mut mgr, &mut cap, 2, 1, false, now);

        let local_lower = peer_id(99).as_bytes() < peer_id(1).as_bytes();
        let survivor = if local_lower { 1 } else { 2 };
        let loser = if local_lower { 2 } else { 1 };

        assert_eq!(mgr.peers.len(), 1);
        assert!(mgr.peers.contains_key(&survivor));
        assert!(cap.0.iter().any(|c| matches!(
            c,
            PeerControl::P2pDisconnect { p2p_connection, .. } if *p2p_connection == loser
        )));
    }

    #[test]
    fn duplicate_same_direction_keeps_newest() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect_dialler(&mut mgr, &mut cap, 1, 1, false, now);
        connect_dialler(&mut mgr, &mut cap, 2, 1, false, now);

        assert_eq!(mgr.peers.len(), 1);
        assert!(mgr.peers.contains_key(&2));
        assert!(cap.0.iter().any(|c| matches!(
            c,
            PeerControl::P2pDisconnect { p2p_connection, .. } if *p2p_connection == 1
        )));
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
        let mut params = ScoreParams::default();
        // Zero free budget so the archived penalty shows in the score.
        params.behaviour_penalty_threshold = 0.0;
        let (mut mgr, mut cap) = fixture(vec![], params);
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
        let (mut mgr, mut cap) = fixture(vec![], params);
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
            now += Duration::from_secs(12);
            mgr.tick(now, &mut |c| cap.0.push(c));
        }
        let s = mgr.score(1).unwrap();
        assert!(s.abs() < 1e-6, "expected score ≈ 0 after decay, got {s}");
    }
}
