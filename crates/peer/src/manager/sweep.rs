use std::{collections::HashMap, mem, time::Instant};

use silver_common::{
    GOSSIP_TOPIC_COUNTER_SLOTS, GossipTopic, P2pSend, PeerControl, PeerScores, RpcOutbound,
    RpcRequest, RpcRequestOutbound, StreamProtocol, ssz_view::MetadataView,
};

use super::{
    IDLE_PEER_MAX_SCORE, IDLE_PEER_MIN_AGE, MAX_IDLE_GOODBYES, PeerManager,
    rpc::MAX_RPC_PROTOCOL_IN_FLIGHT,
};
use crate::{
    counters::GossipTopicCounters,
    scoring,
    state::{IpPrefix, PeerState},
};

/// Per-peer work recorded by its triggers since the last pass, so that one
/// pass over the live peers serves all of it.
#[derive(Default)]
pub(super) struct SweepWork {
    pub(super) reset_heartbeat: bool,
    pub(super) decay: bool,
    /// Rescore, report, census, and the population management that needs the
    /// census.
    pub(super) rescore: bool,
    pub(super) ping: bool,
    pub(super) status: bool,
    pub(super) persist: bool,
    pub(super) drop_inactive_subscriptions: bool,
    /// Sent to every peer in order.
    pub(super) subscriptions: Vec<SubscriptionChange>,
}

impl SweepWork {
    fn is_empty(&self) -> bool {
        !(self.reset_heartbeat ||
            self.decay ||
            self.rescore ||
            self.ping ||
            self.status ||
            self.persist ||
            self.drop_inactive_subscriptions) &&
            self.subscriptions.is_empty()
    }
}

#[derive(Clone, Copy)]
pub(super) struct SubscriptionChange {
    pub(super) topic: GossipTopic,
    pub(super) digest: [u8; 4],
    pub(super) subscribe: bool,
}

/// Moved straight into the caller's callback, never stored, so the variant
/// size gap costs nothing; boxing would allocate per control.
#[allow(clippy::large_enum_variant)]
pub enum SweepOutput {
    Control(PeerControl),
    Scores(PeerScores),
}

/// What the rescore leaves for the population management after the pass.
struct Census {
    subscribers: [u16; GOSSIP_TOPIC_COUNTER_SLOTS],
    negative: [(usize, f64); 256],
    negative_len: usize,
    idle: [usize; MAX_IDLE_GOODBYES],
    idle_len: usize,
    pending_goodbyes: usize,
    graylisted: Vec<usize>,
}

impl Census {
    fn new() -> Self {
        Self {
            subscribers: [0; GOSSIP_TOPIC_COUNTER_SLOTS],
            negative: [(0, 0.0); 256],
            negative_len: 0,
            idle: [0; MAX_IDLE_GOODBYES],
            idle_len: 0,
            pending_goodbyes: 0,
            graylisted: Vec::new(),
        }
    }

    fn count(&mut self, conn: usize, peer: &PeerState, graylist_threshold: f64, now: Instant) {
        if !peer.is_trusted && peer.cached_score < graylist_threshold {
            self.graylisted.push(conn);
        }
        if peer.goodbye_sent {
            self.pending_goodbyes += 1;
            return;
        }
        if !peer.is_trusted && peer.cached_score < 0.0 && self.negative_len < self.negative.len() {
            self.negative[self.negative_len] = (conn, peer.cached_score);
            self.negative_len += 1;
        // Deadweight: long-connected, in no mesh, nothing scored either way.
        // It has had every chance to be grafted.
        } else if !peer.is_trusted &&
            peer.cached_score <= IDLE_PEER_MAX_SCORE &&
            self.idle_len < self.idle.len() &&
            now.saturating_duration_since(peer.connected_at) > IDLE_PEER_MIN_AGE &&
            peer.topic_stats.values().all(|s| s.meshed_since.is_none())
        {
            self.idle[self.idle_len] = conn;
            self.idle_len += 1;
        }
    }
}

impl PeerManager {
    /// Runs the per-peer work recorded since the last call in one pass over
    /// the live peers. A no-op when nothing was recorded.
    pub fn sweep(&mut self, now: Instant, out: &mut impl FnMut(SweepOutput)) {
        if self.sweep_work.is_empty() {
            return;
        }
        let mut work = mem::take(&mut self.sweep_work);
        let census = self.visit_peers(&work, now, out);

        if let Some(census) = census {
            self.manage_population(census, now, &mut |control| out(SweepOutput::Control(control)));
        }

        work.subscriptions.clear();
        self.sweep_work.subscriptions = work.subscriptions;
    }

    fn visit_peers(
        &mut self,
        work: &SweepWork,
        now: Instant,
        out: &mut impl FnMut(SweepOutput),
    ) -> Option<Census> {
        let mut census = work.rescore.then(Census::new);
        let mut ours = [false; GOSSIP_TOPIC_COUNTER_SLOTS];
        for topic in &self.our_topics {
            ours[topic.counter_slot()] = true;
        }
        let peers_by_prefix: HashMap<IpPrefix, usize> = if work.rescore {
            self.ip_colocations.iter().map(|(k, v)| (*k, v.len())).collect()
        } else {
            HashMap::new()
        };
        let mesh_counts = if work.rescore { self.mesh_counts() } else { HashMap::new() };
        let ping = work.ping.then(|| {
            let seq = MetadataView::seq_number(self.metadata());
            RpcRequest::Ping(seq.to_le_bytes())
        });
        let status =
            if work.status { self.status().copied().map(RpcRequest::StatusV2) } else { None };
        let active_domains = self.active_gossip_domains;
        if work.drop_inactive_subscriptions {
            self.subscribers.retain_topics(|&(digest, topic)| {
                Self::topic_active_on_domains(active_domains, topic, digest)
            });
        }

        let Self { peers, params, database, .. } = self;
        for (&conn, peer) in peers.iter_mut() {
            for change in &work.subscriptions {
                let SubscriptionChange { topic, digest, subscribe } = *change;
                let (p2p, p2p_connection) = (peer.peer_id, conn);
                out(SweepOutput::Control(if subscribe {
                    PeerControl::P2pGossipSubscribe { p2p, p2p_connection, topic, digest }
                } else {
                    PeerControl::P2pGossipUnsubscribe { p2p, p2p_connection, topic, digest }
                }));
            }
            if work.drop_inactive_subscriptions {
                peer.subscriptions.retain(|(digest, topic), _| {
                    Self::topic_active_on_domains(active_domains, *topic, *digest)
                });
            }
            if work.reset_heartbeat {
                peer.ihaves_received = 0;
                peer.iwant_ids_sent = 0;
            }
            if work.decay {
                scoring::decay(peer, params);
            }
            if let Some(census) = &mut census {
                let mut counted = [false; GOSSIP_TOPIC_COUNTER_SLOTS];
                for (_, topic) in peer.subscriptions.keys() {
                    let slot = topic.counter_slot();
                    if ours[slot] && !counted[slot] {
                        census.subscribers[slot] = census.subscribers[slot].saturating_add(1);
                        counted[slot] = true;
                    }
                }
                let coloc = *peers_by_prefix.get(&peer.ip_prefix).unwrap_or(&1);
                peer.last_breakdown = scoring::score_breakdown(peer, params, coloc, now);
                peer.cached_score = peer.last_breakdown.total;
                peer.score_valid_at = now;
                if peer.is_trusted || peer.cached_score >= params.graylist_threshold {
                    peer.evict_spared = false;
                }
                census.count(conn, peer, params.graylist_threshold, now);
                out(SweepOutput::Scores(peer.scores(mesh_counts.get(&conn).copied().unwrap_or(0))));
            }
            if let Some(ping) = ping &&
                peer.outbound_has_capacity(
                    conn,
                    StreamProtocol::Ping,
                    1,
                    now,
                    MAX_RPC_PROTOCOL_IN_FLIGHT,
                ) &&
                peer.try_admit_outbound(conn, StreamProtocol::Ping, 1, now, true)
            {
                out(SweepOutput::Control(rpc_request(conn, ping)));
            }
            if let Some(status) = status &&
                peer.try_admit_outbound(conn, StreamProtocol::StatusV2, 1, now, false)
            {
                out(SweepOutput::Control(rpc_request(conn, status)));
            }
            if work.persist &&
                let Some(record) = database.by_p2p_id(conn) &&
                record.status.is_some() &&
                let Some(enr) = record.enr
            {
                out(SweepOutput::Control(PeerControl::PersistPeer { enr }));
            }
        }
        census
    }

    fn manage_population(
        &mut self,
        census: Census,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        GossipTopicCounters::subscribed(&census.subscribers);
        self.evict_graylisted(&census.graylisted, now, emit);
        self.manage_mesh(now, emit);
        self.gc_archived(now);
        self.gc_banned_ips(now, emit);
        self.gc_banned_peers(now, emit);
        self.maybe_request_discovery(now, emit);
        self.sweep_stalled_attempts(now);
        self.expire_dials(now);
        self.manage_peers(
            now,
            census.negative,
            census.negative_len,
            census.idle,
            census.idle_len,
            census.pending_goodbyes,
            emit,
        );
        crate::PeerCounters::PeersConnected.set(self.peers.len() as u64);
    }
}

fn rpc_request(peer: usize, request: RpcRequest) -> PeerControl {
    PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
        application_id: 0,
        peer,
        request,
    })))
}
