use std::time::{Duration, Instant};

use raft::{
    ProgressState, RawNode, StateRole,
    eraftpb::{ConfState, Message, MessageType},
};
use silver_common::{ClusterPeerStats, ClusterProgress};

use super::raft_storage::RaftStorage;

/// An unanswered heartbeat older than this is presumed lost, so the next one
/// starts a fresh measurement.
const HEARTBEAT_LOST: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Peer {
    node_id: u64,
    last_contact: Option<Instant>,
    heartbeat_sent: Option<Instant>,
    raft_rtt: Option<Duration>,
    messages_out: u64,
    messages_in: u64,
}

#[derive(Default)]
pub(super) struct ClusterPeers {
    peers: Vec<Peer>,
}

impl ClusterPeers {
    /// Keeps the stats of members that stay.
    pub(super) fn set_members(&mut self, local_id: u64, membership: &ConfState) {
        let members = || {
            membership
                .voters
                .iter()
                .chain(&membership.voters_outgoing)
                .chain(&membership.learners)
                .chain(&membership.learners_next)
                .copied()
                .filter(move |&node_id| node_id != local_id)
        };
        self.peers.retain(|peer| members().any(|node_id| node_id == peer.node_id));
        for node_id in members() {
            if self.peer(node_id).is_none() {
                self.peers.push(Peer { node_id, ..Peer::default() });
            }
        }
    }

    fn peer(&mut self, node_id: u64) -> Option<&mut Peer> {
        self.peers.iter_mut().find(|peer| peer.node_id == node_id)
    }

    pub(super) fn sent(&mut self, message: &Message, now: Instant) {
        let Some(peer) = self.peer(message.to) else { return };
        peer.messages_out += 1;
        if message.msg_type == MessageType::MsgHeartbeat &&
            peer.heartbeat_sent
                .is_none_or(|sent| now.saturating_duration_since(sent) > HEARTBEAT_LOST)
        {
            peer.heartbeat_sent = Some(now);
        }
    }

    pub(super) fn heard(&mut self, message: &Message, now: Instant) {
        let Some(peer) = self.peer(message.from) else { return };
        peer.messages_in += 1;
        peer.last_contact = Some(now);
        if message.msg_type == MessageType::MsgHeartbeatResponse &&
            let Some(sent) = peer.heartbeat_sent.take()
        {
            peer.raft_rtt = Some(now.saturating_duration_since(sent));
        }
    }

    pub(super) fn stats(
        &self,
        node: &RawNode<RaftStorage>,
        now: Instant,
    ) -> impl Iterator<Item = ClusterPeerStats> {
        let raft = &node.raft;
        let leading = raft.state == StateRole::Leader;
        self.peers.iter().map(move |peer| {
            let progress = leading.then(|| raft.prs().get(peer.node_id)).flatten();
            ClusterPeerStats {
                node_id: peer.node_id,
                is_leader: raft.leader_id == peer.node_id,
                last_contact: peer.last_contact.map(|at| now.saturating_duration_since(at)),
                progress: progress.map_or(ClusterProgress::Follower, |progress| {
                    match progress.state {
                        ProgressState::Probe => ClusterProgress::Probe,
                        ProgressState::Replicate => ClusterProgress::Replicate,
                        ProgressState::Snapshot => ClusterProgress::Snapshot,
                    }
                }),
                match_index: progress.map_or(0, |progress| progress.matched),
                next_index: progress.map_or(0, |progress| progress.next_idx),
                inflight: progress.map_or(0, |progress| progress.ins.count() as u64),
                raft_rtt: peer.raft_rtt.filter(|_| leading),
                messages_out: peer.messages_out,
                messages_in: peer.messages_in,
            }
        })
    }
}
