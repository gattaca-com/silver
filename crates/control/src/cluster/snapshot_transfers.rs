use std::time::{Duration, Instant};

use raft::{
    ProgressState, RawNode, SnapshotStatus, StateRole,
    eraftpb::{Message, MessageType},
};

use super::{metrics::ClusterCounters, raft_storage::RaftStorage};

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(super) struct SnapshotTransfers {
    pending: Vec<Transfer>,
}

struct Transfer {
    peer: u64,
    started: Instant,
}

impl SnapshotTransfers {
    pub fn sent(&mut self, message: &Message, now: Instant) {
        if message.msg_type != MessageType::MsgSnapshot {
            return;
        }
        ClusterCounters::SnapshotsSent.inc();
        if let Some(transfer) = self.pending.iter_mut().find(|transfer| transfer.peer == message.to)
        {
            transfer.started = now;
        } else {
            self.pending.push(Transfer { peer: message.to, started: now });
        }
    }

    /// The network reports only that a send to `peer` failed, not which
    /// message. A lost connection loses an in-flight snapshot too, so a
    /// pending transfer fails rather than waiting out its timeout.
    pub fn unreachable(&mut self, node: &mut RawNode<RaftStorage>, peer: u64) {
        let Some(index) = self.pending.iter().position(|transfer| transfer.peer == peer) else {
            return;
        };
        self.pending.swap_remove(index);
        node.report_snapshot(peer, SnapshotStatus::Failure);
        ClusterCounters::SnapshotTransferFailures.inc();
    }

    #[cfg(test)]
    pub fn is_pending(&self, peer: u64) -> bool {
        self.pending.iter().any(|transfer| transfer.peer == peer)
    }

    pub fn expire(&mut self, node: &mut RawNode<RaftStorage>, now: Instant) {
        self.pending.retain(|transfer| {
            if node.raft.state != StateRole::Leader ||
                node.raft
                    .prs()
                    .get(transfer.peer)
                    .is_none_or(|progress| progress.state != ProgressState::Snapshot)
            {
                return false;
            }
            if now.saturating_duration_since(transfer.started) < TRANSFER_TIMEOUT {
                return true;
            }
            node.report_snapshot(transfer.peer, SnapshotStatus::Failure);
            ClusterCounters::SnapshotTransferTimeouts.inc();
            silver_log::warn!(peer = transfer.peer, "Raft snapshot transfer timed out");
            false
        });
    }
}
