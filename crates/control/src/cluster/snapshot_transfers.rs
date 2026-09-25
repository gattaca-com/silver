use std::time::{Duration, Instant};

use raft::{
    ProgressState, RawNode, SnapshotStatus, StateRole,
    eraftpb::{Message, MessageType},
};

use super::raft_storage::RaftStorage;

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
        if let Some(transfer) = self.pending.iter_mut().find(|transfer| transfer.peer == message.to)
        {
            transfer.started = now;
        } else {
            self.pending.push(Transfer { peer: message.to, started: now });
        }
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
            tracing::warn!(peer = transfer.peer, "Raft snapshot transfer timed out");
            false
        });
    }
}
