//! Wire records for spine-side sources: peer stats and per-block stage
//! events. Stage events come from the tile's one `StageReader`, shared with
//! the other sinks.
use std::time::Duration;

use silver_common::{
    BlockSource, ClusterCommit as NodeClusterCommit, ClusterDuty, ClusterLinkStats, ClusterOutcome,
    ClusterPeerStats, ClusterProgress, ColumnOrigin, P2pConnectionStats,
    PeerScores as NodePeerScores, PeerTopicScores,
};
use silver_observe_wire::{
    ClusterCommit, ClusterDutyCode, ClusterLink, ClusterOutcomeCode, ClusterPeer,
    ClusterProgressCode, PeerP2p, PeerScores, PeerTopic, StageCode, StageRecord,
};
use silver_stages::{Stage, StageEvent};

pub(super) fn p2p_record(s: &P2pConnectionStats) -> PeerP2p<'_> {
    PeerP2p {
        peer: s.id.as_bytes(),
        connection: s.connection as u64,
        addr: s.addr,
        inbound: s.inbound,
        connected_ms: s.connected.as_millis() as u64,
        rtt_us: s.rtt.as_micros() as u64,
        lost_packets: s.lost_packets,
        rx_blocking: s.rx_blocking,
        tx_blocking: s.tx_blocking,
        rx_datagrams: s.rx_datagrams,
        tx_datagrams: s.tx_datagrams,
        streams: s.streams,
    }
}

pub(super) fn cluster_peer_record(
    s: &ClusterPeerStats,
    link: Option<&ClusterLinkStats>,
) -> ClusterPeer {
    ClusterPeer {
        node_id: s.node_id,
        is_leader: s.is_leader,
        progress: match s.progress {
            ClusterProgress::Follower => ClusterProgressCode::Follower,
            ClusterProgress::Probe => ClusterProgressCode::Probe,
            ClusterProgress::Replicate => ClusterProgressCode::Replicate,
            ClusterProgress::Snapshot => ClusterProgressCode::Snapshot,
        },
        last_contact_us: s.last_contact.map(|age| age.as_micros() as u64),
        match_index: s.match_index,
        next_index: s.next_index,
        inflight: s.inflight,
        raft_rtt_us: s.raft_rtt.map(|rtt| rtt.as_micros() as u64),
        messages_out: s.messages_out,
        messages_in: s.messages_in,
        link: link.map(|link| ClusterLink {
            connected: link.connected,
            rtt_us: link.rtt.as_micros() as u64,
            out_queue_len: link.out_queue_len,
            overwrites: link.overwrites,
        }),
    }
}

pub(super) fn cluster_commit_record(c: &NodeClusterCommit) -> ClusterCommit {
    let us = |d: Duration| d.as_micros() as u64;
    ClusterCommit {
        slot: c.slot,
        slot_offset_us: us(c.slot_offset),
        total_us: us(c.total),
        append_us: c.append.map(us),
        persist_us: c.persist.map(us),
        quorum_us: c.quorum.map(us),
        duty: match c.duty {
            ClusterDuty::Attestation => ClusterDutyCode::Attestation,
            ClusterDuty::Block => ClusterDutyCode::Block,
        },
        leader_origin: c.leader_origin,
        outcome: match c.outcome {
            ClusterOutcome::Accepted => ClusterOutcomeCode::Accepted,
            ClusterOutcome::Same => ClusterOutcomeCode::Same,
            ClusterOutcome::Conflicting => ClusterOutcomeCode::Conflicting,
            ClusterOutcome::Surrounding => ClusterOutcomeCode::Surrounding,
            ClusterOutcome::TooOld => ClusterOutcomeCode::TooOld,
            ClusterOutcome::Invalid => ClusterOutcomeCode::Invalid,
            ClusterOutcome::TimedOut => ClusterOutcomeCode::TimedOut,
        },
    }
}

pub(super) fn scores_record(s: &NodePeerScores) -> PeerScores<'_> {
    PeerScores {
        peer: s.id.as_bytes(),
        user_agent: s.user_agent.as_str(),
        mesh_count: s.mesh_count,
        p1_time_in_mesh: s.p1_time_in_mesh,
        p2_first_deliveries: s.p2_first_deliveries,
        p3_mesh_deficit: s.p3_mesh_deficit,
        p3b_mesh_failure: s.p3b_mesh_failure,
        p4_invalid: s.p4_invalid,
        p5_application: s.p5_application,
        p6_ip_colocation: s.p6_ip_colocation,
        p7_behaviour: s.p7_behaviour,
        total: s.total,
    }
}

pub(super) fn topic_record(s: &PeerTopicScores) -> PeerTopic<'_> {
    PeerTopic {
        peer: s.id.as_bytes(),
        topic_slot: s.topic.counter_slot() as u16,
        p3_scored: s.p3_scored,
        mesh_active: s.mesh_active,
        meshed_secs: s.meshed_secs,
        fanout_total: s.fanout_total,
        fanout_sent: s.fanout_sent,
        first_deliveries: s.first_deliveries,
        mesh_deliveries: s.mesh_deliveries,
        mesh_failure_penalty: s.mesh_failure_penalty,
        invalid_deliveries: s.invalid_deliveries,
    }
}

pub(super) fn stage_record(e: &StageEvent) -> StageRecord {
    let source = |s: BlockSource| match s {
        BlockSource::Gossip => 0,
        BlockSource::Rpc => 1,
    };
    let origin = |o: ColumnOrigin| match o {
        ColumnOrigin::Gossip => 0,
        ColumnOrigin::Rpc => 1,
        ColumnOrigin::El => 2,
        ColumnOrigin::Assembly => 3,
    };
    let (stage, detail, column_index) = match e.stage {
        Stage::Received { source: s } => (StageCode::Received, source(s), None),
        Stage::ColumnRecv { index, origin: o } => (StageCode::ColumnRecv, origin(o), Some(index)),
        Stage::ColumnValidated { index, origin: o } => {
            (StageCode::ColumnValidated, origin(o), Some(index))
        }
        Stage::ElSent { source: s } => (StageCode::ElSent, source(s), None),
        Stage::ElVerdict { verdict } => (StageCode::ElVerdict, verdict as u8, None),
        Stage::DaAvailable => (StageCode::DaAvailable, 0, None),
        Stage::CustodyDone => (StageCode::CustodyDone, 0, None),
        Stage::StfDone => (StageCode::StfDone, 0, None),
        Stage::Attestable => (StageCode::Attestable, 0, None),
    };
    StageRecord {
        block_root: e.block_root,
        ts_ns: e.ts.0,
        slot: e.slot,
        column_index,
        stage,
        detail,
    }
}
