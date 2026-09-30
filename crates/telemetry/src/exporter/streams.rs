//! Spine-side sources: peer stats and per-block stage events, streamed as
//! they arrive rather than bucketed. Stage events come from the tile's one
//! `StageReader`, shared with the other sinks.

use flux::spine::SpineAdapter;
use silver_common::{
    BlockSource, ColumnOrigin, P2pConnectionStats, PeerScores as NodePeerScores, PeerStats,
    PeerTopicScores, SilverSpine,
};
use silver_observe_wire::{Encoder, PeerP2p, PeerScores, PeerTopic, StageCode, StageRecord};
use silver_stages::{Stage, StageEvent};

/// The exporter is the only reader of `peer_stats`.
pub fn drain_peer_stats(
    adapter: &mut SpineAdapter<SilverSpine>,
    enc: &mut Encoder,
    ts_ns: u64,
    emit: &mut impl FnMut(&[u8]),
) {
    adapter.consume(|stats: PeerStats, _| match &stats {
        PeerStats::P2p(s) => enc.peer_p2p(ts_ns, &p2p_record(s), emit),
        PeerStats::Scores(s) => enc.peer_scores(ts_ns, &scores_record(s), emit),
        PeerStats::Topic(s) => enc.peer_topic(ts_ns, &topic_record(s), emit),
    });
}

pub fn encode_stage(
    enc: &mut Encoder,
    ts_ns: u64,
    event: &StageEvent,
    emit: &mut impl FnMut(&[u8]),
) {
    enc.stage(ts_ns, &stage_record(event), emit);
}

fn p2p_record(s: &P2pConnectionStats) -> PeerP2p<'_> {
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

fn scores_record(s: &NodePeerScores) -> PeerScores<'_> {
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

fn topic_record(s: &PeerTopicScores) -> PeerTopic<'_> {
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

fn stage_record(e: &StageEvent) -> StageRecord {
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
