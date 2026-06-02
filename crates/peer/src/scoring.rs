//! Score computation for a single peer.
//!
//! `compute_score` is a pure function over `&PeerState` + `&ScoreParams` +
//! `Instant`, with `ip_colocation_peers` passed explicitly so the function
//! stays independent of the outer manager's indexes. This keeps unit tests
//! trivial — hand-craft a `PeerState`, call, assert.

use std::time::Instant;

use silver_config::ScoreParams;

use crate::state::PeerState;

/// Per-component score contributions. P1–P4 are summed across topics; total
/// is the sum of all fields and matches `compute_score`. Used for eviction
/// diagnostics so the dominant negative component is visible.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct ScoreBreakdown {
    pub p1_time_in_mesh: f64,
    pub p2_first_deliveries: f64,
    pub p3_mesh_deficit: f64,
    pub p3b_mesh_failure: f64,
    pub p4_invalid: f64,
    pub p5_application: f64,
    pub p6_ip_colocation: f64,
    pub p7_behaviour: f64,
    pub total: f64,
}

/// Compute the current peer score.
///
/// `ip_colocation_peers` is the count of currently-connected peers sharing
/// this peer's /24 (v4) or /64 (v6) prefix (including this peer). The
/// manager supplies this value at call time; the scoring fn has no state.
pub(crate) fn compute_score(
    state: &PeerState,
    params: &ScoreParams,
    ip_colocation_peers: usize,
    now: Instant,
) -> f64 {
    score_breakdown(state, params, ip_colocation_peers, now).total
}

/// Per-component score breakdown. `compute_score` delegates to this.
pub(crate) fn score_breakdown(
    state: &PeerState,
    params: &ScoreParams,
    ip_colocation_peers: usize,
    now: Instant,
) -> ScoreBreakdown {
    let mut b = ScoreBreakdown::default();

    for t in state.topic_stats.values() {
        // P1 — time in mesh (linear, capped).
        if let Some(since) = t.meshed_since {
            let age = now.saturating_duration_since(since).as_secs_f64();
            b.p1_time_in_mesh += age.min(params.time_in_mesh_cap_s) * params.time_in_mesh_weight;
        }
        // P2 — first-message deliveries (linear, capped).
        b.p2_first_deliveries += t.first_deliveries.min(params.first_message_deliveries_cap) *
            params.first_message_deliveries_weight;
        // P3 — mesh delivery deficit, squared. Only active after the grace
        // window, and only penalises below threshold (weight is negative).
        if t.mesh_active && t.mesh_deliveries < params.mesh_message_deliveries_threshold {
            let deficit = params.mesh_message_deliveries_threshold - t.mesh_deliveries;
            b.p3_mesh_deficit += deficit * deficit * params.mesh_message_deliveries_weight;
        }
        // P3b — carried forward from prior mesh pruning.
        b.p3b_mesh_failure += t.mesh_failure_penalty * params.mesh_failure_penalty_weight;
        // P4 — invalid-message deliveries, squared (weight negative).
        b.p4_invalid +=
            t.invalid_deliveries * t.invalid_deliveries * params.invalid_message_deliveries_weight;
    }

    // P5 — application-specific score.
    b.p5_application = state.application_score;

    // P6 — IP colocation, squared excess over threshold.
    if ip_colocation_peers > params.ip_colocation_threshold {
        let excess = (ip_colocation_peers - params.ip_colocation_threshold) as f64;
        b.p6_ip_colocation = excess * excess * params.ip_colocation_weight;
    }

    // P7 — behaviour penalty, squared excess over threshold.
    if state.behaviour_penalty > params.behaviour_penalty_threshold {
        let excess = state.behaviour_penalty - params.behaviour_penalty_threshold;
        b.p7_behaviour = excess * excess * params.behaviour_penalty_weight;
    }

    b.total = b.p1_time_in_mesh +
        b.p2_first_deliveries +
        b.p3_mesh_deficit +
        b.p3b_mesh_failure +
        b.p4_invalid +
        b.p5_application +
        b.p6_ip_colocation +
        b.p7_behaviour;
    b
}

/// Apply per-tick decay to all counters on a peer. Counters below
/// `decay_to_zero` after multiplication are clamped to 0 to avoid floats
/// hovering forever.
pub(crate) fn decay(state: &mut PeerState, params: &ScoreParams) {
    decay_to_floor(
        &mut state.behaviour_penalty,
        params.behaviour_penalty_decay,
        params.decay_to_zero,
    );

    for t in state.topic_stats.values_mut() {
        decay_to_floor(
            &mut t.first_deliveries,
            params.first_message_deliveries_decay,
            params.decay_to_zero,
        );
        decay_to_floor(
            &mut t.mesh_deliveries,
            params.mesh_message_deliveries_decay,
            params.decay_to_zero,
        );
        decay_to_floor(
            &mut t.invalid_deliveries,
            params.invalid_message_deliveries_decay,
            params.decay_to_zero,
        );
        decay_to_floor(
            &mut t.mesh_failure_penalty,
            params.mesh_failure_penalty_decay,
            params.decay_to_zero,
        );
    }
}

#[inline]
fn decay_to_floor(x: &mut f64, decay: f64, floor: f64) {
    *x *= decay;
    if *x < floor {
        *x = 0.0;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };

    use silver_common::{GossipTopic, Keypair};

    use super::*;
    use crate::state::TopicScore;

    fn mk_state(now: Instant) -> PeerState {
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4242);
        PeerState::new(kp.peer_id(), addr, now)
    }

    #[test]
    fn empty_state_scores_zero() {
        let params = ScoreParams::default();
        let now = Instant::now();
        let state = mk_state(now);
        assert_eq!(compute_score(&state, &params, 1, now), 0.0);
    }

    #[test]
    fn invalid_deliveries_is_quadratic_and_negative() {
        let params = ScoreParams::default();
        let now = Instant::now();
        let mut state = mk_state(now);
        let mut t = TopicScore::default();
        t.invalid_deliveries = 3.0;
        state.topic_stats.insert(GossipTopic::BeaconBlock, t);
        // 3^2 * -100 = -900
        let s = compute_score(&state, &params, 1, now);
        assert!((s - -900.0).abs() < 1e-9, "got {s}");
    }

    #[test]
    fn behaviour_penalty_squared_over_threshold() {
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 2.0;
        params.behaviour_penalty_weight = -5.0;
        let now = Instant::now();
        let mut state = mk_state(now);
        state.behaviour_penalty = 5.0; // excess = 3
        // 3^2 * -5 = -45
        let s = compute_score(&state, &params, 1, now);
        assert!((s - -45.0).abs() < 1e-9, "got {s}");
    }

    #[test]
    fn behaviour_penalty_below_threshold_contributes_zero() {
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 5.0;
        let now = Instant::now();
        let mut state = mk_state(now);
        state.behaviour_penalty = 4.0; // below threshold
        assert_eq!(compute_score(&state, &params, 1, now), 0.0);
    }

    #[test]
    fn ip_colocation_excess_is_quadratic() {
        let mut params = ScoreParams::default();
        params.ip_colocation_threshold = 2;
        params.ip_colocation_weight = -1.0;
        let now = Instant::now();
        let state = mk_state(now);
        // 5 peers on same prefix, threshold 2 → excess 3 → 9 * -1 = -9
        let s = compute_score(&state, &params, 5, now);
        assert!((s - -9.0).abs() < 1e-9, "got {s}");
    }

    #[test]
    fn time_in_mesh_capped() {
        let mut params = ScoreParams::default();
        params.time_in_mesh_cap_s = 10.0;
        params.time_in_mesh_weight = 1.0;
        let now = Instant::now();
        let mut state = mk_state(now);
        let mut t = TopicScore::default();
        t.meshed_since = Some(now - Duration::from_secs(100)); // way past cap
        state.topic_stats.insert(GossipTopic::BeaconBlock, t);
        let s = compute_score(&state, &params, 1, now);
        assert!((s - 10.0).abs() < 1e-9, "got {s}");
    }

    #[test]
    fn mesh_delivery_deficit_quadratic_below_threshold() {
        let mut params = ScoreParams::default();
        params.mesh_message_deliveries_threshold = 10.0;
        params.mesh_message_deliveries_weight = -2.0;
        let now = Instant::now();
        let mut state = mk_state(now);
        let mut t = TopicScore::default();
        t.mesh_active = true;
        t.mesh_deliveries = 3.0; // deficit = 7
        state.topic_stats.insert(GossipTopic::BeaconBlock, t);
        // 7^2 * -2 = -98
        let s = compute_score(&state, &params, 1, now);
        assert!((s - -98.0).abs() < 1e-9, "got {s}");
    }

    #[test]
    fn mesh_deficit_zero_when_inactive() {
        let params = ScoreParams::default();
        let now = Instant::now();
        let mut state = mk_state(now);
        let mut t = TopicScore::default();
        t.mesh_active = false;
        t.mesh_deliveries = 0.0;
        state.topic_stats.insert(GossipTopic::BeaconBlock, t);
        assert_eq!(compute_score(&state, &params, 1, now), 0.0);
    }

    #[test]
    fn breakdown_total_matches_compute_score() {
        let mut params = ScoreParams::default();
        params.time_in_mesh_cap_s = 10.0;
        params.time_in_mesh_weight = 1.0;
        params.ip_colocation_threshold = 2;
        params.ip_colocation_weight = -1.0;
        let now = Instant::now();
        let mut state = mk_state(now);
        state.behaviour_penalty = 5.0;
        state.application_score = -7.0;
        let mut t = TopicScore::default();
        t.meshed_since = Some(now - Duration::from_secs(100));
        t.first_deliveries = 4.0;
        t.invalid_deliveries = 2.0;
        t.mesh_active = true;
        t.mesh_deliveries = 1.0;
        state.topic_stats.insert(GossipTopic::BeaconBlock, t);

        let b = score_breakdown(&state, &params, 5, now);
        let s = compute_score(&state, &params, 5, now);
        assert!((b.total - s).abs() < 1e-9, "breakdown {} vs compute {}", b.total, s);
    }

    #[test]
    fn decay_drives_counters_to_zero() {
        let params = ScoreParams::default();
        let now = Instant::now();
        let mut state = mk_state(now);
        state.behaviour_penalty = 10.0;
        for _ in 0..100_000 {
            decay(&mut state, &params);
        }
        assert_eq!(state.behaviour_penalty, 0.0);
    }
}
