//! Who we let in and who we keep out: discovery hits filtered to dialable
//! candidates, redials of peers we already know, over-population trimming,
//! and the graylist — eviction, the bans it feeds, and their expiry.

use std::{
    net::IpAddr,
    time::{Duration, Instant},
};

use flux_profiler::timed;
use silver_common::{
    Enr, P2pSend, PeerControl, PeerId, RpcOutbound, RpcRequestOutbound, RpcSeverity,
};

use super::PeerManager;

const GOODBYE_CLIENT_SHUTDOWN: u64 = 1;

const REMOTE_BAN_TTL: Duration = Duration::from_secs(12 * 3600);

impl PeerManager {
    pub(super) fn ban_disc_peer(
        &mut self,
        peer_id: PeerId,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if self.banned_peers.insert(peer_id, now).is_none() {
            crate::PeerCounters::PeersBanned.inc();
            emit(PeerControl::Ban { p2p: peer_id });
        }
    }

    /// Discovery surfaced a candidate peer: filter (fork digest, bans,
    /// backoffs, QUIC support) and ingest into the database. Dialing is
    /// `redial_known_peers`'s — the next tick picks the record up.
    #[timed]
    pub(super) fn on_disc_node_found(
        &mut self,
        enr: Enr,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        // 1. Fork-digest gate. Spec-conformant CL nodes always advertise `eth2`;
        //    missing-or-mismatched is a drop (matches lighthouse).
        if let Some(my_digest) = self.our_fork_digest {
            match enr.eth2() {
                Some(eth2) => {
                    if !self.is_our_fork_digest(&eth2[..4]) {
                        crate::PeerCounters::DiscDroppedForkDigest.inc();
                        tracing::warn!(
                            theirs = hex::encode(&eth2[..4]),
                            ours = hex::encode(my_digest),
                            ?enr,
                            "fork digest mismatch"
                        );
                        self.ban_disc_peer(
                            PeerId::from_secp256k1_pubkey(&enr.public_key().serialize()),
                            now,
                            emit,
                        );
                        return;
                    }
                }
                None => {
                    crate::PeerCounters::DiscDroppedForkDigest.inc();
                    tracing::trace!("Not a beacon node, no eth2");
                    self.ban_disc_peer(
                        PeerId::from_secp256k1_pubkey(&enr.public_key().serialize()),
                        now,
                        emit,
                    );
                    return;
                }
            }
        }

        // 2. IP-ban gate.
        let ip = enr.ip4().map(IpAddr::V4).or_else(|| enr.ip6().map(IpAddr::V6));
        if let Some(ip) = ip &&
            self.banned_ips.contains_key(&ip)
        {
            crate::PeerCounters::DiscDroppedBanned.inc();
            tracing::warn!(?ip, "peer with banned ip");
            return;
        }

        // 3. Check if already have this node, or ban applies at PeerId level.
        let compressed = enr.public_key().serialize();
        let peer_id = PeerId::from_secp256k1_pubkey(&compressed);
        if self.banned_peers.contains_key(&peer_id) {
            crate::PeerCounters::DiscDroppedBanned.inc();
            tracing::warn!(?peer_id, "banned peer id");
            return;
        }
        if self.remote_banned_peers.contains_key(&peer_id) {
            crate::PeerCounters::DiscDroppedRemoteBan.inc();
            tracing::debug!(?peer_id, "remote-banned peer id; dial backoff");
            return;
        }
        if self.database.dial_backoff_active(&peer_id, now) {
            tracing::debug!(?peer_id, "dial-failure backoff active");
            return;
        }
        if self.peers_by_id.contains_key(&peer_id) {
            // Normal high-frequency case: discovery re-surfaces connected peers
            // every poll cycle. trace, not warn — else it floods the log.
            tracing::trace!(?peer_id, "known peer id");
            return;
        }
        if self.dialing.contains_key(&peer_id) {
            tracing::trace!(?peer_id, "already dialing peer id");
            return;
        }

        if enr.quic4_socket().is_none() && enr.quic6_socket().is_none() {
            tracing::debug!(udp4=?enr.udp4(), udp6=enr.udp6(), tcp4=?enr.tcp4(), tcp6=enr.tcp6(), "Peer does not support quic");
            self.ban_disc_peer(peer_id, now, emit);
            return;
        }

        tracing::debug!(id=?enr.node_id(), ?enr, "new node");

        self.database.add_enr(enr);
    }

    /// The sole dial issuer: connects disconnected-but-known peers from the
    /// database up to `target_peers`, or `max_priority_peers` for candidates
    /// covering a subnet/custody column we need. Discovery only feeds the
    /// database; this loop dials on the next tick.
    pub fn redial_known_peers(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let mut connected = self.peers.len() + self.dialing.len();
        if connected >= self.params.max_priority_peers {
            return;
        }
        for record in self.database.redial_candidates(now) {
            let (Some(peer_id), Some(enr)) = (record.peer_id, record.enr.as_ref()) else {
                continue;
            };
            if self.dialing.contains_key(&peer_id) ||
                self.banned_peers.contains_key(&peer_id) ||
                self.remote_banned_peers.contains_key(&peer_id)
            {
                continue;
            }
            let ip = enr.ip4().map(IpAddr::V4).or_else(|| enr.ip6().map(IpAddr::V6));
            if ip.is_some_and(|ip| self.banned_ips.contains_key(&ip)) {
                continue;
            }

            if self.our_fork_digest.is_some() &&
                enr.eth2().is_none_or(|e| !self.is_our_fork_digest(&e[..4]))
            {
                continue;
            }
            let cap = if enr_matches_subnets(
                enr,
                self.required_attnets,
                self.required_syncnets,
                self.custody_columns,
            ) {
                self.params.max_priority_peers
            } else {
                self.params.target_peers
            };
            if connected >= cap {
                continue;
            }
            tracing::debug!(?peer_id, "redialing known peer");
            self.dialing.insert(peer_id, now);
            emit(PeerControl::P2pDial { p2p: peer_id, enr: *enr });
            connected += 1;
            if connected >= self.params.max_priority_peers {
                break;
            }
        }
    }

    /// Trim over-population: past `max_priority_peers` + 10% inbound
    /// headroom, goodbye (TooManyPeers) the worst strictly-negative scorers
    /// back toward `max_priority_peers`. Neutral peers — including fresh
    /// connections, which start at 0 — are never trimmed: with no negatives
    /// we stay over cap until scores differentiate. Per-beat cap keeps
    /// removal a trickle rather than a burst.
    pub(super) fn manage_peers(&mut self, emit: &mut impl FnMut(PeerControl)) {
        const MAX_GOODBYES_PER_BEAT: usize = 16;
        let cap = self.params.max_priority_peers + self.params.max_priority_peers / 10;
        if self.peers.len() <= cap {
            return;
        }
        let excess = self.peers.len() - self.params.max_priority_peers;

        // Bounded scan, no alloc: gather up to array-size negative
        // candidates (first found, not globally worst), goodbye the worst
        // of those.
        let mut candidates = [(0usize, 0.0f64); 256];
        let mut found = 0;
        for (id, peer) in &self.peers {
            if peer.cached_score < 0.0 && !peer.goodbye_sent {
                candidates[found] = (*id, peer.cached_score);
                found += 1;
                if found == candidates.len() {
                    break;
                }
            }
        }
        let candidates = &mut candidates[..found];
        candidates.sort_unstable_by(|(_, a), (_, b)| a.total_cmp(b));

        let to_remove = excess.min(MAX_GOODBYES_PER_BEAT).min(found);
        for (id, _) in &candidates[..to_remove] {
            let Some(peer) = self.peers.get_mut(id) else { continue };
            peer.goodbye_sent = true;

            let goodbye = RpcOutbound::Request(RpcRequestOutbound {
                application_id: 0,
                peer: *id,
                request: silver_common::RpcRequest::Goodbye(129u64.to_le_bytes()),
            });

            emit(PeerControl::P2pSend(P2pSend::Rpc(goodbye)));
        }
    }

    pub(super) fn maybe_request_discovery(
        &mut self,
        now: Instant,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if self.peers.len() >= self.params.target_peers {
            return;
        }
        if now.saturating_duration_since(self.last_discovery) < self.params.discovery_query_interval
        {
            return;
        }
        self.last_discovery = now;
        emit(PeerControl::DiscoverNodes);
    }

    pub(crate) fn on_p2p_peer_goodbye(
        &mut self,
        p2p_peer: usize,
        now: Instant,
        code: u64,
        emit: &mut impl FnMut(PeerControl),
    ) {
        if let Some(peer_record) =
            self.on_disconnected(p2p_peer, now, Self::goodbye_reason(code), emit) &&
            let Some(peer_id) = peer_record.peer_id
        {
            let user_agent = peer_record.identify.as_ref().map(|i| i.user_agent());
            let backoff = Self::goodbye_dial_backoff(code);
            tracing::info!(
                p2p_peer,
                code = Self::goodbye_reason(code),
                ?user_agent,
                ?backoff,
                "received goodbye"
            );
            emit(PeerControl::P2pDisconnect { p2p: peer_id, p2p_connection: p2p_peer });

            if let Some(backoff) = backoff {
                self.remote_banned_peers.insert(peer_id, now + backoff);
            }
        }
        self.peers.remove(&p2p_peer);
    }

    /// Translate RPC misbehaviour severity into a P5 application-score
    /// delta. Calibrated so a single `Fatal` report drops the peer below the
    /// default `graylist_threshold = -80`, triggering eviction on the next
    /// `tick`. Lighter severities accumulate over time until decay catches
    /// up — same recovery dynamics as gossipsub-domain behaviour penalty.
    pub(crate) fn on_rpc_misbehaviour(
        &mut self,
        conn: usize,
        severity: RpcSeverity,
        offence: &'static str,
    ) {
        let delta = match severity {
            RpcSeverity::Fatal => -200.0,
            RpcSeverity::LowTolerance => -10.0,
            RpcSeverity::MidTolerance => -5.0,
            RpcSeverity::HighTolerance => -2.0,
        };
        crate::PeerCounters::RpcMisbehaviour.inc();
        if let Some(peer) = self.peers.get_mut(&conn) {
            peer.application_score += delta;
            tracing::info!(
                peer_id = conn,
                offence,
                ?severity,
                delta,
                score = peer.application_score,
                "P5 rpc misbehaviour"
            );
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────

    pub(super) fn evict_graylisted(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let threshold = self.params.graylist_threshold;
        // Two-phase: identify + remove (can't mutate self.peers while
        // iterating it); emit is inline in phase 2.
        let mut evict: Vec<(usize, PeerId, IpAddr)> = Vec::new();
        let mut spared: Vec<usize> = Vec::new();
        let mut recovered: Vec<usize> = Vec::new();
        for (conn, peer) in &self.peers {
            if peer.cached_score >= threshold {
                if peer.evict_spared {
                    recovered.push(*conn);
                }
                continue;
            }
            let (dc_subscribed, dc_advertised) = self.data_column_overlap(*conn, peer);
            if (dc_subscribed > 0 || dc_advertised > 0) &&
                self.data_column_peer_count(*conn) < self.params.d_low as usize
            {
                spared.push(*conn);
                continue;
            }
            let b = peer.last_breakdown;
            tracing::warn!(
                peer_id = ?peer.peer_id,
                addr = ?peer.addr,
                total = b.total,
                threshold,
                dc_subscribed,
                dc_advertised,
                p1_time_in_mesh = b.p1_time_in_mesh,
                p2_first_deliveries = b.p2_first_deliveries,
                p3_mesh_deficit = b.p3_mesh_deficit,
                p3b_mesh_failure = b.p3b_mesh_failure,
                p4_invalid = b.p4_invalid,
                p5_application = b.p5_application,
                p6_ip_colocation = b.p6_ip_colocation,
                p7_behaviour = b.p7_behaviour,
                "evicting greylisted peer: {conn}"
            );
            evict.push((*conn, peer.peer_id, peer.addr.ip()));
        }
        for conn in recovered {
            if let Some(peer) = self.peers.get_mut(&conn) {
                peer.evict_spared = false;
            }
        }
        for conn in spared {
            if let Some(peer) = self.peers.get_mut(&conn) &&
                !peer.evict_spared
            {
                peer.evict_spared = true;
                tracing::warn!(
                    p2p_peer = conn,
                    peer_id = ?peer.peer_id,
                    score = peer.cached_score,
                    threshold,
                    "sparing graylisted data-column peer: few alternatives"
                );
            }
        }
        for (conn, peer_id, ip) in evict {
            emit(PeerControl::Ban { p2p: peer_id });
            crate::PeerCounters::PeersEvicted.inc();
            crate::PeerCounters::PeersBanned.inc();
            self.banned_peers.insert(peer_id, now);
            // Bump the per-IP eviction count; only escalate to `BanIp`
            // once we've seen `ip_ban_threshold` peer-level graylists from
            // this IP within the TTL window. Avoids first-strike IP bans
            // for honest NAT/CGN endpoints sharing an address.
            let count = {
                let entry = self.ip_eviction_counts.entry(ip).or_insert((0, now));
                entry.0 += 1;
                entry.1 = now;
                entry.0
            };
            if count >= self.params.ip_ban_threshold {
                tracing::info!(?ip, evictions = count, "banning ip");
                emit(PeerControl::BanIp { ip });
                crate::PeerCounters::IpsBanned.inc();
                self.banned_ips.insert(ip, now);
            }
            self.on_disconnected(conn, now, "evicted", emit);
        }
    }

    /// Sweep expired entries from `banned_ips`, emitting `UnbanIp` for each
    /// expired IP so the network/discovery tile can drop their socket-level
    /// deny entries. Also ages out `ip_eviction_counts` (no emit — purely
    /// internal accounting).
    pub(super) fn gc_banned_ips(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let ttl = self.params.banned_ip_ttl;
        self.banned_ips.retain(|ip, t| {
            if now.saturating_duration_since(*t) >= ttl {
                emit(PeerControl::UnbanIp { ip: *ip });
                false
            } else {
                true
            }
        });
        self.ip_eviction_counts.retain(|_, (_, t)| now.saturating_duration_since(*t) < ttl);
    }

    /// Sweep expired entries from `banned_peers`, emitting `Unban` per
    /// expired PeerId. Symmetric to `gc_banned_ips` but on a separate TTL.
    pub(super) fn gc_banned_peers(&mut self, now: Instant, emit: &mut impl FnMut(PeerControl)) {
        let ttl = self.params.banned_peer_ttl;
        self.banned_peers.retain(|p2p, t| {
            if now.saturating_duration_since(*t) >= ttl {
                emit(PeerControl::Unban { p2p: *p2p });
                false
            } else {
                true
            }
        });
        // No Unban: remote-banned peers were never network-side banned.
        self.remote_banned_peers.retain(|_, expiry| *expiry > now);
    }

    /// Human label for a Goodbye reason code (spec codes 1-3, plus the
    /// 128+ extensions lighthouse and prysm share).
    pub(super) fn goodbye_reason(code: u64) -> &'static str {
        match code {
            1 => "ClientShutdown",
            2 => "IrrelevantNetwork",
            3 => "Fault",
            128 => "UnableToVerifyNetwork",
            129 => "TooManyPeers",
            250 => "BadScore",
            251 => "Banned",
            252 => "BannedIP",
            _ => "Unknown",
        }
    }

    /// Dial backoff earned by a Goodbye, `None` = stay dialable. Banned
    /// matches lighthouse's 12h `BANNED_BEFORE_DECAY`; BadScore is only
    /// their *disconnect* threshold — the score keeps decaying and their
    /// slowest component (attestation P3b) fades in ~30 min; TooManyPeers
    /// is a routine excess-peer shed that expects us back; wrong-network
    /// codes are futile to redial until a fork change.
    fn goodbye_dial_backoff(code: u64) -> Option<Duration> {
        match code {
            GOODBYE_CLIENT_SHUTDOWN => None,
            129 => Some(Duration::from_secs(5 * 60)),
            250 => Some(Duration::from_secs(30 * 60)),
            3 => Some(Duration::from_secs(3600)),
            _ => Some(REMOTE_BAN_TTL),
        }
    }
}

/// True iff the ENR advertises subscription to at least one attnet/syncnet
/// we also subscribe to. Both bitfields are SSZ Bitvectors so a bytewise
/// AND is sufficient — any non-zero result means at least one shared bit.
fn enr_matches_subnets(
    enr: &Enr,
    attnets_mask: [u8; 8],
    syncnets_mask: u8,
    custody_columns: u128,
) -> bool {
    if let Some(enr_attnets) = enr.attnets() {
        for i in 0..8 {
            if enr_attnets[i] & attnets_mask[i] != 0 {
                return true;
            }
        }
    }
    if let Some(enr_syncnets) = enr.syncnets() &&
        enr_syncnets & syncnets_mask != 0
    {
        return true;
    }
    if let Some(cgc) = enr.cgc() {
        return enr.node_id().custody_groups(cgc as u8) & custody_columns != 0
    }
    false
}

#[cfg(test)]
mod tests {
    use silver_common::{GossipTopic, IpBytes, Keypair, PeerEvent};
    use silver_config::ScoreParams;

    use super::*;
    use crate::manager::{
        DIAL_FAILURE_BACKOFF, SHORT_LIVED_CONNECTION, SHORT_LIVED_DIAL_BACKOFF, fixture::*,
    };

    fn dials(cap: &Captured) -> usize {
        cap.0.iter().filter(|c| matches!(c, PeerControl::P2pDial { .. })).count()
    }

    /// Same key derivation as `peer_id(seed)` so an ENR built with this
    /// helper has a `public_key()` whose derived `PeerId` matches what
    /// `connect(...)` registers. Critical for `banned_peers` /
    /// `archived` filter tests.
    fn test_enr(seed: u8, ip: std::net::Ipv4Addr) -> silver_common::Enr {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 1;
        let kp = Keypair::from_secret(&bytes).unwrap();
        // QUIC port required — `on_disc_node_found` drops ENRs that don't
        // advertise a quic4/quic6 socket.
        silver_common::Enr::builder().ip4(ip).udp4(9000).quic4(9000).build(kp.secret_key()).unwrap()
    }

    /// Builder variant for fork-digest / subnet-bitfield tests. `eth2` is
    /// the full ENRForkID (16 bytes — fork_digest first 4, then next-fork-
    /// version 4, then next-fork-epoch 8); only the leading 4 are matched
    /// against `set_fork_digest`.
    fn test_enr_with(
        seed: u8,
        ip: std::net::Ipv4Addr,
        eth2: Option<[u8; 16]>,
        attnets: Option<[u8; 8]>,
        syncnets: Option<u8>,
    ) -> silver_common::Enr {
        // Match `peer_id(seed)`'s derivation for cross-test consistency.
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        bytes[31] = 1;
        let kp = Keypair::from_secret(&bytes).unwrap();
        let mut b = silver_common::Enr::builder();
        b.ip4(ip).udp4(9000).quic4(9000);
        if let Some(e) = eth2 {
            b.eth2(e);
        }
        if let Some(a) = attnets {
            b.attnets(a);
        }
        if let Some(s) = syncnets {
            b.syncnets(s);
        }
        b.build(kp.secret_key()).unwrap()
    }

    #[test]
    fn redial_known_peer_after_disconnect_with_failure_backoff() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let enr =
            test_enr_with(5, std::net::Ipv4Addr::new(10, 0, 0, 5), Some([0u8; 16]), None, None);
        mgr.database.add_enr(enr);

        // Connected peers are not redial candidates.
        connect(&mut mgr, &mut cap, 1, 5, now);
        cap.0.clear();
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 0, "live peer must not be redialed");

        // Disconnect past the short-lived window: an ordinary drop.
        let t_drop = now + SHORT_LIVED_CONNECTION + Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: peer_id(5) },
            t_drop,
            &mut |c| cap.0.push(c),
        );
        cap.0.clear();
        mgr.redial_known_peers(t_drop, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 1, "disconnected known peer should be dialed");

        // In-flight dial is not repeated.
        cap.0.clear();
        mgr.redial_known_peers(t_drop, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 0, "in-flight dial must not repeat");

        // Dial times out via the stale-dial sweep -> 1h backoff.
        let after_sweep = t_drop + Duration::from_secs(16);
        mgr.tick(after_sweep, &mut |c| cap.0.push(c));
        cap.0.clear();
        mgr.redial_known_peers(after_sweep, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 0, "failed dial must back off");

        // Backoff expires -> dialable again.
        let after_backoff = after_sweep + DIAL_FAILURE_BACKOFF + Duration::from_secs(1);
        cap.0.clear();
        mgr.redial_known_peers(after_backoff, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 1, "peer should be redialed after backoff expiry");
    }

    #[test]
    fn failed_dial_zombie_disconnect_backs_off() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let enr =
            test_enr_with(5, std::net::Ipv4Addr::new(10, 0, 0, 5), Some([0u8; 16]), None, None);
        mgr.database.add_enr(enr);

        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 1);

        // Dial dies pre-handshake: P2pDisconnect with no prior
        // P2pNewConnection. Must arm the dial-failure backoff even though
        // the `dialing` entry is gone before the stale-dial sweep.
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 999, peer_id: peer_id(5) },
            now + Duration::from_secs(1),
            &mut |c| cap.0.push(c),
        );
        cap.0.clear();
        mgr.redial_known_peers(now + Duration::from_secs(2), &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 0, "zombie dial must back off");

        let after = now + DIAL_FAILURE_BACKOFF + Duration::from_secs(3);
        cap.0.clear();
        mgr.redial_known_peers(after, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 1, "redial resumes after backoff");
    }

    #[test]
    fn short_lived_transport_disconnect_backs_off_redial() {
        let now = Instant::now();
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        let enr =
            test_enr_with(5, std::net::Ipv4Addr::new(10, 0, 0, 5), Some([0u8; 16]), None, None);
        mgr.database.add_enr(enr);

        // Connect then die within the short-lived window (remote gater
        // denial pattern: handshake ok, closed moments later).
        connect(&mut mgr, &mut cap, 1, 5, now);
        let t_drop = now + Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: peer_id(5) },
            t_drop,
            &mut |c| cap.0.push(c),
        );

        cap.0.clear();
        mgr.redial_known_peers(t_drop, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 0, "short-lived drop must arm a dial backoff");

        let after = t_drop + SHORT_LIVED_DIAL_BACKOFF + Duration::from_secs(1);
        cap.0.clear();
        mgr.redial_known_peers(after, &mut |c| cap.0.push(c));
        assert_eq!(dials(&cap), 1, "redial resumes after the short backoff");
    }

    #[test]
    fn disc_node_found_below_target_emits_dial() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params);
        // ENR must carry an `eth2` field matching the fixture's [0u8;4]
        // fork digest now that `our_fork_digest` is always set.
        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some([0u8; 16]), None, None);

        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "expected P2pDial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_redials_archived_peer() {
        // Archive persists reputation but must not veto redial: a benign
        // disconnect (not a ban) has to be re-dialable or we strand ourselves.
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params);

        connect(&mut mgr, &mut cap, 1, 7, now);
        // Age the connection past the short-lived window first: an instant
        // drop would (correctly) arm the short-lived dial backoff instead.
        let t_drop = now + SHORT_LIVED_CONNECTION + Duration::from_secs(1);
        mgr.handle_event(
            PeerEvent::P2pDisconnect { p2p_peer: 1, peer_id: peer_id(7) },
            t_drop,
            &mut |c| cap.0.push(c),
        );
        assert_eq!(mgr.archived_count(), 1);
        cap.0.clear();

        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some([0u8; 16]), None, None);
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, t_drop, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(t_drop, &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "archived (non-banned) peer must be redialed, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_at_target_does_not_dial() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 2;
        let (mut mgr, mut cap) = fixture(vec![], params);

        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        cap.0.clear();

        let enr = test_enr(99, std::net::Ipv4Addr::new(10, 0, 0, 99));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));

        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "at-target manager must not dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_skips_banned_ip() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.ip_ban_threshold = 1; // single eviction → BanIp for this test
        let (mut mgr, mut cap) = fixture(vec![], params);

        // Connect a peer on 10.0.0.42, drive their score below graylist, tick
        // to evict — that should record 10.0.0.42 in `banned_ips`.
        connect(&mut mgr, &mut cap, 42, 42, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 42 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));
        cap.0.clear();

        // Same /32 reappears via discovery — must be dropped.
        let enr = test_enr(42, std::net::Ipv4Addr::new(10, 0, 0, 42));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));

        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "banned-IP discovery hit must not dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn banned_ip_clears_after_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.banned_ip_ttl = Duration::from_secs(10);
        // Match peer-TTL so both filters expire on the same tick — this
        // test exercises the IP-level filter; without aligning these
        // we'd still be blocked at the PeerId-level filter post-TTL.
        params.banned_peer_ttl = Duration::from_secs(10);
        params.ip_ban_threshold = 1; // single eviction → BanIp for this test
        // Decay must be slow enough that "5 invalid frames -> tick -> ban"
        // still trips the gate after the test's first tick.
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params);

        connect(&mut mgr, &mut cap, 42, 42, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 42 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));

        // Pre-TTL: discovery hit on banned IP is dropped.
        cap.0.clear();
        // ENR must carry an `eth2` field matching the fixture's [0u8;4]
        // fork digest (always-on filter since `our_fork_digest` is set).
        let enr =
            test_enr_with(42, std::net::Ipv4Addr::new(10, 0, 0, 42), Some([0u8; 16]), None, None);
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })));

        // Advance past banned_ip_ttl + tick to GC the ban entry.
        now += Duration::from_secs(11);
        mgr.tick(now, &mut |c| cap.0.push(c));

        // Same IP via discovery now dials.
        cap.0.clear();
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "post-TTL discovery hit must dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn ip_ban_threshold_gates_ban_ip_emission() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 16;
        params.ip_ban_threshold = 3;
        // Slow decay so we don't flap above threshold between iterations.
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 99);

        // Evict 3 distinct peers from the same IP. The first two should
        // emit `Ban` only; the third should also emit `BanIp` (threshold).
        for seed in 1..=3u8 {
            mgr.handle_event(
                PeerEvent::P2pNewConnection {
                    p2p_peer_id: seed as usize,
                    peer_id_full: peer_id(seed),
                    ip: IpBytes::V4(ip.octets()),
                    port: 4000 + seed as u16,
                    local_dial: false,
                },
                now,
                &mut |c| cap.0.push(c),
            );
            for _ in 0..5 {
                mgr.handle_event(
                    PeerEvent::P2pGossipInvalidFrame { p2p_peer: seed as usize },
                    now,
                    &mut |c| cap.0.push(c),
                );
            }
            cap.0.clear();
            mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

            let banned = cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. }));
            let banned_peer = cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. }));
            assert!(banned_peer, "every eviction should emit Ban (seed {seed})");
            if seed < 3 {
                assert!(!banned, "below-threshold eviction must not emit BanIp (seed {seed})");
            } else {
                assert!(banned, "threshold-reaching eviction must emit BanIp (seed {seed})");
            }
        }
    }

    #[test]
    fn ip_ban_count_decays_with_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 16;
        params.ip_ban_threshold = 2;
        params.banned_ip_ttl = Duration::from_secs(10);
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 88);
        // First eviction: bumps count to 1. No BanIp yet (threshold=2).
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 1,
                peer_id_full: peer_id(1),
                ip: IpBytes::V4(ip.octets()),
                port: 4001,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));
        cap.0.clear();

        // Past the TTL — gc clears the eviction-count entry.
        now += Duration::from_secs(11);
        mgr.tick(now, &mut |c| cap.0.push(c));

        // Fresh eviction post-TTL: count starts at 0 again, single eviction
        // bumps to 1 (still under threshold=2) → no BanIp.
        mgr.handle_event(
            PeerEvent::P2pNewConnection {
                p2p_peer_id: 2,
                peer_id_full: peer_id(2),
                ip: IpBytes::V4(ip.octets()),
                port: 4002,
                local_dial: false,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 2 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        cap.0.clear();
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })),
            "post-TTL fresh count must not BanIp on first eviction, got {:?}",
            cap.0
        );
    }

    #[test]
    fn banned_ip_emits_unban_after_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.ip_ban_threshold = 1;
        params.banned_ip_ttl = Duration::from_secs(10);
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params);

        connect(&mut mgr, &mut cap, 42, 42, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 42 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::BanIp { .. })));
        cap.0.clear();

        // Pre-TTL: no UnbanIp.
        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::UnbanIp { .. })));

        // Past TTL: gc fires → UnbanIp emitted exactly once.
        now += Duration::from_secs(6);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let unban_count = cap.0.iter().filter(|e| matches!(e, PeerControl::UnbanIp { .. })).count();
        assert_eq!(unban_count, 1, "expected one UnbanIp after TTL, got {:?}", cap.0);

        // Subsequent tick: nothing more — entry already gc'd.
        cap.0.clear();
        now += Duration::from_secs(1);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::UnbanIp { .. })));
    }

    #[test]
    fn banned_peer_emits_unban_after_ttl() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        params.banned_peer_ttl = Duration::from_secs(10);
        // Decouple peer-TTL from IP-TTL so the IP ban doesn't gc + emit
        // UnbanIp at the same tick and confuse the assertion. Also keep
        // ip_ban_threshold=2 so this single eviction stays peer-only.
        params.banned_ip_ttl = Duration::from_secs(60);
        params.ip_ban_threshold = 2;
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params);

        connect(&mut mgr, &mut cap, 1, 1, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        assert!(cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })));
        cap.0.clear();

        now += Duration::from_secs(5);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(!cap.0.iter().any(|e| matches!(e, PeerControl::Unban { .. })));

        now += Duration::from_secs(6);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let unban_count = cap.0.iter().filter(|e| matches!(e, PeerControl::Unban { .. })).count();
        assert_eq!(unban_count, 1, "expected one Unban after TTL, got {:?}", cap.0);
    }

    #[test]
    fn disc_node_found_skips_banned_peer_id() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.behaviour_penalty_threshold = 0.0;
        params.behaviour_penalty_weight = -10.0;
        params.graylist_threshold = -80.0;
        params.target_peers = 8;
        // Long peer TTL, never expires during this test. Keep the IP ban
        // threshold high so we test PeerId-only filter (not IP).
        params.banned_peer_ttl = Duration::from_secs(3600);
        params.ip_ban_threshold = 100;
        params.behaviour_penalty_decay = 0.999;
        let (mut mgr, mut cap) = fixture(vec![], params);

        // Connect peer with seed=7 on 10.0.0.7 → drive below graylist → tick.
        connect(&mut mgr, &mut cap, 1, 7, now);
        for _ in 0..5 {
            mgr.handle_event(PeerEvent::P2pGossipInvalidFrame { p2p_peer: 1 }, now, &mut |c| {
                cap.0.push(c)
            });
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));
        cap.0.clear();

        // ENR re-presents the same PeerId (same seed → same secp256k1 key).
        // Even from a different IP, it must drop on banned-peer-id filter.
        now += Duration::from_secs(1);
        let enr = test_enr(7, std::net::Ipv4Addr::new(10, 0, 0, 200));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "banned PeerId discovery hit must not dial, got {:?}",
            cap.0
        );
    }

    #[test]
    fn tick_under_target_emits_discover_nodes_throttled() {
        let mut now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        params.discovery_query_interval = Duration::from_secs(5);
        params.heartbeat_interval = Duration::from_millis(10);
        let (mut mgr, mut cap) = fixture(vec![], params);

        // First tick after construction: under target, throttle has elapsed
        // (last_discovery was set to construction time, query_interval=5s).
        now += Duration::from_secs(6);
        mgr.tick(now, &mut |c| cap.0.push(c));
        let first_count = cap.0.iter().filter(|e| matches!(e, PeerControl::DiscoverNodes)).count();
        assert_eq!(first_count, 1, "first tick should fire one DiscoverNodes, got {:?}", cap.0);

        // Immediate second tick should be throttled.
        cap.0.clear();
        now += Duration::from_millis(50);
        mgr.tick(now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::DiscoverNodes)),
            "throttle should suppress second emission, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_drops_mismatched_fork_digest() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params);
        mgr.set_fork_digest([0xAA, 0xBB, 0xCC, 0xDD]);

        let mut wrong_eth2 = [0u8; 16];
        wrong_eth2[..4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some(wrong_eth2), None, None);

        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "wrong-fork ENR must be dropped, got {:?}",
            cap.0
        );
    }

    /// A record is a snapshot of what the peer had when it last re-signed, so
    /// just after a fork our copy of a good peer still names the digest we
    /// left. Dropping those is how a restart into a new fork finds nobody
    /// to dial.
    #[test]
    fn disc_node_found_keeps_the_digest_we_left_behind() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params);
        let (before, after) = ([0xAA, 0xBB, 0xCC, 0xDDu8], [0x0A, 0x0B, 0x0C, 0x0Du8]);
        mgr.set_fork_digest(before);
        mgr.set_fork_digest(after);

        let mut stale_eth2 = [0u8; 16];
        stale_eth2[..4].copy_from_slice(&before);
        let enr =
            test_enr_with(7, std::net::Ipv4Addr::new(10, 0, 0, 7), Some(stale_eth2), None, None);

        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "the digest we advertised before the fork is one of ours, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_drops_missing_eth2_when_filter_set() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params);
        mgr.set_fork_digest([0xAA, 0xBB, 0xCC, 0xDD]);

        // ENR with no eth2 field — same drop policy as lighthouse.
        let enr = test_enr(7, std::net::Ipv4Addr::new(10, 0, 0, 7));
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "ENR without eth2 must be dropped when filter set, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_priority_subnet_dials_past_target() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 2;
        params.max_priority_peers = 4;
        // Subscribe to attnet 5 — our required mask flips bit 5.
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconAttestation(5)], params);
        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        cap.0.clear();

        // ENR advertises attnet 5 (byte 0, bit 5 = 0x20). Also include an
        // `eth2` matching the fixture's [0u8;4] fork digest — that filter
        // is always on now.
        let mut attnets = [0u8; 8];
        attnets[0] = 0x20;
        let enr = test_enr_with(
            99,
            std::net::Ipv4Addr::new(10, 0, 0, 99),
            Some([0u8; 16]),
            Some(attnets),
            None,
        );
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "priority subnet match should dial past target, got {:?}",
            cap.0
        );
    }

    #[test]
    fn disc_node_found_priority_capped_at_max_priority() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.target_peers = 2;
        params.max_priority_peers = 2; // already at the priority cap
        let (mut mgr, mut cap) = fixture(vec![GossipTopic::BeaconAttestation(5)], params);
        connect(&mut mgr, &mut cap, 1, 1, now);
        connect(&mut mgr, &mut cap, 2, 2, now);
        cap.0.clear();

        let mut attnets = [0u8; 8];
        attnets[0] = 0x20;
        let enr = test_enr_with(
            99,
            std::net::Ipv4Addr::new(10, 0, 0, 99),
            Some([0u8; 16]),
            Some(attnets),
            None,
        );
        mgr.handle_event(PeerEvent::DiscNodeFound { enr, reload: false }, now, &mut |c| {
            cap.0.push(c)
        });
        mgr.redial_known_peers(now, &mut |c| cap.0.push(c));

        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::P2pDial { .. })),
            "priority dial must respect max_priority_peers cap, got {:?}",
            cap.0
        );
    }

    #[test]
    fn manage_peers_trims_worst_negatives_only_once() {
        let now = Instant::now();
        let mut params = ScoreParams::default();
        params.max_priority_peers = 4;
        let (mut mgr, mut cap) = fixture(vec![], params);
        for conn in 1..=6usize {
            connect(&mut mgr, &mut cap, conn, conn as u8, now);
        }
        mgr.peers.get_mut(&1).unwrap().cached_score = -5.0;
        mgr.peers.get_mut(&2).unwrap().cached_score = -2.0;
        cap.0.clear();

        // 6 peers > cap(4): excess 2 — exactly the two negatives go, the
        // four neutral (fresh) peers are never trimmed.
        mgr.manage_peers(&mut |event| cap.0.push(event));
        let goodbyes: Vec<usize> =
            cap.0
                .iter()
                .filter_map(|event| match event {
                    PeerControl::P2pSend(P2pSend::Rpc(RpcOutbound::Request(
                        RpcRequestOutbound { application_id: _, peer, request: _ },
                    ))) => Some(*peer),
                    _ => None,
                })
                .collect();
        assert_eq!(goodbyes, vec![1, 2]);

        // Already-goodbyed peers are not re-selected while they drain.
        cap.0.clear();
        mgr.manage_peers(&mut |event| cap.0.push(event));
        assert!(cap.0.is_empty());
    }

    #[test]
    fn rpc_fatal_misbehaviour_evicts_on_tick() {
        let now = Instant::now();
        // Defaults: graylist_threshold = -80, Fatal delta = -200.
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);
        cap.0.clear();

        mgr.handle_event(
            PeerEvent::RpcMisbehaviour { p2p_peer: 1, severity: silver_common::RpcSeverity::Fatal },
            now,
            &mut |c| cap.0.push(c),
        );
        // Score is recomputed in tick — only then does the eviction fire.
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "Fatal severity must trigger eviction, got {:?}",
            cap.0
        );
        assert!(mgr.score(1).is_none(), "evicted peer should be gone");
    }

    #[test]
    fn rpc_low_tolerance_penalises_but_keeps_peer() {
        let now = Instant::now();
        // Defaults: graylist_threshold = -80, Low delta = -10.
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        mgr.handle_event(
            PeerEvent::RpcMisbehaviour {
                p2p_peer: 1,
                severity: silver_common::RpcSeverity::LowTolerance,
            },
            now,
            &mut |c| cap.0.push(c),
        );
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        let s = mgr.score(1).expect("peer still alive after a single Low report");
        assert!(s < 0.0 && s > -80.0, "expected mild negative score in (-80, 0), got {s}");
        assert!(
            !cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "single Low report must not evict, got {:?}",
            cap.0
        );
    }

    #[test]
    fn rpc_low_tolerance_accumulates_to_eviction() {
        let now = Instant::now();
        // Eight Low reports at -10 each = -80, exactly at graylist (strict <
        // check, so push to nine to trip).
        let (mut mgr, mut cap) = fixture(vec![], ScoreParams::default());
        connect(&mut mgr, &mut cap, 1, 1, now);

        for _ in 0..9 {
            mgr.handle_event(
                PeerEvent::RpcMisbehaviour {
                    p2p_peer: 1,
                    severity: silver_common::RpcSeverity::LowTolerance,
                },
                now,
                &mut |c| cap.0.push(c),
            );
        }
        mgr.tick(now + Duration::from_millis(100), &mut |c| cap.0.push(c));

        assert!(
            cap.0.iter().any(|e| matches!(e, PeerControl::Ban { .. })),
            "9× Low reports should accumulate past graylist, got {:?}",
            cap.0
        );
    }
}
