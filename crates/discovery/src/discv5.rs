use std::{
    io::{BufRead, BufWriter, Write},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use alloy_rlp::{Decodable, Encodable};
use flux::utils::ArrayVec;
use rand::RngCore as _;
use rustc_hash::FxHashMap;
use secp256k1::{SECP256K1, SecretKey};
use silver_common::{Enr, NodeId};
use tracing::{info, trace, warn};

use crate::{
    config::DiscoveryConfig,
    crypto::{
        MAX_PACKET_SIZE, SessionCipher, decrypt_message, ecdh_and_derive_keys_responder,
        ecdh_generate_and_derive, encrypt_message, make_cipher, sign_id_nonce, verify_id_nonce_sig,
    },
    discovery::{Discovery, DiscoveryEvent, DiscoveryMetrics},
    kbucket::{InsertResult, KBucketsTable, Key, MAX_NODES_PER_BUCKET},
    message::{Distances, ENR_RECORD_MAX, Message, MessageKind, NUM_DISTANCES_TO_REQUEST, Packet},
};

const NONCE_RING_SIZE: usize = 64;
const PENDING_PROBES_CAPACITY: usize = 64;
const BANNED_NODES_CAPACITY: usize = 32;

pub struct DiscV5 {
    config: DiscoveryConfig,
    local_key: SecretKey,
    local_id: NodeId,
    local_enr: Enr,
    local_enr_raw: ArrayVec<u8, ENR_RECORD_MAX>,
    fork_digest: [u8; 4],

    kbuckets: KBucketsTable<NodeEntry>,

    sessions: FxHashMap<NodeId, Session>,

    challenges: FxHashMap<NodeId, PendingChallenge>,
    /// FINDNODE to send once a session with the given peer is established.
    pending_findnodes: FxHashMap<NodeId, (u64, Distances)>,
    pending_probe_nonces: FxHashMap<NodeId, [u8; 12]>,
    pending_pings: FxHashMap<u64, (NodeId, Instant)>,
    event_queue: Vec<DiscoveryEvent>,

    ip_votes: FxHashMap<NodeId, (IpAddr, u16)>,
    ip_vote_counts: FxHashMap<(IpAddr, u16), u32>,

    banned_nodes: FxHashMap<NodeId, Option<Instant>>,
    banned_ips: FxHashMap<IpAddr, Option<Instant>>,

    whoareyou_per_ip: FxHashMap<IpAddr, (u32, Instant)>,
    whoareyou_global: (u32, Instant),

    next_request_id: u64,
    last_ping: Instant,
    last_lookup: Instant,
    last_cleanup: Instant,

    ping_cursor: usize,
    lookup_requested: bool,

    metrics: DiscoveryMetrics,
}

impl DiscV5 {
    pub fn new(
        config: DiscoveryConfig,
        local_key: SecretKey,
        local_enr: Enr,
        fork_digest: [u8; 4],
    ) -> Self {
        let local_id = NodeId::from(local_key.public_key(SECP256K1));
        let kbuckets = KBucketsTable::new(Key::from(local_id), config.kbucket_pending_timeout());
        let local_enr_raw = {
            let mut buf: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
            local_enr.encode(&mut buf);
            buf
        };
        let target = config.target_sessions;
        let mut disc = Self {
            config,
            local_key,
            local_id,
            local_enr,
            local_enr_raw,
            fork_digest,
            kbuckets,
            sessions: FxHashMap::with_capacity_and_hasher(target, Default::default()),
            challenges: FxHashMap::with_capacity_and_hasher(target, Default::default()),
            pending_findnodes: FxHashMap::with_capacity_and_hasher(
                PENDING_PROBES_CAPACITY,
                Default::default(),
            ),
            pending_probe_nonces: FxHashMap::with_capacity_and_hasher(
                PENDING_PROBES_CAPACITY,
                Default::default(),
            ),
            pending_pings: FxHashMap::with_capacity_and_hasher(target, Default::default()),
            event_queue: Vec::with_capacity(target),
            ip_votes: FxHashMap::with_capacity_and_hasher(target, Default::default()),
            ip_vote_counts: FxHashMap::with_capacity_and_hasher(8, Default::default()),
            banned_nodes: FxHashMap::with_capacity_and_hasher(
                BANNED_NODES_CAPACITY,
                Default::default(),
            ),
            banned_ips: FxHashMap::with_capacity_and_hasher(
                BANNED_NODES_CAPACITY,
                Default::default(),
            ),
            whoareyou_per_ip: FxHashMap::with_capacity_and_hasher(target, Default::default()),
            whoareyou_global: (0, Instant::now()),
            next_request_id: 0,
            last_ping: Instant::now(),
            last_lookup: Instant::now(),
            last_cleanup: Instant::now(),
            ping_cursor: 0,
            lookup_requested: false,
            metrics: Default::default(),
        };

        disc.load_persisted(Instant::now());
        disc
    }

    fn is_banned(
        banned_nodes: &mut FxHashMap<NodeId, Option<Instant>>,
        banned_ips: &mut FxHashMap<IpAddr, Option<Instant>>,
        id: &NodeId,
        ip: IpAddr,
    ) -> bool {
        if let Some(expires) = banned_nodes.get(id) {
            if expires.is_none_or(|t| Instant::now() < t) {
                return true;
            }
            banned_nodes.remove(id);
        }
        if let Some(expires) = banned_ips.get(&ip) {
            if expires.is_none_or(|t| Instant::now() < t) {
                return true;
            }
            banned_ips.remove(&ip);
        }
        false
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        id
    }

    fn flush_pending_findnode(&mut self, node_id: NodeId, dest_addr: SocketAddr) {
        if let Some((rid, distances)) = self.pending_findnodes.remove(&node_id) &&
            let Some(s) = self.sessions.get(&node_id) &&
            let Some(data) =
                Packet::encode_message(self.local_id, node_id, &s.enc, Message::FindNode {
                    request_id: rid,
                    distances,
                })
        {
            self.event_queue.push(DiscoveryEvent::SendMessage { to: dest_addr, data });
        }
    }

    /// Send a Message packet encrypted with a random key. The remote can't
    /// decrypt it and will respond with WhoAreYou, initiating the handshake.
    /// The probe nonce is recorded so we can verify the WhoAreYou echoes it.
    // todo @nina: pre-generate random material at idle time?
    fn send_probe(&mut self, dest_id: NodeId, dest_addr: SocketAddr) {
        let mut rng_buf = [0u8; 44];
        rand::thread_rng().fill_bytes(&mut rng_buf);

        let nonce: [u8; 12] = rng_buf[..12].try_into().unwrap();
        let iv: u128 = u128::from_be_bytes(rng_buf[12..28].try_into().unwrap());
        let cipher = make_cipher(&rng_buf[28..].try_into().unwrap());

        let mut plain: ArrayVec<u8, 128> = ArrayVec::new();
        Message::Ping { request_id: 0, enr_seq: 0 }.encode(&mut plain);

        let tmp =
            Packet { iv, src_id: self.local_id, nonce, kind: MessageKind::Message, message: &[] };
        let aad = tmp.authenticated_data();

        if let Some(ct) = encrypt_message(&cipher, &nonce, &aad, &plain) {
            let data = Packet {
                iv,
                src_id: self.local_id,
                nonce,
                kind: MessageKind::Message,
                message: &ct,
            }
            .encode(&dest_id);

            self.pending_probe_nonces.insert(dest_id, nonce);
            self.event_queue.push(DiscoveryEvent::SendMessage { to: dest_addr, data });
        }
    }

    fn send_whoareyou(
        &mut self,
        src_id: NodeId,
        src_addr: SocketAddr,
        nonce: [u8; 12],
        now: Instant,
    ) {
        if self.challenges.contains_key(&src_id) {
            return;
        }

        let ip = src_addr.ip();
        let whoareyou_window = self.config.whoareyou_window();
        let entry = self.whoareyou_per_ip.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) > whoareyou_window {
            *entry = (0, now);
        }
        if entry.0 >= self.config.whoareyou_per_ip_limit {
            self.metrics.whoareyou_limit_hits += 1;
            return;
        }

        if now.duration_since(self.whoareyou_global.1) >= whoareyou_window {
            self.whoareyou_global = (0, now);
        }
        if self.whoareyou_global.0 >= self.config.whoareyou_global_limit {
            self.metrics.whoareyou_limit_hits += 1;
            return;
        }

        self.whoareyou_per_ip.get_mut(&ip).unwrap().0 += 1;
        self.whoareyou_global.0 += 1;

        let known_enr_seq =
            self.kbuckets.get(&Key::from(src_id)).map(|n| n.value.enr_seq).unwrap_or(0);

        let rng_buf: [u8; 32] = rand::random();
        let id_nonce: [u8; 16] = rng_buf[..16].try_into().unwrap();
        let iv: u128 = u128::from_be_bytes(rng_buf[16..].try_into().unwrap());

        let wru = Packet {
            iv,
            src_id: NodeId::new(&[0; 32]),
            nonce,
            kind: MessageKind::WhoAreYou { id_nonce, enr_seq: known_enr_seq },
            message: &[],
        };
        let aad_arr = wru.authenticated_data();

        let mut data = [0u8; 63];
        data.copy_from_slice(&aad_arr);

        let wire = wru.encode(&src_id);

        self.challenges.insert(src_id, PendingChallenge { data, sent_at: now });
        self.event_queue.push(DiscoveryEvent::SendMessage { to: src_addr, data: wire });
    }

    fn on_ping(
        &mut self,
        src_id: NodeId,
        src_addr: SocketAddr,
        request_id: u64,
        enr_seq: u64,
        stored_enr_seq: u64,
    ) {
        // Compute rid before borrowing sessions to avoid &mut self conflict.
        let enr_rid = (enr_seq > stored_enr_seq).then(|| self.next_id());
        let Some(s) = self.sessions.get(&src_id) else { return };

        let pong = Message::Pong {
            request_id,
            enr_seq: self.local_enr.seq(),
            ip: src_addr.ip(),
            port: src_addr.port(),
        };
        if let Some(data) = Packet::encode_message(self.local_id, src_id, &s.enc, pong) {
            self.event_queue.push(DiscoveryEvent::SendMessage { to: src_addr, data });
        }

        // If the peer's ENR is newer than what we have, request it.
        if let Some(rid) = enr_rid {
            let mut distances = Distances::new();
            distances.push(0);
            if let Some(data) =
                Packet::encode_message(self.local_id, src_id, &s.enc, Message::FindNode {
                    request_id: rid,
                    distances,
                })
            {
                self.event_queue.push(DiscoveryEvent::SendMessage { to: src_addr, data });
            }
        }
    }

    fn on_pong(&mut self, src_id: NodeId, request_id: u64, ip: IpAddr, port: u16) {
        match self.pending_pings.remove(&request_id) {
            Some((expected, _)) if expected == src_id => {}
            _ => return,
        }

        let addr = (ip, port);
        let old = self.ip_votes.insert(src_id, addr);
        if old == Some(addr) {
            return;
        }

        if let Some(old_addr) = old {
            if let Some(c) = self.ip_vote_counts.get_mut(&old_addr) {
                *c = c.saturating_sub(1);
            }
        }

        let count = self.ip_vote_counts.entry(addr).or_insert(0);
        *count += 1;

        if *count >= self.config.ip_vote_threshold {
            let changed = match ip {
                IpAddr::V4(a) => self.local_enr.ip4() != Some(a),
                IpAddr::V6(a) => self.local_enr.ip6() != Some(a),
            };

            if changed {
                let socket = SocketAddr::new(ip, port);
                let _ = self.local_enr.set_udp_socket(socket, &self.local_key);
                let mut raw: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
                self.local_enr.encode(&mut raw);
                self.local_enr_raw = raw;
                self.event_queue.push(DiscoveryEvent::ExternalAddrChanged(socket));
            }
        }
    }

    fn on_nodes(
        &mut self,
        _src_id: NodeId,
        nodes: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8>,
        now: Instant,
    ) {
        for raw in nodes.iter() {
            let Ok(enr) = Enr::decode(&mut raw.as_slice()) else { continue };
            if enr.eth2().map(|e| e[..4] != self.fork_digest).unwrap_or(false) {
                continue;
            }

            let addr = if let (Some(ip4), Some(udp4)) = (enr.ip4(), enr.udp4()) {
                SocketAddr::new(IpAddr::V4(ip4), udp4)
            } else if let (Some(ip6), Some(udp6)) = (enr.ip6(), enr.udp6()) {
                SocketAddr::new(IpAddr::V6(ip6), udp6)
            } else {
                continue;
            };

            let pk_bytes = enr.public_key().serialize();
            let node_id = enr.node_id();
            let prev_raw = self.kbuckets.get(&Key::from(node_id)).and_then(|n| n.value.enr_raw);
            let result = self.kbuckets.insert_or_update(
                &Key::from(node_id),
                NodeEntry { addr, enr_seq: enr.seq(), pubkey: pk_bytes, enr_raw: Some(*raw) },
                now,
            );
            let is_new = matches!(result, InsertResult::Inserted) || prev_raw != Some(*raw);
            if is_new {
                self.metrics.nodes_discovered += 1;
                self.event_queue.push(DiscoveryEvent::NodeFound(enr));
            }
        }
    }

    fn send_nodes_response(
        &mut self,
        dst_id: NodeId,
        dst_addr: SocketAddr,
        request_id: u64,
        distances: &Distances,
    ) {
        let mut enrs: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 16> = ArrayVec::new();
        if distances.iter().any(|&d| d == 0) {
            enrs.push(self.local_enr_raw);
        }

        let node_ids = self.kbuckets.nodes_by_distances(distances.as_slice(), MAX_NODES_PER_BUCKET);
        for id in node_ids {
            if enrs.is_full() {
                break;
            }
            if let Some(raw) = self.kbuckets.get(&Key::from(id)).and_then(|n| n.value.enr_raw) {
                enrs.push(raw);
            }
        }

        let s = match self.sessions.get(&dst_id) {
            Some(s) => s,
            None => return,
        };

        // IV(16) + header(23) + auth_data(32) + GCM tag(16) + msg overhead(~18)
        const BUDGET: usize = MAX_PACKET_SIZE - 105;

        let mut total: u8 = 1;
        let mut acc: usize = 0;
        for enr in enrs.iter() {
            if acc > 0 && acc + enr.len() > BUDGET {
                total = total.saturating_add(1);
                acc = 0;
            }
            acc += enr.len();
        }

        let mut batch: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8> = ArrayVec::new();
        let batch_bytes = |b: &ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8>| -> usize {
            b.iter().map(|e| e.len()).sum()
        };

        for enr in enrs {
            if batch_bytes(&batch) + enr.len() > BUDGET {
                if let Some(data) =
                    Packet::encode_message(self.local_id, dst_id, &s.enc, Message::Nodes {
                        request_id,
                        total,
                        nodes: batch,
                    })
                {
                    self.event_queue.push(DiscoveryEvent::SendMessage { to: dst_addr, data });
                }
                batch = ArrayVec::new();
            }
            if !batch.is_full() {
                batch.push(enr);
            }
        }

        if let Some(data) = Packet::encode_message(self.local_id, dst_id, &s.enc, Message::Nodes {
            request_id,
            total,
            nodes: batch,
        }) {
            self.event_queue.push(DiscoveryEvent::SendMessage { to: dst_addr, data });
        }
    }

    fn handle_message(&mut self, src_id: NodeId, src_addr: SocketAddr, bytes: &[u8], now: Instant) {
        let msg = match Message::decode(bytes) {
            Some(o) => o,
            None => {
                warn!(%src_id, %src_addr, len = bytes.len(), "failed to decode message payload");
                return;
            }
        };

        let existing = match self.kbuckets.get(&Key::from(src_id)).map(|n| n.value) {
            Some(e) => e,
            None => {
                warn!(%src_id, %src_addr, "message from peer with no kbuckets entry");
                return;
            }
        };

        let msg_enr_seq = match &msg {
            Message::Ping { enr_seq, .. } | Message::Pong { enr_seq, .. } => *enr_seq,
            _ => existing.enr_seq,
        };

        let _ = self.kbuckets.insert_or_update(
            &Key::from(src_id),
            NodeEntry {
                addr: src_addr,
                enr_seq: msg_enr_seq,
                pubkey: existing.pubkey,
                enr_raw: existing.enr_raw,
            },
            now,
        );

        match msg {
            Message::Ping { request_id, enr_seq } => {
                self.on_ping(src_id, src_addr, request_id, enr_seq, existing.enr_seq);
            }
            Message::Pong { request_id, ip, port, .. } => {
                self.on_pong(src_id, request_id, ip, port);
            }
            Message::FindNode { request_id, distances } => {
                if existing.addr == src_addr {
                    self.send_nodes_response(src_id, src_addr, request_id, &distances);
                }
            }
            Message::Nodes { nodes, .. } => {
                self.on_nodes(src_id, nodes, now);
            }
        }
    }

    fn handle_whoareyou(
        &mut self,
        probe_nonce: [u8; 12],
        src_addr: SocketAddr,
        aad: &[u8],
        peer_enr_seq: u64,
        now: Instant,
    ) {
        let (remote_id, remote_pubkey) = match self
            .kbuckets
            .iter_ref()
            .find(|n| n.value.addr == src_addr)
            .map(|n| (*n.key.preimage(), n.value.pubkey))
        {
            Some(v) => v,
            None => {
                warn!(%src_addr, peer_enr_seq, "WhoAreYou from unknown addr, no kbuckets entry");
                return;
            }
        };

        // Verify the WhoAreYou echoes the nonce from our probe. For stale-session
        // re-challenges (we already have a session) we skip this check since the
        // challenged packet was a regular Message, not a probe.
        if !self.sessions.contains_key(&remote_id) {
            match self.pending_probe_nonces.remove(&remote_id) {
                Some(n) if n == probe_nonce => {}
                _ => {
                    warn!(%remote_id, %src_addr, peer_enr_seq, "WhoAreYou nonce mismatch or no pending probe");
                    return;
                }
            }
        } else {
            self.pending_probe_nonces.remove(&remote_id);
        }

        // TODO @nina: pre-generate ephemeral keypairs at idle time?
        let (ephem_pk_bytes, enc_key, dec_key) = match ecdh_generate_and_derive(
            &remote_pubkey,
            &self.local_id,
            &remote_id,
            aad,
        ) {
            Some(v) => v,
            None => {
                warn!(%remote_id, %src_addr, "ECDH key derivation failed during WhoAreYou handling");
                return;
            }
        };

        let sig_bytes = match sign_id_nonce(&self.local_key, aad, &ephem_pk_bytes, &remote_id) {
            Some(s) => s,
            None => {
                warn!(%remote_id, %src_addr, "id-nonce signing failed during WhoAreYou handling");
                return;
            }
        };

        let rng_buf: [u8; 28] = rand::random();
        let handshake_nonce: [u8; 12] = rng_buf[..12].try_into().unwrap();
        let iv: u128 = u128::from_be_bytes(rng_buf[12..].try_into().unwrap());

        // Include our ENR if the peer doesn't have it or has a stale version.
        let enr_record = if peer_enr_seq == 0 || peer_enr_seq < self.local_enr.seq() {
            Some(self.local_enr_raw)
        } else {
            None
        };

        let kind = MessageKind::Handshake {
            id_nonce_sig: sig_bytes,
            ephem_pubkey: ephem_pk_bytes,
            enr_record,
        };

        // Compute the handshake AAD (doesn't include the message body).
        let hs_aad = Packet {
            iv,
            src_id: self.local_id,
            nonce: handshake_nonce,
            kind: kind.clone(),
            message: &[],
        }
        .authenticated_data();

        let enc_cipher = make_cipher(&enc_key);
        let ciphertext = if let Some((rid, dists)) = self.pending_findnodes.remove(&remote_id) {
            let mut plain: ArrayVec<u8, 128> = ArrayVec::new();
            Message::FindNode { request_id: rid, distances: dists }.encode(&mut plain);
            encrypt_message(&enc_cipher, &handshake_nonce, &hs_aad, &plain)
        } else {
            None
        };

        let wire = Packet {
            iv,
            src_id: self.local_id,
            nonce: handshake_nonce,
            kind,
            message: ciphertext.as_ref().map(|c| c.as_slice()).unwrap_or(&[]),
        }
        .encode(&remote_id);

        self.sessions.insert(remote_id, Session::new(enc_key, dec_key, src_addr, now));

        self.event_queue.push(DiscoveryEvent::SendMessage { to: src_addr, data: wire });
        if let Some(enr) = self.decode_enr_for(remote_id) {
            self.event_queue.push(DiscoveryEvent::NodeFound(enr));
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_handshake(
        &mut self,
        src_id: NodeId,
        src_addr: SocketAddr,
        nonce: [u8; 12],
        aad: &[u8],
        id_nonce_sig: [u8; 64],
        ephem_pubkey: [u8; 33],
        enr_record: Option<ArrayVec<u8, ENR_RECORD_MAX>>,
        message: &[u8],
        now: Instant,
    ) {
        let challenge = match self.challenges.remove(&src_id) {
            Some(c) => c,
            None => {
                warn!(%src_id, %src_addr, "handshake from peer with no pending challenge");
                return;
            }
        };

        let existing_entry = self.kbuckets.get(&Key::from(src_id)).map(|n| n.value);
        let (remote_pubkey, stored_enr_raw) = match existing_entry {
            Some(e) => (e.pubkey, e.enr_raw),
            None => {
                // If we don't have the node's record, Handshake must contain it.
                let raw = match enr_record {
                    Some(b) => b,
                    None => {
                        warn!(%src_id, %src_addr, "handshake missing ENR for unknown peer");
                        return;
                    }
                };

                let enr = match Enr::decode(&mut raw.as_slice()) {
                    Ok(e) => e,
                    Err(_) => {
                        warn!(%src_id, %src_addr, "handshake contains invalid ENR");
                        self.metrics.failed_nodes += 1;
                        return;
                    }
                };

                if enr.node_id() != src_id {
                    warn!(%src_id, %src_addr, "handshake ENR node-id mismatch");
                    self.metrics.failed_nodes += 1;
                    return;
                }

                let pk_bytes = enr.public_key().serialize();

                self.kbuckets.insert_or_update(
                    &Key::from(src_id),
                    NodeEntry {
                        addr: src_addr,
                        enr_seq: enr.seq(),
                        pubkey: pk_bytes,
                        enr_raw: Some(raw),
                    },
                    now,
                );

                (pk_bytes, Some(raw))
            }
        };

        // Update enr_raw if a fresher record was provided in this Handshake.
        if let Some(raw) = enr_record {
            if stored_enr_raw != Some(raw) {
                if let Ok(enr) = Enr::decode(&mut raw.as_slice()) {
                    if enr.node_id() == src_id {
                        let _ = self.kbuckets.insert_or_update(
                            &Key::from(src_id),
                            NodeEntry {
                                addr: src_addr,
                                enr_seq: enr.seq(),
                                pubkey: enr.public_key().serialize(),
                                enr_raw: Some(raw),
                            },
                            now,
                        );
                    }
                }
            }
        }

        if !verify_id_nonce_sig(
            &remote_pubkey,
            &challenge.data,
            &ephem_pubkey,
            &self.local_id,
            &id_nonce_sig,
        ) {
            warn!(%src_id, %src_addr, "handshake id-nonce signature verification failed");
            self.metrics.failed_nodes += 1;
            return;
        }

        let (initiator_key, recipient_key) = match ecdh_and_derive_keys_responder(
            &self.local_key,
            &ephem_pubkey,
            &src_id,
            &self.local_id,
            &challenge.data,
        ) {
            Some(v) => v,
            None => {
                warn!(%src_id, %src_addr, "ECDH key derivation failed during handshake");
                return;
            }
        };

        let session = Session::new(recipient_key, initiator_key, src_addr, now);

        if message.is_empty() {
            self.sessions.insert(src_id, session);
        } else if let Some(bytes) = decrypt_message(&session.dec, &nonce, aad, message) {
            self.sessions.insert(src_id, session);
            self.handle_message(src_id, src_addr, &bytes, now);
        } else {
            warn!(%src_id, %src_addr, msg_len = message.len(), "handshake message decryption failed");
            self.metrics.failed_nodes += 1;
            return;
        }

        self.pending_probe_nonces.remove(&src_id);

        if let Some(enr) = self.decode_enr_for(src_id) {
            self.event_queue.push(DiscoveryEvent::NodeFound(enr));
        }
    }

    fn decode_enr_for(&self, id: NodeId) -> Option<Enr> {
        let raw = self.kbuckets.get(&Key::from(id))?.value.enr_raw?;
        Enr::decode(&mut raw.as_slice()).ok()
    }

    fn random_distances(n: usize, include_self: bool) -> Distances {
        let n = n.min(NUM_DISTANCES_TO_REQUEST);
        let mut distances = Distances::new();
        if include_self {
            distances.push(0);
        }
        while distances.len() < n {
            let d = rand::random::<u8>() as u64 + 1; // 1..=256
            if !distances.iter().any(|&x| x == d) {
                distances.push(d);
            }
        }
        distances
    }

    fn do_lookup(&mut self) {
        // Probe all un-sessioned peers first (bootstrap / new additions).
        let without_session: ArrayVec<(NodeId, SocketAddr), 32> = self
            .kbuckets
            .iter_ref()
            .filter(|n| {
                let id = n.key.preimage();
                !self.sessions.contains_key(id) &&
                    !self.pending_findnodes.contains_key(id) &&
                    !Self::is_banned(
                        &mut self.banned_nodes,
                        &mut self.banned_ips,
                        id,
                        n.value.addr.ip(),
                    )
            })
            .take(self.config.probes_per_lookup)
            .map(|n| (*n.key.preimage(), n.value.addr))
            .collect();

        for (node_id, addr) in &without_session {
            let rid = self.next_id();
            let distances = Self::random_distances(self.config.lookup_distances, true);
            self.pending_findnodes.insert(*node_id, (rid, distances));
            self.send_probe(*node_id, *addr);
        }

        // Send FindNode to a random sessioned peer for ongoing discovery.
        if without_session.is_empty() {
            let with_session: ArrayVec<(NodeId, SocketAddr), 32> = self
                .kbuckets
                .iter_ref()
                .filter(|n| {
                    self.sessions.contains_key(n.key.preimage()) &&
                        !Self::is_banned(
                            &mut self.banned_nodes,
                            &mut self.banned_ips,
                            n.key.preimage(),
                            n.value.addr.ip(),
                        )
                })
                .take(self.config.probes_per_lookup)
                .map(|n| (*n.key.preimage(), n.value.addr))
                .collect();

            if !with_session.is_empty() {
                let idx = rand::random::<usize>() % with_session.len();
                let (node_id, addr) = with_session[idx];
                let rid = self.next_id();
                let distances = Self::random_distances(self.config.lookup_distances, false);
                if let Some(s) = self.sessions.get(&node_id) &&
                    let Some(data) = Packet::encode_message(
                        self.local_id,
                        node_id,
                        &s.enc,
                        Message::FindNode { request_id: rid, distances },
                    )
                {
                    self.event_queue.push(DiscoveryEvent::SendMessage { to: addr, data });
                }
            }
        }
    }

    fn load_persisted(&mut self, now: Instant) {
        if let Some(path) = self.config.persisted_kbuckets_path.clone() {
            if let Ok(file) = std::fs::File::open(&path) {
                let mut i = 0usize;
                for line in std::io::BufReader::new(file).lines() {
                    let Ok(line) = line else { continue };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    if let Ok(enr) = line.parse::<Enr>() {
                        self.add_enr(&enr, now);
                        i += 1;
                    }
                }

                info!("loaded {i} persisted kbuckets from {}", path.display());
            }
        }

        if let Some(path) = self.config.persisted_banned_nodes_path.clone() {
            if let Ok(file) = std::fs::File::open(&path) {
                let mut i = 0usize;
                for line in std::io::BufReader::new(file).lines() {
                    let Ok(line) = line else { continue };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }

                    let mut parts = line.split_whitespace();
                    let (Some(kind), Some(key), Some(secs_str)) =
                        (parts.next(), parts.next(), parts.next())
                    else {
                        continue;
                    };

                    let Ok(secs) = secs_str.parse::<u64>() else { continue };
                    let expires = if secs == 0 {
                        None
                    } else {
                        Some(Instant::now() + Duration::from_secs(secs))
                    };

                    match kind {
                        "node" => {
                            let Ok(id_bytes) = hex::decode(key) else { continue };
                            let Ok(arr) = <[u8; 32]>::try_from(id_bytes.as_slice()) else {
                                continue;
                            };
                            self.banned_nodes.insert(NodeId::new(&arr), expires);
                        }
                        "ip" => {
                            let Ok(ip) = key.parse::<IpAddr>() else { continue };
                            self.banned_ips.insert(ip, expires);
                        }
                        _ => continue,
                    }
                    i += 1;
                }

                info!("loaded {i} banned nodes from {}", path.display());
            }
        }
    }

    fn persist_kbuckets(&self) {
        let Some(path) = &self.config.persisted_kbuckets_path else { return };
        let Ok(file) = std::fs::File::create(path) else {
            warn!(path = %path.display(), "failed to create kbuckets file");
            return;
        };

        let mut w = BufWriter::new(file);
        for node in self.kbuckets.iter_ref() {
            if let Some(raw) = &node.value.enr_raw {
                if let Ok(enr) = Enr::decode(&mut raw.as_slice()) {
                    let _ = writeln!(w, "{}", enr.to_base64());
                }
            }
        }
    }

    fn persist_banned_nodes(&self) {
        let Some(path) = &self.config.persisted_banned_nodes_path else { return };
        let Ok(file) = std::fs::File::create(path) else {
            warn!(path = %path.display(), "failed to open banned nodes file");
            return;
        };

        let mut w = BufWriter::new(file);
        let now = Instant::now();
        for (id, expires) in &self.banned_nodes {
            let secs = match expires {
                None => 0,
                Some(t) if *t > now => (*t - now).as_secs(),
                Some(_) => continue,
            };
            let _ = writeln!(w, "node {} {secs}", hex::encode(id.raw()));
        }

        for (ip, expires) in &self.banned_ips {
            let secs = match expires {
                None => 0,
                Some(t) if *t > now => (*t - now).as_secs(),
                Some(_) => continue,
            };
            let _ = writeln!(w, "ip {ip} {secs}");
        }
    }

    fn cleanup(&mut self) {
        let now = Instant::now();
        self.last_cleanup = now;

        let challenge_ttl = self.config.challenge_ttl();
        self.challenges.retain(|_, c| c.sent_at.elapsed() < challenge_ttl);

        let session_timeout = self.config.session_timeout();
        self.sessions.retain(|_, s| s.last_active.elapsed() < session_timeout);

        let request_timeout = self.config.request_timeout();
        self.pending_pings.retain(|_, (_, sent_at)| sent_at.elapsed() < request_timeout);

        let whoareyou_window = self.config.whoareyou_window();
        self.whoareyou_per_ip.retain(|_, (_, t)| t.elapsed() < whoareyou_window);

        self.banned_nodes.retain(|_, exp| exp.is_none_or(|t| now < t));
        self.banned_ips.retain(|_, exp| exp.is_none_or(|t| now < t));

        self.metrics.active_sessions = self.sessions.len();
        self.metrics.pending_challenges = self.challenges.len();
        self.metrics.routing_table_nodes = self.kbuckets.iter_ref().count();
    }
}

impl Discovery for DiscV5 {
    fn local_id(&self) -> NodeId {
        self.local_id
    }

    fn add_enr(&mut self, enr: &Enr, now: Instant) {
        let addr = if let (Some(ip4), Some(udp4)) = (enr.ip4(), enr.udp4()) {
            SocketAddr::new(IpAddr::V4(ip4), udp4)
        } else if let (Some(ip6), Some(udp6)) = (enr.ip6(), enr.udp6()) {
            SocketAddr::new(IpAddr::V6(ip6), udp6)
        } else {
            warn!("skipping adding node enr with no ip4 / ip6 fields: {enr}");
            return;
        };

        let pubkey = enr.public_key().serialize();

        let mut enr_raw: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
        enr.encode(&mut enr_raw);

        let _ = self.kbuckets.insert_or_update(
            &Key::from(enr.node_id()),
            NodeEntry { addr, enr_seq: enr.seq(), pubkey, enr_raw: Some(enr_raw) },
            now,
        );
    }

    fn find_nodes(&mut self) {
        self.lookup_requested = true;
    }

    fn ban_node(&mut self, id: NodeId, duration: Option<Duration>) {
        let expires = duration.map(|d| Instant::now() + d);
        self.banned_nodes.insert(id, expires);
        self.sessions.remove(&id);
        self.pending_findnodes.remove(&id);
        self.pending_probe_nonces.remove(&id);
    }

    fn ban_ip(&mut self, ip: IpAddr, duration: Option<Duration>) {
        let expires = duration.map(|d| Instant::now() + d);
        self.banned_ips.insert(ip, expires);
    }

    fn unban_node(&mut self, id: NodeId) {
        self.banned_nodes.remove(&id);
    }

    fn unban_ip(&mut self, ip: IpAddr) {
        self.banned_ips.remove(&ip);
    }

    fn teardown(&self) {
        self.persist_kbuckets();
        self.persist_banned_nodes();
    }

    fn poll<F>(&mut self, mut f: F)
    where
        F: FnMut(DiscoveryEvent),
    {
        if self.last_cleanup.elapsed() >= self.config.cleanup_interval() {
            self.cleanup();
        }

        while let Some(applied) = self.kbuckets.take_applied_pending() {
            if let Some(enr) = self.decode_enr_for(*applied.inserted.preimage()) {
                self.metrics.nodes_discovered += 1;
                f(DiscoveryEvent::NodeFound(enr));
            }
        }

        if self.last_ping.elapsed() >= self.config.ping_frequency() {
            let mut sent = 0usize;
            let mut visited = 0usize;
            let mut rid = self.next_request_id;

            for node in self.kbuckets.iter_ref().skip(self.ping_cursor) {
                if sent >= self.config.pings_per_poll {
                    break;
                }
                visited += 1;
                let node_id = *node.key.preimage();
                let addr = node.value.addr;
                if Self::is_banned(
                    &mut self.banned_nodes,
                    &mut self.banned_ips,
                    &node_id,
                    addr.ip(),
                ) {
                    continue;
                }
                if let Some(s) = self.sessions.get(&node_id) &&
                    let Some(data) =
                        Packet::encode_message(self.local_id, node_id, &s.enc, Message::Ping {
                            request_id: rid,
                            enr_seq: self.local_enr.seq(),
                        })
                {
                    self.pending_pings.insert(rid, (node_id, Instant::now()));
                    rid = rid.wrapping_add(1);
                    f(DiscoveryEvent::SendMessage { to: addr, data });
                    sent += 1;
                }
            }

            self.next_request_id = rid;
            self.ping_cursor += visited;

            if sent < self.config.pings_per_poll {
                // Iterator exhausted — wrap cursor, wait for next cycle.
                self.ping_cursor = 0;
                self.last_ping = Instant::now();
            }
        }

        let below_capacity = self.sessions.len() < self.config.target_sessions;
        let do_lookup = self.lookup_requested ||
            (below_capacity && self.last_lookup.elapsed() >= self.config.lookup_interval());
        if do_lookup {
            self.lookup_requested = false;
            self.last_lookup = Instant::now();

            self.do_lookup();
        }

        for event in self.event_queue.drain(..) {
            f(event);
        }
    }

    fn handle(&mut self, src_addr: SocketAddr, data: &[u8], now: Instant) {
        let (packet, aad) = match Packet::decode(&self.local_id, data) {
            Ok(v) => v,
            Err(e) => {
                warn!(%src_addr, %e, len = data.len(), "packet decode failed");
                return;
            }
        };

        let src_id = packet.src_id;
        let nonce = packet.nonce;

        if Self::is_banned(&mut self.banned_nodes, &mut self.banned_ips, &src_id, src_addr.ip()) {
            trace!(
                "dropping message from the banned node with node_id = {} and ip = {}",
                src_id,
                src_addr.ip()
            );
            return;
        }

        match packet.kind {
            MessageKind::Message => {
                if let Some(s) = self.sessions.get_mut(&src_id) {
                    if !s.check_and_record_nonce(&nonce, now) {
                        warn!(%src_id, %src_addr, ?nonce, "replayed nonce, dropping message");
                        self.metrics.failed_nodes += 1;
                        return;
                    }

                    let plain = decrypt_message(&s.dec, &nonce, &aad, packet.message);
                    let addr_matches = s.addr == src_addr;

                    match (plain, addr_matches) {
                        (Some(bytes), true) => {
                            self.handle_message(src_id, src_addr, &bytes, now);
                        }
                        (Some(_), false) => {
                            // Decrypted OK but endpoint changed — re-handshake.
                            self.sessions.remove(&src_id);
                            self.send_whoareyou(src_id, src_addr, nonce, now);
                        }
                        (None, _) => {
                            // Stale session or decryption failure; re-challenge.
                            self.send_whoareyou(src_id, src_addr, nonce, now);
                        }
                    }
                } else {
                    self.send_whoareyou(src_id, src_addr, nonce, now);
                }
            }

            MessageKind::WhoAreYou { enr_seq, .. } => {
                self.handle_whoareyou(nonce, src_addr, &aad, enr_seq, now);
            }

            MessageKind::Handshake { id_nonce_sig, ephem_pubkey, enr_record } => {
                self.handle_handshake(
                    src_id,
                    src_addr,
                    nonce,
                    &aad,
                    id_nonce_sig,
                    ephem_pubkey,
                    enr_record,
                    packet.message,
                    now,
                );

                self.flush_pending_findnode(src_id, src_addr);
            }
        }
    }
}

struct NonceRing {
    buf: [[u8; 12]; NONCE_RING_SIZE],
    head: usize,
    len: usize,
}

impl NonceRing {
    fn new() -> Self {
        Self { buf: [[0u8; 12]; NONCE_RING_SIZE], head: 0, len: 0 }
    }

    fn insert(&mut self, nonce: [u8; 12]) -> bool {
        let valid = self.len.min(NONCE_RING_SIZE);
        if self.buf[..valid].contains(&nonce) {
            return false;
        }
        self.buf[self.head] = nonce;
        self.head = (self.head + 1) % NONCE_RING_SIZE;
        if self.len < NONCE_RING_SIZE {
            self.len += 1;
        }
        true
    }
}

struct Session {
    enc: SessionCipher,
    dec: SessionCipher,
    seen_nonces: NonceRing,
    addr: SocketAddr,
    last_active: Instant,
}

impl Session {
    fn new(enc_key: [u8; 16], dec_key: [u8; 16], addr: SocketAddr, now: Instant) -> Self {
        Session {
            enc: make_cipher(&enc_key),
            dec: make_cipher(&dec_key),
            seen_nonces: NonceRing::new(),
            addr,
            last_active: now,
        }
    }

    fn check_and_record_nonce(&mut self, nonce: &[u8; 12], now: Instant) -> bool {
        if !self.seen_nonces.insert(*nonce) {
            return false;
        }
        self.last_active = now;
        true
    }
}

/// Challenge data: `iv(16) || static_header(23) || auth_data(24)`
struct PendingChallenge {
    data: [u8; 63],
    sent_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeEntry {
    pub addr: SocketAddr,
    pub enr_seq: u64,
    /// Compressed secp256k1 public key. Required for ECDH during
    /// WhoAreYou response.
    pub pubkey: [u8; 33],
    /// Raw RLP-encoded ENR record, if known.
    pub enr_raw: Option<ArrayVec<u8, ENR_RECORD_MAX>>,
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Instant,
    };

    use silver_common::{Enr, NodeId};

    use super::*;
    use crate::{
        config::DiscoveryConfig,
        discovery::{Discovery, DiscoveryEvent},
        message::{Message, Packet},
    };

    fn make_node(port: u16) -> (DiscV5, SocketAddr) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let enr = Enr::builder().ip4(Ipv4Addr::LOCALHOST).udp4(port).build(&sk).unwrap();
        let disco = DiscV5::new(DiscoveryConfig::default(), sk, enr, [0u8; 4]);
        (disco, addr)
    }

    fn collect_sends(node: &mut DiscV5) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        node.poll(|e| {
            if let DiscoveryEvent::SendMessage { to, data } = e {
                out.push((to, data.to_vec()));
            }
        });
        out
    }

    fn collect_events(node: &mut DiscV5) -> Vec<DiscoveryEvent> {
        let mut out = Vec::new();
        node.poll(|e| out.push(e));
        out
    }

    fn inject_message(
        from: &mut DiscV5,
        to: &mut DiscV5,
        from_addr: SocketAddr,
        msg: Message,
        now: Instant,
    ) {
        let to_id = to.local_id;
        let data = {
            let s = from.sessions.get(&to_id).expect("no session from->to");
            Packet::encode_message(from.local_id, to_id, &s.enc, msg).expect("encode failed")
        };
        to.handle(from_addr, &data, now);
    }

    /// Drive the probe → WhoAreYou → Handshake exchange between two nodes.
    /// After return both nodes have an established session.
    fn do_handshake(
        a: &mut DiscV5,
        a_addr: SocketAddr,
        b: &mut DiscV5,
        b_addr: SocketAddr,
        now: Instant,
    ) {
        a.add_enr(&b.local_enr, now);
        a.find_nodes();

        // A → probe
        let a_sends = collect_sends(a);
        let probe = a_sends.iter().find(|(to, _)| *to == b_addr).map(|(_, d)| d.clone()).unwrap();

        // B → WhoAreYou
        b.handle(a_addr, &probe, now);
        let b_sends = collect_sends(b);
        let wru = b_sends.iter().find(|(to, _)| *to == a_addr).map(|(_, d)| d.clone()).unwrap();

        // A handles WhoAreYou → queues Handshake + FindNode
        a.handle(b_addr, &wru, now);
        let a_sends = collect_sends(a);

        // Route all A→B packets (Handshake first, then FindNode)
        for (to, data) in &a_sends {
            if *to == b_addr {
                b.handle(a_addr, data, now);
            }
        }
        // B drains its queue (NodeFound, etc.)
        collect_events(b);
    }

    #[test]
    fn test_session_establishment() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19001);
        let (mut b, b_addr) = make_node(19002);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        assert!(a.sessions.contains_key(&b.local_id), "A missing session for B");
        assert!(b.sessions.contains_key(&a.local_id), "B missing session for A");
        assert!(!b.challenges.contains_key(&a.local_id), "B still has challenge for A");
    }

    #[test]
    fn test_ping_pong_roundtrip() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19011);
        let (mut b, b_addr) = make_node(19012);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        let votes_before = a.ip_votes.len();

        // A sends Ping; B replies with Pong. Register the pending ping so A
        // accepts the PONG.
        a.pending_pings.insert(1, (b.local_id, now));
        inject_message(&mut a, &mut b, a_addr, Message::Ping { request_id: 1, enr_seq: 0 }, now);
        let b_sends = collect_sends(&mut b);
        for (to, data) in &b_sends {
            if *to == a_addr {
                a.handle(b_addr, data, now);
            }
        }
        collect_events(&mut a);

        let votes_after = a.ip_votes.len();
        assert!(votes_after > votes_before, "ip_votes not updated after Pong");
    }

    #[test]
    fn test_findnode_distance_zero_returns_own_enr() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19021);
        let (mut b, b_addr) = make_node(19022);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // B sends FindNode(distance=0) to A.
        let mut distances = Distances::new();
        distances.push(0);
        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::FindNode { request_id: 10, distances },
            now,
        );
        let a_sends = collect_sends(&mut a);

        // Route A's Nodes reply to B.
        for (to, data) in &a_sends {
            if *to == b_addr {
                b.handle(a_addr, data, now);
            }
        }
        collect_events(&mut b);

        // A's ENR should now be stored in B's kbuckets.
        let has_a_enr = b
            .kbuckets
            .iter_ref()
            .any(|n| *n.key.preimage() == a.local_id && n.value.enr_raw.is_some());
        assert!(has_a_enr, "B should have A's ENR after distance-0 FindNode");
    }

    #[test]
    fn test_findnode_returns_discovered_peers() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19031);
        let (mut b, b_addr) = make_node(19032);
        // C is a third node known to A with a full ENR.
        let (c, _) = make_node(19033);
        let c_id = c.local_id;

        // Pre-populate A's kbuckets with C's ENR.
        a.add_enr(&c.local_enr, now);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // B sends FindNode over all plausible distances; A should include C.
        let mut distances = Distances::new();
        for d in 250u64..=256 {
            distances.push(d);
        }
        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::FindNode { request_id: 11, distances },
            now,
        );
        let a_sends = collect_sends(&mut a);

        for (to, data) in &a_sends {
            if *to == b_addr {
                b.handle(a_addr, data, now);
            }
        }
        collect_events(&mut b);

        let has_c = b.kbuckets.iter_ref().any(|n| *n.key.preimage() == c_id);
        assert!(has_c, "B should have discovered C via A's FindNode reply");
    }

    #[test]
    fn test_pong_ipv6_vote_updates_enr() {
        let now = Instant::now();
        // A has no IP so every Pong-observed address is "new".
        let sk = SecretKey::new(&mut rand::thread_rng());
        let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19041);
        let enr = Enr::builder().build(&sk).unwrap();
        let mut a = DiscV5::new(DiscoveryConfig::default(), sk, enr, [0u8; 4]);

        // Need 3 distinct peers to cross IP_VOTE_THRESHOLD (one vote per NodeId).
        let (mut b, b_addr) = make_node(19042);
        let (mut c, c_addr) = make_node(19043);
        let (mut d, d_addr) = make_node(19044);
        do_handshake(&mut a, a_addr, &mut b, b_addr, now);
        do_handshake(&mut a, a_addr, &mut c, c_addr, now);
        do_handshake(&mut a, a_addr, &mut d, d_addr, now);

        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let port = 19041u16;

        a.pending_pings.insert(100, (b.local_id, now));
        a.pending_pings.insert(101, (c.local_id, now));
        a.pending_pings.insert(102, (d.local_id, now));

        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::Pong { request_id: 100, enr_seq: 0, ip: ipv6, port },
            now,
        );
        inject_message(
            &mut c,
            &mut a,
            c_addr,
            Message::Pong { request_id: 101, enr_seq: 0, ip: ipv6, port },
            now,
        );
        inject_message(
            &mut d,
            &mut a,
            d_addr,
            Message::Pong { request_id: 102, enr_seq: 0, ip: ipv6, port },
            now,
        );

        let events = collect_events(&mut a);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, DiscoveryEvent::ExternalAddrChanged(sa) if sa.ip() == ipv6)),
            "expected ExternalAddrChanged with IPv6 address"
        );
    }

    #[test]
    fn test_nodes_fork_digest_filter() {
        let now = Instant::now();
        let fork_digest = [0x01, 0x02, 0x03, 0x04u8];
        let sk_a = SecretKey::new(&mut rand::thread_rng());
        let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 19051);
        let enr_a = Enr::builder().ip4(Ipv4Addr::LOCALHOST).udp4(19051u16).build(&sk_a).unwrap();
        let mut a = DiscV5::new(DiscoveryConfig::default(), sk_a, enr_a, fork_digest);

        let (mut b, b_addr) = make_node(19052);
        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Build two ENRs:
        // - good: no eth2 field (passes the filter)
        // - bad: eth2 with wrong fork_digest (dropped)
        let sk_good = SecretKey::new(&mut rand::thread_rng());
        let enr_good =
            Enr::builder().ip4(Ipv4Addr::new(10, 0, 0, 1)).udp4(19053u16).build(&sk_good).unwrap();
        let id_good = enr_good.node_id();

        let sk_bad = SecretKey::new(&mut rand::thread_rng());
        let mut enr_bad =
            Enr::builder().ip4(Ipv4Addr::new(10, 0, 0, 2)).udp4(19054u16).build(&sk_bad).unwrap();
        // Wrong fork digest: all zeros.
        enr_bad.set_eth2([0u8; 16], &sk_bad).unwrap();
        let id_bad = enr_bad.node_id();

        let mut good_raw: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
        enr_good.encode(&mut good_raw);
        let mut bad_raw: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
        enr_bad.encode(&mut bad_raw);

        let mut nodes: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8> = ArrayVec::new();
        nodes.push(bad_raw);
        nodes.push(good_raw);

        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::Nodes { request_id: 20, total: 1, nodes },
            now,
        );
        collect_events(&mut a);

        assert!(
            a.kbuckets.iter_ref().any(|n| *n.key.preimage() == id_good),
            "good (no-eth2) node should be in kbuckets"
        );
        assert!(
            !a.kbuckets.iter_ref().any(|n| *n.key.preimage() == id_bad),
            "bad (wrong fork_digest) node should be filtered"
        );
    }

    #[test]
    fn test_nodes_response_splits_across_packets() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19081);
        let (mut b, b_addr) = make_node(19082);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Populate A's kbuckets with 8 peers whose ENRs include CL fields
        // to push each record to ~180 bytes, forcing multi-packet responses.
        let mut peer_ids: Vec<NodeId> = Vec::new();
        for i in 0u16..8 {
            let sk = SecretKey::new(&mut rand::thread_rng());
            let port = 20000 + i;
            let mut enr = Enr::builder()
                .ip4(Ipv4Addr::new(10, 0, 0, (i + 1) as u8))
                .udp4(port)
                .build(&sk)
                .unwrap();
            // fork_digest [0;4] matches B's fork_digest from make_node.
            enr.set_eth2([0u8; 16], &sk).unwrap();
            enr.set_attnets([0xFF; 8], &sk).unwrap();
            enr.set_syncnets(0x0F, &sk).unwrap();
            let p_id = enr.node_id();
            let p_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, (i + 1) as u8)), port);
            let p_pubkey = sk.public_key(SECP256K1).serialize();
            let mut raw: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
            enr.encode(&mut raw);
            let _ = a.kbuckets.insert_or_update(
                &Key::from(p_id),
                NodeEntry {
                    addr: p_addr,
                    enr_seq: enr.seq(),
                    pubkey: p_pubkey,
                    enr_raw: Some(raw),
                },
                now,
            );
            peer_ids.push(p_id);
        }

        // Request all distances so A returns as many peers as possible.
        let mut distances = Distances::new();
        for d in 241u64..=256 {
            distances.push(d);
        }
        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::FindNode { request_id: 50, distances },
            now,
        );

        // Collect raw packets A sends to B.
        let a_sends = collect_sends(&mut a);
        let packets_to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();

        assert!(
            packets_to_b.len() > 1,
            "expected multiple Nodes packets, got {}",
            packets_to_b.len()
        );

        // Deliver all packets to B and verify peers landed in kbuckets.
        for (_, data) in &packets_to_b {
            b.handle(a_addr, data, now);
        }
        collect_events(&mut b);

        // Verify all peers landed in B's kbuckets.
        let found: Vec<_> = peer_ids
            .iter()
            .filter(|id| b.kbuckets.iter_ref().any(|n| n.key.preimage() == *id))
            .collect();
        assert_eq!(found.len(), peer_ids.len(), "B should have discovered all peers");

        // Decrypt each packet and verify the `total` field matches the actual count.
        let n_packets = packets_to_b.len();
        for (_, wire) in &packets_to_b {
            let (pkt, aad) = Packet::decode(&b.local_id, wire).unwrap();
            let s = b.sessions.get(&a.local_id).unwrap();
            let plain =
                crate::crypto::decrypt_message(&s.dec, &pkt.nonce, &aad, pkt.message).unwrap();
            let msg = Message::decode(&plain).unwrap();
            match msg {
                Message::Nodes { total, .. } => {
                    assert_eq!(
                        total as usize, n_packets,
                        "total field ({total}) must match packet count ({n_packets})"
                    );
                }
                other => panic!("expected Nodes, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_nodes_response_empty_distances() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19091);
        let (mut b, b_addr) = make_node(19092);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Request distance 1 — extremely unlikely any random peer lands there.
        let mut distances = Distances::new();
        distances.push(1);
        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::FindNode { request_id: 60, distances },
            now,
        );

        let a_sends = collect_sends(&mut a);
        let packets_to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();

        // Should still get exactly one Nodes message (with empty list).
        assert_eq!(packets_to_b.len(), 1, "expected 1 empty Nodes response");
    }

    #[test]
    fn test_challenge_inserted_before_handshake_complete() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19061);
        let (mut b, b_addr) = make_node(19062);

        // Add B to A's kbuckets and trigger a probe to generate a challenge in B.
        a.add_enr(&b.local_enr, now);
        a.find_nodes();
        let a_sends = collect_sends(&mut a);
        let probe = a_sends.iter().find(|(to, _)| *to == b_addr).map(|(_, d)| d.clone()).unwrap();

        b.handle(a_addr, &probe, now);
        collect_sends(&mut b); // drain WhoAreYou

        // Challenge was recorded in B.
        assert!(b.challenges.contains_key(&a.local_id), "challenge should be present");
        // Session is not yet established (handshake not completed).
        assert!(!b.sessions.contains_key(&a.local_id));
    }

    #[test]
    fn test_nonce_replay_rejected() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19071);
        let (mut b, b_addr) = make_node(19072);
        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        let wire = {
            let s = a.sessions.get(&b.local_id).expect("no session a→b");
            Packet::encode_message(a.local_id, b.local_id, &s.enc, Message::Ping {
                request_id: 42,
                enr_seq: 0,
            })
            .expect("encode")
        };

        // First delivery succeeds (Pong produced).
        b.handle(a_addr, &wire, now);
        let sends1 = collect_sends(&mut b);
        assert!(!sends1.is_empty(), "first Ping should produce Pong");

        // Replay identical bytes — nonce ring rejects, no response.
        b.handle(a_addr, &wire, now);
        let sends2 = collect_sends(&mut b);
        assert!(sends2.is_empty(), "replayed packet must be dropped");
    }

    #[test]
    fn test_session_expiry_on_poll() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19111);
        let (mut b, b_addr) = make_node(19112);
        do_handshake(&mut a, a_addr, &mut b, b_addr, now);
        assert!(b.sessions.contains_key(&a.local_id));

        b.sessions.get_mut(&a.local_id).unwrap().last_active = Instant::now()
            .checked_sub(b.config.session_timeout() + Duration::from_secs(1))
            .expect("system uptime > session_timeout");

        b.cleanup();
        assert!(!b.sessions.contains_key(&a.local_id), "expired session should be removed");
    }

    #[test]
    fn test_challenge_ttl_expiry() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19121);
        let (mut b, b_addr) = make_node(19122);

        a.add_enr(&b.local_enr, now);
        a.find_nodes();
        let a_sends = collect_sends(&mut a);
        let probe = a_sends.iter().find(|(to, _)| *to == b_addr).unwrap().1.clone();

        b.handle(a_addr, &probe, now);
        collect_sends(&mut b);
        assert!(b.challenges.contains_key(&a.local_id));

        b.challenges.get_mut(&a.local_id).unwrap().sent_at = Instant::now()
            .checked_sub(b.config.challenge_ttl() + Duration::from_secs(1))
            .expect("system uptime > challenge_ttl");

        b.cleanup();
        assert!(!b.challenges.contains_key(&a.local_id), "expired challenge should be removed");
    }

    #[test]
    fn test_ping_with_newer_enr_seq_triggers_enr_refresh() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19101);
        let (mut b, b_addr) = make_node(19102);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // A doesn't have B's ENR yet (add_node sets enr_raw = None, and the
        // handshake piggybacked FindNode response hasn't been routed yet in
        // this test). Stored enr_seq for B in A's kbuckets is whatever
        // add_node set (seq from B's initial ENR, typically 1).
        let stored = a.kbuckets.get(&Key::from(b.local_id)).unwrap().value.enr_seq;

        // B bumps its ENR seq by setting a new field.
        b.local_enr.set_eth2([0u8; 16], &b.local_key).unwrap();
        b.local_enr_raw = {
            let mut buf = ArrayVec::new();
            b.local_enr.encode(&mut buf);
            buf
        };
        let new_seq = b.local_enr.seq();
        assert!(new_seq > stored, "B's ENR seq should have increased");

        // B sends Ping to A with the new enr_seq.
        inject_message(
            &mut b,
            &mut a,
            b_addr,
            Message::Ping { request_id: 100, enr_seq: new_seq },
            now,
        );

        // A should reply with Pong AND send FindNode(distance=0) to fetch B's
        // updated ENR.
        let a_sends = collect_sends(&mut a);
        let packets_to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();

        // Expect at least 2 packets: Pong + FindNode.
        assert!(
            packets_to_b.len() >= 2,
            "expected Pong + FindNode, got {} packets",
            packets_to_b.len()
        );

        // Deliver all to B; B responds with Nodes containing its own ENR.
        for (_, data) in &packets_to_b {
            b.handle(a_addr, data, now);
        }
        let b_sends = collect_sends(&mut b);

        // Route B's Nodes response back to A.
        for (to, data) in &b_sends {
            if *to == a_addr {
                a.handle(b_addr, data, now);
            }
        }
        let a_ev = collect_events(&mut a);

        // A should now have B's updated ENR and emit NodeFound.
        assert!(
            a_ev.iter().any(
                |e| matches!(e, DiscoveryEvent::NodeFound(enr) if enr.node_id() == b.local_id)
            ),
            "A should emit NodeFound with B's refreshed ENR"
        );

        // Verify the stored enr_seq was updated.
        let updated_seq = a.kbuckets.get(&Key::from(b.local_id)).unwrap().value.enr_seq;
        assert_eq!(updated_seq, new_seq, "A's stored enr_seq for B should match B's new seq");
    }

    #[test]
    fn test_ban_node_drops_messages() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19111);
        let (mut b, b_addr) = make_node(19112);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Ban B by node ID (permanent).
        a.ban_node(b.local_id, None);

        // Session should have been removed.
        assert!(!a.sessions.contains_key(&b.local_id), "session should be cleared on ban");

        // B sends a Ping — A should silently drop it.
        let rid = b.next_id();
        let data = {
            // B still has its session with A, re-create one for encoding.
            let s = b.sessions.get(&a.local_id).unwrap();
            Packet::encode_message(b.local_id, a.local_id, &s.enc, Message::Ping {
                request_id: rid,
                enr_seq: 1,
            })
            .unwrap()
        };
        a.handle(b_addr, &data, now);

        // A should produce no events toward B.
        let a_sends = collect_sends(&mut a);
        let to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();
        assert!(to_b.is_empty(), "banned node's messages should be dropped");
    }

    #[test]
    fn test_ban_ip_drops_messages() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19121);
        let (mut b, b_addr) = make_node(19122);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Ban B's IP (permanent).
        a.ban_ip(b_addr.ip(), None);

        // B sends a probe — A should silently drop it.
        let data = {
            let s = b.sessions.get(&a.local_id).unwrap();
            Packet::encode_message(b.local_id, a.local_id, &s.enc, Message::Ping {
                request_id: 0,
                enr_seq: 1,
            })
            .unwrap()
        };
        a.handle(b_addr, &data, now);

        let a_sends = collect_sends(&mut a);
        let to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();
        assert!(to_b.is_empty(), "banned IP's messages should be dropped");
    }

    #[test]
    fn test_ban_skips_ping() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19131);
        let (mut b, b_addr) = make_node(19132);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Ban B, but keep the session to verify the ping loop skips it.
        // (Normally ban_node removes the session, so insert a fresh ban
        //  without going through ban_node.)
        a.banned_nodes.insert(b.local_id, None);

        // Force a ping round.
        a.last_ping = Instant::now() - a.config.ping_frequency() - Duration::from_secs(1);
        let a_sends = collect_sends(&mut a);

        let to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();
        assert!(to_b.is_empty(), "banned node should not receive pings");
    }

    #[test]
    fn test_timed_ban_expires() {
        let now = Instant::now();
        let (mut a, a_addr) = make_node(19141);
        let (mut b, b_addr) = make_node(19142);

        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        // Ban B for 0 duration (already expired).
        a.ban_node(b.local_id, Some(Duration::ZERO));

        // Re-establish session and verify B can communicate again.
        do_handshake(&mut a, a_addr, &mut b, b_addr, now);

        assert!(!a.banned_nodes.contains_key(&b.local_id), "expired ban should be cleaned up");

        inject_message(&mut b, &mut a, b_addr, Message::Ping { request_id: 1, enr_seq: 0 }, now);
        let a_sends = collect_sends(&mut a);
        let to_b: Vec<_> = a_sends.iter().filter(|(to, _)| *to == b_addr).collect();
        assert!(!to_b.is_empty(), "expired ban should allow messages again");
    }

    #[test]
    fn test_whoareyou_per_ip_rate_limit() {
        let now = Instant::now();
        let (mut a, _) = make_node(19151);

        // Simulate messages from unknown nodes at the same IP, each triggering
        // a WhoAreYou. After the per-IP limit, further ones are dropped.
        let limit = a.config.whoareyou_per_ip_limit;
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        for i in 0..(limit + 3) {
            let port = 30000 + i as u16;
            let src_addr = SocketAddr::new(ip, port);
            let sk = SecretKey::new(&mut rand::thread_rng());
            let src_id = NodeId::from(sk.public_key(SECP256K1));
            // Craft a minimal Message packet that A can't decrypt → triggers WhoAreYou.
            let garbage_key = crate::crypto::make_cipher(&[0xAA; 16]);
            if let Some(data) =
                Packet::encode_message(src_id, a.local_id, &garbage_key, Message::Ping {
                    request_id: i as u64,
                    enr_seq: 0,
                })
            {
                a.handle(src_addr, &data, now);
            }
        }

        let events = collect_sends(&mut a);
        let whoareyou_count = events.iter().filter(|(to, _)| to.ip() == ip).count();
        assert_eq!(whoareyou_count, limit as usize, "should cap WhoAreYou at per-IP limit");
    }

    #[test]
    fn test_whoareyou_global_rate_limit() {
        let now = Instant::now();
        let (mut a, _) = make_node(19161);

        // Send from distinct IPs to bypass per-IP limit, hit global limit.
        let limit = a.config.whoareyou_global_limit;
        let count = limit + 10;
        for i in 0..count {
            let octets = [10, (i >> 16) as u8, (i >> 8) as u8, i as u8];
            let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), 30000);
            let sk = SecretKey::new(&mut rand::thread_rng());
            let src_id = NodeId::from(sk.public_key(SECP256K1));
            let garbage_key = crate::crypto::make_cipher(&[0xBB; 16]);
            if let Some(data) =
                Packet::encode_message(src_id, a.local_id, &garbage_key, Message::Ping {
                    request_id: i as u64,
                    enr_seq: 0,
                })
            {
                a.handle(src_addr, &data, now);
            }
        }

        let events = collect_sends(&mut a);
        let whoareyou_count = events.len();
        assert_eq!(whoareyou_count, limit as usize, "should cap WhoAreYou at global limit");
    }
}
