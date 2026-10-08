use std::time::Instant;

use fxhash::{FxHashMap, FxHashSet};
use silver_common::{
    ALL_PROTOCOLS, Enr, Identify, NUMBER_OF_CUSTODY_GROUPS, NodeId, PeerId, PeerStatus,
    StreamProtocol,
    ssz_view::{METADATA_SIZE, MetadataView},
};
use slab::Slab;

pub struct PeerDatabase {
    peers: Slab<PeerRecord>,
    by_peer_id: FxHashMap<PeerId, usize>,
    by_node_id: FxHashMap<NodeId, usize>,
    by_p2p_id: FxHashMap<usize, usize>,
    by_protocol: FxHashMap<StreamProtocol, FxHashSet<usize>>,
}

impl Default for PeerDatabase {
    fn default() -> Self {
        Self {
            peers: Slab::with_capacity(1024),
            by_peer_id: Default::default(),
            by_node_id: Default::default(),
            by_p2p_id: Default::default(),
            by_protocol: Default::default(),
        }
    }
}

impl PeerDatabase {
    /// Returns `true` if this was a preiously unknown peer.
    pub fn add_enr(&mut self, enr: Enr) -> bool {
        self.upsert_enr(enr, false)
    }

    pub fn add_trusted_peer(&mut self, enr: Enr) -> bool {
        self.upsert_enr(enr, true)
    }

    fn upsert_enr(&mut self, enr: Enr, trusted: bool) -> bool {
        let compressed = enr.public_key().serialize();
        let peer_id = PeerId::from_secp256k1_pubkey(&compressed);

        match self.by_node_id.get(&enr.node_id()).and_then(|idx| self.peers.get_mut(*idx)) {
            Some(record) => {
                record.node_id.replace(enr.node_id());
                record.peer_id.replace(peer_id);
                record.enr.replace(enr);
                record.refresh_custody();
                false
            }
            None => {
                let mut record = PeerRecord::default();
                let node_id = enr.node_id();
                record.enr.replace(enr);
                record.node_id.replace(node_id);
                record.peer_id.replace(peer_id);
                record.is_trusted = trusted;
                record.refresh_custody();

                let index = self.peers.insert(record);
                self.by_node_id.insert(node_id, index);
                self.by_peer_id.insert(peer_id, index);

                true
            }
        }
    }

    pub fn add_peer_id(&mut self, peer_id: PeerId, p2p_id: usize) -> bool {
        let node_id = (&peer_id).try_into().unwrap();
        let (index, new_record) =
            match self.by_peer_id.get(&peer_id).or(self.by_node_id.get(&node_id)) {
                Some(index) => (*index, false),
                None => {
                    let index = self.peers.insert(PeerRecord::default());
                    (index, true)
                }
            };

        if let Some(record) = self.peers.get_mut(index) {
            record.peer_id.replace(peer_id);
            record.node_id.replace(node_id);
            record.dial_backoff_until = None;
            record.refresh_custody();
        };
        self.by_node_id.insert(node_id, index);
        self.by_peer_id.insert(peer_id, index);
        if let Some(replaced) = self.by_p2p_id.insert(p2p_id, index) {
            self.release_connection(replaced);
        }
        if let Some(record) = self.peers.get_mut(index) {
            record.live_connections += 1;
        }

        new_record
    }

    pub fn add_p2p_identify(&mut self, p2p_id: usize, identify: Identify) {
        if let Some(idx) = self.by_p2p_id.get(&p2p_id) {
            // index by supported protocol
            for i in 0..32 {
                if identify.protocols & (1 << i) != 0 {
                    let protocol = ALL_PROTOCOLS[i as usize];
                    self.by_protocol
                        .entry(protocol)
                        .and_modify(|s| {
                            s.insert(*idx);
                        })
                        .or_insert_with(|| FxHashSet::from_iter([*idx]));
                }
            }
            if let Some(record) = self.peers.get_mut(*idx) {
                silver_log::debug!(p2p_id, ?identify, "setting peer identify");
                record.identify.replace(identify);
            }
        }
    }

    pub fn peer_disconnected(&mut self, p2p_id: usize) -> Option<&PeerRecord> {
        let index = self.by_p2p_id.remove(&p2p_id)?;
        self.release_connection(index);
        self.peers.get(index)
    }

    fn release_connection(&mut self, index: usize) {
        if let Some(record) = self.peers.get_mut(index) {
            debug_assert!(record.live_connections > 0, "record {index} was not live");
            record.live_connections = record.live_connections.saturating_sub(1);
        }
    }

    pub fn dial_backoff_active(&self, peer_id: &PeerId, now: Instant) -> bool {
        self.by_peer_id
            .get(peer_id)
            .and_then(|idx| self.peers.get(*idx))
            .and_then(|r| r.dial_backoff_until)
            .is_some_and(|t| t > now)
    }

    pub fn dial_failed(&mut self, peer_id: &PeerId, until: Instant) {
        if let Some(record) = self.by_peer_id.get(peer_id).and_then(|idx| self.peers.get_mut(*idx))
        {
            if !record.is_trusted {
                record.dial_backoff_until = Some(until);
            }
        }
    }

    /// Disconnected records that are structurally dialable: known peer id and
    /// an ENR with a QUIC endpoint, no live connection, dial backoff expired.
    /// The caller applies its own gates (bans, in-flight dials, fork digest).
    pub fn redial_candidates(&self, now: Instant) -> impl Iterator<Item = &PeerRecord> + '_ {
        self.peers.iter().filter_map(move |(_, record)| {
            record.peer_id.as_ref()?;
            let enr = record.enr.as_ref()?;
            if enr.quic4_socket().is_none() && enr.quic6_socket().is_none() {
                return None;
            }
            if record.dial_backoff_until.is_some_and(|t| t > now) {
                return None;
            }
            if record.live_connections > 0 {
                return None;
            }
            Some(record)
        })
    }

    pub fn p2p_status(&mut self, p2p_id: usize, status: PeerStatus, earliest_slot: Option<u64>) {
        if let Some(record) = self.by_p2p_id.get(&p2p_id).and_then(|idx| self.peers.get_mut(*idx)) {
            record.status.replace(status);
            record.earliest_slot = earliest_slot;
        }
    }

    #[allow(dead_code)]
    pub fn peer_status_bytes(&self, p2p_id: usize) -> Option<&[u8]> {
        self.by_p2p_id
            .get(&p2p_id)
            .and_then(|idx| self.peers.get(*idx))
            .and_then(|record| record.status.as_ref())
            .map(status_bytes)
    }

    pub fn iter_live_status_bytes(&self) -> impl Iterator<Item = (usize, &[u8])> + '_ {
        self.by_p2p_id.iter().filter_map(|(p2p_id, idx)| {
            let record = self.peers.get(*idx)?;
            Some((*p2p_id, status_bytes(record.status.as_ref()?)))
        })
    }

    pub fn p2p_metadata(&mut self, p2p_id: usize, metadata: [u8; METADATA_SIZE]) {
        if let Some(record) = self.by_p2p_id.get(&p2p_id).and_then(|idx| self.peers.get_mut(*idx)) {
            record.metadata.replace(metadata);
            record.refresh_custody();
        }
    }

    pub fn p2p_metadata_seq(&self, p2p_id: usize) -> Option<u64> {
        self.by_p2p_id
            .get(&p2p_id)
            .and_then(|idx| self.peers.get(*idx))
            .and_then(|record| record.metadata.as_ref())
            .map(MetadataView::seq_number)
    }

    pub fn earliest_available_slot(&self, p2p_id: usize) -> Option<u64> {
        self.by_p2p_id
            .get(&p2p_id)
            .and_then(|idx| self.peers.get(*idx))
            .and_then(|r| r.earliest_slot)
    }

    pub fn data_column_custody_groups_intersection(&self, peer: usize, columns: u128) -> u128 {
        self.by_p2p_id
            .get(&peer)
            .and_then(|idx| self.peers.get(*idx))
            .map_or(0, |record| record.custody_groups & columns)
    }

    /// Live connection ids whose identify advertises `protocol`. A peer is
    /// "live" iff it has an active p2p_id mapping (i.e., currently
    /// connected); the protocol set is populated when an `Identify` record
    /// arrives.
    pub fn live_peers_supporting(
        &self,
        protocol: StreamProtocol,
    ) -> impl Iterator<Item = usize> + '_ {
        let proto = self.by_protocol.get(&protocol);
        self.by_p2p_id
            .iter()
            .filter_map(move |(p2p_id, idx)| proto?.contains(idx).then_some(*p2p_id))
    }

    pub fn by_p2p_id(&self, p2p: usize) -> Option<&PeerRecord> {
        self.by_p2p_id.get(&p2p).and_then(|idx| self.peers.get(*idx))
    }

    pub fn by_peer_id(&self, peer_id: &PeerId) -> Option<&PeerRecord> {
        self.by_peer_id.get(peer_id).and_then(|idx| self.peers.get(*idx))
    }
}

fn status_bytes(s: &PeerStatus) -> &[u8] {
    match s {
        PeerStatus::V1(b) => b.as_slice(),
        PeerStatus::V2(b) => b.as_slice(),
    }
}

#[derive(Debug, Default)]
pub struct PeerRecord {
    /// p2p id
    pub peer_id: Option<PeerId>,
    /// discovery id
    pub node_id: Option<NodeId>,
    /// Enr
    pub enr: Option<Enr>,
    /// Latest peer status
    pub status: Option<PeerStatus>,
    pub earliest_slot: Option<u64>,
    /// Latest peer metadata
    pub metadata: Option<[u8; METADATA_SIZE]>,
    /// Identify record
    pub identify: Option<Identify>,
    /// Not a redial candidate until this instant (dial failed / timed out).
    pub dial_backoff_until: Option<Instant>,
    /// Trusted peer
    pub is_trusted: bool,
    /// Connections in `by_p2p_id` naming this record; more than one while a
    /// duplicate connection is open.
    pub(crate) live_connections: u32,
    /// Hashed out of the node id, so derived once per `custody_inputs`.
    custody_groups: u128,
    custody_inputs: Option<(NodeId, u8)>,
}

impl PeerRecord {
    /// The count is the larger of the ENR `cgc` and the MetaData v3
    /// `custody_group_count`: a node promoted to supernode (e.g. by validator
    /// count) bumps its MetaData cgc immediately but can carry a stale lower
    /// `cgc` in its ENR.
    fn refresh_custody(&mut self) {
        let Some(node_id) = self.node_id else { return };
        let enr_cgc = self.enr.as_ref().and_then(|enr| enr.cgc()).unwrap_or(0);
        let meta_cgc = self.metadata.as_ref().map(MetadataView::custody_group_count).unwrap_or(0);
        let count = enr_cgc.max(meta_cgc).min(NUMBER_OF_CUSTODY_GROUPS as u64) as u8;
        if self.custody_inputs == Some((node_id, count)) {
            return;
        }
        self.custody_inputs = Some((node_id, count));
        self.custody_groups = node_id.custody_groups(count);
    }
}

#[cfg(test)]
mod tests {
    use silver_common::{Enr, Keypair};

    use super::*;

    /// The cached mask tracks the larger of the ENR and MetaData counts.
    #[test]
    fn custody_follows_enr_and_metadata_counts() {
        let mut database = PeerDatabase::default();
        let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().cgc(4).build(keypair.secret_key()).unwrap();
        let node_id = enr.node_id();
        database.add_enr(enr);
        database.add_peer_id(keypair.peer_id(), 1);
        let custody = |database: &PeerDatabase| {
            database.data_column_custody_groups_intersection(1, u128::MAX)
        };
        assert_eq!(custody(&database), node_id.custody_groups(4));

        let mut metadata = [0u8; METADATA_SIZE];
        metadata[17..25].copy_from_slice(&64u64.to_le_bytes());
        database.p2p_metadata(1, metadata);
        assert_eq!(custody(&database), node_id.custody_groups(64));

        metadata[17..25].copy_from_slice(&2u64.to_le_bytes());
        database.p2p_metadata(1, metadata);
        assert_eq!(custody(&database), node_id.custody_groups(4), "the ENR count is larger");
        assert_eq!(
            database.data_column_custody_groups_intersection(1, 0b1111),
            custody(&database) & 0b1111
        );
    }
}
