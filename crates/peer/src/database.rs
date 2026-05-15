use fxhash::{FxHashMap, FxHashSet};
use silver_common::{
    ALL_PROTOCOLS, Enr, Identify, NodeId, PeerId, PeerStatus, StreamProtocol,
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
        let compressed = enr.public_key().serialize();
        let peer_id = PeerId::from_secp256k1_pubkey(&compressed);

        match self.by_node_id.get(&enr.node_id()).and_then(|idx| self.peers.get_mut(*idx)) {
            Some(record) => {
                record.node_id.replace(enr.node_id());
                record.peer_id.replace(peer_id);
                record.enr.replace(enr);
                false
            }
            None => {
                let mut record = PeerRecord::default();
                let node_id = enr.node_id();
                record.enr.replace(enr);
                record.node_id.replace(node_id);
                record.peer_id.replace(peer_id);

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
        };
        self.by_node_id.insert(node_id, index);
        self.by_peer_id.insert(peer_id, index);
        self.by_p2p_id.insert(p2p_id, index);

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
                record.identify.replace(identify);
            }
        }
    }

    pub fn peer_disconnected(&mut self, p2p_id: usize) {
        self.by_p2p_id.remove(&p2p_id);
    }

    pub fn p2p_status(&mut self, p2p_id: usize, status: PeerStatus) {
        if let Some(record) = self.by_p2p_id.get(&p2p_id).and_then(|idx| self.peers.get_mut(*idx)) {
            record.status.replace(status);
        }
    }

    pub fn p2p_metadata(&mut self, p2p_id: usize, metadata: [u8; METADATA_SIZE]) {
        if let Some(record) = self.by_p2p_id.get(&p2p_id).and_then(|idx| self.peers.get_mut(*idx)) {
            record.metadata.replace(metadata);
        }
    }

    pub fn p2p_metadata_seq(&self, p2p_id: usize) -> Option<u64> {
        self.by_p2p_id
            .get(&p2p_id)
            .and_then(|idx| self.peers.get(*idx))
            .and_then(|record| record.metadata.as_ref())
            .map(MetadataView::seq_number)
    }

    pub fn has_data_column_custody_group(&self, peer: usize, column_group: u64) -> bool {
        let custody_groups = self
            .by_p2p_id
            .get(&peer)
            .and_then(|idx| self.peers.get(*idx))
            .and_then(|r| r.node_id.zip(r.enr.as_ref().and_then(|enr| enr.cgc())))
            .map(|(id, count)| id.custody_groups(count as u8))
            .unwrap_or_default();
        custody_groups & 1 << column_group != 0
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
    /// Latest peer metadata
    pub metadata: Option<[u8; METADATA_SIZE]>,
    /// Identify record
    pub identify: Option<Identify>,
}
