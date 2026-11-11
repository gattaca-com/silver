use fxhash::FxHashMap;
use silver_common::{
    PeerId, ProtoIdentify, TCacheError, TCacheId, TCacheProducer, TCacheReader, TProducer,
    TReadMode, TileId, ssz_view::MAX_PAYLOAD_SIZE,
};

use crate::{RemotePeer, p2p::streams::gossip_in::MAX_GOSSIP_RESERVATION_LEN};

pub struct Context {
    pub gossip_producer: TProducer,
    pub rpc_producer: TProducer,
    /// Local identify record.
    pub identify: Option<ProtoIdentify>,
    pub cluster_nodes: Option<ClusterNodes>,
    pub cluster_inbound_producer: TProducer,
    /// Opens the retained data-columns consumer for partial column sends.
    pub partial_columns: bool,
    pub reader: TCacheReader,
}

impl Context {
    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(TCacheId::ControlGossip, "p2p_control_gossip", TReadMode::Strict)?;
        self.reader.open(TCacheId::ControlRpc, "p2p_control_rpc", TReadMode::Sliding)?;
        self.reader.open(TCacheId::StorageDelivery, "p2p_storage_delivery", TReadMode::Sliding)?;
        self.reader.open(
            TCacheId::ClusterOutbound,
            "network_cluster_outbound",
            TReadMode::Strict,
        )?;
        if self.partial_columns {
            self.reader.open(TCacheId::ControlSlot, "p2p_control_slot", TReadMode::Strict)?;
        }
        self.reader.declare(TCacheId::ControlGossip, &[TileId::Control, TileId::Columns]);
        Ok(())
    }

    /// A frame larger than its cache retries its reservation forever.
    pub fn assert_ingress_capacity(&self) {
        let gossip = self.gossip_producer.cache_ref().max_payload_len();
        assert!(
            gossip >= MAX_GOSSIP_RESERVATION_LEN,
            "gossip ingress tcache holds {gossip} bytes, need {MAX_GOSSIP_RESERVATION_LEN}"
        );
        let rpc = self.rpc_producer.cache_ref().max_payload_len();
        assert!(
            rpc >= MAX_PAYLOAD_SIZE,
            "rpc ingress tcache holds {rpc} bytes, need {MAX_PAYLOAD_SIZE}"
        );
    }

    pub fn loop_start(&mut self) {
        self.gossip_producer.loop_start();
        self.rpc_producer.loop_start();
        self.cluster_inbound_producer.loop_start();
    }

    pub fn cluster_peer(&self, raft_id: u64) -> Option<usize> {
        self.cluster_nodes.as_ref().and_then(|n| n.connection_id(raft_id))
    }

    pub fn raft_id(&self, conn: usize) -> Option<u64> {
        self.cluster_nodes.as_ref().and_then(|n| n.raft_id(&conn))
    }
}

#[derive(Default)]
pub struct ClusterNodes {
    /// Membership keyed by authenticated peer identity.
    by_peer_id: FxHashMap<PeerId, u64>,
    /// Mapping of raft id to conneciton id, used in the dispatch
    /// of outbound cluster messages.
    by_raft_id: FxHashMap<u64, usize>,
    /// Mapping of connection id to raft id, used in the dispatch of incoming
    /// cluster messages.
    by_conn_id: FxHashMap<usize, u64>,
}

impl ClusterNodes {
    pub fn raft_id(&self, conn_id: &usize) -> Option<u64> {
        self.by_conn_id.get(conn_id).copied()
    }

    pub fn raft_ids(&self) -> impl Iterator<Item = u64> {
        self.by_peer_id.values().copied()
    }

    pub fn connection_id(&self, raft_id: u64) -> Option<usize> {
        self.by_raft_id.get(&raft_id).copied()
    }

    /// The peer's open connections become cluster links through `connected`.
    pub fn set_member(&mut self, raft_id: u64, peer_id: PeerId) {
        self.by_peer_id.retain(|_, id| *id != raft_id);
        self.by_peer_id.insert(peer_id, raft_id);
    }

    pub fn remove(&mut self, raft_id: u64) {
        self.by_peer_id.retain(|_, id| *id != raft_id);
        self.by_conn_id.retain(|_, id| *id != raft_id);
        self.by_raft_id.remove(&raft_id);
    }

    pub fn connected(&mut self, peer: &RemotePeer) {
        // A connection handle can be reused for a different identity.
        self.disconnected(peer.connection);
        if let Some(&raft_id) = self.by_peer_id.get(&peer.peer_id) {
            self.by_conn_id.insert(peer.connection, raft_id);
            self.by_raft_id.entry(raft_id).or_insert(peer.connection);
        }
    }

    pub fn disconnected(&mut self, connection: usize) {
        let Some(raft_id) = self.by_conn_id.remove(&connection) else {
            return;
        };
        if self.by_raft_id.get(&raft_id) != Some(&connection) {
            return;
        }

        match self.by_conn_id.iter().find_map(|(&conn, &id)| (id == raft_id).then_some(conn)) {
            Some(conn) => {
                self.by_raft_id.insert(raft_id, conn);
            }
            None => {
                self.by_raft_id.remove(&raft_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use silver_common::Keypair;

    use super::*;

    fn cluster() -> (ClusterNodes, RemotePeer) {
        let keypair = Keypair::from_secret(&[1; 32]).unwrap();
        let mut nodes = ClusterNodes::default();
        nodes.set_member(7, keypair.peer_id());
        let peer = RemotePeer {
            peer_id: keypair.peer_id(),
            connection: 10,
            addr: "127.0.0.1:9000".parse().unwrap(),
        };
        (nodes, peer)
    }

    #[test]
    fn members_set_at_runtime_are_mapped_and_removed() {
        let (mut nodes, peer) = cluster();
        let joiner = Keypair::from_secret(&[2; 32]).unwrap().peer_id();
        nodes.set_member(8, joiner);
        let joined = RemotePeer { peer_id: joiner, connection: 20, addr: peer.addr };
        nodes.connected(&joined);
        assert_eq!(nodes.connection_id(8), Some(20));

        nodes.remove(8);
        assert_eq!((nodes.connection_id(8), nodes.raft_id(&20)), (None, None));
        nodes.connected(&joined);
        assert_eq!(nodes.raft_id(&20), None, "a removed member is an ordinary peer");

        nodes.set_member(7, joiner);
        nodes.connected(&peer);
        assert_eq!(nodes.raft_id(&peer.connection), None, "the old key no longer maps to 7");
    }

    #[test]
    fn closing_duplicate_or_unregistered_connection_preserves_selected_route() {
        let (mut nodes, mut peer) = cluster();
        nodes.connected(&peer);
        nodes.disconnected(11);
        assert_eq!(nodes.connection_id(7), Some(10));

        peer.connection = 11;
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), Some(10));
        assert_eq!(nodes.raft_id(&10), Some(7));
        assert_eq!(nodes.raft_id(&11), Some(7));

        nodes.disconnected(11);
        nodes.disconnected(11);
        assert_eq!(nodes.connection_id(7), Some(10));
        assert_eq!(nodes.raft_id(&10), Some(7));
        assert_eq!(nodes.raft_id(&11), None);
    }

    #[test]
    fn closing_selected_connection_uses_surviving_duplicate() {
        let (mut nodes, mut peer) = cluster();
        nodes.connected(&peer);
        peer.connection = 11;
        nodes.connected(&peer);

        nodes.disconnected(10);
        assert_eq!(nodes.connection_id(7), Some(11));
        assert_eq!(nodes.raft_id(&10), None);
        assert_eq!(nodes.raft_id(&11), Some(7));

        nodes.disconnected(10);
        assert_eq!(nodes.connection_id(7), Some(11));

        nodes.disconnected(11);
        assert_eq!(nodes.connection_id(7), None);
        assert_eq!(nodes.raft_id(&11), None);
    }

    #[test]
    fn reused_connection_handle_cannot_authenticate_non_member() {
        let (mut nodes, mut peer) = cluster();
        nodes.connected(&peer);
        let member = peer.peer_id;

        peer.peer_id = Keypair::from_secret(&[2; 32]).unwrap().peer_id();
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), None);
        assert_eq!(nodes.raft_id(&peer.connection), None);

        peer.peer_id = member;
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), Some(peer.connection));
        assert_eq!(nodes.raft_id(&peer.connection), Some(7));
    }

    #[test]
    fn connection_handle_reuse_preserves_other_members_routes() {
        let (mut nodes, mut peer) = cluster();
        let other_keypair = Keypair::from_secret(&[2; 32]).unwrap();
        nodes.by_peer_id.insert(other_keypair.peer_id(), 8);
        nodes.connected(&peer);
        peer.connection = 11;
        nodes.connected(&peer);

        peer.connection = 10;
        peer.peer_id = other_keypair.peer_id();
        nodes.connected(&peer);
        assert_eq!(nodes.connection_id(7), Some(11));
        assert_eq!(nodes.connection_id(8), Some(10));
        assert_eq!(nodes.raft_id(&10), Some(8));
        assert_eq!(nodes.raft_id(&11), Some(7));

        nodes.disconnected(10);
        assert_eq!(nodes.connection_id(7), Some(11));
        assert_eq!(nodes.connection_id(8), None);
    }
}
