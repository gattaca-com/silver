use std::time::{Duration, Instant};

use flux::{spine::SpineAdapter, tile::Tile, tracing};
use fxhash::FxHashMap;
use silver_common::{
    DataColumnsAvailable, NewGossipMsg, P2pStreamId, PeerEvent, RpcInbound, RpcSeverity,
    SilverSpine, TRandomAccess, TRead, Wheel, ssz_view::DataColumnSidecarView,
};

use crate::util;

const BASE_REQUEST_ID: u64 = 0xda5da5 << 40; // DAS prefix. 
const MAX_RETRIES: u8 = 5;

pub struct DataColumnTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    request_id: u64,
    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,

    // keyed by block body root
    validated_columns: FxHashMap<[u8; 32], u128>,
    // outstanding requests - keyed by block body root
    // 16 x 500 millisecond buckets.
    outstanding_requests: Wheel<[u8; 32], (u128, u8), 16>,
}

impl DataColumnTile {
    pub fn new(
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        custody_group_columns: u128,
    ) -> Self {
        Self {
            custody_group_columns,
            request_id: BASE_REQUEST_ID,
            gossip_consumer,
            rpc_consumer,
            validated_columns: FxHashMap::default(),
            outstanding_requests: Wheel::new(Duration::from_millis(500)),
        }
    }

    fn column_request(&mut self, block_root: [u8; 32], columns: u128) -> PeerEvent {
        let id = self.request_id;
        self.request_id += 1;
        PeerEvent::SendDataColumnsByRootRequest { request_id: id, columns, block_root }
    }

    fn beacon_block<F>(&mut self, stream_id: P2pStreamId, block: TRead, emit: &mut F)
    where
        F: FnMut(PeerEvent),
    {
        let buffer = match block.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read beacon block cache buffer");
                return;
            }
        };

        let block_root = util::block_root(buffer);

        if self.outstanding_requests.contains(&block_root) {
            return;
        }

        let mut to_request = self.custody_group_columns;
        if let Some(validated) = self.validated_columns.get(&block_root) {
            to_request &= !validated;
            if to_request == 0 {
                // already have all custody group columns
                return;
            }
        }
        self.outstanding_requests.insert(block_root, (to_request, MAX_RETRIES));
        emit(self.column_request(block_root, to_request));
    }

    fn data_columns<F>(
        &mut self,
        stream_id: P2pStreamId,
        sidecar: TRead,
        emit: &mut F,
    ) -> Option<([u8; 32], u128)>
    where
        F: FnMut(DataColumnsAvailable),
    {
        let buffer = match sidecar.buffer() {
            Ok((buffer, _)) => buffer,
            Err(e) => {
                tracing::error!(?e, ?stream_id, "failed to read data column sidecar cache buffer");
                return None;
            }
        };

        let block_root = util::block_root_from_sidecar(buffer);
        let column_bitmask = 1u128 << DataColumnSidecarView::index(buffer);
        let requested = self.outstanding_requests.remove(&block_root);

        if self
            .validated_columns
            .get(&block_root)
            .map(|c| c & column_bitmask != 0)
            .unwrap_or_default()
        {
            return None;
        }

        if !util::verify_data_column_sidecar(buffer) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return Some((block_root, column_bitmask));
        }
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return Some((block_root, column_bitmask));
        }
        if !util::verify_data_column_sidecar_kzg_proofs(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar kzg proof");
            return Some((block_root, column_bitmask));
        }

        if let Some((mut requested, retries)) = requested {
            requested &= !column_bitmask;
            if requested != 0 {
                // more column responses pending
                self.outstanding_requests.insert(block_root, (requested, retries));
            }
        }

        let validated = self.validated_columns.entry(block_root).or_default();
        *validated |= column_bitmask;

        if *validated == self.custody_group_columns {
            // have all validated data columns for the block.
            emit(DataColumnsAvailable {
                slot: DataColumnSidecarView::slot(buffer),
                proposer_index: DataColumnSidecarView::proposer_index(buffer),
                parent_root: *DataColumnSidecarView::parent_root(buffer),
                state_root: *DataColumnSidecarView::state_root(buffer),
                body_root: *DataColumnSidecarView::body_root(buffer),
                signature: *DataColumnSidecarView::block_signature(buffer),
            })
        }
        None
    }
}

impl Tile<SilverSpine> for DataColumnTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.gossip_consumer.free();
        self.rpc_consumer.free();

        // Check for data columns and incoming blocks with data columns via gossip.
        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock => {
                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                self.beacon_block(gossip.stream_id, t_read, &mut |evt| {
                    producers.peer_events.produce(&evt.into());
                });
            }
            silver_common::GossipTopic::DataColumnSidecar(_custody_group) => {
                // TODO validate that topic group matches sidecar column index
                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                if let Some((block_root, columns)) =
                    self.data_columns(gossip.stream_id, t_read, &mut |msg| {
                        producers.data_columns.produce(&msg.into());
                    })
                {
                    // Validation failed - score down the peer and retransmit
                    producers.peer_events.produce(
                        &PeerEvent::P2pGossipInvalidMsg {
                            p2p_peer: gossip.stream_id.peer(),
                            topic: gossip.topic,
                            hash: gossip.msg_hash,
                        }
                        .into(),
                    );
                    producers.peer_events.produce(&self.column_request(block_root, columns).into());
                }
            }
            _ => {}
        });

        // Check for data columns and incoming blocks via RPC.
        adapter.consume(|rpc: RpcInbound, producers| match rpc {
            RpcInbound::Request(req) => match req.request {
                silver_common::RpcRequest::DataColumnsByRange { ssz: _, len: _ } => {
                    todo!("serve data column requests")
                }
                silver_common::RpcRequest::DataColumnsByRoot(_tcache_read) => {
                    todo!("serve data column requests")
                }
                _ => {}
            },
            RpcInbound::Response(rsp) => match rsp.response {
                silver_common::RpcResponse::BeaconBlock { fork_digest: _, ssz } => {
                    let t_read = self.rpc_consumer.acquire(ssz);
                    self.beacon_block(rsp.stream_id, t_read, &mut |evt| {
                        producers.peer_events.produce(&evt.into());
                    });
                }
                silver_common::RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => {
                    // TODO validate that originating peer has data column index in custody groups
                    let t_read = self.rpc_consumer.acquire(ssz);
                    if let Some((block_root, columns)) =
                        self.data_columns(rsp.stream_id, t_read, &mut |msg| {
                            producers.data_columns.produce(&msg.into());
                        })
                    {
                        // Validation failed - score down the peer and retransmit
                        producers.peer_events.produce(
                            &PeerEvent::RpcMisbehaviour {
                                p2p_peer: rsp.stream_id.peer(),
                                severity: RpcSeverity::Fatal,
                            }
                            .into(),
                        );
                        producers
                            .peer_events
                            .produce(&self.column_request(block_root, columns).into());
                    }
                }
                _ => {}
            },
        });

        // Timeout any pending requests and re-issue
        let mut reinsert = vec![];
        self.outstanding_requests.maybe_rotate(
            Instant::now(),
            &mut |block_root, (columns, retries)| {
                if retries > 0 {
                    let id = self.request_id;
                    self.request_id += 1;
                    adapter.produce(PeerEvent::SendDataColumnsByRootRequest {
                        request_id: id,
                        columns,
                        block_root,
                    });

                    reinsert.push((block_root, (columns, retries - 1)));
                }
            },
        );
        reinsert.into_iter().for_each(|(k, v)| {
            self.outstanding_requests.insert(k, v);
        });
    }
}
