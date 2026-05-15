use std::{
    io::{self, ErrorKind, Write},
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile, tracing};
use fxhash::FxHashMap;
use silver_common::{
    ssz_view::{DataColumnSidecarView, SignedBeaconBlockView}, DataColumnsAvailable, NewGossipMsg, P2pStreamId, PeerEvent, RpcInbound, RpcSeverity, SilverSpine, TCacheProducer, TCacheRead, TMultiProducer, TRandomAccess, TRead, Wheel
};

use crate::util;

const BASE_REQUEST_ID: u64 = 0xda5da5 << 40; // DAS prefix. 

pub struct DataColumnTile {
    // bit set of our custody group columns.
    custody_group_columns: u128,
    request_id: u64,
    gossip_consumer: TRandomAccess,
    rpc_consumer: TRandomAccess,
    rpc_producer: TMultiProducer,

    // keyed by block body root
    validated_columns: FxHashMap<[u8; 32], u128>,
    // outstanding requests - keyed by block body root
    // 16 x 500 millisecond buckets.
    outstanding_requests: Wheel<[u8; 32], u128, 16>,
}

impl DataColumnTile {
    pub fn new(
        gossip_consumer: TRandomAccess,
        rpc_consumer: TRandomAccess,
        rpc_producer: TMultiProducer,
        custody_group_columns: u128,
    ) -> Self {
        Self {
            custody_group_columns,
            request_id: BASE_REQUEST_ID,
            gossip_consumer,
            rpc_consumer,
            rpc_producer,
            validated_columns: FxHashMap::default(),
            outstanding_requests: Wheel::new(Duration::from_millis(500)),
        }
    }

    fn column_request(&mut self, parent_root: [u8; 32], column_index: u64) -> Result<PeerEvent, io::Error> {
        allocate_request_by_root(&mut self.rpc_producer, &parent_root, 1 << column_index).map(|ssz| {       
            let id = self.request_id;
            self.request_id += 1;
            PeerEvent::SendDataColumnsByRootRequest {
                request_id: id,
                column: column_index,
                ssz,
            }
        })
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

        let block_body = SignedBeaconBlockView::body(buffer);
        let parent_root = SignedBeaconBlockView::parent_root(buffer);
        let body_root = util::body_root(block_body);

        if self.outstanding_requests.contains(&body_root) {
            return;
        }

        let mut to_request = self.custody_group_columns;
        if let Some(validated) = self.validated_columns.get(&body_root) {
            to_request &= !validated;
            if to_request == 0 {
                // already have all custody group columns
                return;
            }
        }
        self.outstanding_requests.insert(*parent_root, to_request);

        for i in 0..128 {
            if to_request & (1 << i) != 0 {
                match self.column_request(*parent_root, i) {
                    Ok(evt) => emit(evt),
                    Err(e) => tracing::error!(?e, "failed to allocate data columns request"),
                }
            }
        }
    }

    fn data_columns<F>(&mut self, stream_id: P2pStreamId, sidecar: TRead, emit: &mut F) -> Option<([u8; 32], u128)>
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

        let body_root = DataColumnSidecarView::body_root(buffer);
        let column_bitmask = 1 << DataColumnSidecarView::index(buffer) as u128;
        
        let requested = self.outstanding_requests.remove(body_root);

        if !util::verify_data_column_sidecar(buffer) {
            tracing::warn!(?stream_id, "badly formed data column sidecar");
            return Some((*body_root, column_bitmask));
        }
        if !util::verify_data_column_sidecar_inclusion_proof(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar inclusion proof");
            return Some((*body_root, column_bitmask));
        }
        if !util::verify_data_column_sidecar_kzg_proofs(buffer) {
            tracing::warn!(?stream_id, "failed to verify sidecar kzg proof");
            return Some((*body_root, column_bitmask));
        }

        if let Some(mut requested) = requested {
            requested &= !column_bitmask;
            if requested != 0 {
                // more column responses pending
                self.outstanding_requests.insert(*body_root, requested);
            }
        }
        let validated = self.validated_columns.entry(*body_root).or_default();
        *validated |= column_bitmask;

        if *validated == self.custody_group_columns {
            // have all validated data columns for the block.
            emit(DataColumnsAvailable {
                slot: DataColumnSidecarView::slot(buffer),
                proposer_index: DataColumnSidecarView::proposer_index(buffer),
                parent_root: *DataColumnSidecarView::parent_root(buffer),
                state_root: *DataColumnSidecarView::state_root(buffer),
                body_root: *body_root,
                signature: *DataColumnSidecarView::block_signature(buffer),
            })
        }
        None
    }
}

impl Tile<SilverSpine> for DataColumnTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        // Check for data columns and incoming blocks with data columns via gossip.
        adapter.consume(|gossip: NewGossipMsg, producers| match gossip.topic {
            silver_common::GossipTopic::BeaconBlock => {
                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                self.beacon_block(gossip.stream_id, t_read, &mut |evt| {
                    producers.peer_events.produce(&evt.into());
                });
            }
            silver_common::GossipTopic::DataColumnSidecar(_custody_group) => {
                let t_read = self.gossip_consumer.acquire(gossip.ssz);
                if let Some((parent_root, columns)) = self.data_columns(gossip.stream_id, t_read, &mut |msg| { producers.data_columns.produce(&msg.into()); }) {
                    // Validation failed - score down the peer and retransmit
                    producers.peer_events.produce(&PeerEvent::P2pGossipInvalidMsg { p2p_peer: gossip.stream_id.peer(), topic: gossip.topic, hash: gossip.msg_hash }.into());

                    let column = (128 - columns.leading_zeros()) as u64;
                    if let Ok(evt) = self.column_request(parent_root, column) {
                        producers.peer_events.produce(&evt.into());
                    }
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
                    if let Some((parent_root, columns)) = self.data_columns(rsp.stream_id, t_read, &mut |msg| {
                        producers.data_columns.produce(&msg.into());
                    }) {
                        // Validation failed - score down the peer and retransmit
                        producers.peer_events.produce(&PeerEvent::RpcMisbehaviour { p2p_peer: rsp.stream_id.peer(), severity: RpcSeverity::Fatal }.into());

                        let column = (128 - columns.leading_zeros()) as u64;
                        if let Ok(evt) = self.column_request(parent_root, column) {
                            producers.peer_events.produce(&evt.into());
                        }
                    }
                }
                _ => {}
            },
        });

        // Timeout any pending requests and re-issue
        let mut reinsert = vec![];
        self.outstanding_requests.maybe_rotate(Instant::now(), &mut |root, columns| {
            for i in 0..128 {
                let column_bit = (1 << i) as u128;
                if columns & (1 << i) != 0 {
                    match allocate_request_by_root(&mut self.rpc_producer, &root, column_bit) {
                        Ok(req) => {
                            let id = self.request_id;
                            self.request_id += 1;
                            adapter.produce(PeerEvent::SendDataColumnsByRootRequest {
                                request_id: id,
                                column: i,
                                ssz: req,
                            });
                        }
                        Err(e) => tracing::error!(?e, "failed to allocate data columns request"),
                    }
                }
            }
            reinsert.push((root, columns));
        });
        reinsert.into_iter().for_each(|(k, v)| {
            self.outstanding_requests.insert(k, v);
        });
    }
}

fn allocate_request_by_root(
    producer: &mut TMultiProducer,
    root: &[u8; 32],
    columns: u128,
) -> Result<TCacheRead, io::Error> {
    // the data columns by root request is a list of `DataColumnsByRootIdentifier`.
    // Each of those is the block root followed by the list of column
    // indices. So the layout is: N x 4 byte offsets of list entries (little
    // endian) (so first offset / 4 is list length) Then N times:
    //   32 bytes block root
    //   4  bytes columns data offset (always = 36, little endian)
    //   8 bytes column index for each column, little endian
    let number_of_columns = columns.count_ones() as usize;
    let length = 4 + 32 + 4 + (8 * number_of_columns);
    let Some(mut reservation) = producer.reserve(length, true) else {
        tracing::warn!("Failed to allocate TCache buffer for data columns request");
        return Err(ErrorKind::StorageFull.into());
    };
    reservation.write_all(&4u32.to_le_bytes())?;
    reservation.write_all(root)?;
    reservation.write_all(&36u32.to_le_bytes())?;
    for i in 0..128 {
        if columns & (1 << i) != 0 {
            reservation.write_all(&(i as u64).to_le_bytes())?;
        }
    }
    reservation.flush()?;
    Ok(reservation.read())
}

enum Emission {
    PeerEvent(PeerEvent),
    Availability(DataColumnsAvailable),
}
