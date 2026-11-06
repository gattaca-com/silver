use std::{
    io::{ErrorKind, Write},
    net::SocketAddr,
    time::Instant,
};

use quinn_proto::StreamId;
use silver_common::{
    RpcInbound, TCache, TCacheId, TCacheProducer, TCacheReader, TCacheTable, TReadMode,
    encode_varint,
    ssz_view::{
        DC_BY_ROOT_REQ_MAX, DataColumnsByRootRequestView, MAX_PAYLOAD_SIZE,
        MAX_REQUEST_BLOCKS_DENEB, NUMBER_OF_COLUMNS, SIGNED_BEACON_BLOCK_MIN,
    },
};

use super::*;
use crate::{
    NetEvent,
    p2p::{
        context::Context,
        inbound_rate_limits::{InboundLimits, InboundRateLimits},
        quic::{Leased, OutboundGossip},
        streams::{StreamIo, StreamState},
    },
};

#[test]
fn recovered_request_preserves_application_id_and_inline_payload() {
    let producer = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
    let mut consumer = TCacheReader::single(producer.cache_ref(), "", TReadMode::Strict).unwrap();
    let request = RpcRequest::data_columns_by_range(10, 20, u128::MAX);
    let msg = RpcOutbound::Request(RpcRequestOutbound { application_id: 37, peer: 12, request });
    let recovered = AcquiredRpcOutbound::from((msg, &mut consumer)).into_message(12);
    let RpcOutbound::Request(recovered) = recovered else {
        panic!("expected an RPC request");
    };
    assert_eq!(recovered.application_id, 37);
    assert_eq!(recovered.peer, 12);
    let RpcRequest::DataColumnsByRange { ssz: expected, len: expected_len } = request else {
        unreachable!();
    };
    let RpcRequest::DataColumnsByRange { ssz, len } = recovered.request else {
        panic!("expected a data-column range request");
    };
    assert_eq!(ssz, expected);
    assert_eq!(len, expected_len);
}

#[test]
fn recovered_cached_requests_keep_the_original_descriptor() {
    let mut producer = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
    let mut consumer = TCacheReader::single(producer.cache_ref(), "", TReadMode::Strict).unwrap();
    let mut reservation = producer.reserve(32, true).unwrap();
    reservation.write_all(&[7; 32]).unwrap();
    let read = reservation.read();
    for request in [
        RpcRequest::BlockByRoot(read),
        RpcRequest::DataColumnsByRoot(read),
        RpcRequest::ExecutionPayloadEnvelopesByRoot(read),
    ] {
        let original =
            RpcOutbound::Request(RpcRequestOutbound { application_id: 37, peer: 12, request });
        let recovered = AcquiredRpcOutbound::from((original, &mut consumer)).into_message(12);
        assert_eq!(recovered.protocol(), original.protocol());
        assert_eq!(recovered.tcache_read().unwrap().seq(), read.seq());
        let acquired = consumer.acquire_strict(*recovered.tcache_read().unwrap()).unwrap();
        assert_eq!(acquired.buffer().unwrap().0, &[7; 32]);
    }
}

#[test]
fn data_columns_by_root_request_bound_fits_the_largest_valid_request() {
    let identifier = [&[0u8; 32][..], &36u32.to_le_bytes(), &[0u8; NUMBER_OF_COLUMNS * 8]].concat();
    let count = MAX_REQUEST_BLOCKS_DENEB;
    let mut request = Vec::new();
    for i in 0..count {
        let offset = count * 4 + i * identifier.len();
        request.extend_from_slice(&(offset as u32).to_le_bytes());
    }
    for _ in 0..count {
        request.extend_from_slice(&identifier);
    }
    assert!(DataColumnsByRootRequestView::check_size(&request));
    assert_eq!(request.len(), DC_BY_ROOT_REQ_MAX);

    let mut producer = TCache::producer(TCacheId::NetworkIngress, 1 << 20);
    let id = P2pStreamId::new(0, 0, StreamProtocol::DataColumnSidecarsByRoot, true);
    assert!(alloc_incoming_rpc(&mut producer, &id, DC_BY_ROOT_REQ_MAX).is_ok());
    assert!(alloc_incoming_rpc(&mut producer, &id, DC_BY_ROOT_REQ_MAX + 1).is_err());
}

#[test]
fn block_response_chunks_are_capped_at_max_payload_size() {
    let mut producer = TCache::producer(TCacheId::NetworkProcessing, 1 << 16);
    for protocol in [StreamProtocol::BeaconBlocksByRange, StreamProtocol::BeaconBlocksByRoot] {
        let id = P2pStreamId::new(0, 0, protocol, false);
        let in_bounds = alloc_incoming_rpc(&mut producer, &id, MAX_PAYLOAD_SIZE).err();
        assert_eq!(in_bounds.map(|e| e.kind()), Some(ErrorKind::FileTooLarge));
        let oversize = alloc_incoming_rpc(&mut producer, &id, MAX_PAYLOAD_SIZE + 1).err();
        assert_eq!(oversize.map(|e| e.kind()), Some(ErrorKind::InvalidData));
    }
}

#[test]
fn max_response_chunks_follow_the_request() {
    let blocks = RpcRequest::blocks_by_range(5, 3);
    let msg =
        RpcOutbound::Request(RpcRequestOutbound { application_id: 1, peer: 0, request: blocks });
    let producer = TCache::producer(TCacheId::NetworkIngress, 1 << 16);
    let mut consumer = TCacheReader::single(producer.cache_ref(), "", TReadMode::Strict).unwrap();
    let AcquiredRpcOutbound::Request(blocks) = AcquiredRpcOutbound::from((msg, &mut consumer))
    else {
        unreachable!();
    };
    assert_eq!(blocks.request.max_response_chunks().unwrap(), 3);

    let columns = RpcRequest::data_columns_by_range(10, 4, 0b111);
    let msg =
        RpcOutbound::Request(RpcRequestOutbound { application_id: 1, peer: 0, request: columns });
    let AcquiredRpcOutbound::Request(columns) = AcquiredRpcOutbound::from((msg, &mut consumer))
    else {
        unreachable!();
    };
    assert_eq!(columns.request.max_response_chunks().unwrap(), 12);
    assert_eq!(AcquiredRpcRequest::Ping([0; PING_SIZE]).max_response_chunks().unwrap(), 1);
}

/// Serves a fixed byte stream; sinks writes.
struct WireIo {
    data: Vec<u8>,
    pos: usize,
}

impl StreamIo for WireIo {
    fn write_to_stream(&mut self, _id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
        Ok(data.len())
    }

    fn read_from_stream(&mut self, _id: StreamId, out: &mut [u8]) -> Result<usize, StreamError> {
        let n = out.len().min(self.data.len() - self.pos);
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }

    fn close_write(&mut self, _id: StreamId) -> Result<(), StreamError> {
        Ok(())
    }

    fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
        None
    }

    fn cluster_next(&mut self) -> Option<Leased<TRead>> {
        None
    }

    fn gossip_next(&mut self) -> Option<OutboundGossip> {
        None
    }

    fn remote_addr(&self) -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }
}

#[test]
fn multipart_response_past_the_requested_count_is_rejected() {
    let block = vec![0x11u8; SIGNED_BEACON_BLOCK_MIN];
    let mut body = Vec::new();
    SnappyEncoder::new().compress(&block, &mut body).unwrap();
    let mut chunk = vec![0u8, 1, 2, 3, 4];
    let mut varint = [0u8; 10];
    let n = encode_varint(block.len() as u64, &mut varint).unwrap();
    chunk.extend_from_slice(&varint[..n]);
    chunk.extend_from_slice(&body);
    let wire = [chunk.as_slice(), chunk.as_slice()].concat();

    let mut context = Context {
        gossip_producer: TCache::producer(TCacheId::NetworkIngress, 1 << 16),
        rpc_producer: TCache::producer(TCacheId::NetworkProcessing, 1 << 16),
        identify: None,
        cluster_nodes: None,
        cluster_inbound_producer: TCache::producer(TCacheId::ClusterInbound, 1 << 16),
        partial_columns: false,
        reader: TCacheReader::new(TCacheTable::from_iter([])),
    };
    let now = Instant::now();
    let mut codec = RpcCodec::allocate();
    let mut limits = InboundRateLimits::new(InboundLimits::default(), now);
    let mut id = P2pStreamId::new(0, 0, StreamProtocol::BeaconBlocksByRange, false);
    let mut io = WireIo { data: wire, pos: 0 };
    let state = StreamState::OutgoingRpc {
        rpc: RpcOut::ReadResponse(RpcReadResponse::new(7, 0, now, &mut codec.dec)),
        max_chunks: 1,
    };
    let mut responses = 0;
    let err = state
        .spin(&mut io, &mut id, &mut context, Some(&mut codec), now, &mut limits, &mut |e| {
            if matches!(e, NetEvent::RpcInbound(RpcInbound::Response(_))) {
                responses += 1;
            }
        })
        .unwrap_err();
    assert!(matches!(err, StreamError::ExcessResponseChunks), "{err:?}");
    assert_eq!(responses, 1);
}
