use std::io::Write;

use silver_common::{
    TCache, TCacheId, TCacheProducer, TCacheReader, TReadMode,
    ssz_view::{
        DC_BY_ROOT_REQ_MAX, DataColumnsByRootRequestView, MAX_REQUEST_BLOCKS_DENEB,
        NUMBER_OF_COLUMNS,
    },
};

use super::*;

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
