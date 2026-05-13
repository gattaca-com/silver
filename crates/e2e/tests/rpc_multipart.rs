//! Silver ↔ silver multipart RPC response test. Exercises the
//! BeaconBlocksByRange response path with large (multi-MB) chunks to
//! catch issues in: outbound chunk encoding (varint + snappy frames),
//! inbound chunk decoding (snappy stream → tcache slot), and the
//! synthetic `Complete` event silver emits when the peer FINs the
//! response stream. The controller is bypassed for the responder side
//! — the controller's BlocksByRange handler is a TODO no-op so the
//! test injects responses directly onto the `p2p_send` queue.
//!
//! The test drives BOTH stacks from a single thread via `loop_body` —
//! same pattern as the gossip one-way test. No tokio runtime, no
//! libp2p — pure silver code paths.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::{
    P2pSend, P2pStreamId, PeerEvent, RpcInbound, RpcOutbound, RpcRequest, RpcRequestInbound,
    RpcRequestOutbound, RpcResponse, RpcResponseInbound, RpcResponseOutbound, StreamProtocol,
    TCacheProducer, ssz_view::BLOCKS_BY_RANGE_REQ_SIZE,
};
use silver_e2e::{PublisherStack, keypair_from_seed};
use tempfile::TempDir;

const CHUNK_BYTES: usize = 2 * 1024 * 1024;
const CHUNK_COUNT: usize = 3;
const FORK_DIGEST: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn pick_free_port() -> u16 {
    std::net::UdpSocket::bind(("127.0.0.1", 0))
        .expect("bind")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn build_stack(td: &TempDir, suffix: &str, seed: u8) -> PublisherStack {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port());
    let disc = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port());
    let kp = keypair_from_seed(seed);
    let mut stack = PublisherStack::new(td.path(), suffix, addr, disc, kp).expect("silver stack");
    // Heartbeat ping fan-out would otherwise inject background traffic
    // that races with this test's stream-id capture.
    stack.controller.set_auto_ping(false);
    stack
}

fn spin_both(a: &mut PublisherStack, b: &mut PublisherStack) {
    a.network.loop_body(&mut a.network_adapter);
    a.controller.loop_body(&mut a.controller_adapter);
    b.network.loop_body(&mut b.network_adapter);
    b.controller.loop_body(&mut b.controller_adapter);
}

fn drive_until<F: FnMut(&mut PublisherStack, &mut PublisherStack) -> bool>(
    a: &mut PublisherStack,
    b: &mut PublisherStack,
    timeout: Duration,
    mut cond: F,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        spin_both(a, b);
        if cond(a, b) {
            return true;
        }
    }
    false
}

fn wait_for_connections(
    a: &mut PublisherStack,
    b: &mut PublisherStack,
    a_remote: &silver_common::PeerId,
    b_remote: &silver_common::PeerId,
) -> (usize, usize) {
    let mut a_handle: Option<usize> = None;
    let mut b_handle: Option<usize> = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && (a_handle.is_none() || b_handle.is_none()) {
        spin_both(a, b);
        if a_handle.is_none() {
            let h = &mut a_handle;
            a.injector_adapter.consume::<PeerEvent, _>(|event, _p| {
                if let PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, .. } = event &&
                    peer_id_full == *a_remote
                {
                    *h = Some(p2p_peer_id);
                }
            });
        }
        if b_handle.is_none() {
            let h = &mut b_handle;
            b.injector_adapter.consume::<PeerEvent, _>(|event, _p| {
                if let PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, .. } = event &&
                    peer_id_full == *b_remote
                {
                    *h = Some(p2p_peer_id);
                }
            });
        }
    }
    (
        a_handle.expect("a never observed P2pNewConnection"),
        b_handle.expect("b never observed P2pNewConnection"),
    )
}

/// Build a deterministic SSZ-shaped byte buffer of `len` bytes, seeded
/// by `chunk_index`. Non-zero, non-repeating-pattern so snappy doesn't
/// trivially compress everything to one frame — exercises the multi-
/// frame decode path on the receiver.
fn synth_block_bytes(chunk_index: u8, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut state = chunk_index as u32 ^ 0xdead_beef;
    for byte in out.iter_mut() {
        // xorshift32
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        *byte = state as u8;
    }
    out
}

#[test]
fn silver_receives_multipart_blocks_by_range_response() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let td = TempDir::new().expect("tempdir");
    let mut requester = build_stack(&td, "_req", 21);
    let mut responder = build_stack(&td, "_resp", 22);

    // Wire-level connect: requester dials responder.
    let resp_peer_id = responder.peer_id;
    let req_peer_id = requester.peer_id;
    let resp_addr = responder.addr;
    requester.network.p2p_mut().connect(resp_peer_id, resp_addr, Instant::now()).expect("connect");

    // Drive both until each side sees the new connection. `req_handle`
    // is the requester's local handle for the responder; `resp_handle`
    // is the responder's local handle for the requester.
    let (req_handle, resp_handle) =
        wait_for_connections(&mut requester, &mut responder, &resp_peer_id, &req_peer_id);

    // Requester injects a BlocksByRange request. Application id is
    // free-form here — the responder doesn't read it (the test code
    // synthesises the response).
    let mut req_ssz = [0u8; BLOCKS_BY_RANGE_REQ_SIZE];
    req_ssz[..8].copy_from_slice(&100u64.to_le_bytes()); // start_slot
    req_ssz[8..16].copy_from_slice(&(CHUNK_COUNT as u64).to_le_bytes()); // count
    req_ssz[16..24].copy_from_slice(&1u64.to_le_bytes()); // step
    requester.injector_adapter.produce(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
        application_id: 42,
        peer: req_handle,
        request: RpcRequest::BlocksByRange(req_ssz),
    })));

    // Drive until the responder's spine has the inbound request and we
    // can capture the stream id (needed to address responses).
    let mut resp_stream_id: Option<P2pStreamId> = None;
    let captured = drive_until(&mut requester, &mut responder, Duration::from_secs(5), |_, b| {
        let stash = &mut resp_stream_id;
        b.injector_adapter.consume::<RpcInbound, _>(|event, _p| {
            if let RpcInbound::Request(RpcRequestInbound { stream_id, request }) = event &&
                matches!(request, RpcRequest::BlocksByRange(_)) &&
                stream_id.protocol() == StreamProtocol::BeaconBlocksByRange
            {
                *stash = Some(stream_id);
            }
        });
        resp_stream_id.is_some()
    });
    assert!(captured, "responder never saw the BlocksByRange request");
    let resp_stream_id = resp_stream_id.expect("captured above");
    assert_eq!(resp_stream_id.peer(), resp_handle);

    // Synthesise N large chunks. Keep the originals so we can assert
    // bit-for-bit equality on the receive side.
    let originals: Vec<Vec<u8>> =
        (0..CHUNK_COUNT).map(|i| synth_block_bytes(i as u8, CHUNK_BYTES)).collect();

    // Reserve + write each chunk into the responder's rpc_out cache,
    // then enqueue the corresponding `BeaconBlock` response. The
    // network tile picks them up from `p2p_send` and frames them on
    // the wire (result-byte + fork_digest + varint(len) + snappy).
    for ssz in &originals {
        let mut reservation = responder
            .rpc_out_producer
            .reserve(ssz.len(), /* auto_commit */ true)
            .expect("rpc_out reserve");
        let buf = reservation.buffer().expect("rpc_out buf");
        buf.copy_from_slice(ssz);
        reservation.increment_offset(ssz.len());
        let tcache = reservation.read();
        responder.injector_adapter.produce(P2pSend::Rpc(RpcOutbound::Response(
            RpcResponseOutbound {
                stream_id: resp_stream_id,
                response: RpcResponse::BeaconBlock { fork_digest: FORK_DIGEST, ssz: tcache },
            },
        )));
    }
    // Terminal sentinel — `RpcResponse::Complete` triggers FIN on the
    // outbound stream (see `RpcWriteResponse::Idle` arm in
    // response_out.rs). On the requester side this surfaces as a
    // synthetic `RpcResponse::Complete` event from the recv-EOF path.
    responder.injector_adapter.produce(P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
        stream_id: resp_stream_id,
        response: RpcResponse::Complete,
    })));

    // Drain the requester's inbound RPC queue until we've collected N
    // BeaconBlock chunks + 1 Complete sentinel.
    #[derive(Default)]
    struct Collected {
        chunks: Vec<RpcResponseInbound>,
        complete: bool,
    }
    let mut collected = Collected::default();
    let received_all =
        drive_until(&mut requester, &mut responder, Duration::from_secs(10), |a, _| {
            let c = &mut collected;
            a.injector_adapter.consume::<RpcInbound, _>(|event, _p| {
                if let RpcInbound::Response(resp) = event {
                    match &resp.response {
                        RpcResponse::BeaconBlock { .. } => c.chunks.push(resp),
                        RpcResponse::Complete => c.complete = true,
                        _ => {}
                    }
                }
            });
            c.chunks.len() == CHUNK_COUNT && c.complete
        });
    assert!(
        received_all,
        "expected {CHUNK_COUNT} BeaconBlock chunks + Complete; got {} chunks, complete={}",
        collected.chunks.len(),
        collected.complete
    );

    // Each chunk's tcache payload must equal the original bytes the
    // responder wrote. Acquire via the requester's rpc_in random-access
    // handle and compare byte-for-byte.
    for (i, resp) in collected.chunks.iter().enumerate() {
        let RpcResponse::BeaconBlock { ssz, .. } = &resp.response else {
            panic!("non-BeaconBlock in chunks vec");
        };
        let acquired = requester.rpc_in_ra.acquire(*ssz);
        let (bytes, _ts) = acquired.buffer().expect("acquire chunk bytes");
        assert_eq!(bytes.len(), CHUNK_BYTES, "chunk {i}: wire-decoded len mismatch");
        assert_eq!(bytes, originals[i].as_slice(), "chunk {i}: bytes mismatch");
    }
    requester.rpc_in_ra.free();
}
