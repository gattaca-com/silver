//! Shared scaffolding for `lh_*` integration tests. Each test file `mod`s
//! this in. Mark the file with `#![allow(dead_code)]` because not every
//! test consumes every helper.

#![allow(dead_code)]

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::{
    P2pSend, PeerEvent, PeerId, RpcOutbound, RpcRequestOutbound,
    ssz_view::{METADATA_SIZE, STATUS_V2_SIZE},
};
use silver_e2e::{LhClient, PublisherStack, keypair_from_seed};
use tempfile::TempDir;

pub fn pick_free_port() -> u16 {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    s.local_addr().expect("local_addr").port()
}

/// Build a silver listener on a fresh port. Returns the stack and a
/// kept-alive tempdir. Disables the controller's heartbeat-driven
/// outbound Ping fan-out so tests assert against deterministic RPC
/// traffic only.
pub fn build_silver_listener(seed: u8) -> (PublisherStack, TempDir) {
    let tempdir = TempDir::new().expect("tempdir");
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port());
    let disc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port());
    let kp = keypair_from_seed(seed);
    let mut silver = PublisherStack::new(tempdir.path(), "_lh_test", addr, disc_addr, kp)
        .expect("silver listener");
    silver.controller.set_auto_ping(false);
    (silver, tempdir)
}

/// Drive both silver and the libp2p test client until `cond` returns true
/// or the deadline passes. Returns `true` on success, `false` on timeout.
pub fn drive_until<F: FnMut(&mut PublisherStack, &mut LhClient) -> bool>(
    silver: &mut PublisherStack,
    client: &mut LhClient,
    timeout: Duration,
    mut cond: F,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        silver.network.loop_body(&mut silver.network_adapter);
        silver.controller.loop_body(&mut silver.controller_adapter);
        client.tick(Duration::from_millis(20));
        if cond(silver, client) {
            return true;
        }
    }
    false
}

/// Wait until silver fires `PeerEvent::P2pNewConnection` on its injector
/// adapter. Returns the connection's `p2p_peer_id` (silver-side handle).
pub fn wait_for_silver_connect(
    silver: &mut PublisherStack,
    client: &mut LhClient,
    timeout: Duration,
) -> Option<usize> {
    let mut handle = None;
    drive_until(silver, client, timeout, |s, c| {
        // Side-effect: drain the peer-events queue into `handle`.
        let h = &mut handle;
        s.injector_adapter.consume::<PeerEvent, _>(|event, _producers| {
            if let PeerEvent::P2pNewConnection { p2p_peer_id, .. } = event {
                *h = Some(p2p_peer_id);
            }
        });
        let _ = s; // suppress unused
        let _ = c;
        handle.is_some()
    });
    handle
}

/// Convert a libp2p `PeerId` to silver's `PeerId` (both are libp2p
/// multihash bytes — different wrapper types).
pub fn libp2p_to_silver_peer_id(pid: libp2p::PeerId) -> PeerId {
    let bytes = pid.to_bytes();
    PeerId::from_multihash_bytes(&bytes).expect("multihash fits")
}

/// Inject a one-shot outbound RPC request onto silver's spine via the
/// injector adapter (mirrors how the harness produces gossip).
pub fn inject_silver_rpc_request(
    silver: &mut PublisherStack,
    peer: usize,
    application_id: u64,
    request: silver_common::RpcRequest,
) {
    silver.injector_adapter.produce(P2pSend::Rpc(RpcOutbound::Request(RpcRequestOutbound {
        application_id,
        peer,
        request,
    })));
}

/// Dummy values: zeros are perfectly fine for the controller's response
/// path on Status / MetaData / Ping — silver doesn't validate the inner
/// SSZ shape, just round-trips bytes.
pub const DUMMY_STATUS: [u8; STATUS_V2_SIZE] = [0u8; STATUS_V2_SIZE];
pub const DUMMY_METADATA: [u8; METADATA_SIZE] = [0u8; METADATA_SIZE];
