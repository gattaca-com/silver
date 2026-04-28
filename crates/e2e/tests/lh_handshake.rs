//! libp2p ↔ silver QUIC handshake spike.
//!
//! Spins up a silver `PublisherStack` listening on a real UDP port, then
//! dials it with a rust-libp2p `Swarm` configured for QUIC + libp2p TLS.
//! The test passes when both sides observe the connection — silver fires
//! `PeerEvent::P2pNewConnection` on its peer-events queue, and libp2p
//! reports a `ConnectionEstablished` on the client side.
//!
//! This is the framework spike: silver's RPC response path isn't wired
//! yet, so we don't drive any application-level traffic.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use flux::tile::Tile;
use silver_common::PeerEvent;
use silver_e2e::{LhClient, PublisherStack, keypair_from_seed};
use tempfile::TempDir;

fn pick_free_port() -> u16 {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("bind");
    s.local_addr().expect("local_addr").port()
}

#[test]
fn libp2p_connects_to_silver() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let tempdir = TempDir::new().expect("tempdir");
    let silver_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port());
    let silver_disc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port());
    let silver_kp = keypair_from_seed(7);

    let mut silver = PublisherStack::new(
        tempdir.path(),
        "_lh_listener",
        silver_addr,
        silver_disc_addr,
        silver_kp,
    )
    .expect("silver listener");

    let mut client = LhClient::new();
    client.dial(silver_addr).expect("dial");

    let mut silver_saw_connection = false;
    let deadline = Instant::now() + Duration::from_secs(10);

    while Instant::now() < deadline {
        // Drive silver's network tile.
        silver.network.loop_body(&mut silver.network_adapter);

        // Drain peer events emitted by silver into local state.
        silver.injector_adapter.consume::<PeerEvent, _>(|event, _producers| {
            if matches!(event, PeerEvent::P2pNewConnection { .. }) {
                silver_saw_connection = true;
            }
        });

        // Drive the libp2p side for a short slice.
        client.tick(Duration::from_millis(20));

        if silver_saw_connection && client.connected_peer().is_some() {
            return;
        }
    }

    panic!(
        "did not handshake within deadline; silver_saw_connection={silver_saw_connection}, \
         libp2p_connected_peer={:?}",
        client.connected_peer()
    );
}
