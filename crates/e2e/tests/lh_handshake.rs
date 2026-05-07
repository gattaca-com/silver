//! libp2p ↔ silver QUIC handshake tests, both directions:
//!   - silver listens, libp2p dials.
//!   - libp2p listens, silver dials.

mod lh_common;

use std::time::Duration;

use lh_common::{build_silver_listener, drive_until, libp2p_to_silver_peer_id, pick_free_port};
use silver_e2e::LhClient;

#[test]
fn libp2p_dials_silver() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(7);
    let mut client = LhClient::new_dialer();
    client.dial(silver.addr).expect("dial");

    let connected = drive_until(&mut silver, &mut client, Duration::from_secs(10), |_, c| {
        c.connected_peer().is_some()
    });
    assert!(connected, "libp2p never saw ConnectionEstablished");
}

/// Reverse direction: libp2p listens on a known port, silver dials it.
#[test]
fn silver_dials_libp2p() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(8);
    let mut client = LhClient::new_listener();
    let lh_addr = client.listen_addr().expect("listener bound");
    let lh_silver_pid = libp2p_to_silver_peer_id(client.local_peer_id());
    let _ = pick_free_port; // suppress unused-import warning when only this fn is used

    silver
        .network
        .p2p_mut()
        .connect(lh_silver_pid, lh_addr, std::time::Instant::now())
        .expect("silver connect");

    let connected = drive_until(&mut silver, &mut client, Duration::from_secs(10), |_, c| {
        c.connected_peer().is_some()
    });
    assert!(connected, "libp2p never accepted silver's dial");
}
