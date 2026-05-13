//! Identify (`/ipfs/id/1.0.0`) round-trip tests against rust-libp2p's
//! `identify::Behaviour`. Each direction exercises one half of the
//! exchange — silver dials and reads libp2p's identify in one test;
//! libp2p dials and reads silver's identify in the other. The libp2p
//! side is configured with a known `protocol_version` / `agent_version`
//! so silver-side assertions are deterministic.

mod lh_common;

use std::time::{Duration, Instant};

use lh_common::{
    build_silver_listener, drive_until, libp2p_to_silver_peer_id, wait_for_silver_connect,
    wait_for_silver_identify,
};
use silver_common::AGENT_VERSION;
use silver_e2e::{LhClient, lh_client};

#[test]
fn silver_dials_libp2p_identify_round_trip() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(40);
    let mut client = LhClient::new_listener();

    let lh_addr = client.listen_addr().expect("listener bound");
    let lh_pid = client.local_peer_id();
    let lh_silver_pid = libp2p_to_silver_peer_id(lh_pid);
    silver.network.p2p_mut().connect(lh_silver_pid, lh_addr, Instant::now()).expect("connect");

    let peer = wait_for_silver_connect(&mut silver, &mut client, Duration::from_secs(5))
        .expect("silver never observed PeerConnected");

    // Silver → libp2p identify: silver auto-opens the outbound identify
    // stream from `on_connected`, reads libp2p's response, and emits
    // `PeerEvent::P2pPeerIdentity` onto the spine. We drain that off the
    // injector adapter.
    let identify = wait_for_silver_identify(&mut silver, &mut client, peer, Duration::from_secs(5))
        .expect("silver never observed P2pPeerIdentity");
    let user_agent = &identify.user_agent[..identify.user_agent_len];
    assert_eq!(user_agent, lh_client::IDENTIFY_AGENT_VERSION.as_bytes());
    assert_ne!(identify.public_key, [0u8; 33], "peer pubkey not populated");

    // libp2p → silver identify: libp2p's `identify::Behaviour` issues its
    // own outbound query on the same connection. Drive until it lands.
    let got_lh_identify = drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        !c.received_identifies().is_empty()
    });
    assert!(got_lh_identify, "libp2p never received silver's Identify");
    let recv = client.received_identifies().last().expect("identify");
    assert_eq!(recv.protocol_version, lh_client::IDENTIFY_PROTOCOL_VERSION);
    assert_eq!(recv.agent_version, AGENT_VERSION);
}

#[test]
fn libp2p_dials_silver_identify_round_trip() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).try_init().ok();

    let (mut silver, _td) = build_silver_listener(41);
    let mut client = LhClient::new_dialer();
    client.dial(silver.addr).expect("dial");

    let peer = wait_for_silver_connect(&mut silver, &mut client, Duration::from_secs(5))
        .expect("silver never observed PeerConnected");

    // Both sides initiate their own outbound identify query on connect.
    let identify = wait_for_silver_identify(&mut silver, &mut client, peer, Duration::from_secs(5))
        .expect("silver never observed P2pPeerIdentity");
    let user_agent = &identify.user_agent[..identify.user_agent_len];
    assert_eq!(user_agent, lh_client::IDENTIFY_AGENT_VERSION.as_bytes());
    assert_ne!(identify.public_key, [0u8; 33], "peer pubkey not populated");

    let got_lh_identify = drive_until(&mut silver, &mut client, Duration::from_secs(5), |_, c| {
        !c.received_identifies().is_empty()
    });
    assert!(got_lh_identify, "libp2p never received silver's Identify");
    let recv = client.received_identifies().last().expect("identify");
    assert_eq!(recv.protocol_version, lh_client::IDENTIFY_PROTOCOL_VERSION);
    assert_eq!(recv.agent_version, AGENT_VERSION);
}
