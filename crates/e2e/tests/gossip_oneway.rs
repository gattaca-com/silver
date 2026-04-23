//! First integration profile: publisher sends N synthetic gossip messages
//! on a single topic; echo side must receive all of them with zero invalid.

use std::time::Duration;

use rand::RngCore;
use silver_common::GossipTopic;
use silver_e2e::TwoStackHarness;

const FORK_DIGEST_HEX: &str = "abcd1234";

#[test]
fn publisher_echo_one_way() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::WARN).try_init().ok();

    let mut harness = TwoStackHarness::new(FORK_DIGEST_HEX).expect("harness");
    harness.connect();

    assert!(
        harness.spin_until(|h| h.is_connected(), Duration::from_secs(5)),
        "publisher never saw PeerConnected for echo within 5s"
    );

    const N: usize = 100;
    let mut rng = rand::thread_rng();
    let mut payload = vec![0u8; 512];
    for i in 0..N {
        rng.fill_bytes(&mut payload);
        harness
            .publish_synthetic(GossipTopic::BeaconBlock, &payload)
            .unwrap_or_else(|e| panic!("publish_synthetic #{i}: {e}"));
        // Tick in between to keep the send queue flowing.
        harness.spin_once();
    }

    let got_all =
        harness.spin_until(|h| h.echo.stats.gossip_received as usize >= N, Duration::from_secs(5));

    let stats = harness.echo.stats;
    assert!(
        got_all,
        "echo received {}/{N} within 5s; invalid={}",
        stats.gossip_received, stats.invalid_msgs
    );
    assert_eq!(stats.invalid_msgs, 0, "unexpected invalid msgs on echo side");
}
