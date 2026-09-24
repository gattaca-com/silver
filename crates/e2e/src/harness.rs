//! Two-stack harness: publisher + echo in one process.

use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use flux::{tile::Tile, timing::Nanos};
use silver_common::{
    GossipMsgOut, GossipTopic, NewGossipMsg, P2pSend, PeerEvent, test_util::ShmemDir,
};

use crate::{
    inject::{InjectError, build_publish_frame, snappy_compress},
    stack::{EchoStack, PublisherStack, keypair_from_seed, on_free_loopback_ports},
};

/// Sentinel in the publisher's peer-handle slot indicating "not yet known".
const NO_HANDLE: usize = usize::MAX;

pub struct TwoStackHarness {
    pub publisher: PublisherStack,
    pub echo: EchoStack,
    pub fork_digest_hex: String,

    /// Publisher's connection-handle for echo, discovered via
    /// `PeerEvent::P2pNewConnection` after QUIC handshake completes.
    publisher_echo_handle: Arc<AtomicUsize>,

    /// Last `GossipMsgOut` produced by `publish_synthetic`, retained so the
    /// caller can re-emit it via `republish_last` (e.g. simulating mesh
    /// fan-in / duplicate delivery for dedup exercises).
    last_msg: Option<GossipMsgOut>,

    /// Kept alive so tempdir is retained.
    _tempdir: ShmemDir,
}

impl TwoStackHarness {
    /// Defaults: loopback addresses on high random ports, deterministic
    /// keypairs from seeds 1 (publisher) and 2 (echo).
    pub fn new(fork_digest_hex: impl Into<String>) -> io::Result<Self> {
        let fork_digest_hex: String = fork_digest_hex.into();
        let tempdir = ShmemDir::new()?;

        let publisher_kp = keypair_from_seed(1);
        let echo_kp = keypair_from_seed(2);

        let publisher = on_free_loopback_ports(|addr, disc_addr| {
            PublisherStack::new(tempdir.path(), "_pub", addr, disc_addr, publisher_kp)
        })?;
        let echo = on_free_loopback_ports(|addr, disc_addr| {
            EchoStack::new(
                tempdir.path(),
                "_echo",
                addr,
                disc_addr,
                echo_kp,
                fork_digest_hex.clone(),
            )
        })?;

        Ok(Self {
            publisher,
            echo,
            fork_digest_hex,
            publisher_echo_handle: Arc::new(AtomicUsize::new(NO_HANDLE)),
            last_msg: None,
            _tempdir: tempdir,
        })
    }

    /// Publisher dials echo. Returns immediately — call `spin_until_ready` to
    /// wait for handshake completion.
    pub fn connect(&mut self) {
        let echo_peer_id = self.echo.peer_id;
        let echo_addr = self.echo.addr;
        self.publisher.network.p2p_mut().connect(echo_peer_id, echo_addr, Instant::now()).unwrap();
    }

    /// True when publisher has observed a `PeerConnected` with the echo's
    /// peer_id.
    pub fn is_connected(&self) -> bool {
        self.publisher_echo_handle.load(Ordering::Acquire) != NO_HANDLE
    }

    /// Single pass: tick both stacks' `loop_body`, then drain peer events
    /// into harness state + stats.
    pub fn spin_once(&mut self) {
        // Publisher: network + controller (no compression).
        self.publisher.network.loop_body(&mut self.publisher.network_adapter);
        self.publisher.controller.loop_body(&mut self.publisher.controller_adapter);

        // Echo: network + compression + controller.
        self.echo.network.loop_body(&mut self.echo.network_adapter);
        self.echo.controller.loop_body(&mut self.echo.controller_adapter);

        // Drain publisher-side peer events to discover echo's connection handle.
        let handle_slot = self.publisher_echo_handle.clone();
        let echo_peer_id = self.echo.peer_id;
        self.publisher.injector_adapter.consume::<PeerEvent, _>(|event, _p| {
            if let PeerEvent::P2pNewConnection { p2p_peer_id, peer_id_full, .. } = event &&
                peer_id_full == echo_peer_id
            {
                handle_slot.store(p2p_peer_id, Ordering::Release);
            }
        });

        // Drain echo-side events into stats. For each NewInbound we read the
        // decompressed SSZ payload out of its TCache slot; if the payload is
        // ≥8 bytes we interpret the first 8 bytes as a
        // `flux::timing::Instant::now().0` stamp from the publisher and
        // record the one-way latency in the histogram.
        self.echo.stats_adapter.consume::<NewGossipMsg, _>(|new_msg, _p| {
            // Saturating subtract guards against garbage/unstamped
            // timestamps: a `recv_ts` that somehow ends up in the future
            // yields 0 ns rather than panicking.
            tracing::debug!("new gossip!");
            let acquired = self.echo.ssz_consumer.acquire(new_msg.ssz);

            let _ = self.echo.stats.receive_ns.record(new_msg.recv_ts.elapsed_saturating().0);

            let now_wall = Instant::now();
            self.echo.stats.gossip_received += 1;
            self.echo.stats.first_seen_at.get_or_insert(now_wall);
            self.echo.stats.last_seen_at = Some(now_wall);

            if let Ok((bytes, _)) = acquired.buffer() {
                self.echo.stats.gossip_decompressed_bytes += bytes.len() as u64;
                if bytes.len() >= 8 {
                    let sent_ns = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
                    // Same guard: integration tests may publish unstamped
                    // (random) bytes, where `sent_ns` is meaningless.
                    let _ =
                        self.echo.stats.latency_ns.record(Nanos(sent_ns).elapsed_saturating().0);
                }
            }
        });
        self.echo.ssz_consumer.free();

        self.echo.stats_adapter.consume::<PeerEvent, _>(|event, _p| {
            if let PeerEvent::P2pGossipInvalidMsg { .. } = event {
                self.echo.stats.invalid_msgs += 1;
            }
        });
    }

    /// Repeatedly `spin_once` until `cond` returns true or `timeout` elapses.
    /// Returns true on success, false on timeout.
    pub fn spin_until<F: FnMut(&Self) -> bool>(&mut self, mut cond: F, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if cond(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.spin_once();
        }
    }

    /// Inject one synthetic gossip message on the publisher side, addressed
    /// to the echo connection. Returns an error if:
    /// - not yet connected (handshake hasn't completed),
    /// - mcache reserve fails (saturated),
    /// - the underlying TCache write fails.
    pub fn publish_synthetic(
        &mut self,
        topic: GossipTopic,
        ssz_payload: &[u8],
    ) -> Result<(), InjectError> {
        let handle = self.publisher_echo_handle.load(Ordering::Acquire);
        if handle == NO_HANDLE {
            return Err(InjectError::ReserveFailed); // not connected yet
        }

        let wire_topic = topic.to_wire(&self.fork_digest_hex);
        let snappy = snappy_compress(ssz_payload);
        let tcache =
            build_publish_frame(&mut self.publisher.mcache_producer, &wire_topic, &snappy)?;
        let msg = GossipMsgOut { peer_id: handle, tcache };
        self.publisher.injector_adapter.produce(P2pSend::Gossip(msg));
        self.last_msg = Some(msg);
        Ok(())
    }

    /// Re-emit the most recently published `GossipMsgOut` — same underlying
    /// `TCacheRead`, no new encoding, no new mcache reservation. Drives the
    /// echo side's dedup path. Returns `false` if nothing has been published
    /// yet.
    pub fn republish_last(&mut self) -> bool {
        let Some(msg) = self.last_msg else {
            return false;
        };
        // Refresh peer handle in case the connection handle changed (e.g.
        // reconnect); `msg.peer_id` is captured at original publish time.
        self.publisher.injector_adapter.produce(P2pSend::Gossip(msg));
        true
    }
}
