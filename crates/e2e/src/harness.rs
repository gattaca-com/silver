//! Two-stack harness: publisher + echo in one process.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use flux::{tile::Tile, timing::Nanos};
use silver_common::{Gossip, GossipMsgOut, GossipTopic, PeerEvent};
use tempfile::TempDir;

use crate::{
    inject::{InjectError, build_publish_frame, snappy_compress},
    stack::{EchoStack, PublisherStack, keypair_from_seed},
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
    _tempdir: TempDir,
}

impl TwoStackHarness {
    /// Defaults: loopback addresses on high random ports, deterministic
    /// keypairs from seeds 1 (publisher) and 2 (echo).
    pub fn new(fork_digest_hex: impl Into<String>) -> io::Result<Self> {
        let fork_digest_hex: String = fork_digest_hex.into();
        let tempdir = TempDir::new()?;

        let publisher_kp = keypair_from_seed(1);
        let echo_kp = keypair_from_seed(2);

        let publisher_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port()?);
        let echo_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port()?);
        let publisher_disc_addr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port()?);
        let echo_disc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), pick_free_port()?);

        let publisher = PublisherStack::new(
            tempdir.path(),
            "_pub",
            publisher_addr,
            publisher_disc_addr,
            publisher_kp,
        )?;
        let echo = EchoStack::new(
            tempdir.path(),
            "_echo",
            echo_addr,
            echo_disc_addr,
            echo_kp,
            fork_digest_hex.clone(),
        )?;

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
        self.publisher.network.p2p_mut().connect(echo_peer_id, echo_addr);
    }

    /// True when publisher has observed a `PeerConnected` with the echo's
    /// peer_id.
    pub fn is_connected(&self) -> bool {
        self.publisher_echo_handle.load(Ordering::Acquire) != NO_HANDLE
    }

    /// Single pass: tick both stacks' `loop_body`, then drain peer events
    /// into harness state + stats.
    pub fn spin_once(&mut self) {
        // Publisher: network tile only (no compression).
        self.publisher.network.loop_body(&mut self.publisher.network_adapter);

        // Echo: network + compression tiles.
        self.echo.network.loop_body(&mut self.echo.network_adapter);
        self.echo.compression.loop_body(&mut self.echo.compression_adapter);

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
        self.echo.stats_adapter.consume::<Gossip, _>(|msg, _p| {
            if let Gossip::NewInbound(new_msg) = msg {
                // Saturating subtract guards against garbage/unstamped
                // timestamps: a `recv_ts` that somehow ends up in the future
                // yields 0 ns rather than panicking.
                let _ = self.echo.stats.receive_ns.record(new_msg.recv_ts.elapsed_saturating().0);

                let now_wall = Instant::now();
                self.echo.stats.gossip_received += 1;
                self.echo.stats.first_seen_at.get_or_insert(now_wall);
                self.echo.stats.last_seen_at = Some(now_wall);

                if let Ok((bytes, _)) = self.echo.ssz_consumer.read_at(new_msg.ssz.seq()) {
                    self.echo.stats.gossip_decompressed_bytes += bytes.len() as u64;
                    if bytes.len() >= 8 {
                        let sent_ns = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
                        // Same guard: integration tests may publish unstamped
                        // (random) bytes, where `sent_ns` is meaningless.
                        let _ = self
                            .echo
                            .stats
                            .latency_ns
                            .record(Nanos(sent_ns).elapsed_saturating().0);
                    }
                }
            }
        });

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
        self.publisher.injector_adapter.produce(msg);
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
        self.publisher.injector_adapter.produce(msg);
        true
    }
}

/// Bind a fresh UDP socket to port 0, read back the OS-assigned port, drop
/// the socket. Race window is small; acceptable for tests.
fn pick_free_port() -> io::Result<u16> {
    let s = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    s.local_addr().map(|a| a.port())
}
