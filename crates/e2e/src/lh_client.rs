//! rust-libp2p test peer for end-to-end wire-format checks against silver.
//!
//! Two roles in one type:
//!   - `LhClient::new_dialer()` builds a Swarm bound to an ephemeral QUIC port.
//!     The harness then dials silver's listener.
//!   - `LhClient::new_listener()` binds a known QUIC port the harness hands to
//!     silver's dialer. The bound multiaddr is exposed via `listen_addr()`.
//!
//! Behaviour stack: `request_response::Behaviour` over a custom
//! `Eth2RpcCodec` that does the eth2 framing
//! (`varint(ssz_len) || snappy_frames`). One behaviour instance covers all
//! request-response RPC protocols silver speaks (Ping/Status/MetaData
//! today; BlocksByRange/Root etc. plug in the same way once we need
//! them).
//!
//! Auto-response mode (`set_auto_response`): when silver dials and sends
//! a request, the test client automatically replies with a canned result.
//! Tests verify the *request* silver sent without needing silver to
//! observe the response.

use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    time::Duration,
};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    identity::Keypair,
    multiaddr::Protocol,
    request_response::{
        self, Codec, InboundRequestId, Message, OutboundRequestId, ProtocolSupport, ResponseChannel,
    },
    swarm::SwarmEvent,
};
use tokio::runtime::Runtime;

/// Eth2 RPC protocol IDs we exercise. Mirrors `silver_common::StreamProtocol`
/// for the request-response subset.
pub const PING_PROTOCOL: &str = "/eth2/beacon_chain/req/ping/1/ssz_snappy";
pub const STATUS_V2_PROTOCOL: &str = "/eth2/beacon_chain/req/status/2/ssz_snappy";
pub const METADATA_V3_PROTOCOL: &str = "/eth2/beacon_chain/req/metadata/3/ssz_snappy";

/// Whether a given protocol has a SSZ request body. MetaData is empty.
fn has_request_body(p: &StreamProtocol) -> bool {
    p.as_ref() != METADATA_V3_PROTOCOL
}

#[derive(Default, Clone)]
pub struct Eth2RpcCodec;

/// Body bytes stamped with the negotiated protocol. The wire only carries
/// the body; the codec tags it on read so callers can dispatch.
#[derive(Debug, Clone)]
pub struct TaggedRequest {
    pub protocol: StreamProtocol,
    pub body: Vec<u8>,
}

#[async_trait]
impl Codec for Eth2RpcCodec {
    type Protocol = StreamProtocol;
    type Request = TaggedRequest;
    type Response = (u8, Vec<u8>);

    async fn read_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<TaggedRequest>
    where
        T: AsyncRead + Unpin + Send,
    {
        let body = if has_request_body(protocol) { read_ssz_chunk(io).await? } else { Vec::new() };
        Ok(TaggedRequest { protocol: protocol.clone(), body })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<(u8, Vec<u8>)>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut result = [0u8; 1];
        io.read_exact(&mut result).await?;
        let body = read_ssz_chunk(io).await?;
        Ok((result[0], body))
    }

    async fn write_request<T>(
        &mut self,
        protocol: &Self::Protocol,
        io: &mut T,
        req: TaggedRequest,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        if !has_request_body(protocol) {
            return Ok(());
        }
        write_ssz_chunk(io, &req.body).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        (result_byte, body): (u8, Vec<u8>),
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&[result_byte]).await?;
        write_ssz_chunk(io, &body).await
    }
}

/// Read an SSZ chunk from `io`: varint-length prefix + snappy-frame body.
/// Reads the rest of the stream until EOF (stream is half-closed by the
/// sender after the request/response is fully written).
async fn read_ssz_chunk<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let expected_len = read_varint(io).await? as usize;
    let mut compressed = Vec::new();
    io.read_to_end(&mut compressed).await?;
    let mut decoder = snap::read::FrameDecoder::new(compressed.as_slice());
    let mut decoded = Vec::with_capacity(expected_len);
    std::io::Read::read_to_end(&mut decoder, &mut decoded)
        .map_err(|e| io::Error::other(format!("snappy decode: {e}")))?;
    if decoded.len() != expected_len {
        return Err(io::Error::other(format!(
            "ssz length mismatch: varint says {expected_len}, got {} bytes",
            decoded.len()
        )));
    }
    Ok(decoded)
}

async fn write_ssz_chunk<T>(io: &mut T, body: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    let mut varint = [0u8; 10];
    let n = silver_common::encode_varint(body.len() as u64, &mut varint)
        .map_err(|e| io::Error::other(format!("varint encode: {e:?}")))?;
    io.write_all(&varint[..n]).await?;

    let mut compressed = Vec::with_capacity(body.len() + 32);
    {
        let mut encoder = snap::write::FrameEncoder::new(&mut compressed);
        std::io::Write::write_all(&mut encoder, body)
            .map_err(|e| io::Error::other(format!("snappy encode: {e}")))?;
        // FrameEncoder flushes on Drop; explicit drop here for clarity.
    }
    io.write_all(&compressed).await?;
    Ok(())
}

async fn read_varint<T>(io: &mut T) -> io::Result<u64>
where
    T: AsyncRead + Unpin + Send,
{
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut byte = [0u8; 1];
    loop {
        io.read_exact(&mut byte).await?;
        value |= ((byte[0] & 0x7f) as u64) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(io::Error::other("varint overflow"));
        }
    }
}

/// Snapshot of a request the test client received, for the test to assert.
#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub from: PeerId,
    pub protocol: StreamProtocol,
    pub body: Vec<u8>,
}

pub struct LhClient {
    runtime: Runtime,
    swarm: Swarm<request_response::Behaviour<Eth2RpcCodec>>,
    /// Local listening multiaddr (set after `listen_on` resolves and the
    /// runtime emits `NewListenAddr`). For listener-mode tests we surface
    /// `listen_addr()` to drive silver's dialer.
    listen_addr: Option<SocketAddr>,
    /// Connected peer captured at first `ConnectionEstablished`.
    connected: Option<PeerId>,
    /// Inbound requests we've observed but not yet responded to. Auto-
    /// response mode pops from here on every `tick`.
    pending_inbound: VecDeque<(InboundRequestId, RecordedRequest)>,
    /// Inbound requests recorded for test assertions, preserved even after
    /// auto-response sends a reply.
    received_requests: Vec<RecordedRequest>,
    /// Channels held while waiting to send a response. Indexed by request id.
    pending_channels: HashMap<InboundRequestId, ResponseChannel<(u8, Vec<u8>)>>,
    /// Outbound responses we received, keyed by request id.
    received_responses: HashMap<OutboundRequestId, (u8, Vec<u8>)>,
    /// Per-protocol canned response body to auto-reply with when in
    /// `auto_response = true` mode. Result byte defaults to 0 (success).
    auto_response: bool,
    canned_responses: HashMap<String, (u8, Vec<u8>)>,
}

impl LhClient {
    fn build(listen: bool, protocols: Vec<(StreamProtocol, ProtocolSupport)>) -> Self {
        let keypair = Keypair::generate_secp256k1();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let mut swarm = runtime.block_on(async {
            libp2p::SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_quic()
                .with_behaviour(|_| {
                    request_response::Behaviour::<Eth2RpcCodec>::new(
                        protocols,
                        request_response::Config::default(),
                    )
                })
                .expect("rr behaviour")
                .build()
        });

        // Always bind a local QUIC socket — both dialer and listener modes
        // need a source address. For listener mode the test reads back the
        // bound port via `listen_addr()`.
        runtime.block_on(async {
            swarm
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr"))
                .expect("listen_on");
        });

        let mut client = Self {
            runtime,
            swarm,
            listen_addr: None,
            connected: None,
            pending_inbound: VecDeque::new(),
            received_requests: Vec::new(),
            pending_channels: HashMap::new(),
            received_responses: HashMap::new(),
            auto_response: false,
            canned_responses: HashMap::new(),
        };

        if listen {
            // Pump events until NewListenAddr resolves so callers can
            // immediately read `listen_addr()`. Bounded so a test never
            // hangs here.
            for _ in 0..50 {
                if client.listen_addr.is_some() {
                    break;
                }
                client.tick(Duration::from_millis(20));
            }
        }

        client
    }

    /// Dialer that supports all eth2 RPC protocols. The actual protocol
    /// libp2p picks for an outbound `send_request` is the first
    /// mutually-supported protocol via multistream-select — useful for the
    /// handshake test, but **not** for protocol-specific tests where the
    /// caller must use [`Self::new_dialer_for`] to pin a single protocol.
    pub fn new_dialer() -> Self {
        Self::build(false, eth2_protocols())
    }

    /// Dialer that registers exactly one eth2 RPC protocol. All outbound
    /// requests will negotiate this protocol. Listener mode shouldn't use
    /// this — listeners want to accept all protocols silver might dial.
    pub fn new_dialer_for(protocol: &str) -> Self {
        let protocols =
            vec![(StreamProtocol::new(static_protocol(protocol)), ProtocolSupport::Full)];
        Self::build(false, protocols)
    }

    pub fn new_listener() -> Self {
        Self::build(true, eth2_protocols())
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Bound listen address (resolved after `NewListenAddr`). Listener-mode
    /// tests pass this to silver as the dial target.
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen_addr
    }

    pub fn dial(&mut self, addr: SocketAddr) -> Result<(), libp2p::swarm::DialError> {
        let multiaddr: Multiaddr = format!("/ip4/{}/udp/{}/quic-v1", addr.ip(), addr.port())
            .parse()
            .expect("valid multiaddr");
        let swarm = &mut self.swarm;
        self.runtime.block_on(async move { swarm.dial(multiaddr) })
    }

    pub fn tick(&mut self, timeout: Duration) {
        let connected = &mut self.connected;
        let listen_addr = &mut self.listen_addr;
        let pending_inbound = &mut self.pending_inbound;
        let received_requests = &mut self.received_requests;
        let pending_channels = &mut self.pending_channels;
        let received_responses = &mut self.received_responses;
        let swarm = &mut self.swarm;
        self.runtime.block_on(async {
            if let Ok(event) = tokio::time::timeout(timeout, swarm.select_next_some()).await {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        *connected = Some(peer_id);
                    }
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(addr) = multiaddr_to_socket(&address) {
                            *listen_addr = Some(addr);
                        }
                    }
                    SwarmEvent::Behaviour(request_response::Event::Message {
                        peer,
                        message,
                        ..
                    }) => match message {
                        Message::Request { request_id, request, channel } => {
                            let recorded = RecordedRequest {
                                from: peer,
                                protocol: request.protocol.clone(),
                                body: request.body,
                            };
                            received_requests.push(recorded.clone());
                            pending_inbound.push_back((request_id, recorded));
                            pending_channels.insert(request_id, channel);
                        }
                        Message::Response { request_id, response } => {
                            received_responses.insert(request_id, response);
                        }
                    },
                    _ => {}
                }
            }
        });

        if self.auto_response {
            self.flush_auto_responses();
        }
    }

    pub fn connected_peer(&self) -> Option<PeerId> {
        self.connected
    }

    pub fn received_requests(&self) -> &[RecordedRequest] {
        &self.received_requests
    }

    /// Send an outbound request to `peer` on `protocol`. Returns the
    /// outbound request id; pair the eventual response by polling
    /// `take_response(id)`.
    pub fn send_request(
        &mut self,
        peer: PeerId,
        protocol: &str,
        body: Vec<u8>,
    ) -> OutboundRequestId {
        let req = TaggedRequest { protocol: StreamProtocol::new(static_protocol(protocol)), body };
        self.swarm.behaviour_mut().send_request(&peer, req)
    }

    /// Protocol-typed convenience wrappers — each picks the matching
    /// `StreamProtocol` so the test caller doesn't have to.
    pub fn send_ping(&mut self, peer: PeerId, seq: u64) -> OutboundRequestId {
        self.send_request(peer, PING_PROTOCOL, seq.to_le_bytes().to_vec())
    }

    pub fn send_status(&mut self, peer: PeerId, status_ssz: Vec<u8>) -> OutboundRequestId {
        self.send_request(peer, STATUS_V2_PROTOCOL, status_ssz)
    }

    pub fn send_metadata(&mut self, peer: PeerId) -> OutboundRequestId {
        self.send_request(peer, METADATA_V3_PROTOCOL, Vec::new())
    }

    pub fn take_response(&mut self, id: OutboundRequestId) -> Option<(u8, Vec<u8>)> {
        self.received_responses.remove(&id)
    }

    /// Configure the test client to automatically reply to inbound
    /// requests with the given canned bodies (result byte = 0 success).
    pub fn set_auto_response(&mut self, protocol: &str, body: Vec<u8>) {
        self.canned_responses.insert(protocol.to_owned(), (0u8, body));
        self.auto_response = true;
    }

    fn flush_auto_responses(&mut self) {
        while let Some((id, recorded)) = self.pending_inbound.pop_front() {
            let response = self
                .canned_responses
                .get(recorded.protocol.as_ref())
                .cloned()
                .unwrap_or((0u8, Vec::new()));
            if let Some(channel) = self.pending_channels.remove(&id) {
                let _ = self.swarm.behaviour_mut().send_response(channel, response);
            }
        }
    }
}

impl Default for LhClient {
    fn default() -> Self {
        Self::new_dialer()
    }
}

fn eth2_protocols() -> Vec<(StreamProtocol, ProtocolSupport)> {
    [PING_PROTOCOL, STATUS_V2_PROTOCOL, METADATA_V3_PROTOCOL]
        .into_iter()
        .map(|p| (StreamProtocol::new(p), ProtocolSupport::Full))
        .collect()
}

/// libp2p's `StreamProtocol::new` requires `&'static str`. Map the runtime
/// strings we accept to the matching static value.
fn static_protocol(p: &str) -> &'static str {
    match p {
        PING_PROTOCOL => PING_PROTOCOL,
        STATUS_V2_PROTOCOL => STATUS_V2_PROTOCOL,
        METADATA_V3_PROTOCOL => METADATA_V3_PROTOCOL,
        other => panic!("unknown eth2 protocol {other}"),
    }
}

fn multiaddr_to_socket(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();
    let ip = match iter.next()? {
        Protocol::Ip4(v4) => std::net::IpAddr::V4(v4),
        Protocol::Ip6(v6) => std::net::IpAddr::V6(v6),
        _ => return None,
    };
    let port = match iter.next()? {
        Protocol::Udp(p) => p,
        Protocol::Tcp(p) => p,
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}
