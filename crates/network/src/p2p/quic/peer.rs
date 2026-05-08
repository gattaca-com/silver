use std::{cell::Cell, hash::BuildHasherDefault, time::Instant};

use bytes::Bytes;
use flux::utils::ArrayVec;
use fxhash::{FxHashMap, FxHashSet};
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, Dir, EndpointEvent, Side, StreamId, Transmit,
    VarInt,
};
use silver_common::{
    P2pStreamId, PeerId, RpcOutbound, RpcRequest, RpcResponse, StreamProtocol, TCacheRead,
};

use crate::{
    RemotePeer,
    p2p::{
        NetEvent,
        context::Context,
        quic::{SendResult, stream::StreamIoImpl},
        streams::StreamState,
        tls::peer_id_from_certificate,
    },
};

pub(crate) struct Peer {
    id: RemotePeer,
    handle: ConnectionHandle,
    connection: Connection,
    streams: FxHashMap<StreamId, Stream>,
    inbound_gossip: Option<StreamId>,
    outbound_gossip: Option<StreamId>,
}

impl Peer {
    pub(crate) fn new(handle: ConnectionHandle, connection: Connection) -> Self {
        Self {
            id: RemotePeer {
                peer_id: PeerId::default(),
                connection: handle.0,
                addr: connection.remote_address(),
            },
            handle,
            connection,
            streams: FxHashMap::with_capacity_and_hasher(16, BuildHasherDefault::default()),
            inbound_gossip: None,
            outbound_gossip: None,
        }
    }

    pub(crate) fn id(&self) -> &RemotePeer {
        &self.id
    }

    pub(crate) fn event(&mut self, event: ConnectionEvent) {
        self.connection.handle_event(event);
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.connection.is_drained()
    }

    pub(crate) fn send_gossip(&mut self, msg: TCacheRead) -> SendResult {
        if let Some(stream) = match &self.outbound_gossip {
            Some(id) => self.streams.get_mut(id),
            None => self.open_stream(StreamProtocol::GossipSub).and_then(|id| {
                self.outbound_gossip.replace(id);
                self.streams.get_mut(&id)
            }),
        } {
            if let OutboundBuffer::Gossip(buffer) = &mut stream.out_buffer {
                match buffer.add_msg(msg) {
                    true => return SendResult::MessageDropped,
                    false => return SendResult::Ok,
                }
            }
        }
        SendResult::StreamCreationError
    }

    pub(crate) fn send_rpc(&mut self, msg: RpcOutbound) -> SendResult {
        if let Some(stream) = match &msg {
            RpcOutbound::Request(req) => {
                self.open_stream(req.request.protocol()).and_then(|id| self.streams.get_mut(&id))
            }
            RpcOutbound::Response(rsp) => self.streams.get_mut(&rsp.stream_id.stream_id()),
        } {
            if let OutboundBuffer::Rpc(buffer) = &mut stream.out_buffer {
                match buffer.add_msg(msg) {
                    true => return SendResult::MessageDropped,
                    false => return SendResult::Ok,
                }
            }
        };
        SendResult::StreamCreationError
    }

    pub(crate) fn send_identify(&mut self) -> SendResult {
        match self.open_stream(StreamProtocol::Identity) {
            Some(_) => SendResult::Ok,
            None => SendResult::StreamCreationError,
        }
    }

    pub(crate) fn gossip_tail(&self) -> u64 {
        let mut min = u64::MAX;
        if let Some(stream) = self.inbound_gossip.as_ref().and_then(|id| self.streams.get(id)) {
            min = min.min(stream.out_buffer.cache_tail());
        }
        if let Some(stream) = self.outbound_gossip.as_ref().and_then(|id| self.streams.get(id)) {
            min = min.min(stream.out_buffer.cache_tail());
        }
        min
    }

    pub(crate) fn rpc_tail(&self) -> u64 {
        let mut min = u64::MAX;
        for stream in self.streams.values() {
            if stream.p2p_id.protocol().is_request_response() {
                min = min.min(stream.out_buffer.cache_tail());
            }
        }
        min
    }

    pub(crate) fn has_pending_outbound(&self) -> bool {
        self.streams.values().any(|s| !s.out_buffer.is_empty())
    }

    pub(crate) fn pending(&self) -> usize {
        self.streams.values().map(|s| s.out_buffer.len()).sum()
    }

    /// Open an outbound stream with the given protocol. Returns `None` if
    /// the connection isn't ready (e.g. stream limit not yet negotiated).
    /// Multistream-select negotiation runs internally; `NetEvent::StreamReady`
    /// is emitted once it completes.
    fn open_stream(&mut self, protocol: StreamProtocol) -> Option<StreamId> {
        // All streams are Bi — multistream-select requires bidirectional I/O
        // even for request-response protocols.
        tracing::debug!(?protocol, "open outbound stream");

        if protocol == StreamProtocol::GossipSub && self.outbound_gossip.is_some() {
            tracing::warn!(id=?self.id, "open stream: already have outbound gossip stream");
            return None;
        }

        let id = self.connection.streams().open(Dir::Bi)?;
        let p2p_id = P2pStreamId::new(self.id.connection, id.into(), protocol, false);

        // allocate out buffer.
        let out_buffer = out_buffer(&p2p_id, false);
        let stream = StreamState::new_outbound(protocol);
        self.streams.insert(id, Stream { p2p_id, state: Cell::new(stream), out_buffer });
        Some(id)
    }

    pub(crate) fn transmit(
        &mut self,
        now: Instant,
        max_datagrams: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        self.connection.poll_transmit(now, max_datagrams, buf)
    }

    pub(crate) fn spin<F, E>(
        &mut self,
        now: Instant,
        ep_callback: &mut F,
        context: &mut Context,
        on_event: &mut E,
        banned_peers: &FxHashSet<PeerId>,
    ) -> Option<Instant>
    where
        F: FnMut(ConnectionHandle, EndpointEvent) -> Option<ConnectionEvent>,
        E: FnMut(crate::NetEvent),
    {
        while self.connection.poll_timeout().is_some_and(|t| t <= now) {
            self.connection.handle_timeout(now);
        }
        let next_timeout = self.connection.poll_timeout();

        while let Some(ep_event) = self.connection.poll_endpoint_events() {
            if let Some(conn_event) = (ep_callback)(self.handle, ep_event) {
                self.connection.handle_event(conn_event);
            }
        }

        while let Some(event) = self.connection.poll() {
            match event {
                quinn_proto::Event::Connected => {
                    let peer_id = match id_from_connection(&self.connection) {
                        Some(id) if !banned_peers.contains(&id) => id,
                        _ => {
                            self.connection.close(
                                now,
                                VarInt::from_u32(400),
                                Bytes::from_static(b"bad peer id"),
                            );
                            continue;
                        }
                    };
                    self.id.peer_id = peer_id;
                    tracing::info!(handle = ?self.handle, "connected");
                    on_event(NetEvent::PeerConnected {
                        peer: self.id.clone(),
                        addr: self.connection.remote_address(),
                        local_dialler: self.connection.side() == Side::Client,
                    });
                }
                quinn_proto::Event::ConnectionLost { reason } => {
                    tracing::info!(handle = ?self.handle, ?reason, "connection lost");
                }
                quinn_proto::Event::Stream(stream_event) => {
                    self.handle_stream_event(stream_event, context, on_event);
                }
                _ => {}
            }
        }

        while let Some(ep_event) = self.connection.poll_endpoint_events() {
            if let Some(conn_event) = (ep_callback)(self.handle, ep_event) {
                self.connection.handle_event(conn_event);
            }
        }

        // Drive all streams (negotiating and active) — catches pending writes.
        let mut to_remove = ArrayVec::<StreamId, 8>::new();
        for (id, stream) in &mut self.streams {
            match stream.spin(&mut self.connection, context, on_event) {
                SpinResult::Ok => {}
                SpinResult::Protocol(protocol) => {
                    tracing::debug!(?id, ?protocol, "incoming stream negotatied");
                    if protocol == StreamProtocol::GossipSub {
                        self.inbound_gossip.replace(*id);
                    }
                }
                SpinResult::End => {
                    to_remove.try_push(stream.p2p_id.stream_id());
                }
            }
        }
        for id in to_remove {
            if let Some(in_id) = self.inbound_gossip &&
                in_id == id
            {
                self.inbound_gossip.take();
            }
            if let Some(in_id) = self.outbound_gossip &&
                in_id == id
            {
                self.outbound_gossip.take();
            }
            self.streams.remove(&id);
        }

        next_timeout
    }

    fn handle_stream_event<E>(
        &mut self,
        event: quinn_proto::StreamEvent,
        context: &mut Context,
        on_event: &mut E,
    ) where
        E: FnMut(crate::NetEvent),
    {
        match event {
            quinn_proto::StreamEvent::Opened { dir } => {
                tracing::debug!("stream open event");
                while let Some(id) = self.connection.streams().accept(dir) {
                    let p2p_id = P2pStreamId::new(
                        self.id.connection,
                        id.into(),
                        StreamProtocol::Unset,
                        true,
                    );

                    self.streams.insert(id, Stream {
                        p2p_id,
                        state: Cell::new(StreamState::new_inbound()),
                        out_buffer: OutboundBuffer::Unset,
                    });
                    on_event(NetEvent::StreamReady { stream: p2p_id });
                    tracing::debug!(?p2p_id, "stream open");
                }
            }
            quinn_proto::StreamEvent::Readable { id } |
            quinn_proto::StreamEvent::Writable { id } => {
                let remove = match self.streams.get_mut(&id) {
                    Some(stream) => match stream.spin(&mut self.connection, context, on_event) {
                        SpinResult::Ok => false,
                        SpinResult::Protocol(protocol) => {
                            tracing::debug!(?id, ?protocol, "incoming stream negotatied");
                            if protocol == StreamProtocol::GossipSub {
                                self.inbound_gossip.replace(id);
                            }
                            false
                        }
                        SpinResult::End => true,
                    },
                    None => false,
                };
                if remove {
                    if let Some(in_id) = self.inbound_gossip &&
                        in_id == id
                    {
                        self.inbound_gossip.take();
                    }
                    if let Some(in_id) = self.outbound_gossip &&
                        in_id == id
                    {
                        self.outbound_gossip.take();
                    }
                    self.streams.remove(&id);
                }
            }
            quinn_proto::StreamEvent::Finished { id } => {
                tracing::debug!(?id, "stream finished");
                if let Some(stream) = self.streams.remove(&id) {
                    on_event(NetEvent::StreamClosed { stream: stream.p2p_id });
                }
            }
            quinn_proto::StreamEvent::Stopped { id, error_code } => {
                tracing::warn!(?id, ?error_code, "stream stopped");
                if let Some(stream) = self.streams.remove(&id) {
                    // TODO include error
                    on_event(NetEvent::StreamClosed { stream: stream.p2p_id });
                }
            }
            quinn_proto::StreamEvent::Available { dir: _ } => {}
        }
    }
}

fn id_from_connection(conn: &Connection) -> Option<PeerId> {
    let identity = conn.crypto_session().peer_identity();
    let Some(certs): Option<Box<Vec<rustls::pki_types::CertificateDer>>> =
        identity.map(|i| i.downcast()).and_then(|r| r.ok())
    else {
        tracing::error!("identity cannot be downcast to certificates");
        return None;
    };
    peer_id_from_certificate(certs[0].as_ref())
        .inspect_err(|e| {
            tracing::error!(?e, "failed to extract peer id from certificate");
        })
        .ok()
}

fn out_buffer(id: &P2pStreamId, incoming: bool) -> OutboundBuffer {
    match id.protocol() {
        StreamProtocol::GossipSub => OutboundBuffer::Gossip(OutBuffer::new(1024)),
        StreamProtocol::BeaconBlocksByRange |
        StreamProtocol::BeaconBlocksByRoot |
        StreamProtocol::DataColumnSidecarsByRange |
        StreamProtocol::DataColumnSidecarsByRoot
            if incoming =>
        {
            OutboundBuffer::Rpc(OutBuffer::new(128))
        }
        _ => OutboundBuffer::Rpc(OutBuffer::new(1)),
    }
}

struct Stream {
    p2p_id: P2pStreamId,
    state: Cell<StreamState>,
    out_buffer: OutboundBuffer,
}

enum SpinResult {
    Ok,
    End,
    Protocol(StreamProtocol),
}

impl Stream {
    fn spin<E>(
        &mut self,
        connection: &mut Connection,
        context: &mut Context,
        on_event: &mut E,
    ) -> SpinResult
    where
        E: FnMut(crate::NetEvent),
    {
        let state = self.state.take();
        let mut io = StreamIoImpl { connection, outbound: &mut self.out_buffer };

        match state.spin(&mut io, &mut self.p2p_id, context, on_event) {
            Ok(StreamState::Finished) => {
                self.state.replace(StreamState::Finished);
                SpinResult::End
            }
            Ok(state) => {
                tracing::trace!(id=?self.p2p_id, ?state, "stream state");
                let mut result = SpinResult::Ok;
                // After the negotiate state machine has transitioned past
                // Done (`set_protocol` fires inside `state.spin`), the
                // inbound stream still has an `OutboundBuffer::Unset`.
                // Initialise it the first time we observe a non-Unset
                // protocol so RPC responses have somewhere to land.
                if self.p2p_id.is_incoming() &&
                    matches!(self.out_buffer, OutboundBuffer::Unset) &&
                    self.p2p_id.protocol() != StreamProtocol::Unset
                {
                    self.out_buffer = out_buffer(&self.p2p_id, true);
                    result = SpinResult::Protocol(self.p2p_id.protocol());
                }

                self.state.replace(state);
                result
            }
            Err(e) => {
                tracing::error!(id=?self.p2p_id, ?e, "stream error");
                let id = self.p2p_id.stream_id();
                let _ = connection.send_stream(id).finish();
                let _ = connection.recv_stream(id).stop(VarInt::from_u32(1));

                // TODO error info.
                on_event(NetEvent::StreamClosed { stream: self.p2p_id });
                SpinResult::End
            }
        }
    }
}

pub(super) enum OutboundBuffer {
    Unset,
    Gossip(OutBuffer<TCacheRead>),
    Rpc(OutBuffer<RpcOutbound>),
}

impl OutboundBuffer {
    fn cache_tail(&self) -> u64 {
        match self {
            OutboundBuffer::Unset => u64::MAX,
            OutboundBuffer::Gossip(out_buffer) => out_buffer.cache_tail,
            OutboundBuffer::Rpc(out_buffer) => out_buffer.cache_tail,
        }
    }

    fn len(&self) -> usize {
        match self {
            OutboundBuffer::Unset => 0,
            OutboundBuffer::Gossip(out_buffer) => out_buffer.len(),
            OutboundBuffer::Rpc(out_buffer) => out_buffer.len(),
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            OutboundBuffer::Unset => true,
            OutboundBuffer::Gossip(out_buffer) => out_buffer.is_empty(),
            OutboundBuffer::Rpc(out_buffer) => out_buffer.is_empty(),
        }
    }
}

pub(super) trait HasSeq {
    fn seq(&self) -> u64;
}

impl HasSeq for TCacheRead {
    fn seq(&self) -> u64 {
        self.seq()
    }
}

impl HasSeq for RpcOutbound {
    fn seq(&self) -> u64 {
        match self {
            RpcOutbound::Request(req) => match &req.request {
                RpcRequest::BlockByRoot(tcache_read) => tcache_read.seq(),
                RpcRequest::DataColumnsByRoot(tcache_read) => tcache_read.seq(),
                _ => u64::MAX,
            },
            RpcOutbound::Response(rsp) => match &rsp.response {
                RpcResponse::BeaconBlock { fork_digest: _, ssz } => ssz.seq(),
                RpcResponse::DataColumnSidecar { fork_digest: _, ssz } => ssz.seq(),
                _ => u64::MAX,
            },
        }
    }
}

pub(super) struct OutBuffer<T: HasSeq + Clone> {
    cache_tail: u64,
    msgs: Box<[Option<T>]>,
    len: usize,
    head: usize,
    tail: usize,
}

impl<T: HasSeq + Clone> OutBuffer<T> {
    fn new(len: usize) -> Self {
        assert!(len.is_power_of_two());
        Self {
            cache_tail: u64::MAX,
            msgs: vec![None; len].into_boxed_slice(),
            len,
            head: 0,
            tail: 0,
        }
    }

    fn pos(&self, seq: usize) -> usize {
        seq & (self.len - 1)
    }

    /// Returns `true` if adding the new message overwrote an old message.
    fn add_msg(&mut self, msg: T) -> bool {
        if self.cache_tail == u64::MAX {
            self.cache_tail = msg.seq();
        }

        let old_msg = self.msgs[self.pos(self.head)].replace(msg);
        self.head += 1;
        old_msg.is_some()
    }

    /// Called when the current read is complete.
    pub(super) fn pop(&mut self) -> Option<T> {
        match self.msgs[self.pos(self.tail)].take() {
            Some(msg) => {
                if msg.seq() != u64::MAX {
                    self.cache_tail = msg.seq();
                }
                //println!("popped - cache tail is {}", self.cache_tail);
                self.tail += 1;
                Some(msg)
            }
            None => {
                //self.cache_tail = u64::MAX;
                None
            }
        }
    }

    /// Moves the cache tail to the next message - if any
    #[allow(dead_code)]
    pub(super) fn send_complete(&mut self) {
        match &self.msgs[self.pos(self.tail)] {
            Some(msg) => {
                if msg.seq() != u64::MAX {
                    self.cache_tail = msg.seq();
                }
            }
            None => {
                self.cache_tail = u64::MAX;
            }
        }
    }

    pub(super) fn len(&self) -> usize {
        self.head - self.tail
    }

    pub(super) fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io::Write, net::SocketAddr, sync::Arc, time::Instant};

    use quinn_proto::{DatagramEvent, Endpoint, EndpointConfig};
    use silver_common::{Keypair, TCache, TCacheProducer, TConsumer, TProducer};

    use super::*;

    const TCACHE_BYTES: usize = 64 * 1024;

    /// Per-peer test plumbing. Owns the four tcaches plus the `Context`
    /// passed into `Peer::spin`.
    struct PeerHarness {
        context: Context,
        /// Tail-reads inbound gossip frames (the network's `gossip_producer`
        /// writes here).
        gossip_in_consumer: TConsumer,
        /// Test enqueues outbound gossip payloads here. The network's
        /// `gossip_consumer` reads via random access.
        gossip_out_producer: TProducer,
        /// Bytes received per stream — extracted from inbound frames in
        /// `drain_inbound`.
        received: HashMap<P2pStreamId, Vec<u8>>,
    }

    impl PeerHarness {
        fn new() -> Self {
            let gossip_in_p = TCache::producer(TCACHE_BYTES);
            let gossip_in_c = gossip_in_p.cache_ref().consumer().unwrap();
            let gossip_out_p = TCache::producer(TCACHE_BYTES);
            let gossip_out_c = gossip_out_p.cache_ref().random_access().unwrap();

            let rpc_in_p = TCache::producer(TCACHE_BYTES);
            let rpc_out_p = TCache::producer(TCACHE_BYTES);
            let rpc_out_c = rpc_out_p.cache_ref().random_access().unwrap();

            Self {
                context: Context {
                    gossip_producer: gossip_in_p,
                    gossip_consumer: gossip_out_c,
                    rpc_producer: rpc_in_p,
                    rpc_consumer: rpc_out_c,
                    identify: None,
                },
                gossip_in_consumer: gossip_in_c,
                gossip_out_producer: gossip_out_p,
                received: HashMap::new(),
            }
        }

        /// Stage `payload` for outbound delivery on `stream_id`. Reserves
        /// space in the gossip-out tcache, copies the payload, then queues
        /// the `TCacheRead` so the gossip-out state machine can pick it up.
        fn send_gossip(&mut self, _stream_id: P2pStreamId, payload: &[u8], peer: &mut Peer) {
            let mut res =
                self.gossip_out_producer.reserve(payload.len(), true).expect("tcache full");
            res.write_all(payload).unwrap();
            assert!(res.is_committed());
            peer.send_gossip(res.read());
        }

        /// Pull all newly-arrived inbound frames out of the consumer and
        /// merge into `received`. Each frame is `[P2pStreamId | body]`.
        fn drain_inbound(&mut self) {
            while let Ok((data, _)) = self.gossip_in_consumer.read() {
                let id_bytes = &data[..size_of::<P2pStreamId>()];
                let id: &P2pStreamId = id_bytes.into();
                let body = &data[size_of::<P2pStreamId>()..];
                self.received.entry(*id).or_default().extend_from_slice(body);
                self.gossip_in_consumer.free();
            }
        }
    }

    /// Two endpoints + peers connected via in-memory datagram shuttle.
    struct PeerPair {
        client_ep: Endpoint,
        server_ep: Endpoint,
        client_peer: Peer,
        server_peer: Peer,
        client_addr: SocketAddr,
        server_addr: SocketAddr,
    }

    impl PeerPair {
        fn new() -> Self {
            let server_addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
            let client_addr: SocketAddr = "127.0.0.1:5001".parse().unwrap();
            let now = Instant::now();

            let server_kp = Keypair::from_secret(&[1u8; 32]).unwrap();
            let client_kp = Keypair::from_secret(&[2u8; 32]).unwrap();

            let server_config = super::super::create_server_config(&server_kp).unwrap();
            let mut server_ep = Endpoint::new(
                Arc::new(EndpointConfig::default()),
                Some(Arc::new(server_config)),
                false,
                None,
            );

            let mut client_ep =
                Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None);

            let client_config =
                super::super::create_client_config(&client_kp, Some(server_kp.peer_id())).unwrap();
            let (client_handle, client_conn) =
                client_ep.connect(now, client_config, server_addr, "x").unwrap();
            let mut client_peer = Peer::new(client_handle, client_conn);

            let mut buf = Vec::new();
            let mut scratch = vec![0u8; 2048];
            let mut server_peer: Option<Peer> = None;

            while let Some(tx) = client_peer.transmit(now, 1, &mut buf) {
                let data = bytes::BytesMut::from(&buf[..tx.size]);
                buf.clear();
                if let Some(event) =
                    server_ep.handle(now, client_addr, None, None, data, &mut scratch)
                {
                    match event {
                        DatagramEvent::NewConnection(incoming) => {
                            let (handle, conn) =
                                server_ep.accept(incoming, now, &mut scratch, None).unwrap();
                            server_peer = Some(Peer::new(handle, conn));
                        }
                        DatagramEvent::ConnectionEvent(_, ce) => {
                            if let Some(ref mut p) = server_peer {
                                p.event(ce);
                            }
                        }
                        _ => {}
                    }
                }
            }

            let mut pair = Self {
                client_ep,
                server_ep,
                client_peer,
                server_peer: server_peer.expect("server never received initial packet"),
                client_addr,
                server_addr,
            };

            // Pump until both sides are connected.
            let mut client_h = PeerHarness::new();
            let mut server_h = PeerHarness::new();
            let mut client_connected = false;
            let mut server_connected = false;
            for _ in 0..100 {
                {
                    let mut ccb = |e: NetEvent| {
                        if matches!(e, NetEvent::PeerConnected { .. }) {
                            client_connected = true;
                        }
                    };
                    let mut scb = |e: NetEvent| {
                        if matches!(e, NetEvent::PeerConnected { .. }) {
                            server_connected = true;
                        }
                    };
                    pair.step(now, &mut client_h, &mut server_h, &mut ccb, &mut scb);
                }
                if client_connected && server_connected {
                    break;
                }
            }

            pair
        }

        fn step<CE, SE>(
            &mut self,
            now: Instant,
            client_h: &mut PeerHarness,
            server_h: &mut PeerHarness,
            client_on_event: &mut CE,
            server_on_event: &mut SE,
        ) where
            CE: FnMut(NetEvent),
            SE: FnMut(NetEvent),
        {
            let mut buf = Vec::new();
            let mut scratch = vec![0u8; 2048];

            for _ in 0..20 {
                let mut progress = false;

                while let Some(tx) = self.client_peer.transmit(now, 1, &mut buf) {
                    progress = true;
                    let data = bytes::BytesMut::from(&buf[..tx.size]);
                    buf.clear();
                    if let Some(event) =
                        self.server_ep.handle(now, self.client_addr, None, None, data, &mut scratch)
                    {
                        if let DatagramEvent::ConnectionEvent(_, ce) = event {
                            self.server_peer.event(ce);
                        }
                    }
                }

                while let Some(tx) = self.server_peer.transmit(now, 1, &mut buf) {
                    progress = true;
                    let data = bytes::BytesMut::from(&buf[..tx.size]);
                    buf.clear();
                    if let Some(event) =
                        self.client_ep.handle(now, self.server_addr, None, None, data, &mut scratch)
                    {
                        if let DatagramEvent::ConnectionEvent(_, ce) = event {
                            self.client_peer.event(ce);
                        }
                    }
                }

                {
                    let mut cb = |h, e| self.client_ep.handle_event(h, e);
                    self.client_peer.spin(
                        now,
                        &mut cb,
                        &mut client_h.context,
                        client_on_event,
                        &FxHashSet::default(),
                    );
                }
                {
                    let mut cb = |h, e| self.server_ep.handle_event(h, e);
                    self.server_peer.spin(
                        now,
                        &mut cb,
                        &mut server_h.context,
                        server_on_event,
                        &FxHashSet::default(),
                    );
                }

                client_h.drain_inbound();
                server_h.drain_inbound();

                if !progress {
                    break;
                }
            }
        }
    }

    fn wait_for<F: FnMut(&PeerHarness, &PeerHarness) -> bool>(
        pair: &mut PeerPair,
        client_h: &mut PeerHarness,
        server_h: &mut PeerHarness,
        max: usize,
        mut cond: F,
    ) {
        let now = Instant::now();
        for _ in 0..max {
            let mut noop_c = |_: NetEvent| {};
            let mut noop_s = |_: NetEvent| {};
            pair.step(now, client_h, server_h, &mut noop_c, &mut noop_s);
            if cond(client_h, server_h) {
                break;
            }
        }
    }

    /// Negotiation completion is observed indirectly by sending a tiny
    /// payload and waiting for it to arrive — only possible after the
    /// gossip-write state machine has crossed out of `NegotiateState`.
    #[test]
    fn outbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );
        client_h.send_gossip(stream_id, b"ping", &mut pair.client_peer);

        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| !s.received.is_empty());

        assert!(!server_h.received.is_empty(), "server never received data");
    }

    #[test]
    fn outbound_stream_data_transfer() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );

        let payload = b"hello from the client side".to_vec();
        client_h.send_gossip(stream_id, &payload, &mut pair.client_peer);

        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| !s.received.is_empty());

        let data: Vec<u8> = server_h.received.values().flat_map(|v| v.clone()).collect();
        assert_eq!(data, payload);
    }

    #[test]
    fn bidirectional_data_transfer() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let client_stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );

        let c2s = b"client to server".to_vec();
        client_h.send_gossip(client_stream_id, &c2s, &mut pair.client_peer);

        // Wait for server to see the inbound frame so it knows the stream id
        // (server-side P2pStreamId differs — its connection field is the
        // server's handle, not the client's).
        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| !s.received.is_empty());

        let server_stream_id =
            *server_h.received.keys().next().expect("server should have one stream");
        let s2c = b"server to client".to_vec();
        server_h.send_gossip(server_stream_id, &s2c, &mut pair.server_peer);

        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |c, _| !c.received.is_empty());

        let server_got: Vec<u8> = server_h.received.values().flat_map(|v| v.clone()).collect();
        let client_got: Vec<u8> = client_h.received.values().flat_map(|v| v.clone()).collect();
        assert_eq!(server_got, c2s);
        assert_eq!(client_got, s2c);
    }

    #[test]
    fn inbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        let sid = pair.server_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let server_stream_id = P2pStreamId::new(
            pair.server_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );
        server_h.send_gossip(server_stream_id, b"pong", &mut pair.server_peer);

        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |c, _| !c.received.is_empty());

        assert!(!client_h.received.is_empty(), "client never received server-initiated data");
    }

    /// Multiple buffered messages on a single gossip stream — the new
    /// `GossipQueues` design is one queue per peer, so this exercises the
    /// per-peer buffer's pop / send-complete cycle under back-to-back
    /// enqueues.
    #[test]
    fn multiple_streams() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );

        client_h.send_gossip(stream_id, b"stream one", &mut pair.client_peer);
        client_h.send_gossip(stream_id, b"stream two", &mut pair.client_peer);

        wait_for(&mut pair, &mut client_h, &mut server_h, 300, |_, s| {
            s.received.values().any(|v| v.windows(10).any(|w| w == b"stream two"))
        });

        let all: Vec<u8> = server_h.received.values().flat_map(|v| v.clone()).collect();
        assert!(all.windows(10).any(|w| w == b"stream one"));
        assert!(all.windows(10).any(|w| w == b"stream two"));
    }
}
