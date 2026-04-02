use std::{collections::HashMap, time::Instant};

use bytes::Bytes;
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, Dir, EndpointEvent, StreamId, Transmit, VarInt,
};
use silver_common::{P2pStreamId, PeerId, StreamProtocol};

use crate::{
    RemotePeer,
    p2p::{
        NetEvent,
        stream::{Stream, StreamEvent},
        tls::peer_id_from_certificate,
    },
};

pub(crate) struct Peer {
    id: RemotePeer,
    handle: ConnectionHandle,
    connection: Connection,
    streams: HashMap<StreamId, Stream>,
}

impl Peer {
    pub(crate) fn new(handle: ConnectionHandle, connection: Connection) -> Self {
        Self {
            id: RemotePeer { peer_id: PeerId::default(), connection: handle.0 },
            handle,
            connection,
            streams: HashMap::with_capacity(16),
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

    /// Open an outbound stream with the given protocol. Returns `None` if
    /// the connection isn't ready (e.g. stream limit not yet negotiated).
    /// Multistream-select negotiation runs internally; `NetEvent::StreamReady`
    /// is emitted once it completes.
    pub(crate) fn open_stream(&mut self, protocol: StreamProtocol) -> Option<StreamId> {
        // All streams are Bi — multistream-select requires bidirectional I/O
        // even for request-response protocols.
        let id = self.connection.streams().open(Dir::Bi)?;
        let stream =
            Stream::new_outbound(P2pStreamId::new(self.id.connection, id.into(), protocol));
        self.streams.insert(id, stream);
        Some(id)
    }

    /// Half-close the write side of a stream.
    #[allow(dead_code)]
    pub(crate) fn finish_stream(&mut self, id: StreamId) {
        let _ = self.connection.send_stream(id).finish();
    }

    pub(crate) fn transmit(
        &mut self,
        now: Instant,
        max_datagrams: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        self.connection.poll_transmit(now, max_datagrams, buf)
    }

    pub(crate) fn spin<F, S, E>(
        &mut self,
        now: Instant,
        ep_callback: &mut F,
        data: &mut S,
        on_event: &mut E,
    ) -> Option<Instant>
    where
        F: FnMut(ConnectionHandle, EndpointEvent) -> Option<ConnectionEvent>,
        S: crate::StreamData,
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
                    let Some(peer_id) = id_from_connection(&self.connection) else {
                        self.connection.close(
                            now,
                            VarInt::from_u32(400),
                            Bytes::from_static(b"bad peer id"),
                        );
                        continue;
                    };
                    self.id.peer_id = peer_id;
                    tracing::info!(handle = ?self.handle, "connected");
                    on_event(NetEvent::PeerConnected {
                        peer: self.id.clone(),
                        addr: self.connection.remote_address(),
                    });
                }
                quinn_proto::Event::ConnectionLost { reason } => {
                    tracing::info!(handle = ?self.handle, ?reason, "connection lost");
                }
                quinn_proto::Event::Stream(stream_event) => {
                    self.handle_stream_event(stream_event, data, on_event);
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
        self.drive_streams(data, on_event);

        next_timeout
    }

    fn handle_stream_event<S, E>(
        &mut self,
        event: quinn_proto::StreamEvent,
        data: &mut S,
        on_event: &mut E,
    ) where
        S: crate::StreamData,
        E: FnMut(crate::NetEvent),
    {
        match event {
            quinn_proto::StreamEvent::Opened { dir } => {
                while let Some(id) = self.connection.streams().accept(dir) {
                    let mut stream = Stream::new_inbound(P2pStreamId::new(
                        self.id.connection,
                        id.into(),
                        StreamProtocol::Unset,
                    ));
                    let ev = stream.drive(&mut self.connection, data);
                    self.streams.insert(id, stream);
                    self.process_stream_event(id, ev, data, on_event);
                }
            }
            quinn_proto::StreamEvent::Readable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    if stream.is_active() {
                        self.read_active(id, data, on_event);
                    } else {
                        let event = stream.drive_read(&mut self.connection, data);
                        self.process_stream_event(id, event, data, on_event);
                    }
                }
            }
            quinn_proto::StreamEvent::Writable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    let event = stream.drive_write(&mut self.connection, data);
                    self.process_stream_event(id, event, data, on_event);
                }
            }
            quinn_proto::StreamEvent::Finished { id } => {
                tracing::debug!(?id, "stream finished");
                if let Some(stream) = self.streams.remove(&id) {
                    data.stream_closed(stream.p2p_id());
                    on_event(NetEvent::StreamClosed { stream: *stream.p2p_id() });
                    let _ = stream;
                }
            }
            quinn_proto::StreamEvent::Stopped { id, error_code } => {
                tracing::warn!(?id, ?error_code, "stream stopped");
                if let Some(stream) = self.streams.remove(&id) {
                    let p2p_id = *stream.p2p_id();
                    data.stream_closed(&p2p_id);
                    on_event(NetEvent::StreamClosed { stream: p2p_id });
                }
            }
            quinn_proto::StreamEvent::Available { dir: _ } => {}
        }
    }

    fn process_stream_event<S, E>(
        &mut self,
        id: StreamId,
        event: StreamEvent,
        data: &mut S,
        on_event: &mut E,
    ) where
        S: crate::StreamData,
        E: FnMut(crate::NetEvent),
    {
        match &event {
            StreamEvent::Ready(proto) => {
                tracing::info!(peer=?self.id, ?id, ?proto, "stream negotiated");
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.apply(&StreamEvent::Ready(*proto));
                }
                let p2p_id = P2pStreamId::new(self.id.connection, id.into(), *proto);
                data.new_stream(&self.id, &p2p_id);
                on_event(NetEvent::StreamReady { stream: p2p_id });
            }
            StreamEvent::Sent(written) => {
                tracing::debug!(peer=?self.id, ?id, %written, "wrote data to stream");
            }
            StreamEvent::Failed => {
                tracing::warn!(peer=?self.id, ?id, "stream failed");
                let _ = self.connection.recv_stream(id).stop(VarInt::from_u32(1));
                let _ = self.connection.send_stream(id).finish();
                if let Some(p2p) = self.streams.remove(&id) {
                    data.stream_closed(p2p.p2p_id());
                    on_event(NetEvent::StreamClosed { stream: *p2p.p2p_id() });
                }
            }
            StreamEvent::Pending => {}
        }
    }

    /// Read application data from an active stream and forward to data.
    fn read_active<S, E>(&mut self, id: StreamId, data: &mut S, on_event: &mut E)
    where
        S: crate::StreamData,
        E: FnMut(crate::NetEvent),
    {
        let Some(stream) = self.streams.get_mut(&id) else { return };

        if let StreamEvent::Failed = stream.drive_read(&mut self.connection, data) {
            tracing::warn!(peer=?self.id, ?id, "stream actively failed during reading");
            let p2p_id = *stream.p2p_id();
            self.streams.remove(&id);
            let _ = self.connection.recv_stream(id).stop(VarInt::from_u32(1));
            data.stream_closed(&p2p_id);
            on_event(NetEvent::StreamClosed { stream: p2p_id });
        }
    }

    /// Drive all streams — progresses negotiation writes and application
    /// writes where possible.
    fn drive_streams<S, E>(&mut self, data: &mut S, on_event: &mut E)
    where
        S: crate::StreamData,
        E: FnMut(crate::NetEvent),
    {
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(stream) = self.streams.get_mut(&id) {
                let event = stream.drive(&mut self.connection, data);
                self.process_stream_event(id, event, data, on_event);
            }
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

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, io::Error, net::SocketAddr, sync::Arc, time::Instant};

    use quinn_proto::{DatagramEvent, Endpoint, EndpointConfig};
    use silver_common::Keypair;

    use super::*;
    use crate::StreamData;

    /// Records stream data callbacks for integration tests.
    struct Recorder {
        /// Streams that have been polled via poll_new_send (i.e. active).
        active_streams: HashSet<P2pStreamId>,
        /// Received messages by stream.
        received: HashMap<P2pStreamId, Vec<u8>>,
        /// Receive buffer in progress per stream.
        recv_buf: HashMap<P2pStreamId, Vec<u8>>,
        recv_offset: HashMap<P2pStreamId, usize>,
        /// Pending sends — removed when poll_new_send returns.
        to_send: HashMap<P2pStreamId, Vec<u8>>,
        /// In-flight sends (moved from to_send).
        sending: HashMap<P2pStreamId, Vec<u8>>,
    }

    impl Default for Recorder {
        fn default() -> Self {
            Self {
                active_streams: HashSet::new(),
                received: HashMap::new(),
                recv_buf: HashMap::new(),
                recv_offset: HashMap::new(),
                to_send: HashMap::new(),
                sending: HashMap::new(),
            }
        }
    }

    impl StreamData for Recorder {
        fn new_stream(&mut self, _peer: &RemotePeer, _stream: &P2pStreamId) {}
        fn stream_closed(&mut self, _stream: &P2pStreamId) {}

        fn poll_send(&mut self, stream: &P2pStreamId) -> Option<usize> {
            self.active_streams.insert(*stream);
            let data = self.to_send.remove(stream)?;
            let len = data.len();
            self.sending.insert(*stream, data);
            Some(len)
        }

        fn send_data(&mut self, stream: &P2pStreamId, offset: usize) -> Option<&[u8]> {
            self.sending.get(stream).map(|v| &v[offset..])
        }

        fn send_complete(&mut self, stream: &P2pStreamId) {
            self.sending.remove(stream);
        }

        fn alloc_recv(&mut self, stream: &P2pStreamId, length: usize) -> Result<(), Error> {
            self.recv_buf.insert(*stream, vec![0u8; length]);
            self.recv_offset.insert(*stream, 0);
            Ok(())
        }

        fn recv_buf(&mut self, stream: &P2pStreamId) -> Result<&mut [u8], Error> {
            let offset =
                *self.recv_offset.get(stream).ok_or_else(|| Error::other("no alloc_recv"))?;
            let buf =
                self.recv_buf.get_mut(stream).ok_or_else(|| Error::other("no recv buffer"))?;
            Ok(&mut buf[offset..])
        }

        fn recv_advance(&mut self, stream: &P2pStreamId, written: usize) -> Result<(), Error> {
            let offset =
                self.recv_offset.get_mut(stream).ok_or_else(|| Error::other("no recv offset"))?;
            *offset += written;
            let buf = self.recv_buf.get(stream).ok_or_else(|| Error::other("no recv buffer"))?;
            if *offset >= buf.len() {
                // Message complete — append to received.
                let msg = self.recv_buf.remove(stream).unwrap();
                self.recv_offset.remove(stream);
                self.received.entry(*stream).or_default().extend(msg);
            }
            Ok(())
        }
    }

    /// Test harness: two endpoints + peers connected via in-memory datagram
    /// shuttle.
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
            let mut client_rec = Recorder::default();
            let mut server_rec = Recorder::default();
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
                    pair.step(now, &mut client_rec, &mut server_rec, &mut ccb, &mut scb);
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
            client_rec: &mut Recorder,
            server_rec: &mut Recorder,
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
                    self.client_peer.spin(now, &mut cb, client_rec, client_on_event);
                }
                {
                    let mut cb = |h, e| self.server_ep.handle_event(h, e);
                    self.server_peer.spin(now, &mut cb, server_rec, server_on_event);
                }

                if !progress {
                    break;
                }
            }
        }
    }

    fn wait_for<F: FnMut(&Recorder, &Recorder) -> bool>(
        pair: &mut PeerPair,
        client_rec: &mut Recorder,
        server_rec: &mut Recorder,
        max: usize,
        mut cond: F,
    ) {
        let now = Instant::now();
        for _ in 0..max {
            let mut noop_c = |_: NetEvent| {};
            let mut noop_s = |_: NetEvent| {};
            pair.step(now, client_rec, server_rec, &mut noop_c, &mut noop_s);
            if cond(client_rec, server_rec) {
                break;
            }
        }
    }

    #[test]
    fn outbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let _ = pair.client_peer.open_stream(StreamProtocol::GossipSub);

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |c, s| {
            !c.active_streams.is_empty() && !s.active_streams.is_empty()
        });

        assert!(!client_rec.active_streams.is_empty(), "client never got stream ready");
        assert!(!server_rec.active_streams.is_empty(), "server never got stream ready");
    }

    #[test]
    fn outbound_stream_data_transfer() {
        let mut pair = PeerPair::new();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id =
            P2pStreamId::new(pair.client_peer.id.connection, sid.into(), StreamProtocol::GossipSub);

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |c, s| {
            !c.active_streams.is_empty() && !s.active_streams.is_empty()
        });

        // Queue send. Gossipsub adds varint prefix.
        let payload = b"hello from the client side".to_vec();
        client_rec.to_send.insert(stream_id, payload.clone());

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |_c, s| !s.received.is_empty());

        assert!(!server_rec.received.is_empty(), "server never received data");
        let data: Vec<u8> = server_rec.received.values().flat_map(|v| v.clone()).collect();
        assert_eq!(data, payload);
    }

    #[test]
    fn bidirectional_data_transfer() {
        let mut pair = PeerPair::new();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let client_stream_id =
            P2pStreamId::new(pair.client_peer.id.connection, sid.into(), StreamProtocol::GossipSub);

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |c, s| {
            !c.active_streams.is_empty() && !s.active_streams.is_empty()
        });

        let server_stream_id = *server_rec.active_streams.iter().next().unwrap();

        let c2s = b"client to server".to_vec();
        let s2c = b"server to client".to_vec();
        client_rec.to_send.insert(client_stream_id, c2s.clone());
        server_rec.to_send.insert(server_stream_id, s2c.clone());

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |c, s| {
            !c.received.is_empty() && !s.received.is_empty()
        });

        let server_got: Vec<u8> = server_rec.received.values().flat_map(|v| v.clone()).collect();
        let client_got: Vec<u8> = client_rec.received.values().flat_map(|v| v.clone()).collect();
        assert_eq!(server_got, c2s);
        assert_eq!(client_got, s2c);
    }

    #[test]
    fn inbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let _ = pair.server_peer.open_stream(StreamProtocol::GossipSub);

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |c, s| {
            !c.active_streams.is_empty() && !s.active_streams.is_empty()
        });

        assert!(!server_rec.active_streams.is_empty(), "server never got stream ready");
        assert!(!client_rec.active_streams.is_empty(), "client never got stream ready");
    }

    #[test]
    fn multiple_streams() {
        let mut pair = PeerPair::new();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let s1 = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let s1 =
            P2pStreamId::new(pair.client_peer.id.connection, s1.into(), StreamProtocol::GossipSub);
        let s2 = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let s2 =
            P2pStreamId::new(pair.client_peer.id.connection, s2.into(), StreamProtocol::GossipSub);

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 200, |c, s| {
            c.active_streams.len() >= 2 && s.active_streams.len() >= 2
        });

        assert!(client_rec.active_streams.len() >= 2);
        assert!(server_rec.active_streams.len() >= 2);

        client_rec.to_send.insert(s1, b"stream one".to_vec());
        client_rec.to_send.insert(s2, b"stream two".to_vec());

        wait_for(&mut pair, &mut client_rec, &mut server_rec, 100, |_c, s| s.received.len() >= 2);

        assert!(server_rec.received.len() >= 2, "received: {}", server_rec.received.len());
        let all: Vec<u8> = server_rec.received.values().flat_map(|v| v.clone()).collect();
        assert!(all.windows(10).any(|w| w == b"stream one"));
        assert!(all.windows(10).any(|w| w == b"stream two"));
    }
}
