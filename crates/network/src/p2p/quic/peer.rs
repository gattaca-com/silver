use std::{collections::HashMap, time::Instant};

use bytes::Bytes;
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, Dir, EndpointEvent, StreamId, Transmit, VarInt,
};
use silver_common::{P2pStreamId, PeerId, StreamProtocol};

use crate::{
    RemotePeer,
    p2p::{
        PeerHandler,
        handlers::StreamHandler,
        stream::{Stream, StreamEvent},
        tls::peer_id_from_certificate,
    },
};

pub(crate) struct Peer<S: StreamHandler> {
    id: RemotePeer,
    handle: ConnectionHandle,
    connection: Connection,
    streams: HashMap<StreamId, Stream<S>>,
    /// Stream open requests that failed because the connection wasn't ready.
    pending_streams: Vec<StreamProtocol>,
}

impl<S: StreamHandler> Peer<S> {
    pub(crate) fn new(handle: ConnectionHandle, connection: Connection) -> Self {
        Self {
            id: RemotePeer { peer_id: PeerId::default(), connection: handle.0 },
            handle,
            connection,
            streams: HashMap::with_capacity(16),
            pending_streams: Vec::with_capacity(16),
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

    /// Open an outbound stream with the given protocol. Multistream-select
    /// negotiation runs internally — the handler receives on_stream_ready
    /// once complete.
    pub(crate) fn open_stream(
        &mut self,
        protocol: StreamProtocol,
        stream_handler: &mut S,
    ) -> Option<StreamId> {
        // All streams are Bi — multistream-select negotiation requires
        // bidirectional communication even for request-response protocols.
        let id = self.connection.streams().open(Dir::Bi)?;
        let mut stream =
            Stream::new_outbound(P2pStreamId::new(self.id.connection, id.into(), Some(protocol)));
        // Kick off the first write (multistream header + protocol).
        stream.drive(&mut self.connection, stream_handler);
        self.streams.insert(id, stream);
        Some(id)
    }

    /// Half-close the write side of a stream.
    #[allow(dead_code)] // TODO
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

    pub(crate) fn spin<F, P>(
        &mut self,
        now: Instant,
        ep_callback: &mut F,
        stream_handler: &mut S,
        peer_handler: &mut P,
    ) -> Option<Instant>
    where
        F: FnMut(ConnectionHandle, EndpointEvent) -> Option<ConnectionEvent>,
        P: PeerHandler,
    {
        // Retry any pending stream opens from previous cycles.
        let pending_len = self.pending_streams.len();
        for _ in 0..pending_len {
            let Some(protocol) = self.pending_streams.pop() else {
                break;
            };
            if self.open_stream(protocol, stream_handler).is_none() {
                self.pending_streams.push(protocol);
            }
        }

        // New outbound streams from handler.
        while let Some(protocol) = stream_handler.poll_new_stream(self.id.connection) {
            let opened = self.open_stream(protocol, stream_handler);
            if opened.is_none() {
                self.pending_streams.push(protocol);
            }
        }

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
                    peer_handler.new_peer(self.id.clone(), self.connection.remote_address());
                }
                quinn_proto::Event::ConnectionLost { reason } => {
                    tracing::info!(handle = ?self.handle, ?reason, "connection lost");
                }
                quinn_proto::Event::Stream(stream_event) => {
                    self.handle_stream_event(stream_event, stream_handler);
                }
                _ => {}
            }
        }

        while let Some(ep_event) = self.connection.poll_endpoint_events() {
            if let Some(conn_event) = (ep_callback)(self.handle, ep_event) {
                self.connection.handle_event(conn_event);
            }
        }

        // Drive all negotiating streams (they may have writes pending).
        self.drive_streams(stream_handler);

        next_timeout
    }

    fn handle_stream_event(&mut self, event: quinn_proto::StreamEvent, stream_handler: &mut S) {
        match event {
            quinn_proto::StreamEvent::Opened { dir } => {
                while let Some(id) = self.connection.streams().accept(dir) {
                    let mut stream =
                        Stream::new_inbound(P2pStreamId::new(self.id.connection, id.into(), None));
                    let ev = stream.drive(&mut self.connection, stream_handler);
                    self.streams.insert(id, stream);
                    self.process_stream_event(id, ev);
                }
            }
            quinn_proto::StreamEvent::Readable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    if stream.is_active() {
                        self.read_active(id, stream_handler);
                    } else {
                        let event = stream.drive_read(&mut self.connection, stream_handler);
                        self.process_stream_event(id, event);
                    }
                }
            }
            quinn_proto::StreamEvent::Writable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    let event = stream.drive_write(&mut self.connection, stream_handler);
                    self.process_stream_event(id, event);
                }
            }
            quinn_proto::StreamEvent::Finished { id } => {
                tracing::debug!(?id, "stream finished");
                self.streams.remove(&id);
                //self.outbound_queues.remove(&id);
            }
            quinn_proto::StreamEvent::Stopped { id, error_code } => {
                tracing::warn!(?id, ?error_code, "stream stopped");
                self.streams.remove(&id);
            }
            quinn_proto::StreamEvent::Available { dir } => {
                tracing::debug!(?dir, "stream available");
            }
        }
    }

    fn process_stream_event(&mut self, id: StreamId, event: StreamEvent) {
        match &event {
            StreamEvent::Ready(proto) => {
                tracing::info!(peer=?self.id, ?id, ?proto, "stream negotiated");
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.apply(&StreamEvent::Ready(*proto));
                }
                //handler.new_stream(&self.id, &id);
            }
            StreamEvent::Data(_decoded) => {
                //handler.recv(&self.id, &id, &decode_buf[..*decoded]);
            }
            StreamEvent::Sent(written) => {
                tracing::debug!(peer=?self.id, ?id, %written, "wrote data to stream");
            }
            StreamEvent::Failed => {
                tracing::warn!(peer=?self.id, ?id, "stream negotiation failed");
                self.streams.remove(&id);
            }
            StreamEvent::Pending => {}
        }
    }

    /// Read application data from an active stream and forward to handler.
    fn read_active(&mut self, id: StreamId, handler: &mut S) {
        let Some(stream) = self.streams.get_mut(&id) else { return };
        loop {
            let event = stream.drive_read(&mut self.connection, handler);
            match event {
                StreamEvent::Data(_decoded) => {
                    //handler.recv(&self.id, &id, &decode_buf[..decoded]);
                }
                StreamEvent::Failed => {
                    tracing::warn!(peer=?self.id, ?id, "stream actively failed during reading");
                    self.streams.remove(&id);
                    break;
                }
                _ => break, // Pending or empty Ready
            }
        }
    }

    /// Drive all streams that may have pending work (e.g. outbound negotiate
    /// writes).
    fn drive_streams(&mut self, handler: &mut S) {
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(stream) = self.streams.get_mut(&id) {
                let event = stream.drive(&mut self.connection, handler);
                self.process_stream_event(id, event);
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
    use std::{collections::HashSet, net::SocketAddr, sync::Arc, time::Instant};

    use quinn_proto::{DatagramEvent, Endpoint, EndpointConfig};
    use silver_common::Keypair;

    use super::*;
    use crate::RemotePeer;

    #[derive(Default)]
    struct PeerRecorder {
        connections: Vec<RemotePeer>,
    }

    impl PeerHandler for PeerRecorder {
        fn new_peer(&mut self, remote_peer: RemotePeer, _remote_addr: SocketAddr) {
            self.connections.push(remote_peer);
        }

        fn poll_new_peer(&mut self) -> Option<(PeerId, SocketAddr)> {
            None
        }
    }

    /// Records all stream handler callbacks.
    struct Recorder {
        /// Streams that have been polled via poll_new_send (i.e. active).
        active_streams: HashSet<P2pStreamId>,
        received: Vec<(P2pStreamId, Vec<u8>)>,
        /// Pending sends — removed after poll_new_send returns them.
        to_send: HashMap<P2pStreamId, Vec<u8>>,
        /// In-flight sends (moved from to_send).
        sending: HashMap<P2pStreamId, Vec<u8>>,
    }

    impl Default for Recorder {
        fn default() -> Self {
            Self {
                active_streams: HashSet::new(),
                received: Vec::new(),
                to_send: HashMap::new(),
                sending: HashMap::new(),
            }
        }
    }

    impl StreamHandler for Recorder {
        type BufferId = P2pStreamId;

        fn poll_new_stream(&mut self, _peer: usize) -> Option<StreamProtocol> {
            None
        }

        fn poll_new_send(&mut self, stream: &P2pStreamId) -> Option<(Self::BufferId, usize)> {
            self.active_streams.insert(*stream);
            if let Some(data) = self.to_send.remove(stream) {
                let len = data.len();
                self.sending.insert(*stream, data);
                return Some((*stream, len));
            }
            None
        }

        fn poll_send(&mut self, buffer_id: &Self::BufferId, offset: usize) -> Option<&[u8]> {
            self.sending.get(buffer_id).map(|v| &v[offset..])
        }

        fn recv_new(
            &mut self,
            _length: usize,
            stream: P2pStreamId,
        ) -> Result<Self::BufferId, std::io::Error> {
            Ok(stream)
        }

        fn recv(
            &mut self,
            buffer_id: &Self::BufferId,
            data: &[u8],
        ) -> Result<usize, std::io::Error> {
            self.received.push((*buffer_id, data.to_vec()));
            Ok(data.len())
        }
        
        fn recv_buffer(&mut self, _buffer_id: &Self::BufferId) -> Result<&mut [u8], std::io::Error> {
            Ok(&mut [])
        }
        
        fn recv_buffer_written(&mut self, _buffer_id: &Self::BufferId, _written: usize) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    /// Test harness: two endpoints + peers connected via in-memory datagram
    /// shuttle.
    struct PeerPair {
        client_ep: Endpoint,
        server_ep: Endpoint,
        client_peer: Peer<Recorder>,
        server_peer: Peer<Recorder>,
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

            // Shuttle the initial client transmit to bootstrap the server-side connection.
            let mut buf = Vec::new();
            let mut scratch = vec![0u8; 2048];
            let mut server_peer: Option<Peer<Recorder>> = None;

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
            let mut client_peer_rec = PeerRecorder::default();
            let mut server_peer_rec = PeerRecorder::default();
            let mut client_rec = Recorder::default();
            let mut server_rec = Recorder::default();
            for _ in 0..100 {
                pair.step(
                    now,
                    &mut client_rec,
                    &mut server_rec,
                    &mut client_peer_rec,
                    &mut server_peer_rec,
                );
                if !client_peer_rec.connections.is_empty() &&
                    !server_peer_rec.connections.is_empty()
                {
                    break;
                }
            }
            assert!(!client_peer_rec.connections.is_empty(), "client never connected");
            assert!(!server_peer_rec.connections.is_empty(), "server never connected");

            pair
        }

        /// Shuttle datagrams and spin both peers until quiescent.
        fn step(
            &mut self,
            now: Instant,
            client_rec: &mut Recorder,
            server_rec: &mut Recorder,
            client_peer_rec: &mut PeerRecorder,
            server_peer_rec: &mut PeerRecorder,
        ) {
            let mut buf = Vec::new();
            let mut scratch = vec![0u8; 2048];

            for _ in 0..20 {
                let mut progress = false;

                // Client → Server.
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

                // Server → Client.
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

                // Spin both.
                {
                    let mut cb = |h, e| self.client_ep.handle_event(h, e);
                    self.client_peer.spin(now, &mut cb, client_rec, client_peer_rec);
                }
                {
                    let mut cb = |h, e| self.server_ep.handle_event(h, e);
                    self.server_peer.spin(now, &mut cb, server_rec, server_peer_rec);
                }

                if !progress {
                    break;
                }
            }
        }
    }

    #[test]
    fn outbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();
        let mut client_peer_rec = PeerRecorder::default();
        let mut server_peer_rec = PeerRecorder::default();

        // Client opens a gossipsub (bi) stream.
        let _stream_id =
            pair.client_peer.open_stream(StreamProtocol::GossipSub, &mut client_rec).unwrap();

        // Pump until both sides see the negotiated stream.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !client_rec.active_streams.is_empty() && !server_rec.active_streams.is_empty() {
                break;
            }
        }

        assert!(!client_rec.active_streams.is_empty(), "client never got stream ready");
        assert!(!server_rec.active_streams.is_empty(), "server never got stream ready");
    }

    #[test]
    fn outbound_stream_data_transfer() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();
        let mut client_peer_rec = PeerRecorder::default();
        let mut server_peer_rec = PeerRecorder::default();

        let stream_id =
            pair.client_peer.open_stream(StreamProtocol::GossipSub, &mut client_rec).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            stream_id.into(),
            Some(StreamProtocol::GossipSub),
        );

        // Negotiate.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !client_rec.active_streams.is_empty() && !server_rec.active_streams.is_empty() {
                break;
            }
        }
        assert!(!client_rec.active_streams.is_empty());
        assert!(!server_rec.active_streams.is_empty());

        // Client sends data. (length prefix 26 = 0x1a)
        let payload = b"\x1ahello from the client side";
        client_rec.to_send.insert(stream_id, payload.to_vec());
        // let wrote = pair.client_peer.write(stream_id, payload).unwrap();
        // assert_eq!(wrote, payload.len());

        // Pump until server receives.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !server_rec.received.is_empty() {
                break;
            }
        }

        assert!(!server_rec.received.is_empty(), "server never received data");
        let all_data: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(all_data, payload);
    }

    #[test]
    fn bidirectional_data_transfer() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();
        let mut client_peer_rec = PeerRecorder::default();
        let mut server_peer_rec = PeerRecorder::default();

        // Client opens bi stream (gossipsub).
        let client_stream_id =
            pair.client_peer.open_stream(StreamProtocol::GossipSub, &mut client_rec).unwrap();
        let client_stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            client_stream_id.into(),
            Some(StreamProtocol::GossipSub),
        );

        // Negotiate.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !client_rec.active_streams.is_empty() && !server_rec.active_streams.is_empty() {
                break;
            }
        }
        assert!(!server_rec.active_streams.is_empty());

        // The server-side stream id for the same stream.
        let server_stream_id = *server_rec.active_streams.iter().next().unwrap();

        // Client → Server. (length 16)
        let c2s = b"\x10client to server";
        client_rec.to_send.insert(client_stream_id, c2s.to_vec());
        //pair.client_peer.write(client_stream_id, c2s).unwrap();

        // Server → Client.
        let s2c = b"\x10server to client";
        server_rec.to_send.insert(server_stream_id, s2c.to_vec());
        //pair.server_peer.write(server_stream_id, s2c).unwrap();

        // Pump both directions.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !server_rec.received.is_empty() && !client_rec.received.is_empty() {
                break;
            }
        }

        let server_got: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        let client_got: Vec<u8> = client_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(server_got, c2s);
        assert_eq!(client_got, s2c);
    }

    #[test]
    fn inbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();
        let mut client_peer_rec = PeerRecorder::default();
        let mut server_peer_rec = PeerRecorder::default();

        // Server opens a stream toward the client.
        let _stream_id =
            pair.server_peer.open_stream(StreamProtocol::GossipSub, &mut server_rec).unwrap();

        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !server_rec.active_streams.is_empty() && !client_rec.active_streams.is_empty() {
                break;
            }
        }

        assert!(!server_rec.active_streams.is_empty(), "server never got stream ready");
        assert!(!client_rec.active_streams.is_empty(), "client never got stream ready");
    }

    #[test]
    fn stream_finish() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();
        let mut client_peer_rec = PeerRecorder::default();
        let mut server_peer_rec = PeerRecorder::default();

        let stream_id =
            pair.client_peer.open_stream(StreamProtocol::GossipSub, &mut client_rec).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            stream_id.into(),
            Some(StreamProtocol::GossipSub),
        );

        // Negotiate.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !client_rec.active_streams.is_empty() && !server_rec.active_streams.is_empty() {
                break;
            }
        }

        // Send data then finish. (length 12)
        let payload = b"\x0clast message";
        client_rec.to_send.insert(stream_id, payload.to_vec());

        // Pump until server receives.
        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if !server_rec.received.is_empty() {
                break;
            }
        }

        pair.client_peer.finish_stream((&stream_id).into());

        let data: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(data, payload);
    }

    #[test]
    fn multiple_streams() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();
        let mut client_peer_rec = PeerRecorder::default();
        let mut server_peer_rec = PeerRecorder::default();

        // Open two gossipsub streams.
        let s1 = pair.client_peer.open_stream(StreamProtocol::GossipSub, &mut client_rec).unwrap();
        let s1 = P2pStreamId::new(
            pair.client_peer.id.connection,
            s1.into(),
            Some(StreamProtocol::GossipSub),
        );

        let s2 = pair.client_peer.open_stream(StreamProtocol::GossipSub, &mut client_rec).unwrap();
        let s2 = P2pStreamId::new(
            pair.client_peer.id.connection,
            s2.into(),
            Some(StreamProtocol::GossipSub),
        );

        // Negotiate both.
        for _ in 0..200 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if client_rec.active_streams.len() >= 2 && server_rec.active_streams.len() >= 2 {
                break;
            }
        }

        assert!(
            client_rec.active_streams.len() >= 2,
            "client streams: {}",
            client_rec.active_streams.len()
        );
        assert!(
            server_rec.active_streams.len() >= 2,
            "server streams: {}",
            server_rec.active_streams.len()
        );

        // Send different data on each stream.
        client_rec.to_send.insert(s1, b"\x0astream one".to_vec());
        client_rec.to_send.insert(s2, b"\x0astream two".to_vec());

        for _ in 0..100 {
            pair.step(
                now,
                &mut client_rec,
                &mut server_rec,
                &mut client_peer_rec,
                &mut server_peer_rec,
            );
            if server_rec.received.len() >= 2 {
                break;
            }
        }

        assert!(server_rec.received.len() >= 2, "received: {}", server_rec.received.len());
        let all: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert!(all.windows(10).any(|w| w == b"stream one"));
        assert!(all.windows(10).any(|w| w == b"stream two"));
    }
}
