use std::{collections::HashMap, io::Error, time::Instant};

use bytes::Bytes;
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, Dir, EndpointEvent, StreamId, Transmit, VarInt,
};
use silver_common::PeerId;

use crate::{
    NetworkRecv, RemotePeer,
    p2p::{
        stream::{Stream, StreamEvent, StreamProtocol},
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

    /// Open an outbound stream with the given protocol. Multistream-select
    /// negotiation runs internally — the handler receives on_stream_ready
    /// once complete.
    pub(crate) fn open_stream(&mut self, protocol: StreamProtocol) -> Option<StreamId> {
        // All streams are Bi — multistream-select negotiation requires
        // bidirectional communication even for request-response protocols.
        let id = self.connection.streams().open(Dir::Bi)?;
        let mut stream = Stream::new_outbound(id, protocol);
        // Kick off the first write (multistream header + protocol).
        stream.drive(&mut self.connection);
        self.streams.insert(id, stream);
        Some(id)
    }

    /// Write application data to a negotiated stream.
    /// Returns 0 if the stream is still negotiating.
    pub(crate) fn write(&mut self, stream_id: StreamId, data: &[u8]) -> Result<usize, Error> {
        let active = self.streams.get(&stream_id).is_some_and(|s| s.is_active());
        if !active {
            return Ok(0);
        }
        match self.connection.send_stream(stream_id).write(data) {
            Ok(wrote) => Ok(wrote),
            Err(quinn_proto::WriteError::Blocked) => Ok(0),
            Err(e) => Err(Error::other(e)),
        }
    }

    /// Half-close the write side of a stream.
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

    pub(crate) fn spin<F>(
        &mut self,
        now: Instant,
        ep_callback: &mut F,
        handler: &mut impl NetworkRecv,
        decode_buf: &mut [u8],
    ) -> Option<Instant>
    where
        F: FnMut(ConnectionHandle, EndpointEvent) -> Option<ConnectionEvent>,
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
                    handler.new_connection(self.id.clone(), self.connection.remote_address());
                }
                quinn_proto::Event::ConnectionLost { reason } => {
                    tracing::info!(handle = ?self.handle, ?reason, "connection lost");
                }
                quinn_proto::Event::Stream(stream_event) => {
                    self.handle_stream_event(stream_event, handler, decode_buf);
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
        self.drive_streams(handler, decode_buf);

        next_timeout
    }

    fn handle_stream_event(
        &mut self,
        event: quinn_proto::StreamEvent,
        handler: &mut impl NetworkRecv,
        decode_buf: &mut [u8],
    ) {
        match event {
            quinn_proto::StreamEvent::Opened { dir } => {
                while let Some(id) = self.connection.streams().accept(dir) {
                    let mut stream = Stream::new_inbound(id);
                    let ev = stream.drive(&mut self.connection);
                    self.streams.insert(id, stream);
                    self.process_stream_event(id, ev, handler, decode_buf);
                }
            }
            quinn_proto::StreamEvent::Readable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    if stream.is_active() {
                        self.read_active(id, handler, decode_buf);
                    } else {
                        let event = stream.drive_read(&mut self.connection, decode_buf);
                        self.process_stream_event(id, event, handler, decode_buf);
                    }
                }
            }
            quinn_proto::StreamEvent::Writable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    let mut dummy_queue = std::collections::VecDeque::new();
                    let event = stream.drive_write(&mut self.connection, &mut dummy_queue);
                    self.process_stream_event(id, event, handler, decode_buf);
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

    fn process_stream_event(
        &mut self,
        id: StreamId,
        event: StreamEvent,
        handler: &mut impl NetworkRecv,
        decode_buf: &mut [u8],
    ) {
        match &event {
            StreamEvent::Ready(proto) => {
                tracing::info!(peer=?self.id, ?id, ?proto, "stream negotiated");
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.apply(&StreamEvent::Ready(*proto));
                }
                handler.new_stream(&self.id, &id);
            }
            StreamEvent::Data(decoded) => {
                handler.recv(&self.id, &id, &decode_buf[..*decoded]);
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
    fn read_active(&mut self, id: StreamId, handler: &mut impl NetworkRecv, decode_buf: &mut [u8]) {
        loop {
            let Some(stream) = self.streams.get_mut(&id) else { return };
            let event = stream.drive_read(&mut self.connection, decode_buf);
            match event {
                StreamEvent::Data(decoded) => {
                    handler.recv(&self.id, &id, &decode_buf[..decoded]);
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
    fn drive_streams(&mut self, handler: &mut impl NetworkRecv, decode_buf: &mut [u8]) {
        let ids: Vec<StreamId> = self.streams.keys().copied().collect();
        for id in ids {
            if let Some(stream) = self.streams.get_mut(&id) {
                let event = stream.drive(&mut self.connection);
                self.process_stream_event(id, event, handler, decode_buf);
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
    use std::{net::SocketAddr, sync::Arc, time::Instant};

    use quinn_proto::{ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, StreamId};
    use silver_common::Keypair;

    use super::*;
    use crate::{NetworkRecv, RemotePeer, p2p::stream::StreamProtocol};

    /// Records all callbacks from NetworkRecv.
    #[derive(Default)]
    struct Recorder {
        connections: Vec<RemotePeer>,
        streams: Vec<(RemotePeer, StreamId)>,
        received: Vec<(StreamId, Vec<u8>)>,
    }

    impl NetworkRecv for Recorder {
        fn new_connection(&mut self, remote_peer: RemotePeer, _remote_addr: SocketAddr) {
            self.connections.push(remote_peer);
        }

        fn new_stream(&mut self, peer: &RemotePeer, stream_id: &StreamId) {
            self.streams.push((peer.clone(), *stream_id));
        }

        fn recv(&mut self, _peer: &RemotePeer, stream_id: &StreamId, data: &[u8]) {
            self.received.push((*stream_id, data.to_vec()));
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
        decode_buf: Vec<u8>,
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
                decode_buf: vec![0u8; 1024 * 1024],
            };

            // Pump until both sides are connected.
            let mut client_rec = Recorder::default();
            let mut server_rec = Recorder::default();
            for _ in 0..100 {
                pair.step(now, &mut client_rec, &mut server_rec);
                if !client_rec.connections.is_empty() && !server_rec.connections.is_empty() {
                    break;
                }
            }
            assert!(!client_rec.connections.is_empty(), "client never connected");
            assert!(!server_rec.connections.is_empty(), "server never connected");

            pair
        }

        /// Shuttle datagrams and spin both peers until quiescent.
        fn step(&mut self, now: Instant, client_rec: &mut Recorder, server_rec: &mut Recorder) {
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
                    self.client_peer.spin(now, &mut cb, client_rec, &mut self.decode_buf);
                }
                {
                    let mut cb = |h, e| self.server_ep.handle_event(h, e);
                    self.server_peer.spin(now, &mut cb, server_rec, &mut self.decode_buf);
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

        // Client opens a gossipsub (bi) stream.
        let stream_id = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();

        // Pump until both sides see the negotiated stream.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !client_rec.streams.is_empty() && !server_rec.streams.is_empty() {
                break;
            }
        }

        assert!(!client_rec.streams.is_empty(), "client never got stream ready");
        assert!(!server_rec.streams.is_empty(), "server never got stream ready");
    }

    #[test]
    fn outbound_stream_data_transfer() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let stream_id = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();

        // Negotiate.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !client_rec.streams.is_empty() && !server_rec.streams.is_empty() {
                break;
            }
        }
        assert!(!client_rec.streams.is_empty());
        assert!(!server_rec.streams.is_empty());

        // Client sends data. (length prefix 26 = 0x1a)
        let payload = b"\x1ahello from the client side";
        let wrote = pair.client_peer.write(stream_id, payload).unwrap();
        assert_eq!(wrote, payload.len());

        // Pump until server receives.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !server_rec.received.is_empty() {
                break;
            }
        }

        assert!(!server_rec.received.is_empty(), "server never received data");
        let all_data: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(all_data, payload[1..]); // match without the uvarint since decoder strips it
    }

    #[test]
    fn bidirectional_data_transfer() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        // Client opens bi stream (gossipsub).
        let client_stream_id = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();

        // Negotiate.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !client_rec.streams.is_empty() && !server_rec.streams.is_empty() {
                break;
            }
        }
        assert!(!server_rec.streams.is_empty());

        // The server-side stream id for the same stream.
        let server_stream_id = server_rec.streams[0].1;

        // Client → Server. (length 16)
        let c2s = b"\x10client to server";
        pair.client_peer.write(client_stream_id, c2s).unwrap();

        // Server → Client.
        let s2c = b"\x10server to client";
        pair.server_peer.write(server_stream_id, s2c).unwrap();

        // Pump both directions.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !server_rec.received.is_empty() && !client_rec.received.is_empty() {
                break;
            }
        }

        let server_got: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        let client_got: Vec<u8> = client_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(server_got, c2s[1..]);
        assert_eq!(client_got, s2c[1..]);
    }

    #[test]
    fn inbound_stream_negotiation() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        // Server opens a stream toward the client.
        let stream_id = pair.server_peer.open_stream(StreamProtocol::Ping).unwrap();

        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !server_rec.streams.is_empty() && !client_rec.streams.is_empty() {
                break;
            }
        }

        assert!(!server_rec.streams.is_empty(), "server never got stream ready");
        assert!(!client_rec.streams.is_empty(), "client never got stream ready");
    }

    #[test]
    fn stream_finish() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        let stream_id = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();

        // Negotiate.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !client_rec.streams.is_empty() && !server_rec.streams.is_empty() {
                break;
            }
        }

        // Send data then finish. (length 12)
        let payload = b"\x0clast message";
        pair.client_peer.write(stream_id, payload).unwrap();
        pair.client_peer.finish_stream(stream_id);

        // Pump until server receives.
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if !server_rec.received.is_empty() {
                break;
            }
        }

        let data: Vec<u8> = server_rec.received.iter().flat_map(|(_, d)| d.clone()).collect();
        assert_eq!(data, payload[1..]);
    }

    #[test]
    fn multiple_streams() {
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let mut client_rec = Recorder::default();
        let mut server_rec = Recorder::default();

        // Open two streams with different protocols.
        let s1 = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let s2 = pair.client_peer.open_stream(StreamProtocol::Identity).unwrap();

        // Negotiate both.
        for _ in 0..200 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if client_rec.streams.len() >= 2 && server_rec.streams.len() >= 2 {
                break;
            }
        }

        assert!(client_rec.streams.len() >= 2, "client streams: {}", client_rec.streams.len());
        assert!(server_rec.streams.len() >= 2, "server streams: {}", server_rec.streams.len());

        // Send different data on each stream. (length 10)
        pair.client_peer.write(s1, b"\x0astream one").unwrap();
        // Since Identity Outbound/Inbound no longer takes input gracefully, we will just send standard gossipsub payloads for testing generic streams here
        // Wait, IdentityInbound throws away payloads! So it'll never be received!
        // We will change s2 to GossipSub instead for asserting generic multiplex stream capabilities natively.
        let s3 = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        
        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
            if server_rec.streams.len() >= 3 { break; }
        }
        
        pair.client_peer.write(s3, b"\x0astream two").unwrap();

        for _ in 0..100 {
            pair.step(now, &mut client_rec, &mut server_rec);
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
