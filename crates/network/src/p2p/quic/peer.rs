use std::{io::Error, time::Instant};

use bytes::Bytes;
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, Dir, EndpointEvent, StreamId, Transmit, VarInt,
};
use silver_common::PeerId;

use crate::{NetworkRecv, NetworkSend, RemotePeer, p2p::tls::peer_id_from_certificate};

pub(crate) struct Peer {
    id: RemotePeer,
    handle: ConnectionHandle,
    connection: Connection,
}

impl Peer {
    pub(crate) fn new(handle: ConnectionHandle, connection: Connection) -> Self {
        Self {
            id: RemotePeer { peer_id: PeerId::default(), connection: handle.0 },
            handle,
            connection,
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

    pub(crate) fn spin<F, H: NetworkSend + NetworkRecv>(
        &mut self,
        now: Instant,
        ep_callback: &mut F,
        handler: &mut H,
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
                            Bytes::from_static("bad peer id".as_bytes()),
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
                    match stream_event {
                        // Event produced for incoming streams.
                        quinn_proto::StreamEvent::Opened { dir } => {
                            while let Some(id) = self.connection.streams().accept(dir) {
                                tracing::info!(peer=?self.id, ?id, ?dir, "stream openned");
                                handler.new_stream(&self.id, &id);

                                // try to read
                                if let Ok(mut chunks) = self.connection.recv_stream(id).read(true) {
                                    while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
                                        handler.recv(&self.id, &id, &chunk.bytes);
                                    }
                                    let _should_transmit = chunks.finalize();
                                }
                            }
                        }
                        quinn_proto::StreamEvent::Readable { id } => {
                            if let Ok(mut chunks) = self.connection.recv_stream(id).read(true) {
                                while let Ok(Some(chunk)) = chunks.next(usize::MAX) {
                                    handler.recv(&self.id, &id, &chunk.bytes);
                                }
                                let _should_transmit = chunks.finalize();
                            }
                        }
                        quinn_proto::StreamEvent::Writable { id: _ } => { // TODO
                            // if let Ok(written) =
                            // conn.send_stream(id).write(data) {

                            // }
                            //tracing::info!(spins=self.spin_count, "stream
                            // writable");
                        }
                        quinn_proto::StreamEvent::Finished { id } => {
                            tracing::info!(?id, "stream finished");
                        }
                        quinn_proto::StreamEvent::Stopped { id, error_code } => {
                            tracing::warn!(?id, ?error_code, "stream stopped");
                        }
                        quinn_proto::StreamEvent::Available { dir } => { // TODO
                            // Callback if it is now possible ot open a new stream (when previously
                            // at limits)
                            tracing::info!(?dir, "stream available");
                            //if let Some(id) = self.connection.streams().open(dir) {}
                        }
                    }
                }
                _ => {}
            }
        }

        while let Some(ep_event) = self.connection.poll_endpoint_events() {
            tracing::info!("post spin ep events");
            if let Some(conn_event) = (ep_callback)(self.handle, ep_event) {
                self.connection.handle_event(conn_event);
            }
        }

        next_timeout
    }

    pub(crate) fn transmit(
        &mut self,
        now: Instant,
        max_datagrams: usize,
        buf: &mut Vec<u8>,
    ) -> Option<Transmit> {
        self.connection.poll_transmit(now, max_datagrams, buf)
    }

    pub(crate) fn send(&mut self, stream_id: StreamId, data: &[u8]) -> Result<usize, Error> {
        match self.connection.send_stream(stream_id).write(data) {
            Ok(wrote) => {
                // if wrote < data.len() {
                //     tracing::warn!("only wrote {wrote} / {}", data.len());
                // }
                Ok(wrote)
            }
            Err(e) => match e {
                quinn_proto::WriteError::Blocked => Ok(0),
                e => Err(Error::other(e)),
            },
        }
    }

    pub(crate) fn new_stream<R: NetworkRecv>(&mut self, dir: Dir, recv: &mut R) {
        if let Some(id) = self.connection.streams().open(dir) {
            recv.new_stream(&self.id, &id);
        }
    }
}

fn id_from_connection(conn: &Connection) -> Option<PeerId> {
    let identity = conn.crypto_session().peer_identity();
    let Some(certs): Option<Box<Vec<rustls::pki_types::CertificateDer>>> =
        identity.map(|i| i.downcast()).and_then(|r| r.ok())
    else {
        tracing::error!("identity cannot be downcast to certifactes");
        return None;
    };
    peer_id_from_certificate(certs[0].as_ref())
        .inspect_err(|e| {
            tracing::error!(?e, "failed to extract peer id from certificate");
        })
        .ok()
}
