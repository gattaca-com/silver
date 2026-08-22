use std::{
    cell::Cell,
    hash::BuildHasherDefault,
    time::{Duration, Instant},
};

use bytes::Bytes;
use flux::utils::ArrayVec;
use flux_profiler::timed;
use fxhash::{FxHashMap, FxHashSet};
use quinn_proto::{
    Connection, ConnectionEvent, ConnectionHandle, Dir, EndpointEvent, Side, StreamId, Transmit,
    VarInt,
};
use silver_common::{
    rpc_rate_limit::RpcRateLimitSet, P2pConnectionStats, P2pStreamId, PeerId, StreamProtocol, TRead
};

use crate::{
    RemotePeer,
    p2p::{
        NetEvent,
        context::Context,
        quic::{SendResult, stream::StreamIoImpl},
        streams::{AcquiredRpcOutbound, StreamError, StreamState},
        tls::peer_id_from_certificate,
    },
};

const STREAM_SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Application error codes on abnormal stream teardown, so the remote can
/// tell a protocol violation from our read-timeout giving up on its slow
/// response (the latter is a they-are-slow signal at the receiver, counted
/// as `RemoteResponseTimeout`).
const STREAM_ERR_CODE_PROTOCOL: u32 = 1;
const STREAM_ERR_CODE_RESPONSE_TIMEOUT: u32 = 2;
/// Whole-life budget for an inbound RPC stream (negotiate + request +
/// serve). Generous so a large by-range serve to a slow peer survives.
const INBOUND_RPC_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) struct Peer {
    id: RemotePeer,
    handle: ConnectionHandle,
    connection: Connection,
    streams: FxHashMap<StreamId, Stream>,
    inbound_gossip: Option<StreamId>,
    outbound_gossip: Option<StreamId>,
    /// When the connection object was created (dial initiated / inbound
    /// accepted). Used to report connection age on disconnect.
    created_at: Instant,
    /// Set true once the QUIC+TLS handshake completes (`Event::Connected`).
    /// A connection that dies with this still false is a "zombie" — the
    /// peer never responded to our handshake.
    handshake_completed: bool,
    inbound_rpc_limits: RpcRateLimitSet,
    /// Earliest rpc read-response deadline across streams. A silent peer
    /// emits no event to trip the timeout, so lapse triggers a full sweep.
    next_deadline: Option<Instant>,
    /// Connection has un-polled inputs (fed events, local sends). Cleared
    /// by `settle` once a full transmit+spin cycle quiesces.
    dirty: bool,
    /// Earliest instant the connection needs a poll absent any other
    /// wakeup: min(quinn timer, `next_deadline`). Re-armed by `settle`.
    wake_at: Option<Instant>,
}

impl Peer {
    /// `peer_id`: the dialed identity for outbound connections (known
    /// up-front and TLS-pinned); `PeerId::default()` for inbound until the
    /// handshake reveals it.
    pub(crate) fn new(handle: ConnectionHandle, connection: Connection, peer_id: PeerId) -> Self {
        Self {
            id: RemotePeer { peer_id, connection: handle.0, addr: connection.remote_address() },
            handle,
            connection,
            streams: FxHashMap::with_capacity_and_hasher(16, BuildHasherDefault::default()),
            inbound_gossip: None,
            outbound_gossip: None,
            created_at: Instant::now(),
            handshake_completed: false,
            inbound_rpc_limits: RpcRateLimitSet::default(),
            next_deadline: None,
            // Born dirty: a dial must emit its handshake, an accept its
            // response — neither has a quinn event to trigger the first poll.
            dirty: true,
            wake_at: None,
        }
    }

    pub(crate) fn id(&self) -> &RemotePeer {
        &self.id
    }

    pub(crate) fn event(&mut self, event: ConnectionEvent) {
        self.dirty = true;
        self.connection.handle_event(event);
    }

    pub(crate) fn is_drained(&self) -> bool {
        self.connection.is_drained()
    }

    /// Needs a transmit+spin cycle now: un-polled inputs, a lapsed wake
    /// deadline (quinn timer / rpc read-response timeout), or a drained
    /// connection to reap. A missing deadline is quiescent, not due — treating
    /// it as due pinned `P2p::poll` at `Duration::ZERO`.
    pub(crate) fn due(&self, now: Instant) -> bool {
        self.dirty || self.wake_at.is_some_and(|t| t <= now) || self.is_drained()
    }

    pub(crate) fn wake_at(&self) -> Option<Instant> {
        self.wake_at
    }

    /// Quiesce after a full transmit+spin+transmit cycle: stay dirty while
    /// any stream has non-event work or the socket cut off transmits, and
    /// re-arm the wake deadline. `poll_timeout` must be read here, after the
    /// final transmit drain — transmits re-arm pacing/loss timers.
    pub(crate) fn settle(&mut self, socket_blocked: bool) {
        self.dirty = socket_blocked || self.streams.values().any(|s| s.needs_spin);
        self.wake_at = match (self.connection.poll_timeout(), self.next_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
    }

    pub(crate) fn send_gossip(&mut self, msg: TRead) -> SendResult {
        self.dirty = true;
        if let Some(stream) = match &self.outbound_gossip {
            Some(id) => self.streams.get_mut(id),
            None => self.open_stream(StreamProtocol::GossipSub).and_then(|id| {
                self.outbound_gossip.replace(id);
                self.streams.get_mut(&id)
            }),
        } {
            if let OutboundBuffer::Gossip(buffer) = &mut stream.out_buffer {
                let dropped = buffer.add_msg(msg);
                stream.needs_spin = true;
                return if dropped { SendResult::MessageDropped } else { SendResult::Ok };
            }
        }
        SendResult::StreamCreationError
    }

    pub(crate) fn send_rpc(&mut self, msg: AcquiredRpcOutbound) -> SendResult {
        tracing::debug!(id=?self.id, protocol=?msg.protocol(), "outbound rpc");
        self.dirty = true;

        let stream = match &msg {
            AcquiredRpcOutbound::Request(req) => {
                match self
                    .open_stream(req.request.protocol())
                    .and_then(|id| self.streams.get_mut(&id))
                {
                    Some(stream) => stream,
                    None => return SendResult::StreamCreationError,
                }
            }
            AcquiredRpcOutbound::Response(rsp) => {
                match self.streams.get_mut(&rsp.stream_id.stream_id()) {
                    Some(stream) => stream,
                    None => {
                        tracing::debug!(stream_id = ?rsp.stream_id, "rpc response: stream gone");
                        return SendResult::StreamGone;
                    }
                }
            }
        };
        if let OutboundBuffer::Rpc(buffer) = &mut stream.out_buffer {
            let dropped = buffer.add_msg(msg);
            stream.needs_spin = true;
            return if dropped { SendResult::MessageDropped } else { SendResult::Ok };
        }
        SendResult::StreamCreationError
    }

    pub(crate) fn send_identify(&mut self) -> SendResult {
        self.dirty = true;
        match self.open_stream(StreamProtocol::Identity) {
            Some(_) => SendResult::Ok,
            None => SendResult::StreamCreationError,
        }
    }

    pub(crate) fn has_pending_outbound(&self) -> bool {
        self.streams.values().any(|s| !s.out_buffer.is_empty())
    }

    pub(crate) fn pending(&self) -> usize {
        self.streams.values().map(|s| s.out_buffer.len()).sum()
    }

    pub(crate) fn shutdown(&mut self, now: Instant) {
        self.dirty = true;
        self.connection.close(now, VarInt::from_u32(0), Bytes::new());
    }

    /// Stream-leak diagnostics: one line per over-populated connection
    /// listing each stream's protocol, state, direction, age and queue, so
    /// a stuck state names itself. Steady state is 2 gossip + transient
    /// RPC.
    #[allow(dead_code)]
    pub(crate) fn log_stream_census(&mut self, now: Instant) {
        const CENSUS_MIN_STREAMS: usize = 5;
        if self.streams.len() < CENSUS_MIN_STREAMS {
            return;
        }
        let census: Vec<String> = self
            .streams
            .values_mut()
            .map(|s| {
                format!(
                    "{:?}:{}:{}:{}s:q{}",
                    s.p2p_id.protocol(),
                    s.state.get_mut().name(),
                    if s.p2p_id.is_incoming() { "in" } else { "out" },
                    now.saturating_duration_since(s.created_at).as_secs(),
                    s.out_buffer.len(),
                )
            })
            .collect();
        tracing::info!(
            id = ?self.id,
            count = census.len(),
            streams = census.join(" | "),
            "stream census"
        );
    }

    /// Returns connection stats for peers connected > 30 seconds.
    pub(crate) fn stats(&self, now: Instant) -> Option<P2pConnectionStats> {
        (now - self.created_at > Duration::from_secs(10)).then(|| {
            let stats = self.connection.stats();
            P2pConnectionStats {
                id: self.id.peer_id,
                connection: self.id.connection,
                addr: self.id.addr,
                connected: self.created_at.elapsed(),
                rtt: stats.path.rtt,
                lost_packets: stats.path.lost_packets,
                rx_blocking: stats.frame_rx.data_blocked,
                tx_blocking: stats.frame_tx.data_blocked,
                rx_datagrams: stats.udp_rx.datagrams,
                tx_datagrams: stats.udp_tx.datagrams,
                streams: self.streams.len() as u64,
                inbound: self.connection.side() == Side::Server,
            }
        })
    }

    /// Open an outbound stream with the given protocol. Returns `None` if
    /// the connection isn't ready (e.g. stream limit not yet negotiated).
    /// Multistream-select negotiation runs internally; `NetEvent::StreamReady`
    /// is emitted once it completes.
    fn open_stream(&mut self, protocol: StreamProtocol) -> Option<StreamId> {
        // All streams are Bi — multistream-select requires bidirectional I/O
        // even for request-response protocols.
        if protocol == StreamProtocol::GossipSub && self.outbound_gossip.is_some() {
            tracing::warn!(id=?self.id, "open stream: already have outbound gossip stream");
            return None;
        }

        let id = self.connection.streams().open(Dir::Bi)?;
        let p2p_id = P2pStreamId::new(self.id.connection, id.into(), protocol, false);

        tracing::debug!(?p2p_id, "open outbound stream");

        // allocate out buffer.
        let out_buffer = out_buffer(&p2p_id, false);
        let stream = StreamState::new_outbound(protocol);
        self.streams.insert(id, Stream {
            p2p_id,
            state: Cell::new(stream),
            out_buffer,
            needs_spin: true,
            setup_deadline: None,
            created_at: Instant::now(),
        });
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
    ) where
        F: FnMut(ConnectionHandle, EndpointEvent) -> Option<ConnectionEvent>,
        E: FnMut(crate::NetEvent),
    {
        while self.connection.poll_timeout().is_some_and(|t| t <= now) {
            self.connection.handle_timeout(now);
        }

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
                        Some(id) => {
                            tracing::info!(
                                handle = ?self.handle,
                                peer_id = ?id,
                                addr = ?self.connection.remote_address(),
                                "closing connection: peer banned"
                            );
                            self.connection.close(
                                now,
                                VarInt::from_u32(400),
                                Bytes::from_static(b"banned"),
                            );
                            continue;
                        }
                        None => {
                            self.connection.close(
                                now,
                                VarInt::from_u32(400),
                                Bytes::from_static(b"bad peer id"),
                            );
                            continue;
                        }
                    };
                    self.id.peer_id = peer_id;
                    self.handshake_completed = true;
                    let local_dialler = self.connection.side() == Side::Client;
                    if local_dialler {
                        crate::NetworkCounters::DialHandshakeOk.inc();
                    } else {
                        crate::NetworkCounters::InboundHandshakeOk.inc();
                    }
                    tracing::info!(
                        handle = ?self.handle,
                        peer_id = ?peer_id,
                        addr = ?self.connection.remote_address(),
                        local_dialler,
                        "connected"
                    );
                    on_event(NetEvent::PeerConnected {
                        peer: self.id.clone(),
                        addr: self.connection.remote_address(),
                        local_dialler,
                    });
                }
                quinn_proto::Event::ConnectionLost { reason } => {
                    let zombie = !self.handshake_completed;
                    bump_disconnect_counter(&reason, zombie);
                    tracing::info!(
                        handle = ?self.handle,
                        peer_id = ?self.id.peer_id,
                        addr = ?self.connection.remote_address(),
                        ?reason,
                        age_ms = self.created_at.elapsed().as_millis(),
                        handshake_completed = self.handshake_completed,
                        zombie,
                        "connection lost"
                    );
                }
                quinn_proto::Event::Stream(stream_event) => {
                    self.handle_stream_event(stream_event, now, context, on_event);
                }
                _ => {}
            }
        }

        while let Some(ep_event) = self.connection.poll_endpoint_events() {
            if let Some(conn_event) = (ep_callback)(self.handle, ep_event) {
                self.connection.handle_event(conn_event);
            }
        }

        // Drive only streams flagged for non-event work; quinn-I/O parks are
        // re-driven by Readable/Writable via `handle_stream_event`.
        let to_remove = spin_streams(
            now,
            &mut self.connection,
            context,
            &mut self.streams,
            &mut self.inbound_rpc_limits,
            &mut self.next_deadline,
            &mut self.inbound_gossip,
            false,
            on_event,
        );
        for id in to_remove {
            self.remove_stream(id);
        }

        // Read-response timeouts only fire inside a spin; sweep everything
        // when the earliest deadline lapses.
        if self.next_deadline.is_some_and(|d| now >= d) {
            self.next_deadline = None;
            let to_remove = spin_streams(
                now,
                &mut self.connection,
                context,
                &mut self.streams,
                &mut self.inbound_rpc_limits,
                &mut self.next_deadline,
                &mut self.inbound_gossip,
                true,
                on_event,
            );
            for id in to_remove {
                self.remove_stream(id);
            }
        }
    }

    /// Spin one stream and re-arm its bookkeeping: the `needs_spin` flag
    /// for non-event work and the min read-response deadline.
    fn spin_stream<E>(
        &mut self,
        id: StreamId,
        now: Instant,
        context: &mut Context,
        on_event: &mut E,
    ) where
        E: FnMut(crate::NetEvent),
    {
        let Some(stream) = self.streams.get_mut(&id) else {
            return;
        };
        let result =
            stream.spin(&mut self.connection, context, now, &mut self.inbound_rpc_limits, on_event);
        if let SpinResult::End = result {
            if stream.p2p_id.protocol() == StreamProtocol::Goodbye {
                self.shutdown(now);
            }
            self.remove_stream(id);

            return;
        }

        let state = stream.state.get_mut();
        stream.needs_spin =
            state.awaiting_alloc() || (state.write_idle() && !stream.out_buffer.is_empty());
        if let Some(d) = stream.wake_deadline() {
            self.next_deadline = Some(self.next_deadline.map_or(d, |cur| cur.min(d)));
        }

        if let SpinResult::Protocol(protocol) = result {
            tracing::debug!(?id, ?protocol, "incoming stream negotiated");
            if protocol == StreamProtocol::GossipSub {
                self.inbound_gossip.replace(id);
            }
        }
    }

    #[timed]
    fn handle_stream_event<E>(
        &mut self,
        event: quinn_proto::StreamEvent,
        now: Instant,
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
                        needs_spin: true,
                        setup_deadline: None,
                        created_at: Instant::now(),
                    });
                    on_event(NetEvent::StreamReady { stream: p2p_id });
                    tracing::debug!(?p2p_id, "stream open");
                }
            }
            quinn_proto::StreamEvent::Readable { id } |
            quinn_proto::StreamEvent::Writable { id } => {
                self.spin_stream(id, now, context, on_event);
            }
            quinn_proto::StreamEvent::Finished { id } => {
                // This event is emitted after we call 'finish()' on the send side of
                // the stream. Indicates that data was sent and acked.
                tracing::debug!(?id, "send half finished");
                // Fully-served inbound stream: response acked, nothing left
                // to write. Reclaim here — quinn requesters reclaim it for
                // us via a spurious STOP_SENDING (`stop_send`), but netty
                // (teku) just FINs and the state would leak.
                if let Some(stream) = self.streams.get_mut(&id) &&
                    stream.p2p_id.is_incoming() &&
                    stream.is_complete() &&
                    stream.out_buffer.is_empty()
                {
                    self.remove_stream(id);
                }
            }
            quinn_proto::StreamEvent::Stopped { id, error_code } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    let p2p_id = stream.p2p_id;
                    if let SpinResult::End =
                        stream.stop_send(error_code, &mut self.connection, on_event)
                    {
                        // Remove the stream
                        self.remove_stream(id);
                    }

                    if let Some(out_id) = self.outbound_gossip &&
                        out_id == id
                    {
                        // peer has asked to stop receiving gossip
                        self.remove_stream(id);
                        self.outbound_gossip.take();
                        on_event(NetEvent::StreamClosed { stream: p2p_id })
                    }
                }
            }
            quinn_proto::StreamEvent::Available { dir: _ } => {}
        }
    }

    fn remove_stream(&mut self, id: StreamId) {
        let _ = self.connection.send_stream(id).finish();
        let _ = self.connection.recv_stream(id).stop(VarInt::from_u32(0));

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

#[allow(clippy::too_many_arguments)]
fn spin_streams<E>(
    now: Instant,
    connection: &mut Connection,
    context: &mut Context,
    streams: &mut FxHashMap<StreamId, Stream>,
    inbound_rpc_limits: &mut RpcRateLimitSet,
    next_deadline: &mut Option<Instant>,
    inbound_gossip: &mut Option<StreamId>,
    all: bool,
    on_event: &mut E,
) -> ArrayVec<StreamId, 64>
where
    E: FnMut(crate::NetEvent),
{
    let mut to_remove = ArrayVec::new();
    for (id, stream) in streams {
        if !all && !stream.needs_spin {
            continue;
        }

        let result = stream.spin(connection, context, now, inbound_rpc_limits, on_event);
        if let SpinResult::End = result {
            to_remove.push(*id);
            continue;
        }

        let state = stream.state.get_mut();
        stream.needs_spin =
            state.awaiting_alloc() || (state.write_idle() && !stream.out_buffer.is_empty());
        if let Some(d) = stream.wake_deadline() {
            *next_deadline = Some(next_deadline.map_or(d, |cur| cur.min(d)));
        }

        if let SpinResult::Protocol(protocol) = result {
            tracing::debug!(?id, ?protocol, "incoming stream negotiated");
            if protocol == StreamProtocol::GossipSub {
                inbound_gossip.replace(*id);
            }
        }
    }
    to_remove
}

/// Bucket a `ConnectionLost` reason into the `NetworkCounters` disconnect
/// histogram, and separately count pre-handshake deaths ("zombies").
fn bump_disconnect_counter(reason: &quinn_proto::ConnectionError, zombie: bool) {
    use quinn_proto::ConnectionError::*;
    match reason {
        TimedOut => crate::NetworkCounters::DisconnectTimedOut.inc(),
        Reset => crate::NetworkCounters::DisconnectReset.inc(),
        ApplicationClosed(_) | ConnectionClosed(_) => {
            crate::NetworkCounters::DisconnectAppClosed.inc()
        }
        LocallyClosed => crate::NetworkCounters::DisconnectLocal.inc(),
        _ => crate::NetworkCounters::DisconnectOther.inc(),
    }
    if zombie {
        crate::NetworkCounters::DialTimeoutZombie.inc();
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
        StreamProtocol::GossipSub => OutboundBuffer::Gossip(OutBuffer::new(32 * 1024)),
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
    /// Has work no quinn event re-drives: a tcache-alloc retry, or queued
    /// outbound msgs with the write side idle (mid-write parks are
    /// Writable-driven — flagging those busy-loops until the peer grants
    /// credit). Fresh streams are born flagged — the initial negotiate
    /// write, and bytes delivered with `Opened`, emit no event.
    needs_spin: bool,
    setup_deadline: Option<Instant>,
    created_at: Instant,
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
        now: Instant,
        inbound_rpc_limits: &mut RpcRateLimitSet,
        on_event: &mut E,
    ) -> SpinResult
    where
        E: FnMut(crate::NetEvent),
    {
        if self.state.get_mut().in_setup() {
            let deadline = *self.setup_deadline.get_or_insert(now + STREAM_SETUP_TIMEOUT);
            if now >= deadline {
                return self.timed_out("stream setup timeout", connection, on_event);
            }
        }

        // Inbound RPC streams have no state-machine deadline of their own:
        // a starved request read, a response lost before enqueue, or an
        // unacked FIN would otherwise park the stream forever (observed as
        // aged `IncomingRpc` census entries from teku).
        if matches!(self.state.get_mut(), StreamState::IncomingRpc { .. }) &&
            now >= self.created_at + INBOUND_RPC_TIMEOUT
        {
            return self.timed_out("inbound rpc timeout", connection, on_event);
        }

        let state = self.state.take();
        // Capture the phase before `spin` consumes `state`, so a stream
        // error/teardown log can report which protocol phase it failed in.
        let state_name = state.name();
        let was_negotiate = matches!(state, StreamState::Negotiate(_));
        let mut io = StreamIoImpl { connection, outbound: &mut self.out_buffer };

        let result = state
            .spin(&mut io, &mut self.p2p_id, context, now, inbound_rpc_limits, on_event)
            .and_then(|state| {
                // Negotiation completion transitions into a state that may
                // already have work — request/response bytes to write, or
                // surplus bytes quinn buffered past the capped negotiate
                // read — with no event armed. Step the successor once.
                if was_negotiate &&
                    !matches!(state, StreamState::Negotiate(_) | StreamState::Finished)
                {
                    state.spin(
                        &mut io,
                        &mut self.p2p_id,
                        context,
                        now,
                        inbound_rpc_limits,
                        on_event,
                    )
                } else {
                    Ok(state)
                }
            });

        match result {
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
                tracing::error!(
                    id = ?self.p2p_id,
                    protocol = ?self.p2p_id.protocol(),
                    state = state_name,
                    ?e,
                    "stream error"
                );
                let id = self.p2p_id.stream_id();
                let code = if matches!(e, StreamError::ReadResponseTimeout) {
                    STREAM_ERR_CODE_RESPONSE_TIMEOUT
                } else {
                    STREAM_ERR_CODE_PROTOCOL
                };
                // reset, not finish: see the setup-timeout teardown above.
                let _ = connection.send_stream(id).reset(VarInt::from_u32(code));
                let _ = connection.recv_stream(id).stop(VarInt::from_u32(code));

                // TODO error info.
                on_event(NetEvent::StreamClosed { stream: self.p2p_id });
                SpinResult::End
            }
        }
    }

    /// Remote peer has called 'stop' on their recv stream (our send side).
    fn timed_out<E>(
        &mut self,
        reason: &'static str,
        connection: &mut Connection,
        on_event: &mut E,
    ) -> SpinResult
    where
        E: FnMut(crate::NetEvent),
    {
        tracing::warn!(
            id = ?self.p2p_id,
            protocol = ?self.p2p_id.protocol(),
            state = self.state.get_mut().name(),
            reason,
            "stream timeout"
        );
        let id = self.p2p_id.stream_id();
        // reset, not finish: FIN queues behind buffered data the stalled
        // peer isn't draining, so the stream — and its MAX_STREAMS credit —
        // would leak at the QUIC layer.
        let _ = connection.send_stream(id).reset(VarInt::from_u32(1));
        let _ = connection.recv_stream(id).stop(VarInt::from_u32(1));
        on_event(NetEvent::StreamClosed { stream: self.p2p_id });
        SpinResult::End
    }

    /// Earliest instant this stream needs an unprompted poll: setup and
    /// inbound-RPC lifetime budgets, or the state machine's own deadline.
    fn wake_deadline(&mut self) -> Option<Instant> {
        let state = self.state.get_mut();
        if state.in_setup() {
            self.setup_deadline
        } else if matches!(state, StreamState::IncomingRpc { .. }) {
            Some(self.created_at + INBOUND_RPC_TIMEOUT)
        } else {
            state.deadline()
        }
    }

    fn stop_send<E>(
        &mut self,
        error_code: VarInt,
        connection: &mut Connection,
        on_event: &mut E,
    ) -> SpinResult
    where
        E: FnMut(crate::NetEvent),
    {
        let _ = connection.send_stream(self.p2p_id.stream_id()).reset(VarInt::from_u32(0));
        if error_code.into_inner() == STREAM_ERR_CODE_RESPONSE_TIMEOUT as u64 {
            crate::NetworkCounters::RemoteResponseTimeout.inc();
        }
        if self.state.get_mut().is_receive_only(self.p2p_id.protocol()) {
            return SpinResult::Ok;
        }
        // Fully-responded incoming stream: the requester tears down with a
        // (possibly spurious — quinn sends one when the app never read the
        // FIN) STOP_SENDING once it has the response. Normal completion,
        // not misbehaviour; also reclaims the otherwise-leaked Idle stream.
        if self.p2p_id.is_incoming() && self.is_complete() && self.out_buffer.is_empty() {
            return SpinResult::End;
        }
        tracing::warn!(
            error_code = error_code.into_inner(),
            protocol = ?self.p2p_id.protocol(),
            state = ?self.state.get_mut(),
            "Stop send called in non-receive only state."
        );
        on_event(NetEvent::StreamClosed { stream: self.p2p_id });
        SpinResult::End
    }

    // Unused — see `StreamState::on_close` / `is_complete` for the
    // pending recv-EOF hook these wrappers will be called from.
    #[allow(dead_code)]
    fn on_close<F>(&mut self, emit: &mut F)
    where
        F: FnMut(NetEvent),
    {
        self.state.get_mut().on_close(&self.p2p_id, emit);
    }

    fn is_complete(&mut self) -> bool {
        self.state.get_mut().is_complete()
    }
}

pub(super) enum OutboundBuffer {
    Unset,
    Gossip(OutBuffer<TRead>),
    Rpc(OutBuffer<AcquiredRpcOutbound>),
}

impl OutboundBuffer {
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

pub(super) struct OutBuffer<T: Clone> {
    msgs: Box<[Option<T>]>,
    len: usize,
    head: usize,
    tail: usize,
}

impl<T: Clone> OutBuffer<T> {
    fn new(len: usize) -> Self {
        assert!(len.is_power_of_two());
        Self { msgs: vec![None; len].into_boxed_slice(), len, head: 0, tail: 0 }
    }

    fn pos(&self, seq: usize) -> usize {
        seq & (self.len - 1)
    }

    /// Returns `true` if adding the new message dropped the oldest queued
    /// message.
    fn add_msg(&mut self, msg: T) -> bool {
        let dropped = self.head - self.tail == self.msgs.len();
        if dropped {
            // Full: pos(head) == pos(tail), so the overwrite below replaces
            // the oldest message. Advance tail with it — otherwise head/tail
            // desync and is_empty() reports non-empty while pop() yields
            // None, leaving the stream flagged needs_spin forever.
            self.tail += 1;
        }
        self.msgs[self.pos(self.head)].replace(msg);
        self.head += 1;
        dropped
    }

    /// Called when the current read is complete.
    pub(super) fn pop(&mut self) -> Option<T> {
        match self.msgs[self.pos(self.tail)].take() {
            Some(msg) => {
                self.tail += 1;
                Some(msg)
            }
            None => {
                debug_assert!(self.head == self.tail, "OutBuffer head/tail desync");
                None
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

    #[test]
    fn out_buffer_overflow_keeps_ring_consistent() {
        let mut buf = OutBuffer::new(4);
        for i in 0..4usize {
            assert!(!buf.add_msg(i));
        }

        // Two overwrites drop the two oldest messages.
        assert!(buf.add_msg(4));
        assert!(buf.add_msg(5));
        assert_eq!(buf.len(), 4);

        let drained: Vec<_> = std::iter::from_fn(|| buf.pop()).collect();
        assert_eq!(drained, vec![2, 3, 4, 5]);
        assert!(buf.is_empty());
        assert!(buf.pop().is_none());

        // Buffer must remain usable after an overflow episode.
        assert!(!buf.add_msg(6));
        assert_eq!(buf.pop(), Some(6));
        assert!(buf.is_empty());
    }

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
            let gossip_in_p = TCache::producer("gossip_in", TCACHE_BYTES);
            let gossip_in_c = gossip_in_p.cache_ref().consumer("peer_gossip_in").unwrap();
            let gossip_out_p = TCache::producer("gossip_out", TCACHE_BYTES);
            let gossip_out_c =
                gossip_out_p.cache_ref().random_access("peer_gossip_out", false).unwrap();

            let rpc_in_p = TCache::producer("rpc_in", TCACHE_BYTES);
            let rpc_out_p = TCache::producer("rpc_out", TCACHE_BYTES);
            let rpc_out_c = rpc_out_p.cache_ref().random_access("peer_rpc_out", false).unwrap();

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
            let read = self.context.gossip_consumer.acquire(res.read());
            peer.send_gossip(read);
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
            let mut client_peer = Peer::new(client_handle, client_conn, PeerId::default());

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
                            server_peer = Some(Peer::new(handle, conn, PeerId::default()));
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
            self.step_inner(now, client_h, server_h, client_on_event, server_on_event, true)
        }

        /// `drain: false` leaves inbound frames unread so tests can hold the
        /// gossip-in tcache full.
        fn step_inner<CE, SE>(
            &mut self,
            now: Instant,
            client_h: &mut PeerHarness,
            server_h: &mut PeerHarness,
            client_on_event: &mut CE,
            server_on_event: &mut SE,
            drain: bool,
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

                if drain {
                    client_h.drain_inbound();
                    server_h.drain_inbound();
                }

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

    #[test]
    fn stream_setup_timeout_reaps_unnegotiated_stream() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();

        let t0 = Instant::now();
        pair.client_peer.open_stream(StreamProtocol::Ping).unwrap();

        let PeerPair { client_ep, client_peer, .. } = &mut pair;
        let mut cb = |h, e| client_ep.handle_event(h, e);
        let closed = Cell::new(0usize);
        let mut on_event = |e: NetEvent| {
            if matches!(e, NetEvent::StreamClosed { .. }) {
                closed.set(closed.get() + 1);
            }
        };

        client_peer.spin(t0, &mut cb, &mut client_h.context, &mut on_event, &FxHashSet::default());
        assert_eq!(client_peer.streams.len(), 1);

        client_peer.spin(
            t0 + STREAM_SETUP_TIMEOUT / 2,
            &mut cb,
            &mut client_h.context,
            &mut on_event,
            &FxHashSet::default(),
        );
        assert_eq!(client_peer.streams.len(), 1);
        assert_eq!(closed.get(), 0);

        client_peer.spin(
            t0 + STREAM_SETUP_TIMEOUT + Duration::from_secs(1),
            &mut cb,
            &mut client_h.context,
            &mut on_event,
            &FxHashSet::default(),
        );
        assert!(client_peer.streams.is_empty());
        assert_eq!(closed.get(), 1);
    }

    /// A negotiated inbound RPC stream whose request never arrives must be
    /// reaped by `INBOUND_RPC_TIMEOUT` — only the server is spun past the
    /// deadline, so the reap can't be masked by the client's own teardown.
    #[test]
    fn inbound_rpc_timeout_reaps_unanswered_stream() {
        use silver_common::{RpcInbound, RpcOutbound, RpcRequest, RpcRequestOutbound};

        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        let t0 = Instant::now();
        let request = RpcOutbound::Request(RpcRequestOutbound {
            application_id: 7,
            peer: pair.client_peer.id.connection,
            request: RpcRequest::Ping([0u8; 8]),
        });
        let msg = AcquiredRpcOutbound::from((request, &mut client_h.context.rpc_consumer));
        assert!(matches!(pair.client_peer.send_rpc(msg), SendResult::Ok));

        // Step until the server has read the request; nothing ever responds,
        // so its stream parks in `WriteResponse(Idle)` — the leak shape.
        let mut server_got_request = false;
        for _ in 0..300 {
            let mut noop_c = |_: NetEvent| {};
            let mut scb = |e: NetEvent| {
                if matches!(e, NetEvent::RpcInbound(RpcInbound::Request(_))) {
                    server_got_request = true;
                }
            };
            pair.step(t0, &mut client_h, &mut server_h, &mut noop_c, &mut scb);
            if server_got_request {
                break;
            }
        }
        assert!(server_got_request, "server never read the ping request");
        assert!(
            pair.server_peer.streams.values().any(|s| s.p2p_id.protocol() == StreamProtocol::Ping),
            "server should hold the unanswered inbound ping stream"
        );

        let PeerPair { server_ep, server_peer, .. } = &mut pair;
        let mut cb = |h, e| server_ep.handle_event(h, e);
        let mut on_event = |_: NetEvent| {};
        server_peer.spin(
            t0 + INBOUND_RPC_TIMEOUT + Duration::from_secs(1),
            &mut cb,
            &mut server_h.context,
            &mut on_event,
            &FxHashSet::default(),
        );
        assert!(
            !server_peer.streams.values().any(|s| s.p2p_id.protocol() == StreamProtocol::Ping),
            "unanswered inbound rpc stream survived its timeout"
        );
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

    /// TCache-full park + poll-retry. No quinn event re-drives a reader
    /// parked in `AllocBody` (space frees when another tile consumes) — only
    /// the `pending_spin` retry does. Fill the server's gossip-in tcache so
    /// the second frame parks, then free and verify delivery resumes.
    #[test]
    fn tcache_full_park_and_retry() {
        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();

        // Shrink the server's inbound gossip tcache: one 6 KB frame fits,
        // two don't.
        server_h.context.gossip_producer = TCache::producer("gossip_in_small", 8 * 1024);
        server_h.gossip_in_consumer =
            server_h.context.gossip_producer.cache_ref().consumer("peer_gossip_in_small").unwrap();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );

        let msg1 = vec![0xA5u8; 6 * 1024];
        let msg2 = vec![0x5Au8; 6 * 1024];
        client_h.send_gossip(stream_id, &msg1, &mut pair.client_peer);
        client_h.send_gossip(stream_id, &msg2, &mut pair.client_peer);

        // Pump without draining: frame 1 lands in the tcache, frame 2 must
        // park in AllocBody and stay in the retry set.
        let now = Instant::now();
        let mut noop_c = |_: NetEvent| {};
        let mut noop_s = |_: NetEvent| {};
        for _ in 0..50 {
            pair.step_inner(now, &mut client_h, &mut server_h, &mut noop_c, &mut noop_s, false);
        }
        let parked =
            pair.server_peer.streams.values_mut().any(|s| s.state.get_mut().awaiting_alloc());
        assert!(parked, "reader should be parked awaiting tcache space");
        assert!(
            pair.server_peer.streams.values().any(|s| s.needs_spin),
            "parked stream must stay flagged for retry"
        );

        // Free the tcache (drain reads + frees) and pump — the retry must
        // deliver frame 2 with no further client writes.
        server_h.drain_inbound();
        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| {
            s.received.values().map(|v| v.len()).sum::<usize>() == msg1.len() + msg2.len()
        });

        let all: Vec<u8> = server_h.received.values().flat_map(|v| v.clone()).collect();
        assert_eq!(all.len(), msg1.len() + msg2.len());
        assert_eq!(&all[..msg1.len()], &msg1[..]);
        assert_eq!(&all[msg1.len()..], &msg2[..]);
    }

    /// A completed single-chunk exchange: the requester tears down after
    /// reading the response without consuming the FIN, so quinn sends a
    /// spurious STOP_SENDING. The responder must treat it as clean
    /// completion — no `StreamClosed` (which costs the requester a PM
    /// misbehaviour penalty) — and reclaim the stream.
    #[test]
    fn requester_teardown_after_response_is_clean() {
        use silver_common::{
            RpcInbound, RpcOutbound, RpcRequest, RpcRequestOutbound, RpcResponse,
            RpcResponseOutbound, ssz_view::STATUS_V2_SIZE,
        };

        let mut pair = PeerPair::new();
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let now = Instant::now();

        let request = RpcOutbound::Request(RpcRequestOutbound {
            application_id: 7,
            peer: pair.client_peer.id.connection,
            request: RpcRequest::StatusV2([1u8; STATUS_V2_SIZE]),
        });
        let msg = AcquiredRpcOutbound::from((request, &mut client_h.context.rpc_consumer));
        assert!(matches!(pair.client_peer.send_rpc(msg), SendResult::Ok));

        let mut request_stream = None;
        let mut server_closed = false;
        let mut client_got_response = false;
        let mut responded = false;
        for _ in 0..300 {
            {
                let mut ccb = |e: NetEvent| {
                    if matches!(e, NetEvent::RpcInbound(RpcInbound::Response(_))) {
                        client_got_response = true;
                    }
                };
                let mut scb = |e: NetEvent| match e {
                    NetEvent::RpcInbound(RpcInbound::Request(req)) => {
                        request_stream = Some(req.stream_id);
                    }
                    NetEvent::StreamClosed { .. } => server_closed = true,
                    _ => {}
                };
                pair.step(now, &mut client_h, &mut server_h, &mut ccb, &mut scb);
            }

            if let Some(stream_id) = request_stream &&
                !responded
            {
                responded = true;
                let response = RpcOutbound::Response(RpcResponseOutbound {
                    stream_id,
                    response: RpcResponse::StatusV2([2u8; STATUS_V2_SIZE]),
                });
                let msg = AcquiredRpcOutbound::from((response, &mut server_h.context.rpc_consumer));
                assert!(matches!(pair.server_peer.send_rpc(msg), SendResult::Ok));
            }

            if client_got_response && pair.client_peer.streams.is_empty() {
                break;
            }
        }

        let mut noop_c = |_: NetEvent| {};
        let mut scb = |e: NetEvent| {
            if matches!(e, NetEvent::StreamClosed { .. }) {
                server_closed = true;
            }
        };
        for _ in 0..50 {
            pair.step(now, &mut client_h, &mut server_h, &mut noop_c, &mut scb);
        }

        assert!(client_got_response, "client never received the status response");
        assert!(!server_closed, "clean requester teardown must not report StreamClosed");
        assert!(pair.client_peer.streams.is_empty(), "requester stream should be torn down");
        assert!(
            pair.server_peer.streams.is_empty(),
            "responder must close its stream after the final response chunk"
        );
    }
}
