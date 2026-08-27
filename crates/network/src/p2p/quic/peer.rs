use std::{
    cell::Cell,
    hash::BuildHasherDefault,
    ops::Deref,
    ptr::NonNull,
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
    P2pConnectionStats, P2pStreamId, PeerId, StreamProtocol, TRead, rpc_rate_limit::RpcRateLimitSet,
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

/// Upper bound on waiting for a sent Goodbye to be acked before closing the
/// connection anyway (peer dead or not acking).
const GOODBYE_LINGER: Duration = Duration::from_secs(1);

/// Application error codes on abnormal stream teardown, so the remote can
/// tell a protocol violation from our read-timeout giving up on its slow
/// response (the latter is a they-are-slow signal at the receiver, counted
/// as `RemoteResponseTimeout`).
const STREAM_ERR_CODE_PROTOCOL: u32 = 1;
const STREAM_ERR_CODE_RESPONSE_TIMEOUT: u32 = 2;
const INBOUND_RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// End-to-end age after which outbound gossip delivery is stale, measured from
/// enqueue until Quinn releases every owner after ACK or teardown. Expiry is
/// rounded up to the next wheel tick, so detection occurs within one
/// additional second.
const GOSSIP_DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);
const OUTBOUND_LEASE_TICK: Duration = Duration::from_secs(1);
const OUTBOUND_LEASE_BUCKETS: usize = 32;

/// Per-peer timer wheel for outbound delivery leases. The allocation keeps
/// every counter at a stable address while `Peer` moves in its hash map.
/// Access is confined to NetworkTile, so the counters are `Cell`s rather than
/// atomics.
pub(crate) struct OutboundLeaseWheel {
    counts: [Cell<u32>; OUTBOUND_LEASE_BUCKETS],
    /// Bucket inspected at `next_tick`.
    head: Cell<usize>,
    next_tick: Cell<Instant>,
    /// Set once the connection starts teardown. Buckets are never reused after
    /// this point, but late Quinn drops still decrement their original count.
    terminal: Cell<bool>,
}

impl OutboundLeaseWheel {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            counts: std::array::from_fn(|_| Cell::new(0)),
            head: Cell::new(0),
            next_tick: Cell::new(now + OUTBOUND_LEASE_TICK),
            terminal: Cell::new(false),
        }
    }

    pub(crate) fn leased<T>(&self, value: T, now: Instant) -> Leased<T> {
        Leased { value, lease: self.lease(now) }
    }

    fn lease(&self, now: Instant) -> OutboundLease {
        assert!(!self.terminal.get(), "cannot acquire a terminal outbound lease wheel");
        assert!(
            now < self.next_tick.get(),
            "outbound lease wheel must be advanced before acquiring"
        );

        // Round up to a bucket boundary so a lease never expires early.
        let until = (now + GOSSIP_DELIVERY_TIMEOUT).saturating_duration_since(self.next_tick.get());
        let tick_nanos = OUTBOUND_LEASE_TICK.as_nanos();
        let ticks = until.as_nanos().div_ceil(tick_nanos) as usize;
        assert!(ticks < OUTBOUND_LEASE_BUCKETS, "delivery timeout exceeds wheel horizon");

        let bucket = (self.head.get() + ticks) % OUTBOUND_LEASE_BUCKETS;
        self.increment(bucket);
        OutboundLease { wheel: NonNull::from(self), bucket }
    }

    fn increment(&self, bucket: usize) {
        let count = &self.counts[bucket];
        count.set(count.get().checked_add(1).expect("outbound lease count overflow"));
    }

    /// Process every elapsed bucket. A non-zero expired bucket is terminal:
    /// callers close the peer, so it is neither cleared nor reused while late
    /// `Bytes` drops may still refer to it.
    fn expire(&self, now: Instant) -> Option<u32> {
        if self.terminal.get() {
            return None;
        }
        if now < self.next_tick.get() {
            return None;
        }

        // With no leases there is no phase to preserve. Rebase directly after
        // a long idle period instead of rotating once per elapsed second.
        if self.counts.iter().all(|count| count.get() == 0) {
            if now >= self.next_tick.get() {
                self.head.set(0);
                self.next_tick.set(now + OUTBOUND_LEASE_TICK);
            }
            return None;
        }

        while now >= self.next_tick.get() {
            let head = self.head.get();
            let retained = self.counts[head].get();
            if retained != 0 {
                self.terminal.set(true);
                return Some(retained);
            }
            self.head.set((head + 1) % OUTBOUND_LEASE_BUCKETS);
            self.next_tick.set(self.next_tick.get() + OUTBOUND_LEASE_TICK);
        }
        None
    }

    fn deadline(&self) -> Option<Instant> {
        if self.terminal.get() {
            return None;
        }
        self.counts.iter().enumerate().find_map(|(offset, _)| {
            let bucket = (self.head.get() + offset) % OUTBOUND_LEASE_BUCKETS;
            (self.counts[bucket].get() != 0)
                .then_some(self.next_tick.get() + OUTBOUND_LEASE_TICK * offset as u32)
        })
    }

    fn terminate(&self) {
        self.terminal.set(true);
    }

    pub(crate) fn active_count(&self) -> u64 {
        self.counts.iter().map(|count| u64::from(count.get())).sum()
    }
}

impl Drop for OutboundLeaseWheel {
    fn drop(&mut self) {
        debug_assert_eq!(self.active_count(), 0, "outbound lease wheel dropped with active leases");
    }
}

#[derive(Debug)]
struct OutboundLease {
    wheel: NonNull<OutboundLeaseWheel>,
    bucket: usize,
}

// SAFETY: `Bytes::from_owner` requires its owner to be `Send`, but all
// creation and destruction remains confined to NetworkTile. The wheel
// outlives every lease by `Peer` field drop order, documented on its field.
unsafe impl Send for OutboundLease {}

impl Clone for OutboundLease {
    fn clone(&self) -> Self {
        // SAFETY: the boxed wheel has a stable address and outlives every
        // root and child lease.
        unsafe { self.wheel.as_ref() }.increment(self.bucket);
        Self { wheel: self.wheel, bucket: self.bucket }
    }
}

impl Drop for OutboundLease {
    fn drop(&mut self) {
        // SAFETY: the boxed wheel has a stable address and is declared after
        // every Peer field that can contain a Quinn-owned `Bytes` clone.
        let wheel = unsafe { self.wheel.as_ref() };
        let count = &wheel.counts[self.bucket];
        count.set(count.get().checked_sub(1).expect("outbound lease count underflow"));
    }
}

/// Value carrying one reference to its original enqueue-time delivery lease.
/// Moving the wrapper preserves the lease; `child` deliberately forks another
/// reference in the same timeout bucket for a Quinn-owned body segment.
#[derive(Debug)]
pub(crate) struct Leased<T> {
    value: T,
    lease: OutboundLease,
}

impl<T> Leased<T> {
    pub(crate) fn child<U>(&self, value: U) -> Leased<U> {
        Leased { value, lease: self.lease.clone() }
    }
}

impl<T> Deref for Leased<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Leased<T> {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

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
    /// A sent Goodbye awaiting delivery before the connection closes:
    /// (stream, linger deadline). Closing inline would race quinn's
    /// transmit and drop the goodbye bytes. The ack (`StreamEvent::
    /// Finished`) closes promptly; the deadline bounds a non-acking peer.
    /// A repeated goodbye re-arms the stream id but keeps the earliest
    /// deadline, so retries can't defer the close.
    pending_shutdown: Option<(StreamId, Instant)>,
    /// Must remain the final field: Quinn-owned `Bytes` in `connection` and
    /// queued stream state must drop before leases can no longer reach this
    /// stable allocation.
    outbound_lease_wheel: Box<OutboundLeaseWheel>,
}

impl Peer {
    /// `peer_id`: the dialed identity for outbound connections (known
    /// up-front and TLS-pinned); `PeerId::default()` for inbound until the
    /// handshake reveals it.
    pub(crate) fn new(handle: ConnectionHandle, connection: Connection, peer_id: PeerId) -> Self {
        let now = Instant::now();
        Self {
            id: RemotePeer { peer_id, connection: handle.0, addr: connection.remote_address() },
            handle,
            connection,
            streams: FxHashMap::with_capacity_and_hasher(16, BuildHasherDefault::default()),
            inbound_gossip: None,
            outbound_gossip: None,
            created_at: now,
            handshake_completed: false,
            inbound_rpc_limits: RpcRateLimitSet::default(),
            next_deadline: None,
            // Born dirty: a dial must emit its handshake, an accept its
            // response — neither has a quinn event to trigger the first poll.
            dirty: true,
            wake_at: None,
            pending_shutdown: None,
            outbound_lease_wheel: Box::new(OutboundLeaseWheel::new(now)),
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
        self.wake_at = [
            self.connection.poll_timeout(),
            self.next_deadline,
            self.pending_shutdown.map(|(_, at)| at),
            self.outbound_lease_wheel.deadline(),
        ]
        .into_iter()
        .flatten()
        .min();
    }

    pub(crate) fn send_gossip(&mut self, msg: TRead) -> SendResult {
        if self.connection.is_closed() {
            return SendResult::ConnectionClosing;
        }
        let now = Instant::now();
        if self.check_outbound_delivery_timeout(now) {
            return SendResult::ConnectionClosing;
        }
        self.dirty = true;
        let stream_id = match self.outbound_gossip {
            Some(id) => id,
            None => match self.open_stream(StreamProtocol::GossipSub) {
                Some(id) => {
                    self.outbound_gossip.replace(id);
                    id
                }
                None => return SendResult::StreamCreationError,
            },
        };
        let msg = self.outbound_lease_wheel.leased(msg, now);
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            if let OutboundBuffer::Gossip(buffer) = &mut stream.out_buffer {
                let dropped = buffer.add_msg(msg);
                stream.needs_spin = true;
                return if dropped { SendResult::MessageDropped } else { SendResult::Ok };
            }
        }
        SendResult::StreamCreationError
    }

    fn check_outbound_delivery_timeout(&mut self, now: Instant) -> bool {
        if self.connection.is_closed() {
            self.outbound_lease_wheel.terminate();
            return false;
        }
        if let Some(retained) = self.outbound_lease_wheel.expire(now) {
            tracing::warn!(id = ?self.id, retained, "outbound gossip delivery timeout");
            self.disconnect_on_stall(now);
            return true;
        }
        false
    }

    pub(crate) fn send_rpc(&mut self, msg: AcquiredRpcOutbound) -> SendResult {
        if self.connection.is_closed() {
            return SendResult::ConnectionClosing;
        }
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
                    Some(stream) => {
                        stream.last_activity = Instant::now();
                        stream
                    }
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
        if self.connection.is_closed() {
            return SendResult::ConnectionClosing;
        }
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
        self.pending_shutdown = None;
        self.outbound_lease_wheel.terminate();
        self.connection.close(now, VarInt::from_u32(0), Bytes::new());
        self.clear_streams();
    }

    /// A stalled gossip stream costs the connection, not just the stream:
    /// reopening on the same connection spends one of rust-libp2p's five
    /// per-connection substream attempts, after which the remote disables
    /// gossipsub on it silently. A redial gives both sides a fresh budget.
    fn disconnect_on_stall(&mut self, now: Instant) {
        crate::NetworkCounters::GossipStallDisconnect.inc();
        tracing::warn!(id = ?self.id, "gossip stall: closing connection");
        self.shutdown(now);
    }

    /// Drop every stream state — and the queued messages (and tcache
    /// acquires) in their outbound buffers — as soon as the connection can
    /// no longer deliver, rather than at the drained reap up to 3×PTO later.
    /// No per-stream `StreamClosed` events: the PM tears the peer down on
    /// disconnect, and a close event for an outgoing RPC would read as the
    /// peer abandoning a response.
    fn clear_streams(&mut self) {
        self.streams.clear();
        self.inbound_gossip = None;
        self.outbound_gossip = None;
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
            last_activity: Instant::now(),
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

        if self.pending_shutdown.is_some_and(|(_, at)| now >= at) {
            self.shutdown(now);
        }

        while let Some(ep_event) = self.connection.poll_endpoint_events() {
            if let Some(conn_event) = (ep_callback)(self.handle, ep_event) {
                self.connection.handle_event(conn_event);
            }
        }

        // Feeding datagrams to `Connection::handle_event` releases newly
        // ACKed send-buffer owners synchronously. Inspect and advance the
        // wheel now, before a queued Writable event can create another lease.
        if self.check_outbound_delivery_timeout(now) {
            return;
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
                    self.clear_streams();
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
        let (to_remove, stalled) = spin_streams(
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
            self.end_stream(id, now);
        }
        if stalled {
            self.disconnect_on_stall(now);
        }

        // Read-response timeouts only fire inside a spin; sweep everything
        // when the earliest deadline lapses.
        if self.next_deadline.is_some_and(|d| now >= d) {
            self.next_deadline = None;
            let (to_remove, stalled) = spin_streams(
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
                self.end_stream(id, now);
            }
            if stalled {
                self.disconnect_on_stall(now);
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
        if let SpinResult::Stalled = result {
            self.disconnect_on_stall(now);
            return;
        }
        if let SpinResult::End = result {
            self.end_stream(id, now);
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
                        last_activity: Instant::now(),
                    });
                    on_event(NetEvent::StreamReady { stream: p2p_id });
                    tracing::debug!(?p2p_id, "stream open");
                }
            }
            quinn_proto::StreamEvent::Readable { id } |
            quinn_proto::StreamEvent::Writable { id } => {
                if let Some(stream) = self.streams.get_mut(&id) {
                    stream.last_activity = now;
                }
                self.spin_stream(id, now, context, on_event);
            }
            quinn_proto::StreamEvent::Finished { id } => {
                // This event is emitted after we call 'finish()' on the send side of
                // the stream. Indicates that data was sent and acked.
                tracing::debug!(?id, "send half finished");
                // Goodbye acked: safe to hang up without dropping it.
                if self.pending_shutdown.is_some_and(|(gid, _)| gid == id) {
                    self.shutdown(now);
                    return;
                }
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
                    let ended = matches!(
                        stream.stop_send(error_code, &mut self.connection, on_event),
                        SpinResult::End
                    );

                    if ended &&
                        p2p_id.protocol() == StreamProtocol::Goodbye &&
                        !p2p_id.is_incoming()
                    {
                        // There are no Goodbye bytes left to flush once the
                        // remote has stopped the send side. Tear down now
                        // instead of arming the delivery linger.
                        self.remove_stream(id);
                        self.shutdown(now);
                        return;
                    }

                    if let Some(out_id) = self.outbound_gossip &&
                        out_id == id
                    {
                        // peer has asked to stop receiving gossip
                        self.remove_stream(id);
                        self.outbound_gossip.take();
                        on_event(NetEvent::StreamClosed { stream: p2p_id })
                    } else if ended {
                        self.end_stream(id, now);
                    }
                }
            }
            quinn_proto::StreamEvent::Available { dir: _ } => {}
        }
    }

    /// Stream state machine reached its end. A flushed outbound Goodbye
    /// additionally closes the whole connection — the goodbye contract:
    /// send, then hang up. Inbound goodbye streams don't shut down here;
    /// the PM owns that disconnect (and a rate-limit-dropped goodbye flood
    /// must not hand the flooder a connection close).
    fn end_stream(&mut self, id: StreamId, now: Instant) {
        if let Some(stream) = self.streams.get(&id) &&
            stream.p2p_id.protocol() == StreamProtocol::Goodbye &&
            !stream.p2p_id.is_incoming()
        {
            let deadline = self
                .pending_shutdown
                .map_or(now + GOODBYE_LINGER, |(_, at)| at.min(now + GOODBYE_LINGER));
            self.pending_shutdown = Some((id, deadline));
        }
        self.remove_stream(id);
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
) -> (ArrayVec<StreamId, 64>, bool)
where
    E: FnMut(crate::NetEvent),
{
    let mut to_remove = ArrayVec::new();
    let mut stalled = false;
    for (id, stream) in streams {
        if !all && !stream.needs_spin {
            continue;
        }

        if to_remove.is_full() {
            break;
        }

        let result = stream.spin(connection, context, now, inbound_rpc_limits, on_event);
        if let SpinResult::Stalled = result {
            stalled = true;
            to_remove.push(*id);
            continue;
        }
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
    (to_remove, stalled)
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
        StreamProtocol::GossipSub => OutboundBuffer::Gossip(OutBuffer::new(8 * 1024)),
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
    /// Last observed progress (event-driven only — the periodic sweep must
    /// not touch it, or the idle timeout never fires).
    last_activity: Instant,
}

enum SpinResult {
    Ok,
    End,
    /// Gossip stream stalled: the owner closes the whole connection.
    Stalled,
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
        // aged `IncomingRpc` census entries from teku). Idle-based, so a
        // long multi-chunk serve to a slow-but-progressing peer survives.
        if matches!(self.state.get_mut(), StreamState::IncomingRpc { .. }) &&
            now >= self.last_activity + INBOUND_RPC_IDLE_TIMEOUT
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
                if matches!(e, StreamError::GossipReadStall) {
                    SpinResult::Stalled
                } else {
                    SpinResult::End
                }
            }
        }
    }

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
        let _ =
            connection.send_stream(id).reset(VarInt::from_u32(STREAM_ERR_CODE_RESPONSE_TIMEOUT));
        let _ = connection.recv_stream(id).stop(VarInt::from_u32(STREAM_ERR_CODE_RESPONSE_TIMEOUT));
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
            Some(self.last_activity + INBOUND_RPC_IDLE_TIMEOUT)
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
    Gossip(OutBuffer<Leased<TRead>>),
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

pub(super) struct OutBuffer<T> {
    msgs: Box<[Option<T>]>,
    len: usize,
    head: usize,
    tail: usize,
}

impl<T> OutBuffer<T> {
    fn new(len: usize) -> Self {
        assert!(len.is_power_of_two());
        let msgs = std::iter::repeat_with(|| None).take(len).collect();
        Self { msgs, len, head: 0, tail: 0 }
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
        struct Item(usize);

        let mut buf = OutBuffer::new(4);
        for i in 0..4usize {
            assert!(!buf.add_msg(Item(i)));
        }

        // Two overwrites drop the two oldest messages.
        assert!(buf.add_msg(Item(4)));
        assert!(buf.add_msg(Item(5)));
        assert_eq!(buf.len(), 4);

        let drained: Vec<_> = std::iter::from_fn(|| buf.pop()).map(|u| u.0).collect();
        assert_eq!(drained, vec![2, 3, 4, 5]);
        assert!(buf.is_empty());
        assert!(buf.pop().is_none());

        // Buffer must remain usable after an overflow episode.
        assert!(!buf.add_msg(Item(6)));
        assert_eq!(buf.pop().map(|u| u.0), Some(6));
        assert!(buf.is_empty());
    }

    #[test]
    fn outbound_lease_wheel_drop_cancels_lease_after_box_moves() {
        let t0 = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(t0));
        let lease = wheel.lease(t0);
        assert_eq!(wheel.active_count(), 1);
        assert_eq!(wheel.deadline(), Some(t0 + GOSSIP_DELIVERY_TIMEOUT));

        // Moving the Box (as the peer map may move `Peer`) does not move the
        // allocation addressed by the lease.
        let moved = wheel;
        assert_eq!(moved.expire(t0 + GOSSIP_DELIVERY_TIMEOUT - Duration::from_nanos(1)), None);
        drop(lease);

        assert_eq!(moved.active_count(), 0);
        assert_eq!(moved.deadline(), None);
        assert_eq!(moved.expire(t0 + GOSSIP_DELIVERY_TIMEOUT), None);
    }

    #[test]
    fn outbound_lease_wheel_expires_retained_lease_and_accepts_late_drop() {
        let t0 = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(t0));
        let released = wheel.lease(t0);
        let retained = wheel.lease(t0);
        drop(released);

        assert_eq!(wheel.active_count(), 1);
        assert_eq!(wheel.expire(t0 + GOSSIP_DELIVERY_TIMEOUT - Duration::from_nanos(1)), None);
        assert_eq!(wheel.expire(t0 + GOSSIP_DELIVERY_TIMEOUT), Some(1));
        assert_eq!(wheel.deadline(), None, "a terminal wheel must not re-arm");

        // Connection teardown can release Quinn's owner after we detect the
        // timeout. Its original bucket remains live until that drop.
        drop(retained);
        assert_eq!(wheel.active_count(), 0);
    }

    #[test]
    fn outbound_lease_wheel_rounds_expiry_up_to_tick() {
        let t0 = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(t0));
        let acquired = t0 + Duration::from_millis(1);
        let lease = wheel.lease(acquired);
        let rounded_deadline = t0 + GOSSIP_DELIVERY_TIMEOUT + OUTBOUND_LEASE_TICK;

        assert_eq!(wheel.deadline(), Some(rounded_deadline));
        assert_eq!(wheel.expire(rounded_deadline - Duration::from_nanos(1)), None);
        assert_eq!(wheel.expire(rounded_deadline), Some(1));
        drop(lease);
    }

    #[test]
    fn outbound_lease_wheel_rebases_before_first_lease_after_idle() {
        let t0 = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(t0));
        let after_idle = t0 + Duration::from_secs(60);

        assert_eq!(wheel.expire(after_idle), None);
        let lease = wheel.lease(after_idle);
        assert_eq!(wheel.deadline(), Some(after_idle + GOSSIP_DELIVERY_TIMEOUT));
        drop(lease);
    }

    #[test]
    fn leased_child_keeps_the_enqueue_deadline_after_root_drops() {
        let t0 = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(t0));
        let root = wheel.leased(1u8, t0);
        assert_eq!(wheel.expire(t0 + GOSSIP_DELIVERY_TIMEOUT / 2), None);
        let child = root.child(2u8);

        assert_eq!(wheel.active_count(), 2);
        assert_eq!(wheel.deadline(), Some(t0 + GOSSIP_DELIVERY_TIMEOUT));
        drop(root);
        assert_eq!(wheel.active_count(), 1);
        assert_eq!(wheel.deadline(), Some(t0 + GOSSIP_DELIVERY_TIMEOUT));

        drop(child);
        assert_eq!(wheel.active_count(), 0);
        assert_eq!(wheel.deadline(), None);
    }

    #[test]
    fn out_buffer_overflow_releases_evicted_delivery_lease() {
        let t0 = Instant::now();
        let wheel = Box::new(OutboundLeaseWheel::new(t0));
        let mut buffer = OutBuffer::new(2);

        assert!(!buffer.add_msg(wheel.leased(1u8, t0)));
        assert!(!buffer.add_msg(wheel.leased(2u8, t0)));
        assert_eq!(wheel.active_count(), 2);

        assert!(buffer.add_msg(wheel.leased(3u8, t0)));
        assert_eq!(wheel.active_count(), 2, "overwrite must drop the oldest root lease");

        drop(buffer);
        assert_eq!(wheel.active_count(), 0);
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
        let mut client_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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

    #[test]
    fn stopped_outbound_goodbye_closes_connection() {
        let mut client_h = PeerHarness::new();
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let stream = pair.client_peer.open_stream(StreamProtocol::Goodbye).unwrap();

        let mut on_event = |_: NetEvent| {};
        pair.client_peer.handle_stream_event(
            quinn_proto::StreamEvent::Stopped { id: stream, error_code: VarInt::from_u32(0) },
            now,
            &mut client_h.context,
            &mut on_event,
        );

        assert!(pair.client_peer.connection.is_closed());
        assert!(!pair.client_peer.streams.contains_key(&stream));
    }

    #[test]
    fn stopped_outbound_gossip_keeps_connection_open() {
        let mut client_h = PeerHarness::new();
        let mut pair = PeerPair::new();
        let now = Instant::now();
        let stream = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();

        let mut on_event = |_: NetEvent| {};
        pair.client_peer.handle_stream_event(
            quinn_proto::StreamEvent::Stopped { id: stream, error_code: VarInt::from_u32(0) },
            now,
            &mut client_h.context,
            &mut on_event,
        );

        assert!(!pair.client_peer.connection.is_closed());
        assert!(!pair.client_peer.streams.contains_key(&stream));
    }

    /// Closing drops stream state (and the queued acquires in its buffers)
    /// immediately on both ends — locally at `shutdown`, remotely on
    /// `ConnectionLost` — instead of holding it until the drained reap, and
    /// a send into a closing connection is refused rather than misreported
    /// as stream-credit exhaustion.
    #[test]
    fn closing_connection_refuses_sends_and_drops_streams() {
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let now = Instant::now();
        let mut pair = PeerPair::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );
        client_h.send_gossip(stream_id, b"ping", &mut pair.client_peer);
        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| !s.received.is_empty());
        assert!(!pair.server_peer.streams.is_empty(), "server holds the inbound gossip stream");

        pair.client_peer.shutdown(now);
        assert!(pair.client_peer.streams.is_empty(), "local close drops streams at once");
        assert!(pair.client_peer.outbound_gossip.is_none());
        let mut res = client_h.gossip_out_producer.reserve(4, true).unwrap();
        res.write_all(b"late").unwrap();
        let late = client_h.context.gossip_consumer.acquire(res.read());
        assert!(matches!(pair.client_peer.send_gossip(late), SendResult::ConnectionClosing));
        assert!(pair.client_peer.streams.is_empty(), "refused send opens nothing");

        let mut noop_c = |_: NetEvent| {};
        let mut noop_s = |_: NetEvent| {};
        for _ in 0..200 {
            pair.step(now, &mut client_h, &mut server_h, &mut noop_c, &mut noop_s);
            if pair.server_peer.connection.is_closed() {
                break;
            }
        }
        assert!(pair.server_peer.connection.is_closed(), "CONNECTION_CLOSE must reach the server");
        assert!(pair.server_peer.streams.is_empty(), "connection loss drops the server's streams");
    }

    /// A gossip stall (here: the server's inbound frame parked mid-body past
    /// the window) closes the connection rather than just the stream.
    #[test]
    fn gossip_stall_closes_connection() {
        use crate::p2p::streams::{
            gossip_in::{GOSSIP_BODY_STALL_TIMEOUT, GossipReadState},
            gossip_out::GossipWriteState,
        };

        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );
        client_h.send_gossip(stream_id, b"ping", &mut pair.client_peer);
        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| !s.received.is_empty());

        let t0 = Instant::now();
        let stalled_since = t0 - GOSSIP_BODY_STALL_TIMEOUT - Duration::from_secs(1);
        let reservation = server_h.context.gossip_producer.reserve(100, false).expect("reserve");
        let stream = pair
            .server_peer
            .streams
            .values_mut()
            .find(|s| s.p2p_id.protocol() == StreamProtocol::GossipSub)
            .expect("inbound gossip stream");
        stream.state.replace(StreamState::Gossip {
            read: GossipReadState::ReadingBody {
                reservation,
                remaining: 90,
                last_read: stalled_since,
            },
            write: GossipWriteState::Idle,
        });
        stream.needs_spin = true;

        let PeerPair { server_ep, server_peer, .. } = &mut pair;
        let mut cb = |h, e| server_ep.handle_event(h, e);
        let mut on_event = |_: NetEvent| {};
        server_peer.spin(t0, &mut cb, &mut server_h.context, &mut on_event, &FxHashSet::default());

        assert!(server_peer.connection.is_closed(), "stall must close the connection");
        assert!(server_peer.streams.is_empty(), "closing drops every stream");
    }

    #[test]
    fn retained_outbound_gossip_lease_closes_connection() {
        let mut client_h = PeerHarness::new();
        let mut pair = PeerPair::new();
        let now = Instant::now();

        // Place one synthetic delivery lease exactly at its deadline. The
        // connection itself sees current time, so this specifically exercises
        // the outbound watchdog rather than QUIC's idle timeout.
        let acquired = now - GOSSIP_DELIVERY_TIMEOUT;
        pair.client_peer.outbound_lease_wheel = Box::new(OutboundLeaseWheel::new(acquired));
        let retained = pair.client_peer.outbound_lease_wheel.lease(acquired);
        assert_eq!(pair.client_peer.outbound_lease_wheel.deadline(), Some(now));

        let PeerPair { client_ep, client_peer, .. } = &mut pair;
        let mut cb = |h, e| client_ep.handle_event(h, e);
        let mut on_event = |_: NetEvent| {};
        client_peer.spin(now, &mut cb, &mut client_h.context, &mut on_event, &FxHashSet::default());

        assert!(client_peer.connection.is_closed(), "delivery timeout must close the connection");
        assert!(client_peer.streams.is_empty(), "closing drops every stream");
        assert!(client_peer.outbound_lease_wheel.terminal.get());

        // Model Quinn releasing its send buffer during the later connection
        // drop: terminal buckets remain valid for late lease destruction.
        drop(retained);
        assert_eq!(client_peer.outbound_lease_wheel.active_count(), 0);
    }

    /// A negotiated inbound RPC stream whose request never arrives must be
    /// reaped by `INBOUND_RPC_IDLE_TIMEOUT` — only the server is spun past the
    /// deadline, so the reap can't be masked by the client's own teardown.
    #[test]
    fn inbound_rpc_timeout_reaps_unanswered_stream() {
        use silver_common::{RpcInbound, RpcOutbound, RpcRequest, RpcRequestOutbound};

        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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
            t0 + INBOUND_RPC_IDLE_TIMEOUT + Duration::from_secs(1),
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
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

        let sid = pair.client_peer.open_stream(StreamProtocol::GossipSub).unwrap();
        let stream_id = P2pStreamId::new(
            pair.client_peer.id.connection,
            sid.into(),
            StreamProtocol::GossipSub,
            false,
        );

        let payload = b"hello from the client side".to_vec();
        client_h.send_gossip(stream_id, &payload, &mut pair.client_peer);
        assert_eq!(
            pair.client_peer.outbound_lease_wheel.active_count(),
            1,
            "enqueue must create the root delivery lease"
        );

        wait_for(&mut pair, &mut client_h, &mut server_h, 200, |_, s| !s.received.is_empty());

        let data: Vec<u8> = server_h.received.values().flat_map(|v| v.clone()).collect();
        assert_eq!(data, payload);
        assert_eq!(
            pair.client_peer.outbound_lease_wheel.active_count(),
            0,
            "the sender's ACK must release its tracked tcache owner"
        );
    }

    #[test]
    fn bidirectional_data_transfer() {
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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
        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let mut pair = PeerPair::new();

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
    /// Regression: the goodbye-then-shutdown path closed the connection in
    /// the same spin that buffered the goodbye bytes, so quinn dropped them
    /// and the peer saw a bare CONNECTION_CLOSE. The close must wait for the
    /// goodbye's ack (linger-bounded).
    #[test]
    fn goodbye_delivered_before_shutdown() {
        use silver_common::{RpcInbound, RpcOutbound, RpcRequest, RpcRequestOutbound};

        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let now = Instant::now();
        let mut pair = PeerPair::new();

        let goodbye = RpcOutbound::Request(RpcRequestOutbound {
            application_id: 0,
            peer: pair.client_peer.id.connection,
            request: RpcRequest::Goodbye(129u64.to_le_bytes()),
        });
        let msg = AcquiredRpcOutbound::from((goodbye, &mut client_h.context.rpc_consumer));
        assert!(matches!(pair.client_peer.send_rpc(msg), SendResult::Ok));

        // Fixed `now`: the linger deadline never lapses, so the close can
        // only come from the goodbye's ack — the property under test.
        let mut server_got_goodbye = false;
        for _ in 0..300 {
            let mut ccb = |_: NetEvent| {};
            let mut scb = |e: NetEvent| {
                if let NetEvent::RpcInbound(RpcInbound::Request(req)) = e &&
                    matches!(req.request, RpcRequest::Goodbye(code) if u64::from_le_bytes(code) == 129)
                {
                    server_got_goodbye = true;
                }
            };
            pair.step(now, &mut client_h, &mut server_h, &mut ccb, &mut scb);
            if server_got_goodbye && pair.client_peer.connection.is_closed() {
                break;
            }
        }
        assert!(server_got_goodbye, "goodbye must reach the peer, not be dropped by the close");
        assert!(pair.client_peer.connection.is_closed(), "acked goodbye must close the connection");
    }

    #[test]
    fn requester_teardown_after_response_is_clean() {
        use silver_common::{
            RpcInbound, RpcOutbound, RpcRequest, RpcRequestOutbound, RpcResponse,
            RpcResponseOutbound, ssz_view::STATUS_V2_SIZE,
        };

        let mut client_h = PeerHarness::new();
        let mut server_h = PeerHarness::new();
        let now = Instant::now();
        let mut pair = PeerPair::new();

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
