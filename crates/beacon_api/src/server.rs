use std::{
    cell::Cell,
    collections::HashMap,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use mio::{Events, Interest, Registry, Token, event::Event};
use silver_beacon_state_data::{BeaconStateReader, SpecConfig};
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::{
    AfterResponse, Bind, ChunkedResponse, Listener, ParsedRequest, ServerConnection, Stream,
    TokenRange,
};

use crate::{
    NodeStatus,
    events::{self, Channel, ChannelSet, HeadEvent},
    json::Json,
    router::{Router, Served},
    routes::{ApiCtx, ROUTES},
};

const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// nginx's `lingering_close` caps: how long a connection that has already
/// answered may wait between the peer's bytes, and how long the whole drain
/// may run before the slot is taken back.
struct Linger {
    idle: Duration,
    total: Duration,
}

impl Default for Linger {
    fn default() -> Self {
        Self { idle: Duration::from_secs(5), total: Duration::from_secs(30) }
    }
}

/// Quiet subscriptions must survive the request idle timeout. Keep-alive
/// comments also exercise the write path when no events are published.
struct StreamLimits {
    send_deadline: Duration,
    keep_alive_every: Duration,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self { send_deadline: Duration::from_secs(30), keep_alive_every: Duration::from_secs(15) }
    }
}

struct Connection {
    stream: Stream,
    state: State,
}

enum State {
    Requests(Requests),
    Subscription(Subscription),
}

struct Requests {
    http: ServerConnection,
    last_activity: Instant,
    linger_since: Option<Instant>,
}

struct Subscription {
    body: ChunkedResponse,
    channels: ChannelSet,
}

impl Connection {
    fn new(stream: Stream, now: Instant) -> Self {
        Self { stream, state: State::Requests(Requests::new(now)) }
    }

    /// Buffered requests behind the subscription are abandoned; subsequent
    /// inbound bytes are discarded.
    fn subscribed(self, channels: ChannelSet, now: Instant) -> Self {
        let State::Requests(requests) = self.state else {
            unreachable!("only a request handler begins a stream")
        };
        let body = requests.http.into_stream(now);
        Self { stream: self.stream, state: State::Subscription(Subscription { body, channels }) }
    }

    fn expired(
        &self,
        now: Instant,
        idle_timeout: Duration,
        linger: &Linger,
        streams: &StreamLimits,
    ) -> bool {
        match &self.state {
            State::Requests(requests) => requests.expired(now, idle_timeout, linger),
            State::Subscription(subscription) => {
                subscription.body.stalled(now, streams.send_deadline)
            }
        }
    }

    fn handle_event<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
        &mut self,
        registry: &Registry,
        event: &Event,
        now: Instant,
        request_handler: &F,
    ) -> io::Result<bool> {
        match &mut self.state {
            State::Requests(requests) => {
                requests.handle_event(&mut self.stream, registry, event, now, request_handler)
            }
            State::Subscription(subscription) => {
                subscription.handle_event(&mut self.stream, registry, event, now)
            }
        }
    }
}

impl Requests {
    fn new(now: Instant) -> Self {
        Self { http: ServerConnection::new(), last_activity: now, linger_since: None }
    }

    /// A lingering connection has answered already, so it lives by the linger
    /// caps rather than by the idle deadline that holds a served connection
    /// open for its client's next request.
    fn expired(&self, now: Instant, idle_timeout: Duration, linger: &Linger) -> bool {
        let quiet_for = now.duration_since(self.last_activity);
        match self.linger_since {
            Some(since) => quiet_for > linger.idle || now.duration_since(since) > linger.total,
            None => quiet_for > idle_timeout,
        }
    }

    /// Draining unread input before closing avoids a TCP reset that could
    /// prevent the peer from receiving the response.
    fn drain(&mut self, stream: &mut Stream, now: Instant) -> bool {
        match drop_inbound(stream, self.http.discard_space()) {
            None => true,
            Some(0) => false,
            Some(_) => {
                self.last_activity = now;
                false
            }
        }
    }

    fn handle_event<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
        &mut self,
        stream: &mut Stream,
        registry: &Registry,
        event: &Event,
        now: Instant,
        request_handler: &F,
    ) -> io::Result<bool> {
        if self.linger_since.is_some() {
            return Ok(self.drain(stream, now));
        }

        if event.is_readable() {
            // A full buffer always leaves something to answer with: a body
            // declared past the cap is answered from headers already buffered,
            // and a head that outgrows the whole buffer is answered 431. The
            // answer, not the exhaustion, is what ends the connection.
            let mut exhausted = false;
            loop {
                let space = match self.http.read_space() {
                    Ok(space) => space,
                    Err(_) => {
                        exhausted = true;
                        break;
                    }
                };
                match stream.read(space) {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                    Ok(n) => {
                        self.last_activity = now;
                        self.http.commit_read(n);
                    }
                    Err(e) if would_block(&e) => break,
                    Err(e) if interrupted(&e) => continue,
                    Err(e) => return Err(e),
                }
            }

            let mut answered = self.http.dispatch(request_handler);
            if !answered && exhausted {
                self.http.reject_exhausted();
                answered = true;
            }
            if answered {
                registry.reregister(stream, event.token(), Interest::WRITABLE)?;
            }
            return Ok(false);
        }

        if event.is_writable() {
            if !self.http.pending_write().is_empty() {
                loop {
                    match stream.write(self.http.pending_write()) {
                        Ok(0) => {
                            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"))
                        }
                        Ok(n) => {
                            self.last_activity = now;
                            self.http.commit_write(n);
                            if self.http.pending_write().is_empty() {
                                break;
                            }
                        }
                        Err(e) if would_block(&e) => return Ok(false),
                        Err(e) if interrupted(&e) => continue,
                        Err(e) => return Err(e),
                    }
                }
                match self.http.after_response(request_handler) {
                    AfterResponse::Close => return Ok(true),
                    AfterResponse::Linger => {
                        // The FIN tells the peer its answer is whole while the
                        // socket stays readable, so a body still on its way is
                        // drained instead of resetting the connection that
                        // carried the answer.
                        stream.shutdown_write()?;
                        self.linger_since = Some(now);
                        registry.reregister(stream, event.token(), Interest::READABLE)?;
                        return Ok(self.drain(stream, now));
                    }
                    AfterResponse::ResponsePending => {
                        registry.reregister(stream, event.token(), Interest::WRITABLE)?
                    }
                    AfterResponse::AwaitRequest => {
                        registry.reregister(stream, event.token(), Interest::READABLE)?
                    }
                }
            }
            return Ok(false);
        }

        Ok(false)
    }
}

impl Subscription {
    fn handle_event(
        &mut self,
        stream: &mut Stream,
        registry: &Registry,
        event: &Event,
        now: Instant,
    ) -> io::Result<bool> {
        if event.is_readable() && drop_inbound(stream, self.body.discard_space()).is_none() {
            return Ok(true);
        }

        if event.is_writable() {
            while !self.body.pending_write().is_empty() {
                match stream.write(self.body.pending_write()) {
                    Ok(0) => {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"))
                    }
                    Ok(n) => self.body.commit_write(n, now),
                    Err(e) if would_block(&e) => return Ok(false),
                    Err(e) if interrupted(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
            registry.reregister(stream, event.token(), Interest::READABLE)?;
        }

        Ok(false)
    }
}

/// Returns the bytes discarded before `WouldBlock`, or `None` on EOF or
/// an unrecoverable read error.
fn drop_inbound(stream: &mut Stream, scratch: &mut [u8]) -> Option<usize> {
    let mut dropped = 0;
    loop {
        match stream.read(scratch) {
            Ok(0) => return None,
            Ok(n) => dropped += n,
            Err(e) if would_block(&e) => return Some(dropped),
            Err(e) if interrupted(&e) => continue,
            Err(_) => return None,
        }
    }
}

/// Schedules the idle scan so that `pump` walks the connection map at most
/// once per `interval` instead of on every busy-poll iteration.
struct IdleSweep {
    timeout: Duration,
    interval: Duration,
    next: Instant,
}

impl IdleSweep {
    fn new(timeout: Duration) -> Self {
        let interval = MAX_SWEEP_INTERVAL.min(timeout / 4);
        Self { timeout, interval, next: Instant::now() + interval }
    }

    fn due(&mut self, now: Instant) -> bool {
        if now < self.next {
            return false;
        }
        self.next = now + self.interval;
        true
    }
}

pub struct BeaconApi {
    registry: Registry,
    tokens: TokenRange,
    listeners: Vec<Listener>,
    max_connections: usize,
    idle: IdleSweep,
    linger: Linger,
    streams: StreamLimits,
    last_keep_alive: Instant,
    next_connection_offset: usize,
    connections: HashMap<Token, Connection>,
    router: Router,
    ctx: ApiCtx,
}

impl BeaconApi {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        binds: &[Bind],
        max_connections: usize,
        idle_timeout: Duration,
        keypair: &Keypair,
        local_enr: Enr,
        identify: &Identify,
        spec: &SpecConfig,
        state: BeaconStateReader,
    ) -> Self {
        assert!(!binds.is_empty(), "beacon api needs at least one bind");
        let tokens_needed = binds.len().checked_add(max_connections);
        assert!(
            tokens_needed.is_some_and(|needed| needed <= tokens.span()),
            "beacon api needs a token per listener and per connection: {} listeners plus a cap \
             of {max_connections} does not fit a span of {}",
            binds.len(),
            tokens.span()
        );

        let registry = registry.try_clone().expect("mio Registry::try_clone failed");
        let listeners = binds
            .iter()
            .enumerate()
            .map(|(index, bind)| {
                let mut listener = Listener::bind(bind)
                    .unwrap_or_else(|e| panic!("beacon api bind {bind:?}: {e}"));
                registry.register(&mut listener, tokens.at(index), Interest::READABLE).unwrap();
                listener
            })
            .collect::<Vec<_>>();

        Self {
            registry,
            tokens,
            max_connections,
            idle: IdleSweep::new(idle_timeout),
            linger: Linger::default(),
            streams: StreamLimits::default(),
            last_keep_alive: Instant::now(),
            next_connection_offset: listeners.len(),
            listeners,
            connections: HashMap::new(),
            router: Router::new(ROUTES),
            ctx: ApiCtx::new(keypair, &local_enr, identify, spec, state),
        }
    }

    pub fn local_addrs(&self) -> Vec<Bind> {
        self.listeners.iter().map(Listener::local_addr).collect()
    }

    /// In-place update seam for the status's single writer.
    pub fn node_status_mut(&mut self) -> &mut NodeStatus {
        &mut self.ctx.node_status
    }

    /// Import notifications can precede payload validation, so events are
    /// marked optimistic without consulting the current verdict. Repeated
    /// notifications are not deduplicated.
    pub fn publish_block(&mut self, slot: u64, block_root: &[u8; 32]) {
        let mut data = Vec::new();
        Json::new(&mut data).block_event(slot, block_root, true);
        self.publish(Channel::Block, "block", &data);
    }

    /// Head-change detection belongs to the caller.
    pub fn publish_head(&mut self, head: &HeadEvent) {
        let mut data = Vec::new();
        Json::new(&mut data).head_event(head);
        self.publish(Channel::Head, "head", &data);
    }

    pub fn publish_head_v2(&mut self, head: &HeadEvent) {
        let mut data = Vec::new();
        Json::new(&mut data).head_v2_event(head, self.ctx.spec.fork_at_slot(head.slot).name());
        self.publish(Channel::HeadV2, "head_v2", &data);
    }

    fn publish(&mut self, channel: Channel, event: &str, data: &[u8]) {
        let mut frame = Vec::new();
        events::frame(&mut frame, event, data);
        self.fan_out(
            |subscription| subscription.channels.contains(channel),
            &frame,
            Instant::now(),
        );
    }

    /// Returns whether any output was queued, so the pump can report work.
    fn fan_out(
        &mut self,
        wants: impl Fn(&Subscription) -> bool,
        chunk: &[u8],
        now: Instant,
    ) -> bool {
        let Self { connections, registry, .. } = self;
        let mut pushed = false;
        connections.retain(|token, conn| {
            let State::Subscription(subscription) = &mut conn.state else { return true };
            if !wants(subscription) {
                return true;
            }
            if !subscription.body.push(chunk, now) {
                tracing::warn!(
                    "beacon api subscriber would exceed send cap with {} bytes already pending, closing",
                    subscription.body.pending_write().len()
                );
                let _ = registry.deregister(&mut conn.stream);
                return false;
            }
            pushed = true;
            let interest = Interest::READABLE | Interest::WRITABLE;
            if let Err(e) = registry.reregister(&mut conn.stream, *token, interest) {
                tracing::warn!("beacon api subscriber lost: {e}");
                let _ = registry.deregister(&mut conn.stream);
                return false;
            }
            true
        });
        pushed
    }

    pub fn pump(&mut self, events: &Events) -> bool {
        let now = Instant::now();

        let mut did_work = false;
        for event in events.iter() {
            // The batch is the whole loop's; only tokens inside this server's
            // range are its own sockets.
            let Some(offset) = self.tokens.offset_of(event.token()) else { continue };
            did_work |= if offset < self.listeners.len() {
                self.accept_all(offset, now)
            } else {
                self.serve(event, now)
            };
        }

        if self.idle.due(now) {
            did_work |= self.close_expired(now);
        }
        if now.duration_since(self.last_keep_alive) >= self.streams.keep_alive_every {
            self.last_keep_alive = now;
            did_work |= self.fan_out(|_| true, events::KEEP_ALIVE, now);
        }

        did_work
    }

    fn accept_all(&mut self, listener_index: usize, now: Instant) -> bool {
        let mut did_work = false;
        loop {
            let mut stream = match self.listeners[listener_index].accept() {
                Ok(stream) => stream,
                Err(e) if would_block(&e) => break,
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    break;
                }
            };

            did_work = true;
            // Accept-and-close at the cap: with edge-triggered registration,
            // leaving the stream in the backlog would go silent until the next
            // SYN retriggers the listener.
            if self.connections.len() >= self.max_connections {
                tracing::warn!(
                    "beacon api connection cap {} reached, dropping new connection",
                    self.max_connections
                );
                continue;
            }
            let token = self.take_connection_token();
            self.registry.register(&mut stream, token, Interest::READABLE).unwrap();
            self.connections.insert(token, Connection::new(stream, now));
        }
        did_work
    }

    fn serve(&mut self, event: &Event, now: Instant) -> bool {
        let token = event.token();
        let Some(conn) = self.connections.get_mut(&token) else { return false };
        let subscribed = Cell::new(None);
        let outcome = conn.handle_event(&self.registry, event, now, &|req, out| {
            if let Served::Stream(channels) = self.router.dispatch(req, &self.ctx, out) {
                subscribed.set(Some(channels));
            }
        });
        match outcome {
            Ok(false) => {
                if let Some(channels) = subscribed.get() {
                    let conn = self.connections.remove(&token).expect("looked up above");
                    self.connections.insert(token, conn.subscribed(channels, now));
                }
            }
            Ok(true) => {
                let _ = self.registry.deregister(&mut conn.stream);
                self.connections.remove(&token);
            }
            Err(e) => {
                tracing::warn!("connection error: {e}");
                let _ = self.registry.deregister(&mut conn.stream);
                self.connections.remove(&token);
            }
        };
        true
    }

    /// Connections close in any order while the cursor only advances, so the
    /// offset it lands on may still be held. The range holds every socket the
    /// server can register at once, so probing forward ends on a free one.
    fn take_connection_token(&mut self) -> Token {
        assert!(
            self.connections.len() < self.max_connections,
            "beacon api connection cap {} must gate every token taken",
            self.max_connections
        );
        loop {
            let offset = self.next_connection_offset;
            self.next_connection_offset =
                if offset + 1 >= self.tokens.span() { self.listeners.len() } else { offset + 1 };
            let token = self.tokens.at(offset);
            if !self.connections.contains_key(&token) {
                return token;
            }
        }
    }

    fn close_expired(&mut self, now: Instant) -> bool {
        let Self { connections, registry, idle, linger, streams, .. } = self;
        let before = connections.len();
        connections.retain(|_, conn| {
            if !conn.expired(now, idle.timeout, linger, streams) {
                return true;
            }
            match &conn.state {
                State::Subscription(subscription) => tracing::warn!(
                    "beacon api subscriber made no write progress for over {:?} with {} bytes pending, closing",
                    streams.send_deadline,
                    subscription.body.pending_write().len()
                ),
                State::Requests(Requests { linger_since: Some(since), .. }) => tracing::warn!(
                    "beacon api connection still sending {:?} after its answer, closing",
                    now.duration_since(*since)
                ),
                State::Requests(requests) => tracing::warn!(
                    "beacon api connection idle for {:?}, closing",
                    now.duration_since(requests.last_activity)
                ),
            }
            let _ = registry.deregister(&mut conn.stream);
            false
        });
        connections.len() != before
    }
}

fn would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn interrupted(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Interrupted
}

#[cfg(test)]
mod tests {
    use std::{
        net::{SocketAddr, TcpStream},
        os::unix::net::UnixStream,
        path::Path,
        thread::JoinHandle,
        time::Instant,
    };

    use silver_beacon_state_data::{BeaconStateOwner, SLOTS_PER_EPOCH};
    use silver_common::{HeadRoots, PayloadResolution};
    use silver_httpcore::Readiness;

    use super::*;

    /// Longer than any test's 10 s spin deadline: the idle sweep never reaps.
    const LONG_TIMEOUT: Duration = Duration::from_secs(60);

    /// The sole tenant of its readiness loop, which the tile owns in
    /// production and every test here owns for itself.
    struct Server {
        readiness: Readiness,
        api: BeaconApi,
    }

    impl Server {
        fn new(
            tokens: TokenRange,
            binds: &[Bind],
            max_connections: usize,
            idle_timeout: Duration,
        ) -> Self {
            let readiness = Readiness::new(1024);
            let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
            let local_enr = Enr::empty(keypair.secret_key()).unwrap();
            let api = BeaconApi::new(
                readiness.registry(),
                tokens,
                binds,
                max_connections,
                idle_timeout,
                &keypair,
                local_enr,
                &Identify::default(),
                &SpecConfig::mainnet(),
                BeaconStateOwner::empty_test(0).reader(),
            );
            Self { readiness, api }
        }

        fn pump(&mut self) -> bool {
            self.readiness.wait(Duration::ZERO);
            self.api.pump(self.readiness.events())
        }
    }

    fn server_bound_to(binds: &[Bind], max_connections: usize, idle_timeout: Duration) -> Server {
        Server::new(TokenRange::whole(), binds, max_connections, idle_timeout)
    }

    fn server_with(max_connections: usize, idle_timeout: Duration) -> Server {
        server_bound_to(&[Bind::parse("127.0.0.1:0")], max_connections, idle_timeout)
    }

    fn tcp_addrs(server: &Server) -> Vec<SocketAddr> {
        server
            .api
            .local_addrs()
            .into_iter()
            .map(|bind| {
                let Bind::Tcp(addr) = bind else { panic!("expected tcp bind") };
                addr
            })
            .collect()
    }

    fn tcp_addr(server: &Server) -> SocketAddr {
        tcp_addrs(server)[0]
    }

    fn pump_until(server: &mut Server, msg: &str, mut done: impl FnMut(&Server) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(server) {
            assert!(Instant::now() < deadline, "timeout: {msg}");
            server.pump();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn serve<T>(server: &mut Server, client: JoinHandle<T>, msg: &str) -> T {
        pump_until(server, msg, |_| client.is_finished());
        client.join().unwrap()
    }

    fn serve_both<T>(
        server: &mut Server,
        first: JoinHandle<T>,
        second: JoinHandle<T>,
        msg: &str,
    ) -> (T, T) {
        pump_until(server, msg, |_| first.is_finished() && second.is_finished());
        (first.join().unwrap(), second.join().unwrap())
    }

    /// Connection tokens must stay inside this server's share of the loop and
    /// above its listener offsets: a wrap that lands on a listener would have
    /// the server answering an accept socket as if it were a connection, and
    /// one that leaves the range would collide with another tenant.
    #[test]
    fn connection_tokens_wrap_inside_the_range_above_the_listeners() {
        let span = 8;
        let tokens = TokenRange::new(64, span);
        let binds = [Bind::parse("127.0.0.1:0"), Bind::parse("127.0.0.1:0")];
        let mut server = Server::new(tokens, &binds, span - binds.len(), LONG_TIMEOUT);

        let assigned = std::iter::repeat_with(|| server.api.take_connection_token())
            .take(2 * span)
            .collect::<Vec<_>>();

        assert_eq!(assigned[0], Token(64 + binds.len()), "the first token clears the listeners");
        for token in &assigned {
            let offset = tokens.offset_of(*token).expect("token inside the server's range");
            assert!(offset >= binds.len(), "{token:?} aliases a listener");
        }
        assert_eq!(assigned[span - binds.len()], assigned[0], "the wrap lands where it started");
    }

    /// A range with no room for every socket at once has nowhere for the
    /// connection allocator to probe to, so it is refused at construction.
    #[test]
    #[should_panic(expected = "does not fit a span")]
    fn a_range_too_small_for_the_connection_cap_is_rejected() {
        Server::new(TokenRange::new(0, 8), &[Bind::parse("127.0.0.1:0")], 64, LONG_TIMEOUT);
    }

    /// Connections close in any order while the cursor only advances, so the
    /// offset it wraps onto can still belong to a connection that outlived a
    /// later one. Handing that offset out again replaces the map entry, which
    /// drops the older connection and closes its socket unannounced.
    #[test]
    fn a_recycled_offset_skips_the_connection_still_holding_it() {
        let span = 3;
        let tokens = TokenRange::new(64, span);
        let binds = [Bind::parse("127.0.0.1:0")];
        let mut server = Server::new(tokens, &binds, span - binds.len(), LONG_TIMEOUT);
        let addr = tcp_addr(&server);

        let long_lived = connect(addr);
        long_lived.set_nonblocking(true).unwrap();
        pump_until(&mut server, "long-lived connection accepted", |server| {
            server.api.connections.len() == 1
        });
        let held = *server.api.connections.keys().next().expect("one connection");
        assert_eq!(held, tokens.at(binds.len()), "the first connection clears the listeners");

        // Takes the last offset of the range and gives it straight back,
        // leaving the cursor wrapped onto the offset still held above.
        drop(connect(addr));
        pump_until(&mut server, "short-lived connection accepted and reaped", |server| {
            server.api.connections.len() == 1 && server.api.next_connection_offset == binds.len()
        });

        let _newcomer = connect(addr);
        let mut probe = [0u8; 1];
        pump_until(&mut server, "newcomer accepted", |server| {
            server.api.connections.len() == 2 || matches!((&long_lived).read(&mut probe), Ok(0))
        });
        assert_eq!(
            server.api.connections.len(),
            2,
            "the newcomer took the offset a live connection holds"
        );
        assert!(
            matches!((&long_lived).read(&mut probe), Err(e) if would_block(&e)),
            "the long-lived connection lost the socket its offset was handed away with"
        );
    }

    fn connect(addr: SocketAddr) -> TcpStream {
        let stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream
    }

    fn connect_uds(path: &Path) -> UnixStream {
        let stream = UnixStream::connect(path).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        stream
    }

    fn get_identity(mut stream: impl Read + Write) -> Vec<u8> {
        write!(
            stream,
            "GET /eth/v1/node/identity HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        response
    }

    fn assert_identity_ok(response: &[u8]) {
        let text = String::from_utf8_lossy(response);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "unexpected response: {text}");
        assert!(text.contains("\"peer_id\""), "identity body missing: {text}");
    }

    fn read_to_eof(mut stream: impl Read) -> Vec<u8> {
        let mut received = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => return received,
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(e) => panic!("client read: {e}"),
            }
        }
    }

    const PAYLOAD_TOO_LARGE: &[u8] =
        b"HTTP/1.1 413 Payload Too Large\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

    /// go-eth2-client and Prysm post a whole validator set unchunked, so the
    /// declared length is on the wire long before the body is.
    fn declare_oversized_body(stream: &mut impl Write) {
        write!(
            stream,
            "POST /eth/v1/validator/register_validator HTTP/1.1\r\nHost: x\r\n\
             Content-Length: {}\r\n\r\n",
            64 << 20
        )
        .unwrap();
    }

    /// Keeps the body coming after the answer must already have been framed,
    /// slowly enough that the server is answering mid-stream rather than after
    /// the last byte. Every write and the final read has to succeed: a peer
    /// that hangs up on the unread body breaks the send long before the answer
    /// can be read back.
    fn stream_body_past_the_answer(mut stream: impl Read + Write) -> io::Result<Vec<u8>> {
        declare_oversized_body(&mut stream);
        let chunk = vec![b'b'; 64 << 10];
        for _ in 0..64 {
            stream.write_all(&chunk)?;
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer)?;
        Ok(answer)
    }

    #[test]
    #[should_panic(expected = "at least one bind")]
    fn an_empty_bind_list_is_rejected() {
        server_bound_to(&[], 64, LONG_TIMEOUT);
    }

    #[test]
    fn every_tcp_listener_serves_the_api() {
        let mut server = server_bound_to(
            &[Bind::parse("127.0.0.1:0"), Bind::parse("127.0.0.1:0")],
            64,
            LONG_TIMEOUT,
        );

        let addrs = tcp_addrs(&server);
        assert_eq!(addrs.len(), 2, "one resolved address per bind");
        assert_ne!(addrs[0], addrs[1], "each bind resolves to its own port");
        assert!(addrs.iter().all(|addr| addr.port() != 0), "port-0 binds resolve: {addrs:?}");

        let (first_addr, second_addr) = (addrs[0], addrs[1]);
        let (first, second) = serve_both(
            &mut server,
            std::thread::spawn(move || get_identity(connect(first_addr))),
            std::thread::spawn(move || get_identity(connect(second_addr))),
            "both tcp listeners served",
        );
        assert_identity_ok(&first);
        assert_identity_ok(&second);
    }

    #[test]
    fn tcp_and_uds_listeners_serve_side_by_side() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let mut server = server_bound_to(
            &[Bind::parse("127.0.0.1:0"), Bind::Unix(socket.clone())],
            64,
            LONG_TIMEOUT,
        );

        let addrs = server.api.local_addrs();
        let [Bind::Tcp(tcp_addr), Bind::Unix(uds_path)] = &addrs[..] else {
            panic!("expected a tcp bind and a uds bind: {addrs:?}")
        };
        assert_eq!(uds_path, &socket);

        let tcp_addr = *tcp_addr;
        let (over_tcp, over_uds) = serve_both(
            &mut server,
            std::thread::spawn(move || get_identity(connect(tcp_addr))),
            std::thread::spawn(move || get_identity(connect_uds(&socket))),
            "tcp and uds listeners served",
        );
        assert_identity_ok(&over_tcp);
        assert_identity_ok(&over_uds);
    }

    /// The cap counts connections, not listeners: a slot held through one
    /// listener refuses clients arriving on any other.
    #[test]
    fn connection_cap_is_shared_across_listeners() {
        let mut server = server_bound_to(
            &[Bind::parse("127.0.0.1:0"), Bind::parse("127.0.0.1:0")],
            1,
            LONG_TIMEOUT,
        );
        let addrs = tcp_addrs(&server);
        let (held, other) = (addrs[0], addrs[1]);

        let held_open = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(held);
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                let mut response = Vec::new();
                let mut chunk = [0u8; 1024];
                while !response.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "server closed the held connection");
                    response.extend_from_slice(&chunk[..n]);
                }
                stream
            }),
            "first listener's client took the only slot",
        );

        assert_eq!(server.api.connections.len(), 1);
        assert!(
            server.api.connections.keys().all(|token| token.0 >= 2),
            "connection tokens must clear the listener range: {:?}",
            server.api.connections.keys().collect::<Vec<_>>()
        );

        let denied = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(other);
                let _ = write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
                let mut chunk = [0u8; 1024];
                stream.read(&mut chunk)
            }),
            "second listener's client refused at the cap",
        );
        assert!(
            !matches!(denied, Ok(n) if n > 0),
            "a slot held on one listener must refuse the other: {denied:?}"
        );

        drop(held_open);
        pump_until(&mut server, "closed connection reaped", |server| {
            server.api.connections.is_empty()
        });

        let response = serve(
            &mut server,
            std::thread::spawn(move || get_identity(connect(other))),
            "second listener served once the slot freed",
        );
        assert_identity_ok(&response);
    }

    #[test]
    fn connection_cap_drops_excess_then_recovers() {
        let mut server = server_with(1, LONG_TIMEOUT);
        let addr = tcp_addr(&server);

        let held_open = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                let mut response = Vec::new();
                let mut chunk = [0u8; 1024];
                while !response.windows(4).any(|w| w == b"\r\n\r\n") {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "server closed the first connection");
                    response.extend_from_slice(&chunk[..n]);
                }
                assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
                stream
            }),
            "first client served",
        );

        let denied = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                let _ = write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
                let mut chunk = [0u8; 1024];
                stream.read(&mut chunk)
            }),
            "second client dropped at cap",
        );
        assert!(
            !matches!(denied, Ok(n) if n > 0),
            "connection over the cap must not be served: {denied:?}"
        );

        drop(held_open);
        pump_until(&mut server, "closed connection reaped", |server| {
            server.api.connections.is_empty()
        });

        let response = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            }),
            "third client served after the slot freed",
        );
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    /// A partial request that never completes holds its slot until the idle
    /// deadline reaps it. Definitively malformed input gets 400-and-close
    /// at parse time.
    #[test]
    fn partial_request_is_reaped_after_the_idle_deadline() {
        let mut server = server_with(64, Duration::from_millis(200));
        let addr = tcp_addr(&server);

        let received = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n").unwrap();
                read_to_eof(stream)
            }),
            "partial request reaped",
        );

        assert!(received.is_empty(), "half a request must not be answered: {received:?}");
        assert!(server.api.connections.is_empty(), "reaped connection must leave the map");
    }

    /// An operator large enough to declare more body than the read buffer
    /// holds gets a status back rather than a connection that goes quiet.
    #[test]
    fn a_body_declared_past_the_read_cap_is_answered_with_413() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let addr = tcp_addr(&server);

        let received = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                declare_oversized_body(&mut stream);
                read_to_eof(stream)
            }),
            "oversized declaration accepted",
        );

        assert_eq!(received, PAYLOAD_TOO_LARGE, "{}", String::from_utf8_lossy(&received));
        pump_until(&mut server, "answered connection closed on the peer's own close", |server| {
            server.api.connections.is_empty()
        });
    }

    /// A head that outgrows the whole read buffer declares no length to
    /// answer from, so filling the buffer is the verdict: a 431, delivered
    /// like every other reject, where dropping the socket mid-send would be
    /// the reset that costs a client its node.
    #[test]
    fn a_head_that_outgrows_the_read_buffer_is_answered_with_431() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let addr = tcp_addr(&server);

        let received = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                write!(stream, "GET /eth/v1/node/health HTTP/1.1\r\nHost: x\r\nCookie: ")?;
                let chunk = vec![b'c'; 1 << 20];
                for _ in 0..17 {
                    stream.write_all(&chunk)?;
                }
                Ok::<_, io::Error>(read_to_eof(stream))
            }),
            "unending head absorbed and answered",
        );

        let received = received.expect("the head must be absorbed, not reset under the sender");
        let text = String::from_utf8_lossy(&received);
        assert!(text.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"), "{text}");
        pump_until(&mut server, "lingering connection closed once the peer went away", |server| {
            server.api.connections.is_empty()
        });
    }

    /// The reason the answer outlives the request: a client still pushing a
    /// body the server has already refused must be left to finish and read the
    /// whole status. A connection broken under it is a transport error to its
    /// caller and costs the node its place in the rotation, where a 413 costs
    /// nothing.
    #[test]
    fn a_client_still_streaming_when_the_413_is_framed_reads_all_of_it() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let addr = tcp_addr(&server);

        let received = serve(
            &mut server,
            std::thread::spawn(move || stream_body_past_the_answer(connect(addr))),
            "413 delivered to a client still sending",
        );

        assert_answer_survived(received);
        pump_until(&mut server, "lingering connection closed once the peer went away", |server| {
            server.api.connections.is_empty()
        });
    }

    /// Unix sockets take the same half-close, so the drain ends on the peer's
    /// own close there too rather than running to the linger cap.
    #[test]
    fn a_client_still_streaming_over_uds_reads_all_of_the_413() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let mut server = server_bound_to(&[Bind::Unix(socket.clone())], 64, LONG_TIMEOUT);

        let received = serve(
            &mut server,
            std::thread::spawn(move || stream_body_past_the_answer(connect_uds(&socket))),
            "413 delivered over uds to a client still sending",
        );

        assert_answer_survived(received);
        pump_until(
            &mut server,
            "lingering uds connection closed once the peer went away",
            |server| server.api.connections.is_empty(),
        );
    }

    fn assert_answer_survived(received: io::Result<Vec<u8>>) {
        match received {
            Ok(answer) => {
                assert_eq!(answer, PAYLOAD_TOO_LARGE, "{}", String::from_utf8_lossy(&answer))
            }
            Err(e) => panic!("the client's connection did not survive its answer: {e}"),
        }
    }

    /// Draining an answered connection is bounded: one client cannot hold a
    /// slot for as long as it cares to keep sending.
    #[test]
    fn a_client_that_never_stops_sending_is_dropped_at_the_linger_cap() {
        let mut server = server_with(64, Duration::from_millis(800));
        // A peer that never pauses keeps the wait between reads at zero, so the
        // total cap is the only one that can end it.
        server.api.linger =
            Linger { idle: Duration::from_millis(400), total: Duration::from_millis(200) };
        let addr = tcp_addr(&server);

        let flooding = std::thread::spawn(move || {
            let mut stream = connect(addr);
            declare_oversized_body(&mut stream);
            let chunk = vec![b'b'; 64 << 10];
            let deadline = Instant::now() + Duration::from_secs(9);
            while Instant::now() < deadline {
                if stream.write_all(&chunk).is_err() {
                    return true;
                }
            }
            false
        });

        let midway = Instant::now() + Duration::from_millis(100);
        pump_until(&mut server, "server pumped past the answer", |_| Instant::now() >= midway);
        assert_eq!(
            server.api.connections.len(),
            1,
            "the answered connection must drain, not close"
        );

        pump_until(&mut server, "flooding client dropped at the linger cap", |server| {
            server.api.connections.is_empty()
        });
        assert!(flooding.join().unwrap(), "the server must be the one to end it");
    }

    /// A peer that neither sends nor closes after its answer holds a slot for
    /// the wait between reads, not for the whole draining window — and not for
    /// the far longer deadline that keeps a served connection available.
    #[test]
    fn a_lingering_connection_that_goes_quiet_is_dropped_at_the_idle_cap() {
        let idle_timeout = Duration::from_secs(2);
        let mut server = server_with(64, idle_timeout);
        server.api.linger =
            Linger { idle: Duration::from_millis(100), total: Duration::from_secs(30) };
        let addr = tcp_addr(&server);

        let (release, on_release) = std::sync::mpsc::channel::<()>();
        let holding = std::thread::spawn(move || {
            let mut stream = connect(addr);
            declare_oversized_body(&mut stream);
            let answer = read_to_eof(&mut stream);
            let _ = on_release.recv();
            answer
        });

        pump_until(&mut server, "oversized declaration accepted", |server| {
            server.api.connections.len() == 1
        });
        let answered = Instant::now();
        pump_until(&mut server, "quiet lingering connection dropped at the idle cap", |server| {
            server.api.connections.is_empty()
        });
        let held_for = answered.elapsed();
        assert!(held_for < idle_timeout / 2, "held for {held_for:?}, as if it were still serving");

        release.send(()).unwrap();
        assert_eq!(holding.join().unwrap(), PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn idle_keep_alive_connection_is_reaped_after_the_idle_deadline() {
        let idle_timeout = Duration::from_millis(200);
        let mut server = server_with(64, idle_timeout);
        let addr = tcp_addr(&server);

        let (received, alive_for) = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                // Timed from before the request: the server's activity stamp
                // cannot predate it, so the deadline it enforces is at least
                // this long.
                let sent_at = Instant::now();
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                (read_to_eof(stream), sent_at.elapsed())
            }),
            "idle keep-alive connection reaped",
        );

        assert!(received.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(alive_for >= idle_timeout, "closed before the deadline, after {alive_for:?}");
        assert!(server.api.connections.is_empty(), "reaped connection must leave the map");
    }

    #[test]
    fn traffic_refreshes_the_idle_deadline() {
        let idle_timeout = Duration::from_millis(400);
        let mut server = server_with(64, idle_timeout);
        let addr = tcp_addr(&server);

        // Five requests spaced a quarter of the deadline apart run well past it
        // in total; each read/write must push the deadline out.
        let _still_open = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                let mut chunk = [0u8; 1024];
                for i in 0..5 {
                    write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "server closed a connection that kept transferring (#{i})");
                    std::thread::sleep(idle_timeout / 4);
                }
                stream
            }),
            "keep-alive client kept alive by its own traffic",
        );

        assert_eq!(server.api.connections.len(), 1, "an active connection must survive the sweep");
    }

    /// Connection exhaustion scenario end to end: a hung client owns the only
    /// slot, so every other client is refused until the sweep frees it.
    #[test]
    fn idle_sweep_frees_a_slot_held_at_the_cap() {
        let mut server = server_with(1, Duration::from_millis(800));
        let addr = tcp_addr(&server);

        let hung = std::thread::spawn(move || {
            let mut stream = connect(addr);
            write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n").unwrap();
            read_to_eof(stream)
        });
        pump_until(&mut server, "hung client holds the only slot", |server| {
            server.api.connections.len() == 1
        });

        let denied = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                let _ = write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n");
                let mut chunk = [0u8; 1024];
                stream.read(&mut chunk)
            }),
            "second client refused while the slot is held",
        );
        assert!(
            !matches!(denied, Ok(n) if n > 0),
            "the held slot must refuse other clients: {denied:?}"
        );

        assert!(serve(&mut server, hung, "hung client reaped").is_empty());

        let response = serve(
            &mut server,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .unwrap();
                let mut response = Vec::new();
                stream.read_to_end(&mut response).unwrap();
                response
            }),
            "fresh client served once the sweep freed the slot",
        );
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    const SSE_HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

    fn subscribe(stream: &mut impl Write, topics: &str) {
        write!(
            stream,
            "GET /eth/v1/events?topics={topics} HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\n\r\n"
        )
        .unwrap();
    }

    fn subscribers(server: &Server) -> usize {
        server
            .api
            .connections
            .values()
            .filter(|conn| matches!(conn.state, State::Subscription(_)))
            .count()
    }

    fn bytes_waiting_for_subscribers(server: &Server) -> usize {
        server
            .api
            .connections
            .values()
            .map(|conn| match &conn.state {
                State::Subscription(subscription) => subscription.body.pending_write().len(),
                State::Requests(_) => 0,
            })
            .sum()
    }

    fn chunk(payload: &[u8]) -> Vec<u8> {
        let mut out = format!("{:x}\r\n", payload.len()).into_bytes();
        out.extend_from_slice(payload);
        out.extend_from_slice(b"\r\n");
        out
    }

    fn block_frame(slot: u64, block_root: &[u8; 32]) -> Vec<u8> {
        let data = format!(
            "event: block\ndata: {{\"slot\":\"{slot}\",\"block\":\"0x{}\",\"execution_optimistic\":true}}\n\n",
            hex::encode(block_root)
        );
        chunk(data.as_bytes())
    }

    fn read_exactly(mut stream: impl Read + Send + 'static, n: usize) -> JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut got = vec![0; n];
            stream.read_exact(&mut got).unwrap();
            got
        })
    }

    fn assert_same_bytes(got: &[u8], expected: &[u8]) {
        assert!(
            got == expected,
            "\n     got: {:?}\nexpected: {:?}",
            String::from_utf8_lossy(got),
            String::from_utf8_lossy(expected)
        );
    }

    #[test]
    fn a_subscriber_gets_the_head_then_every_block_published_on_its_channel() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let mut client = connect(tcp_addr(&server));
        subscribe(&mut client, "block");
        pump_until(&mut server, "subscribed", |server| subscribers(server) == 1);

        server.api.publish_block(10, &[0xab; 32]);
        server.api.publish_block(11, &[0xcd; 32]);

        let expected =
            [SSE_HEAD, &block_frame(10, &[0xab; 32]), &block_frame(11, &[0xcd; 32])].concat();
        let got = serve(&mut server, read_exactly(client, expected.len()), "two block frames");
        assert_same_bytes(&got, &expected);
        assert_eq!(subscribers(&server), 1, "delivery keeps the subscription");
    }

    fn head_event(slot: u64, block_root: &[u8; 32], execution_optimistic: bool) -> HeadEvent {
        HeadEvent {
            slot,
            block_root: *block_root,
            roots: HeadRoots {
                state_root: [0x60; 32],
                previous_duty_dependent_root: [0x5e; 32],
                current_duty_dependent_root: [0x91; 32],
            },
            payload: PayloadResolution::Full,
            epoch_transition: false,
            execution_optimistic,
        }
    }

    fn head_v2_frame(
        slot: u64,
        block_root: &[u8; 32],
        version: &str,
        execution_optimistic: bool,
    ) -> Vec<u8> {
        let data = format!(
            "event: head_v2\ndata: {{\"version\":\"{version}\",\"data\":{{\"slot\":\"{slot}\",\"block\":\"0x{}\",\"state\":\"0x{}\",\"payload_status\":\"full\",\"epoch_transition\":false,\"current_epoch_dependent_root\":\"0x{}\",\"next_epoch_dependent_root\":\"0x{}\",\"execution_optimistic\":{execution_optimistic}}}}}\n\n",
            hex::encode(block_root),
            "60".repeat(32),
            "5e".repeat(32),
            "91".repeat(32),
        );
        chunk(data.as_bytes())
    }

    fn head_frame(slot: u64, block_root: &[u8; 32], execution_optimistic: bool) -> Vec<u8> {
        let data = format!(
            "event: head\ndata: {{\"slot\":\"{slot}\",\"block\":\"0x{}\",\"state\":\"0x{}\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0x{}\",\"current_duty_dependent_root\":\"0x{}\",\"execution_optimistic\":{execution_optimistic}}}\n\n",
            hex::encode(block_root),
            "60".repeat(32),
            "5e".repeat(32),
            "91".repeat(32),
        );
        chunk(data.as_bytes())
    }

    #[test]
    fn each_subscriber_receives_only_the_channels_it_asked_for() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let addr = tcp_addr(&server);
        let (mut blocks, mut heads, mut both) = (connect(addr), connect(addr), connect(addr));
        subscribe(&mut blocks, "block");
        subscribe(&mut heads, "head");
        subscribe(&mut both, "block,head");
        pump_until(&mut server, "three subscribed", |server| subscribers(server) == 3);

        server.api.publish_block(10, &[0xab; 32]);
        server.api.publish_head(&head_event(10, &[0xab; 32], true));

        let block_only = [SSE_HEAD, &block_frame(10, &[0xab; 32])].concat();
        let head_only = [SSE_HEAD, &head_frame(10, &[0xab; 32], true)].concat();
        let mixed =
            [SSE_HEAD, &block_frame(10, &[0xab; 32]), &head_frame(10, &[0xab; 32], true)].concat();

        let readers = [
            read_exactly(blocks, block_only.len()),
            read_exactly(heads, head_only.len()),
            read_exactly(both, mixed.len()),
        ];
        pump_until(&mut server, "every subscriber served", |_| {
            readers.iter().all(JoinHandle::is_finished)
        });
        let [got_blocks, got_heads, got_both] = readers.map(|r| r.join().unwrap());

        assert_same_bytes(&got_blocks, &block_only);
        assert_same_bytes(&got_heads, &head_only);
        assert_same_bytes(&got_both, &mixed);
    }

    #[test]
    fn head_and_head_v2_are_separate_channels() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let addr = tcp_addr(&server);
        let (mut legacy, mut v2, mut heads, mut all) =
            (connect(addr), connect(addr), connect(addr), connect(addr));
        subscribe(&mut legacy, "head");
        subscribe(&mut v2, "head_v2");
        subscribe(&mut heads, "head,head_v2");
        subscribe(&mut all, "block,head,head_v2");
        pump_until(&mut server, "four subscribed", |server| subscribers(server) == 4);

        let slot = SpecConfig::mainnet().fulu_fork_epoch * SLOTS_PER_EPOCH;
        let root = [0xab; 32];
        server.api.publish_block(slot, &root);
        server.api.publish_head(&head_event(slot, &root, true));
        server.api.publish_head_v2(&head_event(slot, &root, true));

        let legacy_frames = [SSE_HEAD, &head_frame(slot, &root, true)].concat();
        let v2_frames = [SSE_HEAD, &head_v2_frame(slot, &root, "fulu", true)].concat();
        let head_frames =
            [SSE_HEAD, &head_frame(slot, &root, true), &head_v2_frame(slot, &root, "fulu", true)]
                .concat();
        let all_frames = [
            SSE_HEAD,
            &block_frame(slot, &root),
            &head_frame(slot, &root, true),
            &head_v2_frame(slot, &root, "fulu", true),
        ]
        .concat();

        let readers = [
            read_exactly(legacy, legacy_frames.len()),
            read_exactly(v2, v2_frames.len()),
            read_exactly(heads, head_frames.len()),
            read_exactly(all, all_frames.len()),
        ];
        pump_until(&mut server, "every subscriber served", |_| {
            readers.iter().all(JoinHandle::is_finished)
        });
        let [got_legacy, got_v2, got_heads, got_all] = readers.map(|r| r.join().unwrap());

        assert_same_bytes(&got_legacy, &legacy_frames);
        assert_same_bytes(&got_v2, &v2_frames);
        assert_same_bytes(&got_heads, &head_frames);
        assert_same_bytes(&got_all, &all_frames);
    }

    #[test]
    fn head_v2_names_the_fork_at_the_head_slot() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let mut client = connect(tcp_addr(&server));
        subscribe(&mut client, "head_v2");
        pump_until(&mut server, "subscribed", |server| subscribers(server) == 1);

        let fulu = SpecConfig::mainnet().fulu_fork_epoch * SLOTS_PER_EPOCH;
        let root = [0xab; 32];
        for slot in [fulu - 1, fulu, fulu + 1, fulu - 1] {
            server.api.publish_head_v2(&head_event(slot, &root, false));
        }

        let expected = [
            SSE_HEAD,
            &head_v2_frame(fulu - 1, &root, "electra", false),
            &head_v2_frame(fulu, &root, "fulu", false),
            &head_v2_frame(fulu + 1, &root, "fulu", false),
            &head_v2_frame(fulu - 1, &root, "electra", false),
        ]
        .concat();
        let got = serve(&mut server, read_exactly(client, expected.len()), "four versioned frames");
        assert_same_bytes(&got, &expected);
    }

    #[test]
    fn a_topic_silver_does_not_serve_is_refused_on_an_ordinary_connection() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let addr = tcp_addr(&server);
        let client = std::thread::spawn(move || {
            let mut stream = connect(addr);
            write!(
                stream,
                "GET /eth/v1/events?topics=chain_reorg HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            read_to_eof(stream)
        });

        let got = serve(&mut server, client, "400 for an unserved topic");
        assert_same_bytes(
            &got,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 54\r\n\r\n{\"code\":400,\"message\":\"unknown topic \\\"chain_reorg\\\"\"}",
        );
        assert_eq!(subscribers(&server), 0);
    }

    #[test]
    fn keep_alive_comments_reach_a_subscriber_nothing_is_published_to() {
        let mut server = server_with(64, LONG_TIMEOUT);
        server.api.streams.keep_alive_every = Duration::from_millis(20);
        let mut client = connect(tcp_addr(&server));
        subscribe(&mut client, "block");

        let expected = [SSE_HEAD, &chunk(events::KEEP_ALIVE), &chunk(events::KEEP_ALIVE)].concat();
        let got =
            serve(&mut server, read_exactly(client, expected.len()), "two keep-alive comments");
        assert_same_bytes(&got, &expected);
    }

    #[test]
    fn a_subscriber_that_stops_reading_is_closed_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let mut server = server_bound_to(&[Bind::Unix(socket.clone())], 64, LONG_TIMEOUT);
        let mut client = connect_uds(&socket);
        subscribe(&mut client, "block");
        pump_until(&mut server, "subscribed", |server| subscribers(server) == 1);

        let deadline = Instant::now() + Duration::from_secs(10);
        let mut published = 0;
        while subscribers(&server) == 1 {
            assert!(Instant::now() < deadline, "timeout: subscriber closed at the cap");
            server.api.publish_block(published, &[0x11; 32]);
            published += 1;
            server.pump();
        }
        assert!(server.api.connections.is_empty(), "closed, not demoted");
        assert!(published > 64, "the cap is bytes, not frames: {published} frames");
        drop(client);
    }

    #[test]
    fn a_subscriber_that_takes_nothing_for_the_send_deadline_is_closed() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let mut server = server_bound_to(&[Bind::Unix(socket.clone())], 64, LONG_TIMEOUT);
        server.api.streams.send_deadline = Duration::from_millis(100);
        let mut client = connect_uds(&socket);
        subscribe(&mut client, "block");
        pump_until(&mut server, "subscribed and head sent", |server| {
            subscribers(server) == 1 && bytes_waiting_for_subscribers(server) == 0
        });

        let deadline = Instant::now() + Duration::from_secs(10);
        while bytes_waiting_for_subscribers(&server) == 0 {
            assert!(Instant::now() < deadline, "timeout: the kernel buffer never filled");
            server.api.publish_block(1, &[0x22; 32]);
            server.pump();
        }
        assert_eq!(subscribers(&server), 1, "bytes waiting is not yet a stall");

        pump_until(&mut server, "stalled subscriber closed", |server| {
            server.api.connections.is_empty()
        });
        drop(client);
    }

    #[test]
    fn a_quiet_subscriber_outlives_the_idle_timeout() {
        let idle_timeout = Duration::from_millis(100);
        let mut server = server_with(64, idle_timeout);
        let mut client = connect(tcp_addr(&server));
        subscribe(&mut client, "block");
        pump_until(&mut server, "subscribed", |server| subscribers(server) == 1);

        let until = Instant::now() + idle_timeout * 4;
        pump_until(&mut server, "clock", |_| Instant::now() >= until);
        assert_eq!(subscribers(&server), 1);
    }

    #[test]
    fn a_subscriber_that_hangs_up_is_forgotten() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let mut client = connect(tcp_addr(&server));
        subscribe(&mut client, "block");
        pump_until(&mut server, "subscribed", |server| subscribers(server) == 1);

        drop(client);
        pump_until(&mut server, "hung-up subscriber removed", |server| {
            server.api.connections.is_empty()
        });
    }

    #[test]
    fn a_request_pipelined_behind_the_subscribe_is_never_answered() {
        let mut server = server_with(64, LONG_TIMEOUT);
        let mut client = connect(tcp_addr(&server));
        write!(
            client,
            "GET /eth/v1/events?topics=block HTTP/1.1\r\nHost: x\r\n\r\nGET /eth/v1/node/version HTTP/1.1\r\nHost: x\r\n\r\n"
        )
        .unwrap();
        pump_until(&mut server, "subscribed and head sent", |server| {
            subscribers(server) == 1 && bytes_waiting_for_subscribers(server) == 0
        });

        server.api.publish_block(3, &[0x33; 32]);
        let expected = [SSE_HEAD, &block_frame(3, &[0x33; 32])].concat();
        let got = serve(&mut server, read_exactly(client, expected.len()), "only the stream");
        assert_same_bytes(&got, &expected);
    }
}
