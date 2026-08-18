use std::{
    collections::HashMap,
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use mio::{Events, Interest, Poll, Token};
use silver_beacon_state_data::BeaconStateReader;
use silver_common::{Enr, Identify, Keypair};
use silver_httpcore::{AfterResponse, Bind, Listener, ParsedRequest, ServerConnection, Stream};

use crate::{
    router::Router,
    routes::{ApiCtx, ROUTES},
};

const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

struct Connection {
    stream: Stream,
    http: ServerConnection,
    last_activity: Instant,
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
    poll: Poll,
    events: Events,
    listeners: Vec<Listener>,
    max_connections: usize,
    idle: IdleSweep,
    current_token: Token,
    connections: HashMap<Token, Connection>,
    router: Router,
    ctx: ApiCtx,
}

impl BeaconApi {
    pub fn new(
        binds: &[Bind],
        max_connections: usize,
        idle_timeout: Duration,
        keypair: &Keypair,
        local_enr: Enr,
        identify: &Identify,
        state: BeaconStateReader,
    ) -> Self {
        assert!(!binds.is_empty(), "beacon api needs at least one bind");
        let poll = Poll::new().unwrap();
        let listeners = binds
            .iter()
            .enumerate()
            .map(|(index, bind)| {
                let mut listener = Listener::bind(bind)
                    .unwrap_or_else(|e| panic!("beacon api bind {bind:?}: {e}"));
                poll.registry().register(&mut listener, Token(index), Interest::READABLE).unwrap();
                listener
            })
            .collect::<Vec<_>>();

        Self {
            poll,
            events: Events::with_capacity(1024),
            max_connections,
            idle: IdleSweep::new(idle_timeout),
            current_token: Token(listeners.len()),
            listeners,
            connections: HashMap::new(),
            router: Router::new(ROUTES),
            ctx: ApiCtx::new(keypair, &local_enr, identify, state),
        }
    }

    pub fn local_addrs(&self) -> Vec<Bind> {
        self.listeners.iter().map(Listener::local_addr).collect()
    }

    pub fn pump(&mut self) -> bool {
        self.poll.poll(&mut self.events, Some(Duration::ZERO)).unwrap();
        let now = Instant::now();

        let mut did_work = false;
        for event in &self.events {
            match self.listeners.get(event.token().0) {
                Some(listener) => loop {
                    let mut stream = match listener.accept() {
                        Ok(stream) => stream,
                        Err(e) if would_block(&e) => break,
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                            break;
                        }
                    };

                    did_work = true;
                    // Accept-and-close at the cap: with edge-triggered
                    // registration, leaving the stream in the backlog would go
                    // silent until the next SYN retriggers the listener.
                    if self.connections.len() >= self.max_connections {
                        tracing::warn!(
                            "beacon api connection cap {} reached, dropping new connection",
                            self.max_connections
                        );
                        continue;
                    }
                    let token = next(&mut self.current_token, self.listeners.len());
                    self.poll.registry().register(&mut stream, token, Interest::READABLE).unwrap();
                    self.connections.insert(token, Connection {
                        stream,
                        http: ServerConnection::new(),
                        last_activity: now,
                    });
                },
                None => {
                    let token = event.token();
                    if let Some(conn) = self.connections.get_mut(&token) {
                        did_work = true;
                        match handle_event(self.poll.registry(), conn, event, now, &|req, out| {
                            self.router.dispatch(req, &self.ctx, out)
                        }) {
                            Ok(true) => {
                                let _ = self.poll.registry().deregister(&mut conn.stream);
                                self.connections.remove(&token);
                            }
                            Ok(false) => {}
                            Err(e) => {
                                tracing::warn!("connection error: {e}");
                                let _ = self.poll.registry().deregister(&mut conn.stream);
                                self.connections.remove(&token);
                            }
                        };
                    }
                }
            }
        }

        if self.idle.due(now) {
            did_work |= self.close_idle(now);
        }

        did_work
    }

    fn close_idle(&mut self, now: Instant) -> bool {
        let Self { connections, poll, idle, .. } = self;
        let before = connections.len();
        connections.retain(|_, conn| {
            let idle_for = now.duration_since(conn.last_activity);
            if idle_for <= idle.timeout {
                return true;
            }
            tracing::warn!("beacon api connection idle for {idle_for:?}, closing");
            let _ = poll.registry().deregister(&mut conn.stream);
            false
        });
        connections.len() != before
    }
}

fn handle_event<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
    registry: &mio::Registry,
    conn: &mut Connection,
    event: &mio::event::Event,
    now: Instant,
    request_handler: &F,
) -> io::Result<bool> {
    if event.is_readable() {
        loop {
            let space = conn.http.read_space()?;
            match conn.stream.read(space) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => {
                    conn.last_activity = now;
                    conn.http.commit_read(n);
                }
                Err(e) if would_block(&e) => break,
                Err(e) if interrupted(&e) => continue,
                Err(e) => return Err(e),
            }
        }

        if conn.http.dispatch(request_handler) {
            registry.reregister(&mut conn.stream, event.token(), Interest::WRITABLE)?;
        }
        return Ok(false);
    }

    if event.is_writable() {
        if !conn.http.pending_write().is_empty() {
            loop {
                match conn.stream.write(conn.http.pending_write()) {
                    Ok(0) => {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"))
                    }
                    Ok(n) => {
                        conn.last_activity = now;
                        conn.http.commit_write(n);
                        if conn.http.pending_write().is_empty() {
                            break;
                        }
                    }
                    Err(e) if would_block(&e) => return Ok(false),
                    Err(e) if interrupted(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
            match conn.http.after_response(request_handler) {
                AfterResponse::Close => return Ok(true),
                AfterResponse::ResponsePending => {
                    registry.reregister(&mut conn.stream, event.token(), Interest::WRITABLE)?
                }
                AfterResponse::AwaitRequest => {
                    registry.reregister(&mut conn.stream, event.token(), Interest::READABLE)?
                }
            }
        }
        return Ok(false);
    }

    Ok(false)
}

/// Connection tokens sit above the listener range `0..reserved`, which the
/// wrap must skip to avoid aliasing an accept socket.
fn next(current: &mut Token, reserved: usize) -> Token {
    let tok = Token(current.0);
    let n = current.0.wrapping_add(1);
    current.0 = if n < reserved { reserved } else { n };
    tok
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

    use silver_beacon_state_data::BeaconStateOwner;

    use super::*;

    #[test]
    fn token_wrap_skips_the_listener_range() {
        let reserved = 3;

        let mut cur = Token(usize::MAX);
        let assigned = next(&mut cur, reserved);
        assert!(assigned.0 >= reserved, "returned token must not alias a listener");
        assert_eq!(cur, Token(reserved), "the wrap must land above the listener range");

        let mut cur = Token(reserved);
        assert_eq!(next(&mut cur, reserved), Token(reserved));
        assert_eq!(cur, Token(reserved + 1));
    }

    /// Longer than any test's 10 s spin deadline: the idle sweep never reaps.
    const LONG_TIMEOUT: Duration = Duration::from_secs(60);

    fn api_bound_to(binds: &[Bind], max_connections: usize, idle_timeout: Duration) -> BeaconApi {
        let keypair = Keypair::from_secret(&[1u8; 32]).unwrap();
        let local_enr = Enr::empty(keypair.secret_key()).unwrap();
        BeaconApi::new(
            binds,
            max_connections,
            idle_timeout,
            &keypair,
            local_enr,
            &Identify::default(),
            BeaconStateOwner::empty_test(0).reader(),
        )
    }

    fn api_with(max_connections: usize, idle_timeout: Duration) -> BeaconApi {
        api_bound_to(&[Bind::parse("127.0.0.1:0")], max_connections, idle_timeout)
    }

    fn tcp_addrs(api: &BeaconApi) -> Vec<SocketAddr> {
        api.local_addrs()
            .into_iter()
            .map(|bind| {
                let Bind::Tcp(addr) = bind else { panic!("expected tcp bind") };
                addr
            })
            .collect()
    }

    fn tcp_addr(api: &BeaconApi) -> SocketAddr {
        tcp_addrs(api)[0]
    }

    fn pump_until(api: &mut BeaconApi, msg: &str, mut done: impl FnMut(&BeaconApi) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(api) {
            assert!(Instant::now() < deadline, "timeout: {msg}");
            api.pump();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn serve<T>(api: &mut BeaconApi, client: JoinHandle<T>, msg: &str) -> T {
        pump_until(api, msg, |_| client.is_finished());
        client.join().unwrap()
    }

    fn serve_both<T>(
        api: &mut BeaconApi,
        first: JoinHandle<T>,
        second: JoinHandle<T>,
        msg: &str,
    ) -> (T, T) {
        pump_until(api, msg, |_| first.is_finished() && second.is_finished());
        (first.join().unwrap(), second.join().unwrap())
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

    fn read_to_eof(mut stream: TcpStream) -> Vec<u8> {
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

    #[test]
    #[should_panic(expected = "at least one bind")]
    fn an_empty_bind_list_is_rejected() {
        api_bound_to(&[], 64, LONG_TIMEOUT);
    }

    #[test]
    fn every_tcp_listener_serves_the_api() {
        let mut api = api_bound_to(
            &[Bind::parse("127.0.0.1:0"), Bind::parse("127.0.0.1:0")],
            64,
            LONG_TIMEOUT,
        );

        let addrs = tcp_addrs(&api);
        assert_eq!(addrs.len(), 2, "one resolved address per bind");
        assert_ne!(addrs[0], addrs[1], "each bind resolves to its own port");
        assert!(addrs.iter().all(|addr| addr.port() != 0), "port-0 binds resolve: {addrs:?}");

        let (first_addr, second_addr) = (addrs[0], addrs[1]);
        let (first, second) = serve_both(
            &mut api,
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
        let mut api = api_bound_to(
            &[Bind::parse("127.0.0.1:0"), Bind::Unix(socket.clone())],
            64,
            LONG_TIMEOUT,
        );

        let addrs = api.local_addrs();
        let [Bind::Tcp(tcp_addr), Bind::Unix(uds_path)] = &addrs[..] else {
            panic!("expected a tcp bind and a uds bind: {addrs:?}")
        };
        assert_eq!(uds_path, &socket);

        let tcp_addr = *tcp_addr;
        let (over_tcp, over_uds) = serve_both(
            &mut api,
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
        let mut api = api_bound_to(
            &[Bind::parse("127.0.0.1:0"), Bind::parse("127.0.0.1:0")],
            1,
            LONG_TIMEOUT,
        );
        let addrs = tcp_addrs(&api);
        let (held, other) = (addrs[0], addrs[1]);

        let held_open = serve(
            &mut api,
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

        assert_eq!(api.connections.len(), 1);
        assert!(
            api.connections.keys().all(|token| token.0 >= 2),
            "connection tokens must clear the listener range: {:?}",
            api.connections.keys().collect::<Vec<_>>()
        );

        let denied = serve(
            &mut api,
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
        pump_until(&mut api, "closed connection reaped", |api| api.connections.is_empty());

        let response = serve(
            &mut api,
            std::thread::spawn(move || get_identity(connect(other))),
            "second listener served once the slot freed",
        );
        assert_identity_ok(&response);
    }

    #[test]
    fn connection_cap_drops_excess_then_recovers() {
        let mut api = api_with(1, LONG_TIMEOUT);
        let addr = tcp_addr(&api);

        let held_open = serve(
            &mut api,
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
            &mut api,
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
        pump_until(&mut api, "closed connection reaped", |api| api.connections.is_empty());

        let response = serve(
            &mut api,
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
        let mut api = api_with(64, Duration::from_millis(200));
        let addr = tcp_addr(&api);

        let received = serve(
            &mut api,
            std::thread::spawn(move || {
                let mut stream = connect(addr);
                write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n").unwrap();
                read_to_eof(stream)
            }),
            "partial request reaped",
        );

        assert!(received.is_empty(), "half a request must not be answered: {received:?}");
        assert!(api.connections.is_empty(), "reaped connection must leave the map");
    }

    #[test]
    fn idle_keep_alive_connection_is_reaped_after_the_idle_deadline() {
        let idle_timeout = Duration::from_millis(200);
        let mut api = api_with(64, idle_timeout);
        let addr = tcp_addr(&api);

        let (received, alive_for) = serve(
            &mut api,
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
        assert!(api.connections.is_empty(), "reaped connection must leave the map");
    }

    #[test]
    fn traffic_refreshes_the_idle_deadline() {
        let idle_timeout = Duration::from_millis(400);
        let mut api = api_with(64, idle_timeout);
        let addr = tcp_addr(&api);

        // Five requests spaced a quarter of the deadline apart run well past it
        // in total; each read/write must push the deadline out.
        let _still_open = serve(
            &mut api,
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

        assert_eq!(api.connections.len(), 1, "an active connection must survive the sweep");
    }

    /// Connection exhaustion scenario end to end: a hung client owns the only
    /// slot, so every other client is refused until the sweep frees it.
    #[test]
    fn idle_sweep_frees_a_slot_held_at_the_cap() {
        let mut api = api_with(1, Duration::from_millis(800));
        let addr = tcp_addr(&api);

        let hung = std::thread::spawn(move || {
            let mut stream = connect(addr);
            write!(stream, "GET /metrics HTTP/1.1\r\nHost: x\r\n").unwrap();
            read_to_eof(stream)
        });
        pump_until(&mut api, "hung client holds the only slot", |api| api.connections.len() == 1);

        let denied = serve(
            &mut api,
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

        assert!(serve(&mut api, hung, "hung client reaped").is_empty());

        let response = serve(
            &mut api,
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
}
