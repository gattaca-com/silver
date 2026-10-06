use std::{
    io::{self, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    time::{Duration, Instant},
};

use mio::{Events, Interest, Registry, Token, event::Event};

use crate::{
    ClientConnection, ClientRequest, ClientResponse, Stream, TokenRange, client::frame_request,
};

#[derive(Clone)]
pub enum Endpoint {
    Http(String),
    Uds(PathBuf),
}

impl Endpoint {
    fn host(&self) -> String {
        match self {
            Self::Http(endpoint) => endpoint
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("localhost")
                .to_string(),
            Self::Uds(_) => "localhost".to_string(),
        }
    }
}

enum Conn {
    Disconnected,
    Connecting(Stream),
    Connected(Stream),
}

struct PooledConnection {
    endpoint: Endpoint,
    host: String,
    token: Token,
    conn: Conn,
    addr: Option<SocketAddr>,
    machine: ClientConnection,
    in_flight: Option<u64>,
    pending_id: Option<u64>,
    request_started: Option<Instant>,
}

impl PooledConnection {
    fn new(endpoint: Endpoint, token: Token, capacity: BufferCapacity) -> Self {
        let host = endpoint.host();
        Self {
            endpoint,
            host,
            token,
            conn: Conn::Disconnected,
            addr: None,
            machine: ClientConnection::with_capacity(capacity.read, capacity.write),
            in_flight: None,
            pending_id: None,
            request_started: None,
        }
    }

    fn is_free(&self) -> bool {
        self.in_flight.is_none() && self.pending_id.is_none()
    }

    /// Age is measured from enqueue rather than from the write hitting the
    /// wire, so a connect that never completes expires on the same deadline.
    fn expired(&self, now: Instant, timeout: Duration) -> bool {
        self.request_started.is_some_and(|started| now.duration_since(started) > timeout)
    }

    fn enqueue(&mut self, id: u64, request: &ClientRequest<'_>, registry: &Registry) {
        debug_assert!(self.is_free(), "enqueue on busy connection");
        frame_request(self.machine.begin_request(), &self.host, request, true);
        self.pending_id = Some(id);
        self.request_started = Some(Instant::now());

        match self.conn {
            Conn::Disconnected => self.connect(registry),
            Conn::Connected(_) => self.update_interest(registry),
            Conn::Connecting(_) => {}
        }
    }

    fn handle_event<F>(&mut self, event: &Event, registry: &Registry, on_complete: &mut F)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        debug_assert_eq!(event.token(), self.token, "event routed to the wrong connection");
        match &self.conn {
            Conn::Disconnected => {}
            Conn::Connecting(stream) => {
                if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                    self.fail(registry, on_complete, "connect failed");
                    return;
                }
                if event.is_writable() {
                    if stream.connect_complete().is_ok() {
                        let Conn::Connecting(stream) =
                            std::mem::replace(&mut self.conn, Conn::Disconnected)
                        else {
                            unreachable!()
                        };
                        self.conn = Conn::Connected(stream);
                        self.update_interest(registry);
                    } else {
                        self.fail(registry, on_complete, "connect failed");
                    }
                }
            }
            Conn::Connected(_) => {
                if event.is_error() {
                    self.fail(registry, on_complete, "connection error");
                    return;
                }
                if event.is_writable() {
                    if let Err(e) = self.do_write() {
                        let msg = e.to_string();
                        self.fail(registry, on_complete, &msg);
                        return;
                    }
                    self.update_interest(registry);
                }
                if event.is_readable() {
                    // Drain data before checking is_read_closed: when the
                    // remote sends a response + FIN in one exchange
                    // (EPOLLIN|EPOLLRDHUP), we must read the response first.
                    // do_read returns Err on EOF, so the return below covers
                    // that close path too.
                    if let Err(e) = self.do_read(on_complete) {
                        let msg = e.to_string();
                        self.fail(registry, on_complete, &msg);
                        return;
                    }
                }
                if event.is_read_closed() {
                    // Remote closed with no (more) data — in_flight will
                    // never get a response.
                    self.fail(registry, on_complete, "connection closed");
                }
            }
        }
    }

    fn connect(&mut self, registry: &Registry) {
        let stream = match &self.endpoint {
            Endpoint::Http(endpoint) => {
                let addr = if let Some(a) = self.addr {
                    a
                } else {
                    match parse_addr(endpoint) {
                        Ok(a) => {
                            self.addr = Some(a);
                            a
                        }
                        Err(e) => {
                            silver_log::warn!("resolve failed for {endpoint}: {e}");
                            return;
                        }
                    }
                };
                Stream::connect_tcp(addr)
            }
            Endpoint::Uds(path) => Stream::connect_uds(path),
        };
        match stream {
            Ok(mut stream) => {
                if registry.register(&mut stream, self.token, Interest::WRITABLE).is_ok() {
                    self.conn = Conn::Connecting(stream);
                }
            }
            Err(e) => silver_log::warn!("connect error: {e}"),
        }
    }

    fn do_write(&mut self) -> io::Result<()> {
        if self.pending_id.is_none() {
            return Ok(());
        }
        let Self { conn, machine, pending_id, in_flight, .. } = self;
        let Conn::Connected(stream) = conn else { return Ok(()) };
        loop {
            match stream.write(machine.pending_write()) {
                Ok(0) => break,
                Ok(n) => {
                    machine.commit_write(n);
                    if machine.pending_write().is_empty() {
                        *in_flight = pending_id.take();
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn do_read<F>(&mut self, on_complete: &mut F) -> io::Result<()>
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        let Self { conn, machine, in_flight, request_started, .. } = self;
        let Conn::Connected(stream) = conn else { return Ok(()) };
        loop {
            while let Some(response) = machine.take_response() {
                if let Some(id) = in_flight.take() {
                    *request_started = None;
                    on_complete(id, Ok(response));
                }
            }
            match stream.read(machine.read_space()) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "eof")),
                Ok(n) => machine.commit_read(n)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn fail<F>(&mut self, registry: &Registry, on_complete: &mut F, msg: &str)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        silver_log::warn!("{msg}");
        if let Some(id) = self.in_flight.take() {
            on_complete(id, Err(msg));
        }
        if let Some(id) = self.pending_id.take() {
            on_complete(id, Err(msg));
        }
        self.request_started = None;
        self.machine.reset();
        let old = std::mem::replace(&mut self.conn, Conn::Disconnected);
        if let Conn::Connecting(mut stream) | Conn::Connected(mut stream) = old {
            let _ = registry.deregister(&mut stream);
        }
    }

    fn update_interest(&mut self, registry: &Registry) {
        let interest = if self.pending_id.is_none() {
            Interest::READABLE
        } else {
            Interest::READABLE | Interest::WRITABLE
        };
        let stream = match &mut self.conn {
            Conn::Connecting(s) | Conn::Connected(s) => s,
            Conn::Disconnected => return,
        };
        let _ = registry.reregister(stream, self.token, interest);
    }
}

fn parse_addr(endpoint: &str) -> io::Result<SocketAddr> {
    let hostport = endpoint.trim_start_matches("http://").split('/').next().unwrap_or(endpoint);
    hostport
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address resolved"))
}

/// Each pooled connection's buffers, sized for the largest exchange it carries.
#[derive(Clone, Copy)]
pub struct BufferCapacity {
    pub read: usize,
    pub write: usize,
}

/// One request in flight per connection. Connection `i` registers as
/// `tokens.at(i)`, so the span bounds how many the pool can ever open.
pub struct HttpPool {
    connections: Vec<PooledConnection>,
    endpoint: Endpoint,
    tokens: TokenRange,
    capacity: BufferCapacity,
    max_connections: usize,
    request_timeout: Duration,
}

impl HttpPool {
    pub fn new(
        endpoint: Endpoint,
        tokens: TokenRange,
        capacity: BufferCapacity,
        max_connections: usize,
        request_timeout: Duration,
    ) -> Self {
        let connections = vec![PooledConnection::new(endpoint.clone(), tokens.at(0), capacity)];
        Self { connections, endpoint, tokens, capacity, max_connections, request_timeout }
    }

    /// `enqueue` never refuses work; every caller gates on this before
    /// submitting.
    pub fn has_capacity(&self) -> bool {
        self.connections.iter().any(PooledConnection::is_free) ||
            self.connections.len() < self.max_connections
    }

    pub fn enqueue(&mut self, id: u64, request: &ClientRequest<'_>, registry: &Registry) {
        if let Some(conn) = self.connections.iter_mut().find(|c| c.is_free()) {
            conn.enqueue(id, request, registry);
        } else {
            let mut new_conn = PooledConnection::new(
                self.endpoint.clone(),
                self.tokens.at(self.connections.len()),
                self.capacity,
            );
            new_conn.enqueue(id, request, registry);
            self.connections.push(new_conn);
        }
    }

    pub fn dispatch_events<F>(&mut self, events: &Events, registry: &Registry, on_complete: &mut F)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        self.fail_stranded_and_expired(registry, on_complete);

        // The batch is the whole loop's, and a pooled connection's token is
        // `tokens.at(its index)`, so one pass indexing by offset costs
        // O(events) where a pass per connection costs O(connections × events).
        for event in events.iter() {
            let Some(index) = self.tokens.offset_of(event.token()) else { continue };
            let Some(conn) = self.connections.get_mut(index) else { continue };
            conn.handle_event(event, registry, on_complete);
        }
    }

    fn fail_stranded_and_expired<F>(&mut self, registry: &Registry, on_complete: &mut F)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        let now = Instant::now();
        for conn in &mut self.connections {
            // Disconnected with a request pending means connect() could not
            // even start (resolve/connect/register error): no event will ever
            // arrive for it, so fail the rpc here or it is stranded forever.
            if matches!(conn.conn, Conn::Disconnected) && conn.pending_id.is_some() {
                conn.fail(registry, on_complete, "connect failed to start");
            } else if conn.expired(now, self.request_timeout) {
                conn.fail(registry, on_complete, "request timed out");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        path::Path,
    };

    use tempfile::TempDir;

    use super::*;
    use crate::{Method, Readiness};

    /// Longer than any test's 10 s spin deadline: the sweep never fires.
    const LONG_TIMEOUT: Duration = Duration::from_secs(60);

    const CAPACITY: BufferCapacity = BufferCapacity { read: 4096, write: 4096 };

    fn post(body: &[u8]) -> ClientRequest<'_> {
        ClientRequest { method: Method::Post, path: "/", body, authorization: None }
    }

    /// A server that accepts and reads, and answers only when told to.
    struct Server {
        listener: UnixListener,
        stream: Option<UnixStream>,
        received: usize,
    }

    impl Server {
        fn bind(socket: &Path) -> Self {
            let listener = UnixListener::bind(socket).unwrap();
            listener.set_nonblocking(true).unwrap();
            Self { listener, stream: None, received: 0 }
        }

        /// Accepts the next connection and reads what has arrived on it.
        fn pump(&mut self) {
            if let Ok((stream, _)) = self.listener.accept() {
                stream.set_nonblocking(true).unwrap();
                self.stream = Some(stream);
            }
            let Some(stream) = &mut self.stream else { return };
            let mut buf = [0u8; 4096];
            match stream.read(&mut buf) {
                Ok(n) => self.received += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("read: {e}"),
            }
        }

        fn answer_ok(&mut self) {
            let stream = self.stream.as_mut().unwrap();
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").unwrap();
        }
    }

    /// Spins the pool until a request completes, returning its id and status.
    fn complete(
        pool: &mut HttpPool,
        readiness: &mut Readiness,
        mut server: impl FnMut(),
    ) -> (u64, Option<u16>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(Instant::now() < deadline, "no request completed");
            readiness.wait(Duration::from_millis(1));
            let mut completed = None;
            pool.dispatch_events(readiness.events(), readiness.registry(), &mut |id, response| {
                completed = Some((id, response.ok().map(|response| response.status)));
            });
            if let Some(completed) = completed {
                return completed;
            }
            server();
        }
    }

    /// With a cap of one, the pool has capacity again only if the failed
    /// connection was freed.
    #[test]
    fn connect_failure_fails_the_request_and_frees_the_connection() {
        let dir = TempDir::new().unwrap();
        let endpoint = Endpoint::Uds(dir.path().join("missing.sock"));
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1, LONG_TIMEOUT);
        let mut readiness = Readiness::new(1);

        pool.enqueue(3, &post(b"{}"), readiness.registry());
        assert!(!pool.has_capacity());
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (3, None));
        assert!(pool.has_capacity());
    }

    #[test]
    fn peer_closing_fails_the_request_in_flight() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("server.sock");
        let mut server = Server::bind(&socket);
        let endpoint = Endpoint::Uds(socket);
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1, LONG_TIMEOUT);
        let mut readiness = Readiness::new(1);

        pool.enqueue(9, &post(b"{}"), readiness.registry());
        let completed = complete(&mut pool, &mut readiness, || {
            server.pump();
            if server.received > 0 {
                server.stream = None;
            }
        });
        assert_eq!(completed, (9, None));
    }

    #[test]
    fn unanswered_request_times_out_and_frees_the_connection() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("server.sock");
        let mut server = Server::bind(&socket);
        let timeout = Duration::from_millis(200);
        let endpoint = Endpoint::Uds(socket);
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1, timeout);
        let mut readiness = Readiness::new(1);

        pool.enqueue(1, &post(b"{}"), readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || server.pump()), (1, None));
        assert!(server.received > 0, "the server got the request it never answered");
        assert!(pool.has_capacity());

        server.received = 0;
        pool.enqueue(2, &post(b"{}"), readiness.registry());
        let completed = complete(&mut pool, &mut readiness, || {
            server.pump();
            if std::mem::take(&mut server.received) > 0 {
                server.answer_ok();
            }
        });
        assert_eq!(completed, (2, Some(200)), "the next request is served");
    }

    /// A blackholed connect (SYN dropped) is not cheaply reproducible in a unit
    /// test, so with no events ever delivered the connection stays in
    /// `Connecting`, which is the state such a connect is stuck in, and the
    /// deadline must still fire.
    #[test]
    fn pending_request_times_out_while_still_connecting() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("server.sock");
        let _listener = UnixListener::bind(&socket).unwrap();

        let mut pool = HttpPool::new(
            Endpoint::Uds(socket),
            TokenRange::whole(),
            CAPACITY,
            1,
            Duration::from_millis(100),
        );
        let readiness = Readiness::new(1);

        pool.enqueue(7, &post(b"{}"), readiness.registry());
        assert!(matches!(pool.connections[0].conn, Conn::Connecting(_)));
        assert!(!pool.has_capacity());

        std::thread::sleep(Duration::from_millis(150));
        let mut failed: Option<(u64, bool)> = None;
        pool.dispatch_events(readiness.events(), readiness.registry(), &mut |id, response| {
            failed = Some((id, response.is_err()));
        });

        assert_eq!(failed, Some((7, true)), "a stuck connect must fail its request");
        assert!(pool.has_capacity(), "timed-out connection must be reusable");
    }
}
