use std::{
    io::{self, Read, Write},
    path::PathBuf,
    time::{Duration, Instant},
};

use mio::{Events, Interest, Registry, Token, event::Event};

use crate::{
    ClientConnection, ClientRequest, ClientResponse, Stream, TokenRange,
    address::Address,
    client::frame_request,
    transport::{Tls, Transport},
};

#[derive(Clone)]
pub enum Endpoint {
    /// An `http://` or `https://` URL.
    Http(String),
    Uds(PathBuf),
}

struct Target {
    /// The `Host` header.
    host: String,
    tls: Option<Tls>,
    address: Address,
}

impl Endpoint {
    fn target(&self) -> io::Result<Target> {
        let url = match self {
            Self::Http(url) => url,
            Self::Uds(path) => {
                let address = Address::Uds(path.clone());
                return Ok(Target { host: "localhost".into(), tls: None, address });
            }
        };
        let (tls, rest) = match url.strip_prefix("https://") {
            Some(rest) => (true, rest),
            None => (false, url.trim_start_matches("http://")),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !port.contains(']') => (host, Some(port)),
            _ => (authority, None),
        };
        let host_port = match port {
            Some(_) => authority.to_owned(),
            None => format!("{authority}:{}", if tls { 443 } else { 80 }),
        };
        let server_name = host.trim_start_matches('[').trim_end_matches(']');
        let tls = tls.then(|| Tls::webpki(server_name)).transpose()?;
        let address = Address::of_host_port(host_port);
        Ok(Target { host: authority.to_owned(), tls, address })
    }
}

enum Conn {
    Disconnected,
    Resolving,
    Connecting(Stream),
    Connected { transport: Transport, interest: Interest, answered: bool },
}

struct PooledConnection {
    token: Token,
    conn: Conn,
    machine: ClientConnection,
    in_flight: Option<u64>,
    pending_id: Option<u64>,
    /// Why `pending_id` was never written; it holds the connection until the
    /// next sweep answers it, so callers gating on capacity do not resend it.
    unframed: Option<&'static str>,
    request_deadline: Option<Instant>,
}

impl PooledConnection {
    fn new(token: Token, capacity: BufferCapacity) -> Self {
        Self {
            token,
            conn: Conn::Disconnected,
            machine: ClientConnection::with_capacity(capacity.read, capacity.write),
            in_flight: None,
            pending_id: None,
            unframed: None,
            request_deadline: None,
        }
    }

    fn is_free(&self) -> bool {
        self.in_flight.is_none() && self.pending_id.is_none()
    }

    /// The deadline runs from enqueue rather than from the write hitting the
    /// wire, so a connect that never completes expires on the same deadline.
    /// `now` is read only for a connection with a request, and once per sweep.
    fn expired(&self, now: &mut Option<Instant>) -> bool {
        self.request_deadline
            .is_some_and(|deadline| *now.get_or_insert_with(Instant::now) > deadline)
    }

    fn enqueue(
        &mut self,
        id: u64,
        request: &ClientRequest<'_>,
        timeout: Duration,
        host: &str,
        address: &mut Address,
        registry: &Registry,
    ) {
        debug_assert!(self.is_free(), "enqueue on busy connection");
        self.pending_id = Some(id);
        if let Err(error) = frame_request(self.machine.begin_request(), host, request, true) {
            self.unframed = Some(error);
            return;
        }
        self.request_deadline = Some(Instant::now() + timeout);

        match self.conn {
            Conn::Disconnected => self.connect(address, registry),
            Conn::Connected { .. } => self.update_interest(registry),
            Conn::Resolving | Conn::Connecting(_) => {}
        }
    }

    fn handle_event<F>(
        &mut self,
        event: &Event,
        registry: &Registry,
        tls: Option<&Tls>,
        address: &mut Address,
        on_complete: &mut F,
    ) where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        debug_assert_eq!(event.token(), self.token, "event routed to the wrong connection");
        match &self.conn {
            Conn::Disconnected | Conn::Resolving => {}
            Conn::Connecting(stream) => {
                if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                    return self.fail(address, registry, on_complete, "connect failed");
                }
                if !event.is_writable() {
                    return;
                }
                if stream.connect_complete().is_err() {
                    return self.fail(address, registry, on_complete, "connect failed");
                }
                let Conn::Connecting(stream) =
                    std::mem::replace(&mut self.conn, Conn::Disconnected)
                else {
                    unreachable!()
                };
                let transport = match Transport::new(stream, tls) {
                    Ok(transport) => transport,
                    Err(e) => return self.fail(address, registry, on_complete, &e.to_string()),
                };
                self.conn =
                    Conn::Connected { transport, interest: Interest::WRITABLE, answered: false };
                if let Err(e) = self.do_write() {
                    return self.fail(address, registry, on_complete, &e.to_string());
                }
                self.update_interest(registry);
            }
            Conn::Connected { .. } => {
                if event.is_error() {
                    return self.fail(address, registry, on_complete, "connection error");
                }
                if event.is_writable() &&
                    let Err(e) = self.do_write()
                {
                    return self.fail(address, registry, on_complete, &e.to_string());
                }
                // Drain data before checking is_read_closed: when the remote
                // sends a response + FIN in one exchange (EPOLLIN|EPOLLRDHUP),
                // we must read the response first. do_read returns Err on EOF,
                // so the return below covers that close path too.
                if event.is_readable() &&
                    let Err(e) = self.do_read(on_complete)
                {
                    return self.fail(address, registry, on_complete, &e.to_string());
                }
                if event.is_read_closed() {
                    // Remote closed with no (more) data — in_flight will
                    // never get a response.
                    return self.fail(address, registry, on_complete, "connection closed");
                }
                // A TLS read can leave records the socket would not take.
                self.update_interest(registry);
            }
        }
    }

    fn connect(&mut self, address: &mut Address, registry: &Registry) {
        let Some(stream) = address.connect() else {
            self.conn = Conn::Resolving;
            return;
        };
        match stream {
            Ok(mut stream) => {
                if registry.register(&mut stream, self.token, Interest::WRITABLE).is_ok() {
                    self.conn = Conn::Connecting(stream);
                }
            }
            Err(e) => {
                silver_log::warn!("connect error: {e}");
                address.forget_resolved();
            }
        }
    }

    fn do_write(&mut self) -> io::Result<()> {
        let Self { conn, machine, pending_id, in_flight, .. } = self;
        let Conn::Connected { transport, .. } = conn else { return Ok(()) };
        if pending_id.is_some() {
            loop {
                match transport.write(machine.pending_write()) {
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
        }
        transport.flush_records()
    }

    fn do_read<F>(&mut self, on_complete: &mut F) -> io::Result<()>
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        let Self { conn, machine, in_flight, request_deadline, .. } = self;
        let Conn::Connected { transport, answered, .. } = conn else { return Ok(()) };
        loop {
            while let Some(response) = machine.take_response() {
                *answered = true;
                if let Some(id) = in_flight.take() {
                    *request_deadline = None;
                    on_complete(id, Ok(response));
                }
            }
            match transport.read(machine.read_space()) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "eof")),
                Ok(n) => machine.commit_read(n)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// A connection that fails before its first response may have reached a
    /// host that moved, so the next connect looks its name up again.
    fn fail<F>(
        &mut self,
        address: &mut Address,
        registry: &Registry,
        on_complete: &mut F,
        msg: &str,
    ) where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        silver_log::warn!("{msg}");
        if matches!(self.conn, Conn::Connecting(_) | Conn::Connected { answered: false, .. }) {
            address.forget_resolved();
        }
        if let Some(id) = self.in_flight.take() {
            on_complete(id, Err(msg));
        }
        if let Some(id) = self.pending_id.take() {
            on_complete(id, Err(msg));
        }
        self.request_deadline = None;
        self.machine.reset();
        match std::mem::replace(&mut self.conn, Conn::Disconnected) {
            Conn::Connecting(mut stream) => {
                let _ = registry.deregister(&mut stream);
            }
            Conn::Connected { mut transport, .. } => {
                let _ = registry.deregister(transport.stream_mut());
            }
            Conn::Disconnected | Conn::Resolving => {}
        }
    }

    /// Re-registers only on a change, sparing a syscall per event.
    fn update_interest(&mut self, registry: &Registry) {
        let Conn::Connected { transport, interest, .. } = &mut self.conn else { return };
        let wanted = if self.pending_id.is_none() && !transport.wants_write() {
            Interest::READABLE
        } else {
            Interest::READABLE | Interest::WRITABLE
        };
        if *interest != wanted &&
            registry.reregister(transport.stream_mut(), self.token, wanted).is_ok()
        {
            *interest = wanted;
        }
    }
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
    host: String,
    tls: Option<Tls>,
    address: Address,
    tokens: TokenRange,
    capacity: BufferCapacity,
    max_connections: usize,
}

impl HttpPool {
    pub fn new(
        endpoint: Endpoint,
        tokens: TokenRange,
        capacity: BufferCapacity,
        max_connections: usize,
    ) -> io::Result<Self> {
        let Target { host, tls, address } = endpoint.target()?;
        let connections = vec![PooledConnection::new(tokens.at(0), capacity)];
        Ok(Self { connections, host, tls, address, tokens, capacity, max_connections })
    }

    /// `enqueue` never refuses work; every caller gates on this before
    /// submitting.
    pub fn has_capacity(&self) -> bool {
        self.connections.iter().any(PooledConnection::is_free) ||
            self.connections.len() < self.max_connections
    }

    pub fn is_idle(&self) -> bool {
        self.connections.iter().all(PooledConnection::is_free)
    }

    /// The request fails once `timeout` has passed since this call, or at
    /// the next dispatch when its head would carry a CR or LF.
    pub fn enqueue(
        &mut self,
        id: u64,
        request: &ClientRequest<'_>,
        timeout: Duration,
        registry: &Registry,
    ) {
        let conn = match self.connections.iter().position(PooledConnection::is_free) {
            Some(at) => &mut self.connections[at],
            None => {
                let token = self.tokens.at(self.connections.len());
                self.connections.push(PooledConnection::new(token, self.capacity));
                self.connections.last_mut().expect("just pushed")
            }
        };
        conn.enqueue(id, request, timeout, &self.host, &mut self.address, registry);
    }

    pub fn dispatch_events<F>(&mut self, events: &Events, registry: &Registry, on_complete: &mut F)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        self.connect_resolved(registry, on_complete);
        self.fail_stranded_and_expired(registry, on_complete);

        // The batch is the whole loop's, and a pooled connection's token is
        // `tokens.at(its index)`, so one pass indexing by offset costs
        // O(events) where a pass per connection costs O(connections × events).
        for event in events.iter() {
            let Some(index) = self.tokens.offset_of(event.token()) else { continue };
            let Some(conn) = self.connections.get_mut(index) else { continue };
            conn.handle_event(event, registry, self.tls.as_ref(), &mut self.address, on_complete);
        }
    }

    fn connect_resolved<F>(&mut self, registry: &Registry, on_complete: &mut F)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        let Some(resolved) = self.address.poll_resolved() else { return };
        let waiting =
            self.connections.iter_mut().filter(|conn| matches!(conn.conn, Conn::Resolving));
        match resolved {
            Ok(()) => waiting.for_each(|conn| conn.connect(&mut self.address, registry)),
            Err(error) => {
                let msg = format!("resolving {} failed: {error}", self.host);
                waiting.for_each(|conn| conn.fail(&mut self.address, registry, on_complete, &msg));
            }
        }
    }

    fn fail_stranded_and_expired<F>(&mut self, registry: &Registry, on_complete: &mut F)
    where
        F: FnMut(u64, Result<ClientResponse<'_>, &str>),
    {
        let mut now = None;
        for conn in &mut self.connections {
            if let Some(error) = conn.unframed.take() {
                let id = conn.pending_id.take().expect("an unframed request is pending");
                silver_log::warn!(id, error, "request not sent");
                on_complete(id, Err(error));
                continue;
            }
            // Disconnected with a request pending means connect() could not
            // even start (connect/register error): no event will ever arrive
            // for it, so fail the rpc here or it is stranded forever.
            if matches!(conn.conn, Conn::Disconnected) && conn.pending_id.is_some() {
                conn.fail(&mut self.address, registry, on_complete, "connect failed to start");
            } else if conn.expired(&mut now) {
                conn.fail(&mut self.address, registry, on_complete, "request timed out");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read, Write},
        net::{TcpListener, ToSocketAddrs},
        os::unix::net::{UnixListener, UnixStream},
        path::Path,
        sync::Arc,
        thread,
    };

    use rustls::{
        RootCertStore, ServerConfig, ServerConnection, StreamOwned,
        pki_types::{PrivatePkcs8KeyDer, ServerName},
    };
    use tempfile::TempDir;

    use super::*;
    use crate::{Method, Readiness, transport::client_config};

    /// Longer than any test's 10 s spin deadline: the sweep never fires.
    const LONG_TIMEOUT: Duration = Duration::from_secs(60);

    const CAPACITY: BufferCapacity = BufferCapacity { read: 4096, write: 4096 };

    fn post(body: &[u8]) -> ClientRequest<'_> {
        ClientRequest {
            method: Method::Post,
            path: "/",
            body,
            authorization: None,
            accept: None,
            content_type: Some("application/json"),
            headers: &[],
        }
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
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);

        pool.enqueue(3, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
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
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);

        pool.enqueue(9, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
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
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);

        pool.enqueue(1, &post(b"{}"), timeout, readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || server.pump()), (1, None));
        assert!(server.received > 0, "the server got the request it never answered");
        assert!(pool.has_capacity());

        server.received = 0;
        pool.enqueue(2, &post(b"{}"), timeout, readiness.registry());
        let completed = complete(&mut pool, &mut readiness, || {
            server.pump();
            if std::mem::take(&mut server.received) > 0 {
                server.answer_ok();
            }
        });
        assert_eq!(completed, (2, Some(200)), "the next request is served");
    }

    #[test]
    fn request_with_a_line_break_in_its_head_fails_unsent() {
        let dir = TempDir::new().unwrap();
        let socket = dir.path().join("server.sock");
        let mut server = Server::bind(&socket);
        let endpoint = Endpoint::Uds(socket);
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);

        let split = ClientRequest { path: "/a\r\nX-Split: 1", ..post(b"{}") };
        pool.enqueue(1, &split, LONG_TIMEOUT, readiness.registry());
        assert!(!pool.has_capacity(), "the refusal holds its connection until answered");
        let mut failed = None;
        pool.dispatch_events(readiness.events(), readiness.registry(), &mut |id, response| {
            failed = Some((id, response.err().map(str::to_owned)));
        });
        assert_eq!(failed, Some((1, Some("request head carries a CR or LF".to_owned()))));
        server.pump();
        assert_eq!(server.received, 0);

        pool.enqueue(2, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
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

        let mut pool =
            HttpPool::new(Endpoint::Uds(socket), TokenRange::whole(), CAPACITY, 1).unwrap();
        let readiness = Readiness::new(1);

        pool.enqueue(7, &post(b"{}"), Duration::from_millis(100), readiness.registry());
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

    /// Answers one request with `200 ok`, returning its body length.
    fn answer_one_request(mut stream: impl Read + Write) -> usize {
        let mut request = Vec::new();
        let mut buf = [0; 16 << 10];
        loop {
            let n = stream.read(&mut buf).unwrap();
            assert!(n > 0, "closed before the request ended");
            request.extend_from_slice(&buf[..n]);
            let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
            let head_text = String::from_utf8_lossy(&request[..head]).to_lowercase();
            let len = head_text
                .lines()
                .find_map(|line| line.strip_prefix("content-length: "))
                .map_or(0, |len| len.parse().unwrap());
            if request.len() >= head + 4 + len {
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").unwrap();
                stream.flush().unwrap();
                return len;
            }
        }
    }

    #[test]
    fn urls_name_host_tls_and_address() {
        let Target { host, tls, address } =
            Endpoint::Http("https://relay.example/base/".into()).target().unwrap();
        assert_eq!(host, "relay.example");
        assert_eq!(tls.unwrap().server_name, ServerName::try_from("relay.example").unwrap());
        assert!(
            matches!(address, Address::Unresolved(host_port) if host_port == "relay.example:443")
        );

        let Target { host, tls, .. } =
            Endpoint::Http("https://0xabc@relay.example?x=1".into()).target().unwrap();
        assert_eq!(host, "relay.example");
        assert_eq!(tls.unwrap().server_name, ServerName::try_from("relay.example").unwrap());

        let Target { host, tls, address } =
            Endpoint::Http("http://[::1]:9000".into()).target().unwrap();
        assert_eq!(host, "[::1]:9000");
        assert!(tls.is_none());
        assert!(matches!(address, Address::Tcp(addr) if addr.port() == 9000));
    }

    #[test]
    fn invalid_tls_server_names_fail_the_pool() {
        let endpoint = Endpoint::Http("https://relay..example/".into());
        assert!(HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).is_err());
    }

    /// The body outgrows rustls's default plaintext limit, which the
    /// handshake would otherwise hold back.
    #[test]
    fn https_request_completes_through_tls() {
        let certified = rcgen::generate_simple_self_signed(&["127.0.0.1".into()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("https://{}/", listener.local_addr().unwrap());
        let received = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            answer_one_request(StreamOwned::new(ServerConnection::new(server).unwrap(), tcp))
        });

        let endpoint = Endpoint::Http(url);
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(cert).unwrap();
        let tls = pool.tls.as_mut().unwrap();
        assert_eq!(tls.server_name, ServerName::try_from("127.0.0.1").unwrap());
        tls.config = client_config(roots);
        let mut readiness = Readiness::new(1);

        let body = vec![7; 256 << 10];
        pool.enqueue(4, &post(&body), LONG_TIMEOUT, readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (4, Some(200)));
        assert_eq!(received.join().unwrap(), body.len());
    }

    #[test]
    fn host_names_resolve_off_the_enqueuing_thread() {
        let local = ("localhost", 0).to_socket_addrs().unwrap().next().unwrap();
        let listener = TcpListener::bind(local).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || answer_one_request(listener.accept().unwrap().0));

        let endpoint = Endpoint::Http(format!("http://localhost:{port}"));
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);
        pool.enqueue(5, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
        assert!(matches!(pool.connections[0].conn, Conn::Resolving));
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (5, Some(200)));
    }

    #[test]
    fn failed_connects_look_the_host_name_up_again() {
        let local = ("localhost", 0).to_socket_addrs().unwrap().next().unwrap();
        let port = TcpListener::bind(local).unwrap().local_addr().unwrap().port();
        let endpoint = Endpoint::Http(format!("http://localhost:{port}"));
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);

        pool.enqueue(1, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (1, None), "nothing listens");
        assert!(matches!(pool.address, Address::Unresolved(_)));

        let listener = TcpListener::bind((local.ip(), port)).unwrap();
        thread::spawn(move || answer_one_request(listener.accept().unwrap().0));
        pool.enqueue(2, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
        assert!(matches!(pool.connections[0].conn, Conn::Resolving));
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (2, Some(200)));
        assert!(matches!(pool.address, Address::Resolved { .. }));
    }

    /// The old address may belong to another server now, which takes the
    /// connect and then fails the TLS handshake.
    #[test]
    fn connections_failing_before_a_response_look_the_host_name_up_again() {
        let local = ("localhost", 0).to_socket_addrs().unwrap().next().unwrap();
        let listener = TcpListener::bind(local).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || drop(listener.accept().unwrap()));

        let endpoint = Endpoint::Http(format!("https://localhost:{port}"));
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);
        pool.enqueue(1, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (1, None), "handshake fails");
        assert!(matches!(pool.address, Address::Unresolved(_)));
    }

    #[test]
    fn connections_failing_after_a_response_keep_the_address() {
        let local = ("localhost", 0).to_socket_addrs().unwrap().next().unwrap();
        let listener = TcpListener::bind(local).unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || answer_one_request(listener.accept().unwrap().0));

        let endpoint = Endpoint::Http(format!("http://localhost:{port}"));
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);
        pool.enqueue(1, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (1, Some(200)));

        let deadline = Instant::now() + Duration::from_secs(10);
        while !matches!(pool.connections[0].conn, Conn::Disconnected) {
            assert!(Instant::now() < deadline, "the server's close never arrived");
            readiness.wait(Duration::from_millis(1));
            pool.dispatch_events(readiness.events(), readiness.registry(), &mut |_, _| {});
        }
        assert!(matches!(pool.address, Address::Resolved { .. }));
    }

    #[test]
    fn ip_literals_are_never_looked_up() {
        let addr = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let endpoint = Endpoint::Http(format!("http://{addr}"));
        let mut pool = HttpPool::new(endpoint, TokenRange::whole(), CAPACITY, 1).unwrap();
        let mut readiness = Readiness::new(1);

        pool.enqueue(1, &post(b"{}"), LONG_TIMEOUT, readiness.registry());
        assert_eq!(complete(&mut pool, &mut readiness, || {}), (1, None), "nothing listens");
        assert!(matches!(pool.address, Address::Tcp(cached) if cached == addr));
    }
}
