use std::{
    io::{self, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
};

use mio::{Events, Interest, Poll, Token};
use silver_httpcore::{ClientConnection, Stream, frame_request};

use crate::{EngineError, JwtSecret};

// Sized for the largest expected EL response: getPayload with a full
// blobsBundle (~21 blobs × 256 KB hex-encoded + execution payload
// transactions).
const READ_BUF_CAPACITY: usize = 10 * 1024 * 1024;

// Sized for the largest expected outgoing request: newPayload with a full
// block (~30M gas of transactions, hex-encoded in JSON) plus HTTP headers.
const WRITE_BUF_CAPACITY: usize = 10 * 1024 * 1024;

#[derive(Clone)]
pub(crate) enum Endpoint {
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
    jwt: JwtSecret,
    token: Token,
    conn: Conn,
    addr: Option<SocketAddr>,
    machine: ClientConnection,
    in_flight: Option<u64>,
    pending_id: Option<u64>,
}

impl PooledConnection {
    fn new(endpoint: Endpoint, jwt: JwtSecret, token: Token) -> Self {
        let host = endpoint.host();
        Self {
            endpoint,
            host,
            jwt,
            token,
            conn: Conn::Disconnected,
            addr: None,
            machine: ClientConnection::with_capacity(READ_BUF_CAPACITY, WRITE_BUF_CAPACITY),
            in_flight: None,
            pending_id: None,
        }
    }

    fn is_free(&self) -> bool {
        self.in_flight.is_none() && self.pending_id.is_none()
    }

    fn enqueue(&mut self, rpc_id: u64, body: &[u8], poll: &mut Poll) {
        debug_assert!(self.is_free(), "enqueue on busy connection");
        let out = self.machine.begin_request();
        frame_request(out, &self.host, body, Some(self.jwt.bearer_token()), true);
        self.pending_id = Some(rpc_id);

        match self.conn {
            Conn::Disconnected => self.connect(poll),
            Conn::Connected(_) => self.update_interest(poll),
            Conn::Connecting(_) => {}
        }
    }

    fn handle_events<F>(&mut self, events: &Events, poll: &mut Poll, on_complete: &mut F)
    where
        F: FnMut(u64, Result<&mut [u8], EngineError>),
    {
        for event in events.iter() {
            if event.token() != self.token {
                continue;
            }
            match &self.conn {
                Conn::Disconnected => {}
                Conn::Connecting(stream) => {
                    if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                        self.fail(poll, on_complete, "connect failed");
                        break;
                    }
                    if event.is_writable() {
                        if stream.connect_complete().is_ok() {
                            let Conn::Connecting(stream) =
                                std::mem::replace(&mut self.conn, Conn::Disconnected)
                            else {
                                unreachable!()
                            };
                            self.conn = Conn::Connected(stream);
                            self.update_interest(poll);
                        } else {
                            self.fail(poll, on_complete, "connect failed");
                            break;
                        }
                    }
                }
                Conn::Connected(_) => {
                    if event.is_error() {
                        self.fail(poll, on_complete, "connection error");
                        break;
                    }
                    if event.is_writable() {
                        if let Err(e) = self.do_write() {
                            let msg = e.to_string();
                            self.fail(poll, on_complete, &msg);
                            break;
                        }
                        self.update_interest(poll);
                    }
                    if event.is_readable() {
                        // Drain data before checking is_read_closed: when the
                        // remote sends a response + FIN in one exchange
                        // (EPOLLIN|EPOLLRDHUP), we must read the response
                        // first. do_read returns Err on EOF, so the break
                        // below covers that close path too.
                        if let Err(e) = self.do_read(on_complete) {
                            let msg = e.to_string();
                            self.fail(poll, on_complete, &msg);
                            break;
                        }
                    }
                    if event.is_read_closed() {
                        // Remote closed with no (more) data — in_flight will
                        // never get a response.
                        self.fail(poll, on_complete, "connection closed");
                        break;
                    }
                }
            }
        }
    }

    fn connect(&mut self, poll: &mut Poll) {
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
                            tracing::warn!("resolve failed for {endpoint}: {e}");
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
                if poll.registry().register(&mut stream, self.token, Interest::WRITABLE).is_ok() {
                    self.conn = Conn::Connecting(stream);
                }
            }
            Err(e) => tracing::warn!("connect error: {e}"),
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
        F: FnMut(u64, Result<&mut [u8], EngineError>),
    {
        let Self { conn, machine, in_flight, .. } = self;
        let Conn::Connected(stream) = conn else { return Ok(()) };
        loop {
            while let Some(body) = machine.take_response() {
                if let Some(rpc_id) = in_flight.take() {
                    on_complete(rpc_id, Ok(body));
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

    fn fail<F>(&mut self, poll: &mut Poll, on_complete: &mut F, msg: &str)
    where
        F: FnMut(u64, Result<&mut [u8], EngineError>),
    {
        tracing::warn!("{msg}");
        let err = msg.to_string();
        if let Some(rpc_id) = self.in_flight.take() {
            on_complete(rpc_id, Err(EngineError::Http(err.clone())));
        }
        if let Some(rpc_id) = self.pending_id.take() {
            on_complete(rpc_id, Err(EngineError::Http(err.clone())));
        }
        self.machine.reset();
        let old = std::mem::replace(&mut self.conn, Conn::Disconnected);
        if let Conn::Connecting(mut stream) | Conn::Connected(mut stream) = old {
            let _ = poll.registry().deregister(&mut stream);
        }
    }

    fn update_interest(&mut self, poll: &mut Poll) {
        let interest = if self.pending_id.is_none() {
            Interest::READABLE
        } else {
            Interest::READABLE | Interest::WRITABLE
        };
        let stream = match &mut self.conn {
            Conn::Connecting(s) | Conn::Connected(s) => s,
            Conn::Disconnected => return,
        };
        let _ = poll.registry().reregister(stream, self.token, interest);
    }
}

fn parse_addr(endpoint: &str) -> io::Result<SocketAddr> {
    let hostport = endpoint.trim_start_matches("http://").split('/').next().unwrap_or(endpoint);
    hostport
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address resolved"))
}

pub(crate) struct HttpPool {
    connections: Vec<PooledConnection>,
    endpoint: Endpoint,
    jwt: JwtSecret,
    max_connections: usize,
}

impl HttpPool {
    pub(crate) fn new(endpoint: Endpoint, jwt: JwtSecret, max_connections: usize) -> Self {
        let connections = vec![PooledConnection::new(endpoint.clone(), jwt.clone(), Token(0))];
        Self { connections, endpoint, jwt, max_connections }
    }

    /// `enqueue` never refuses work; every caller gates on this before
    /// submitting. The first-run healthcheck trio issues three requests
    /// against one gate check, so the pool can overshoot `max_connections`
    /// by at most two connections, once.
    pub(crate) fn has_capacity(&self) -> bool {
        self.connections.iter().any(PooledConnection::is_free) ||
            self.connections.len() < self.max_connections
    }

    pub(crate) fn enqueue(&mut self, rpc_id: u64, body: &[u8], poll: &mut Poll) {
        if let Some(conn) = self.connections.iter_mut().find(|c| c.is_free()) {
            conn.enqueue(rpc_id, body, poll);
        } else {
            let mut new_conn = PooledConnection::new(
                self.endpoint.clone(),
                self.jwt.clone(),
                Token(self.connections.len()),
            );
            new_conn.enqueue(rpc_id, body, poll);
            self.connections.push(new_conn);
        }
    }

    pub(crate) fn poll_events<F>(&mut self, events: &Events, poll: &mut Poll, on_complete: &mut F)
    where
        F: FnMut(u64, Result<&mut [u8], EngineError>),
    {
        for conn in &mut self.connections {
            // Disconnected with a request pending means connect() could not
            // even start (resolve/connect/register error): no event will ever
            // arrive for it, so fail the rpc here or it is stranded forever.
            if matches!(conn.conn, Conn::Disconnected) && conn.pending_id.is_some() {
                conn.fail(poll, on_complete, "connect failed to start");
            }
            conn.handle_events(events, poll, on_complete);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tempfile::TempDir;

    use crate::{
        EngineClient,
        client::{ReqKind, poll, send_fcu},
        test_el::{FCU_VALID_RESULT, FakeEl, write_jwt},
        types::ForkchoiceState,
    };

    fn fcu_state(byte: u8) -> ForkchoiceState {
        ForkchoiceState {
            head_block_hash: [byte; 32],
            safe_block_hash: [byte; 32],
            finalized_block_hash: [byte; 32],
        }
    }

    fn spin_until(deadline_msg: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timeout: {deadline_msg}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn uds_round_trip_resolves_correlation_with_jwt() {
        let dir = TempDir::new().unwrap();
        let jwt_path = write_jwt(dir.path());
        let socket = dir.path().join("engine.sock");
        let mut el = FakeEl::uds(&socket);

        let mut client = EngineClient::new_uds(&socket, jwt_path.to_str().unwrap(), 32);
        let block_root = [7u8; 32];
        send_fcu(&mut client, block_root, fcu_state(1), None);

        let mut responded = false;
        let mut completed: Option<([u8; 32], Vec<u8>)> = None;
        spin_until("fcu round trip over uds", || {
            poll(&mut client, |kind, response| {
                let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
                completed = Some((root, response.expect("fcu response").to_vec()));
            });
            el.pump();
            if !responded && !el.requests.is_empty() {
                let request = &el.requests[0];
                assert_eq!(request.method, "engine_forkchoiceUpdatedV3");
                let auth = request.authorization.as_deref().expect("JWT header sent over UDS");
                let token = auth.strip_prefix("Bearer ").expect("bearer scheme");
                assert_eq!(token.split('.').count(), 3, "three-part JWT");
                assert!(
                    request.body.contains(&format!("\"headBlockHash\":\"0x{}\"", "01".repeat(32)))
                );
                el.respond(0, FCU_VALID_RESULT);
                responded = true;
            }
            completed.is_some()
        });

        let (root, body) = completed.unwrap();
        assert_eq!(root, block_root, "completion correlated to the issued request");
        assert!(String::from_utf8(body).unwrap().contains("VALID"));
    }

    #[test]
    fn connect_failure_fails_rpc_and_frees_connection() {
        let dir = TempDir::new().unwrap();
        let jwt_path = write_jwt(dir.path());
        let missing_socket = dir.path().join("missing.sock");

        // max_connections = 1: after the failure, has_capacity() can only be
        // true again if the zombie connection was actually freed.
        let mut client = EngineClient::new_uds(&missing_socket, jwt_path.to_str().unwrap(), 1);
        let block_root = [3u8; 32];
        send_fcu(&mut client, block_root, fcu_state(3), None);
        assert!(!client.has_capacity(), "request occupies the only connection");

        let mut failed: Option<[u8; 32]> = None;
        spin_until("connect failure surfaces as rpc error", || {
            poll(&mut client, |kind, response| {
                let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
                assert!(response.is_err(), "unstartable connect must fail the rpc");
                failed = Some(root);
            });
            failed.is_some()
        });

        assert_eq!(failed.unwrap(), block_root);
        assert!(client.has_capacity(), "failed connection must be reusable");
    }

    #[test]
    fn transport_error_fails_in_flight_request() {
        let dir = TempDir::new().unwrap();
        let jwt_path = write_jwt(dir.path());
        let socket = dir.path().join("engine.sock");
        let mut el = FakeEl::uds(&socket);

        let mut client = EngineClient::new_uds(&socket, jwt_path.to_str().unwrap(), 32);
        let block_root = [9u8; 32];
        send_fcu(&mut client, block_root, fcu_state(2), None);

        let mut request_seen = false;
        let mut failure: Option<[u8; 32]> = None;
        spin_until("in-flight request failed on connection close", || {
            poll(&mut client, |kind, response| {
                let ReqKind::Fcu(root) = kind else { panic!("unexpected completion") };
                assert!(response.is_err(), "closed connection must fail the rpc");
                failure = Some(root);
            });
            el.pump();
            if !request_seen && !el.requests.is_empty() {
                el.close_connection_of(0);
                request_seen = true;
            }
            failure.is_some()
        });

        assert_eq!(failure.unwrap(), block_root);
    }
}
