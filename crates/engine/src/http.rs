use std::{
    io::{self, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
};

use mio::{Events, Interest, Poll, Token, net::TcpStream};

use crate::{EngineError, JwtSecret};

// Sized for the largest expected EL response: getPayload with a full
// blobsBundle (~21 blobs × 256 KB hex-encoded + execution payload
// transactions).
const READ_BUF_CAPACITY: usize = 10 * 1024 * 1024;

// Sized for the largest expected outgoing request: newPayload with a full
// block (~30M gas of transactions, hex-encoded in JSON) plus HTTP headers.
const WRITE_BUF_CAPACITY: usize = 10 * 1024 * 1024;

enum Conn {
    Disconnected,
    Connecting(TcpStream),
    Connected(TcpStream),
}

struct HttpConnection {
    endpoint: String,
    host: String,
    jwt: JwtSecret,
    token: Token,
    conn: Conn,
    addr: Option<SocketAddr>,
    in_flight: Option<u64>,
    pending_id: Option<u64>,
    write_buf: Vec<u8>,
    write_pos: usize,
    read_buf: Vec<u8>,
    read_offset: usize,
    // Cached from the first read of the current response; zero = not yet parsed.
    response_header_end: usize,
    response_total: usize, // header_end + content_length
}

impl HttpConnection {
    fn new(endpoint: String, jwt: JwtSecret, token: Token) -> Self {
        let host = endpoint
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("localhost")
            .to_string();
        Self {
            endpoint,
            host,
            jwt,
            token,
            conn: Conn::Disconnected,
            addr: None,
            pending_id: None,
            write_buf: Vec::with_capacity(WRITE_BUF_CAPACITY),
            write_pos: 0,
            in_flight: None,
            read_buf: Vec::with_capacity(READ_BUF_CAPACITY),
            read_offset: 0,
            response_header_end: 0,
            response_total: 0,
        }
    }
}

fn http_is_free(t: &HttpConnection) -> bool {
    t.in_flight.is_none() && t.pending_id.is_none()
}

fn http_enqueue(t: &mut HttpConnection, rpc_id: u64, body: &[u8], poll: &mut Poll) {
    debug_assert!(t.in_flight.is_none() && t.pending_id.is_none(), "enqueue on busy connection");
    let bearer = t.jwt.bearer_token();
    build_request_into(&mut t.write_buf, &t.host, body, bearer, true);
    t.pending_id = Some(rpc_id);
    t.write_pos = 0;

    // matches! borrows t.conn transiently, freeing it before the function call
    // below.
    if matches!(t.conn, Conn::Disconnected) {
        http_connect(t, poll);
    } else if matches!(t.conn, Conn::Connected(_)) {
        http_set_interest(&mut t.conn, t.token, poll, Interest::READABLE | Interest::WRITABLE);
    }
}

fn http_poll<F>(t: &mut HttpConnection, events: &Events, poll: &mut Poll, on_complete: &mut F)
where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    for event in events.iter() {
        if event.token() != t.token {
            continue;
        }
        if matches!(t.conn, Conn::Connecting(_)) {
            if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                http_on_error(t, poll, on_complete, "connect failed");
                break;
            }
            if event.is_writable() {
                // Take ownership to inspect peer_addr and transition state atomically.
                let Conn::Connecting(stream) = std::mem::replace(&mut t.conn, Conn::Disconnected)
                else {
                    unreachable!()
                };
                if stream.peer_addr().is_ok() {
                    t.conn = Conn::Connected(stream);
                    let interest = if t.pending_id.is_none() {
                        Interest::READABLE
                    } else {
                        Interest::READABLE | Interest::WRITABLE
                    };
                    http_set_interest(&mut t.conn, t.token, poll, interest);
                } else {
                    t.conn = Conn::Connecting(stream);
                    http_on_error(t, poll, on_complete, "connect failed");
                    break;
                }
            }
        } else if matches!(t.conn, Conn::Connected(_)) {
            if event.is_error() {
                http_on_error(t, poll, on_complete, "connection error");
                break;
            }
            if event.is_writable() {
                let result = {
                    let Conn::Connected(stream) = &mut t.conn else { unreachable!() };
                    http_do_write(
                        stream,
                        &mut t.pending_id,
                        &t.write_buf,
                        &mut t.write_pos,
                        &mut t.in_flight,
                    )
                };
                if let Err(e) = result {
                    let msg = e.to_string();
                    http_on_error(t, poll, on_complete, &msg);
                    break;
                }
                let interest = if t.pending_id.is_none() {
                    Interest::READABLE
                } else {
                    Interest::READABLE | Interest::WRITABLE
                };
                http_set_interest(&mut t.conn, t.token, poll, interest);
            }
            if event.is_readable() {
                // Drain data before checking is_read_closed: when the remote
                // sends a response + FIN in one exchange (EPOLLIN|EPOLLRDHUP),
                // we must read the response first. http_do_read returns Err on
                // EOF, so the break below covers that close path too.
                let result = {
                    let Conn::Connected(stream) = &mut t.conn else { unreachable!() };
                    http_do_read(
                        stream,
                        &mut t.in_flight,
                        &mut t.read_buf,
                        &mut t.read_offset,
                        &mut t.response_header_end,
                        &mut t.response_total,
                        on_complete,
                    )
                };
                if let Err(e) = result {
                    let msg = e.to_string();
                    http_on_error(t, poll, on_complete, &msg);
                    break;
                }
            }
            if event.is_read_closed() {
                // Remote closed with no (more) data — in_flight will never get
                // a response.
                http_on_error(t, poll, on_complete, "connection closed");
                break;
            }
        }
    }
}

fn http_connect(t: &mut HttpConnection, poll: &mut Poll) {
    let addr = if let Some(a) = t.addr {
        a
    } else {
        match parse_addr(&t.endpoint) {
            Ok(a) => {
                t.addr = Some(a);
                a
            }
            Err(e) => {
                tracing::warn!("resolve failed for {}: {e}", t.endpoint);
                return;
            }
        }
    };
    match TcpStream::connect(addr) {
        Ok(mut stream) => {
            if poll.registry().register(&mut stream, t.token, Interest::WRITABLE).is_ok() {
                t.conn = Conn::Connecting(stream);
            }
        }
        Err(e) => tracing::warn!("connect error: {e}"),
    }
}

fn http_do_write(
    stream: &mut TcpStream,
    pending_id: &mut Option<u64>,
    write_buf: &[u8],
    write_pos: &mut usize,
    in_flight: &mut Option<u64>,
) -> io::Result<()> {
    if pending_id.is_some() {
        loop {
            match stream.write(&write_buf[*write_pos..]) {
                Ok(0) => break,
                Ok(n) => {
                    *write_pos += n;
                    if *write_pos == write_buf.len() {
                        *in_flight = pending_id.take();
                        *write_pos = 0;
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn http_do_read<F>(
    stream: &mut TcpStream,
    in_flight: &mut Option<u64>,
    read_buf: &mut Vec<u8>,
    read_offset: &mut usize,
    response_header_end: &mut usize,
    response_total: &mut usize,
    on_complete: &mut F,
) -> io::Result<()>
where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    loop {
        // Deliver if a complete response is already buffered.
        if *response_total > 0 && read_buf.len() - *read_offset >= *response_total {
            if let Some(rpc_id) = in_flight.take() {
                let start = *read_offset + *response_header_end;
                let end = *read_offset + *response_total;
                on_complete(rpc_id, Ok(&mut read_buf[start..end]));
            }
            *read_offset += *response_total;
            *response_header_end = 0;
            *response_total = 0;
            if *read_offset == read_buf.len() {
                read_buf.clear();
                *read_offset = 0;
            }
            continue;
        }

        let want = if *response_total > 0 {
            // Know total size; read exactly the remaining bytes.
            *response_total - (read_buf.len() - *read_offset)
        } else {
            // Headers not yet parsed; 4096 covers any realistic HTTP response header.
            4096
        };

        let base = read_buf.len();
        read_buf.resize(base + want, 0);
        match stream.read(&mut read_buf[base..]) {
            Ok(0) => {
                return Err(io::Error::new(io::ErrorKind::ConnectionReset, "eof"));
            }
            Ok(n) => {
                read_buf.truncate(base + n);
                if *response_total == 0 {
                    match try_parse_headers(&read_buf[*read_offset..]) {
                        Ok(Some((hend, cl))) => {
                            *response_header_end = hend;
                            *response_total = hend + cl;
                        }
                        Ok(None) => {} // headers still incomplete
                        Err(e) => {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
                        }
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                read_buf.truncate(base);
                break;
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    Ok(())
}

fn http_on_error<F>(t: &mut HttpConnection, poll: &mut Poll, on_complete: &mut F, msg: &str)
where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    tracing::warn!("{msg}");
    let err = msg.to_string();
    if let Some(rpc_id) = t.in_flight.take() {
        on_complete(rpc_id, Err(EngineError::Http(err.clone())));
    }
    if let Some(rpc_id) = t.pending_id.take() {
        on_complete(rpc_id, Err(EngineError::Http(err.clone())));
    }
    t.write_pos = 0;
    t.read_buf.clear();
    t.read_offset = 0;
    t.response_header_end = 0;
    t.response_total = 0;
    let old = std::mem::replace(&mut t.conn, Conn::Disconnected);
    if let Conn::Connecting(mut stream) | Conn::Connected(mut stream) = old {
        let _ = poll.registry().deregister(&mut stream);
    }
}

fn http_set_interest(conn: &mut Conn, token: Token, poll: &mut Poll, interest: Interest) {
    let stream = match conn {
        Conn::Connecting(s) | Conn::Connected(s) => s,
        Conn::Disconnected => return,
    };
    let _ = poll.registry().reregister(stream, token, interest);
}

// Connection helper functions
fn build_request_into(buf: &mut Vec<u8>, host: &str, json: &[u8], bearer: &str, keep_alive: bool) {
    use std::io::Write as _;
    let connection = if keep_alive { "keep-alive" } else { "close" };
    buf.clear();
    // SAFETY: Vec<u8>'s io::Write impl is infallible.
    write!(
        buf,
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nAuthorization: {bearer}\r\nConnection: {connection}\r\n\r\n",
        len = json.len(),
    )
    .unwrap();
    buf.extend_from_slice(json);
}

fn parse_addr(endpoint: &str) -> io::Result<SocketAddr> {
    let hostport = endpoint.trim_start_matches("http://").split('/').next().unwrap_or(endpoint);
    hostport
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address resolved"))
}

// Returns (header_end, content_length) when headers are complete, None if
// partial.
fn try_parse_headers(buf: &[u8]) -> Result<Option<(usize, usize)>, EngineError> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);
    let header_end = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(e) => return Err(EngineError::Http(format!("httparse: {e}"))),
    };
    match headers.iter().find(|h| h.name.eq_ignore_ascii_case("content-length")) {
        Some(h) if h.value.iter().all(|b| b.is_ascii_digit()) => {
            let cl = h.value.iter().copied().fold(0usize, |acc, b| acc * 10 + (b - b'0') as usize);
            Ok(Some((header_end, cl)))
        }
        Some(_) => Err(EngineError::Http("invalid Content-Length".into())),
        None => Err(EngineError::Http("missing Content-Length".into())),
    }
}

pub(crate) struct HttpPool {
    connections: Vec<HttpConnection>,
    endpoint: String,
    jwt: JwtSecret,
}

impl HttpPool {
    pub(crate) fn new(endpoint: String, jwt: JwtSecret) -> Self {
        let connections = vec![HttpConnection::new(endpoint.clone(), jwt.clone(), Token(0))];
        Self { connections, endpoint, jwt }
    }
}

pub(crate) fn http_pool_enqueue(pool: &mut HttpPool, rpc_id: u64, body: &[u8], poll: &mut Poll) {
    if let Some(conn) = pool.connections.iter_mut().find(|c| http_is_free(c)) {
        http_enqueue(conn, rpc_id, body, poll);
    } else {
        let mut new_conn = HttpConnection::new(
            pool.endpoint.clone(),
            pool.jwt.clone(),
            Token(pool.connections.len()),
        );
        http_enqueue(&mut new_conn, rpc_id, body, poll);
        pool.connections.push(new_conn);
    }
}

pub(crate) fn poll_http_pool<F>(
    pool: &mut HttpPool,
    events: &Events,
    poll: &mut Poll,
    on_complete: &mut F,
) where
    F: FnMut(u64, Result<&mut [u8], EngineError>),
{
    for conn in &mut pool.connections {
        http_poll(conn, events, poll, on_complete);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(body: &[u8]) -> Vec<u8> {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut buf = header.into_bytes();
        buf.extend_from_slice(body);
        buf
    }

    #[test]
    fn headers_complete_returns_offsets() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":true}"#;
        let buf = make_response(body);
        let (hend, cl) = try_parse_headers(&buf).unwrap().unwrap();
        assert_eq!(cl, body.len());
        assert_eq!(hend + cl, buf.len());
    }

    #[test]
    fn headers_partial_returns_none() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n";
        assert!(try_parse_headers(partial).unwrap().is_none());
    }

    #[test]
    fn headers_complete_body_incomplete_still_returns_offsets() {
        // try_parse_headers only cares about headers; body completeness is the caller's
        // job.
        let body = br#"{"result":1}"#;
        let mut buf = make_response(body);
        buf.truncate(buf.len() - 3);
        let (hend, cl) = try_parse_headers(&buf).unwrap().unwrap();
        assert_eq!(cl, body.len());
        assert!(buf.len() < hend + cl);
    }

    #[test]
    fn missing_content_length_is_error() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}";
        assert!(try_parse_headers(buf).is_err());
    }

    #[test]
    fn invalid_content_length_is_error() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n{}";
        assert!(try_parse_headers(buf).is_err());
    }
}
