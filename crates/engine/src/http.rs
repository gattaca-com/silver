use std::{
    io::{self, Read, Write},
    net::{SocketAddr, ToSocketAddrs},
};

use mio::{Events, Interest, Poll, Token, net::TcpStream};

use crate::{EngineError, JwtSecret};

pub(crate) const POOL_SIZE: usize = 4;

#[derive(PartialEq)]
enum State {
    Disconnected,
    Connecting,
    Connected,
}

pub(crate) struct HttpConnection {
    endpoint: String,
    host: String,
    jwt: JwtSecret,
    token: Token,
    stream: Option<TcpStream>,
    state: State,
    addr: Option<SocketAddr>,
    pending: Option<(u64, Vec<u8>)>,
    write_pos: usize,
    in_flight: Option<u64>,
    read_buf: Vec<u8>,
    read_offset: usize,
}

impl HttpConnection {
    pub(crate) fn new(endpoint: String, jwt: JwtSecret, token: Token) -> Self {
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
            stream: None,
            state: State::Disconnected,
            addr: None,
            pending: None,
            write_pos: 0,
            in_flight: None,
            read_buf: Vec::new(),
            read_offset: 0,
        }
    }
}

pub(crate) fn http_is_free(t: &HttpConnection) -> bool {
    t.in_flight.is_none() && t.pending.is_none()
}

pub(crate) fn http_enqueue(
    t: &mut HttpConnection,
    rpc_id: u64,
    body: &serde_json::Value,
    poll: &mut Poll,
) {
    let json = serde_json::to_vec(body).unwrap_or_default();
    let bearer = t.jwt.bearer_token();
    let bytes = build_request(&t.host, &json, bearer, true);
    t.pending = Some((rpc_id, bytes));

    match t.state {
        State::Disconnected => http_connect(t, poll),
        State::Connected => http_set_interest(t, poll, Interest::READABLE | Interest::WRITABLE),
        State::Connecting => {}
    }
}

pub(crate) fn http_poll<F>(
    t: &mut HttpConnection,
    events: &Events,
    poll: &mut Poll,
    on_complete: &mut F,
) where
    F: FnMut(u64, Result<serde_json::Value, EngineError>),
{
    for event in events.iter() {
        if event.token() != t.token {
            continue;
        }
        match t.state {
            State::Disconnected => {}
            State::Connecting => {
                if event.is_error() || event.is_read_closed() || event.is_write_closed() {
                    http_on_error(t, poll, on_complete, "connect failed");
                    break;
                }
                if event.is_writable() {
                    let connected = t.stream.as_ref().and_then(|s| s.peer_addr().ok()).is_some();
                    if connected {
                        t.state = State::Connected;
                        let interest = if t.pending.is_none() {
                            Interest::READABLE
                        } else {
                            Interest::READABLE | Interest::WRITABLE
                        };
                        http_set_interest(t, poll, interest);
                    } else {
                        http_on_error(t, poll, on_complete, "connect failed");
                        break;
                    }
                }
            }
            State::Connected => {
                if event.is_error() || event.is_read_closed() {
                    http_on_error(t, poll, on_complete, "connection lost");
                    break;
                }
                if event.is_writable() {
                    if let Err(e) = http_do_write(t) {
                        let msg = e.to_string();
                        http_on_error(t, poll, on_complete, &msg);
                        break;
                    }
                    let interest = if t.pending.is_none() {
                        Interest::READABLE
                    } else {
                        Interest::READABLE | Interest::WRITABLE
                    };
                    http_set_interest(t, poll, interest);
                }
                if event.is_readable() {
                    if let Err(e) = http_do_read(t, on_complete) {
                        let msg = e.to_string();
                        http_on_error(t, poll, on_complete, &msg);
                        break;
                    }
                }
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
                tracing::warn!("engine http: resolve failed for {}: {e}", t.endpoint);
                return;
            }
        }
    };
    match TcpStream::connect(addr) {
        Ok(mut stream) => {
            if poll.registry().register(&mut stream, t.token, Interest::WRITABLE).is_ok() {
                t.stream = Some(stream);
                t.state = State::Connecting;
            }
        }
        Err(e) => tracing::warn!("engine http: connect error: {e}"),
    }
}

fn http_do_write(t: &mut HttpConnection) -> io::Result<()> {
    if let Some((_, bytes)) = t.pending.as_ref() {
        let stream = t.stream.as_mut().unwrap();
        loop {
            match stream.write(&bytes[t.write_pos..]) {
                Ok(0) => break,
                Ok(n) => {
                    t.write_pos += n;
                    if t.write_pos == bytes.len() {
                        let (rpc_id, _) = t.pending.take().unwrap();
                        t.in_flight = Some(rpc_id);
                        t.write_pos = 0;
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

fn http_do_read<F>(t: &mut HttpConnection, on_complete: &mut F) -> io::Result<()>
where
    F: FnMut(u64, Result<serde_json::Value, EngineError>),
{
    let stream = t.stream.as_mut().unwrap();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::ConnectionReset, "eof")),
            Ok(n) => {
                t.read_buf.extend_from_slice(&buf[..n]);
                loop {
                    match try_parse_response(&t.read_buf[t.read_offset..]) {
                        Some((result, consumed)) => {
                            t.read_offset += consumed;
                            if let Some(rpc_id) = t.in_flight.take() {
                                on_complete(rpc_id, result);
                            }
                        }
                        None => break,
                    }
                }
                if t.read_offset == t.read_buf.len() {
                    t.read_buf.clear();
                    t.read_offset = 0;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn http_on_error<F>(t: &mut HttpConnection, poll: &mut Poll, on_complete: &mut F, msg: &str)
where
    F: FnMut(u64, Result<serde_json::Value, EngineError>),
{
    tracing::warn!("engine http: {msg}");
    let err = msg.to_string();
    if let Some(rpc_id) = t.in_flight.take() {
        on_complete(rpc_id, Err(EngineError::Http(err.clone())));
    }
    if let Some((rpc_id, _)) = t.pending.take() {
        on_complete(rpc_id, Err(EngineError::Http(err.clone())));
    }
    t.write_pos = 0;
    t.read_buf.clear();
    t.read_offset = 0;
    if let Some(mut stream) = t.stream.take() {
        let _ = poll.registry().deregister(&mut stream);
    }
    t.state = State::Disconnected;
}

fn http_set_interest(t: &mut HttpConnection, poll: &mut Poll, interest: Interest) {
    if let Some(stream) = t.stream.as_mut() {
        let _ = poll.registry().reregister(stream, t.token, interest);
    }
}

pub(crate) struct HttpPool {
    connections: Vec<HttpConnection>,
    endpoint: String,
    jwt: JwtSecret,
}

impl HttpPool {
    pub(crate) fn new(endpoint: String, jwt: JwtSecret, size: usize) -> Self {
        let connections = (0..size)
            .map(|i| HttpConnection::new(endpoint.clone(), jwt.clone(), Token(i)))
            .collect();
        Self { connections, endpoint, jwt }
    }
}

pub(crate) fn http_pool_enqueue(
    pool: &mut HttpPool,
    rpc_id: u64,
    body: &serde_json::Value,
    poll: &mut Poll,
) {
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
    F: FnMut(u64, Result<serde_json::Value, EngineError>),
{
    for conn in &mut pool.connections {
        http_poll(conn, events, poll, on_complete);
    }
}

fn build_request(host: &str, json: &[u8], bearer: &str, keep_alive: bool) -> Vec<u8> {
    let connection = if keep_alive { "keep-alive" } else { "close" };
    let header = format!(
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {len}\r\nAuthorization: {bearer}\r\nConnection: {connection}\r\n\r\n",
        len = json.len(),
    );
    let mut bytes = header.into_bytes();
    bytes.extend_from_slice(json);
    bytes
}

fn parse_addr(endpoint: &str) -> io::Result<SocketAddr> {
    let hostport = endpoint.trim_start_matches("http://").split('/').next().unwrap_or(endpoint);
    hostport
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address resolved"))
}

pub(crate) fn try_parse_response(
    buf: &[u8],
) -> Option<(Result<serde_json::Value, EngineError>, usize)> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut resp = httparse::Response::new(&mut headers);

    let header_end = match resp.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return None,
        Err(e) => {
            return Some((Err(EngineError::Http(format!("httparse: {e}"))), buf.len()));
        }
    };

    let cl_bytes = headers.iter().find(|h| h.name.eq_ignore_ascii_case("content-length"))?.value;
    if !cl_bytes.iter().all(|b| b.is_ascii_digit()) {
        return Some((Err(EngineError::Http("invalid Content-Length".into())), buf.len()));
    }
    let content_length: usize =
        cl_bytes.iter().copied().fold(0usize, |acc, b| acc * 10 + (b - b'0') as usize);

    let total = header_end + content_length;
    if buf.len() < total {
        return None;
    }

    let body = &buf[header_end..total];
    Some((serde_json::from_slice(body).map_err(EngineError::Json), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_response(body: &[u8]) -> Vec<u8> {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut buf = header.into_bytes();
        buf.extend_from_slice(body);
        buf
    }

    #[test]
    fn parse_complete_response() {
        let body = br#"{"jsonrpc":"2.0","id":1,"result":true}"#;
        let buf = http_response(body);
        let (result, consumed) = try_parse_response(&buf).unwrap();
        assert!(result.is_ok());
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_incomplete_headers_returns_none() {
        let partial = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n";
        assert!(try_parse_response(partial).is_none());
    }

    #[test]
    fn parse_complete_headers_but_truncated_body_returns_none() {
        let body = br#"{"result":1}"#;
        let mut buf = http_response(body);
        buf.truncate(buf.len() - 3);
        assert!(try_parse_response(&buf).is_none());
    }

    #[test]
    fn parse_two_responses_sequentially() {
        let body = br#"{"id":1}"#;
        let single = http_response(body);
        let mut buf = single.clone();
        buf.extend_from_slice(&single);

        let (r1, n1) = try_parse_response(&buf).unwrap();
        assert!(r1.is_ok());
        let (r2, n2) = try_parse_response(&buf[n1..]).unwrap();
        assert!(r2.is_ok());
        assert_eq!(n1, n2, "both responses are the same size");
        assert_eq!(n1 + n2, buf.len());
    }

    #[test]
    fn parse_missing_content_length_returns_none() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}";
        assert!(try_parse_response(buf).is_none(), "no Content-Length header → None");
    }

    #[test]
    fn parse_large_body_correct_consumed_count() {
        let body: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        // wrap in a JSON string so serde accepts it
        let json_body = serde_json::to_vec(&serde_json::Value::String(
            String::from_utf8_lossy(&body).into_owned(),
        ))
        .unwrap();
        let buf = http_response(&json_body);
        let (result, consumed) = try_parse_response(&buf).unwrap();
        assert!(result.is_ok());
        assert_eq!(consumed, buf.len());
    }
}
