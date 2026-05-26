use std::{
    collections::HashMap,
    io::{self, Read, Write},
    time::Duration,
};

use flux::{spine::SpineAdapter, tile::Tile};
use mio::{
    Events, Interest, Poll, Token,
    net::{TcpListener, TcpStream},
};
use serde::{Deserialize, Serialize};
use silver_common::{Enr, Eth2Addr, Identify, Keypair, SilverSpine};

const LISTENER: Token = Token(0);
const IDENTITY_PATH: &str = "/eth/v1/node/identity";
const METRICS_PATH: &str = "/metrics";
const NOT_FOUND: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
const VERSION_NOT_SUPPORTED: &[u8] =
    b"HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Length: 0\r\n\r\n";
const METRICS_EMPTY: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: 0\r\n\r\n";
// Hard cap on the read buffer. Raw SSZ, uncompressed. 16 MiB matches observed
// production maximums (21 blobs × 128 KiB plus block fields).
const READ_BUF_MAX: usize = 16 << 20;
const WRITE_BUF_INIT: usize = 4096;

#[allow(dead_code)]
struct ParsedRequest<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a str,
    body: &'a [u8],
    version: u8,
    keep_alive: bool,
}

#[derive(Debug, Serialize)]
struct IdentityResponse<'a> {
    data: &'a Identity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    peer_id: String,
    enr: String,
    p2p_addresses: Vec<String>,
    discovery_addresses: Vec<String>,
    metadata: Metadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Metadata {
    seq_number: String,
    attnets: String,
    syncnets: String,
    custody_group_count: String,
}

struct HttpConnection {
    stream: TcpStream,
    read_buf: Box<[u8; READ_BUF_MAX]>,
    read_pos: usize,
    read_end: usize,
    write_buf: Vec<u8>,
    write_pos: usize,
    keep_alive: bool,
}

impl HttpConnection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_buf: Box::new([0u8; READ_BUF_MAX]),
            read_pos: 0,
            read_end: 0,
            write_buf: Vec::with_capacity(WRITE_BUF_INIT),
            write_pos: 0,
            keep_alive: true,
        }
    }

    fn reset(&mut self) {
        self.write_buf.clear();
        self.write_pos = 0;
    }
}

pub struct BeaconApiTile {
    poll: Poll,
    events: Events,
    listener: TcpListener,
    current_token: Token,
    connections: HashMap<Token, HttpConnection>,
    identity_response: Vec<u8>,
}

impl BeaconApiTile {
    pub fn new(keypair: &Keypair, local_enr: Enr, identify: &Identify) -> Self {
        let poll = Poll::new().unwrap();
        let addr = "0.0.0.0:5051".parse().unwrap();
        let mut listener = TcpListener::bind(addr).unwrap();
        poll.registry().register(&mut listener, LISTENER, Interest::READABLE).unwrap();

        let identity_response = build_identity_response(keypair, &local_enr, identify);

        Self {
            poll,
            events: Events::with_capacity(1024),
            listener,
            current_token: Token(LISTENER.0 + 1),
            connections: HashMap::new(),
            identity_response,
        }
    }
}

impl Tile<SilverSpine> for BeaconApiTile {
    fn loop_body(&mut self, _adapter: &mut SpineAdapter<SilverSpine>) {
        self.poll.poll(&mut self.events, Some(Duration::from_millis(100))).unwrap();

        for event in &self.events {
            match event.token() {
                LISTENER => {
                    let (mut stream, address) = match self.listener.accept() {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::warn!("accept failed: {e}");
                            continue;
                        }
                    };

                    tracing::info!("accepted connection from {address}");
                    let token = next(&mut self.current_token);
                    self.poll.registry().register(&mut stream, token, Interest::READABLE).unwrap();
                    self.connections.insert(token, HttpConnection::new(stream));
                }
                token => {
                    if let Some(conn) = self.connections.get_mut(&token) {
                        match handle_event(self.poll.registry(), conn, event, &|req, out| match req
                            .path
                        {
                            IDENTITY_PATH => handle_identity(&self.identity_response, out),
                            METRICS_PATH => handle_metrics(out),
                            _ => handle_unknown(req.path, out),
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
    }
}

fn handle_identity(response: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(response);
}

fn handle_metrics(out: &mut Vec<u8>) {
    out.extend_from_slice(METRICS_EMPTY);
}

fn handle_unknown(path: &str, out: &mut Vec<u8>) {
    tracing::warn!("unknown path: {path}");
    out.extend_from_slice(NOT_FOUND);
}

// TODO: write_buf materialises the full response in heap memory. For large
// payloads (beacon states >200 MiB, blocks, blobs) replace with scatter-gather
// streaming: hold a tcache snapshot reference and write headers + body via
// write_vectored without copying. The write loop already drains by position so
// the structure supports a multi-part write state without changes to the outer
// logic.
//
// TODO: path routing here is exact-match only. Most beacon API paths are
// parameterised (/eth/v1/beacon/states/{state_id}/...). Add prefix/pattern
// matching before implementing any parameterised routes.
fn handle_event<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
    registry: &mio::Registry,
    conn: &mut HttpConnection,
    event: &mio::event::Event,
    request_handler: &F,
) -> io::Result<bool> {
    if event.is_readable() {
        loop {
            if conn.read_end == READ_BUF_MAX {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "request too large"));
            }
            match conn.stream.read(&mut conn.read_buf[conn.read_end..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => conn.read_end += n,
                Err(e) if would_block(&e) => break,
                Err(e) if interrupted(&e) => continue,
                Err(e) => return Err(e),
            }
        }

        dispatch(registry, conn, event.token(), request_handler)?;
        return Ok(false);
    }

    if event.is_writable() {
        if conn.write_pos < conn.write_buf.len() {
            loop {
                match conn.stream.write(&conn.write_buf[conn.write_pos..]) {
                    Ok(0) => {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"))
                    }
                    Ok(n) => {
                        conn.write_pos += n;
                        if conn.write_pos == conn.write_buf.len() {
                            break;
                        }
                    }
                    Err(e) if would_block(&e) => return Ok(false),
                    Err(e) if interrupted(&e) => continue,
                    Err(e) => return Err(e),
                }
            }
            if conn.keep_alive {
                conn.reset();
                // Serve any pipelined request buffered while we were writing.
                // Without this, edge-triggered epoll won't re-fire for data
                // that's already in read_buf.
                if !dispatch(registry, conn, event.token(), request_handler)? {
                    registry.reregister(&mut conn.stream, event.token(), Interest::READABLE)?;
                }
            } else {
                return Ok(true);
            }
        }
        return Ok(false);
    }

    Ok(false)
}

fn dispatch<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
    registry: &mio::Registry,
    conn: &mut HttpConnection,
    token: Token,
    handler: &F,
) -> io::Result<bool> {
    let Some((consumed, req)) = try_parse_request(&conn.read_buf[conn.read_pos..conn.read_end])
    else {
        return Ok(false);
    };
    if req.version != 1 {
        tracing::warn!("rejecting HTTP/1.0 request");
        conn.keep_alive = false;
        conn.write_buf.extend_from_slice(VERSION_NOT_SUPPORTED);
    } else {
        conn.keep_alive = req.keep_alive;
        handler(&req, &mut conn.write_buf);
    }
    conn.read_pos += consumed;
    //TODO: check if we actually need to support pipeling. If not, we can simplify
    // this.
    if conn.read_pos == conn.read_end {
        conn.read_pos = 0;
        conn.read_end = 0;
    }
    registry.reregister(&mut conn.stream, token, Interest::WRITABLE)?;
    Ok(true)
}

fn try_parse_request(buf: &[u8]) -> Option<(usize, ParsedRequest<'_>)> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut headers);
    let headers_end = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        _ => return None,
    };
    let method = req.method?;
    let raw_path = req.path?;
    let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));
    let version = req.version?;
    let keep_alive = version == 1 &&
        !headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case("connection") && h.value.eq_ignore_ascii_case(b"close")
        });
    let content_length: usize =
        match headers.iter().find(|h| h.name.eq_ignore_ascii_case("content-length")) {
            None => 0,
            Some(h) => std::str::from_utf8(h.value).ok().and_then(|v| v.trim().parse().ok())?,
        };
    let total = headers_end + content_length;
    if buf.len() < total {
        return None;
    }
    Some((total, ParsedRequest {
        method,
        path,
        query,
        body: &buf[headers_end..total],
        version,
        keep_alive,
    }))
}

fn build_identity_response(keypair: &Keypair, local_enr: &Enr, identify: &Identify) -> Vec<u8> {
    let pid_multiaddr = Eth2Addr::PeerId(keypair.peer_id()).to_string();
    let peer_id_str = pid_multiaddr.strip_prefix("/p2p/").unwrap_or(&pid_multiaddr);

    let mut p2p_addresses = Vec::new();
    if let Some(addr) = identify.tcp_ipv4 {
        p2p_addresses.push(format!("/ip4/{}/tcp/{}/p2p/{}", addr.ip(), addr.port(), peer_id_str));
    }
    if let Some(addr) = identify.tcp_ipv6 {
        p2p_addresses.push(format!("/ip6/{}/tcp/{}/p2p/{}", addr.ip(), addr.port(), peer_id_str));
    }
    if let Some(addr) = identify.udp_ipv4 {
        p2p_addresses.push(format!(
            "/ip4/{}/udp/{}/quic-v1/p2p/{}",
            addr.ip(),
            addr.port(),
            peer_id_str
        ));
    }
    if let Some(addr) = identify.udp_ipv6 {
        p2p_addresses.push(format!(
            "/ip6/{}/udp/{}/quic-v1/p2p/{}",
            addr.ip(),
            addr.port(),
            peer_id_str
        ));
    }

    let mut discovery_addresses = Vec::new();
    if let (Some(ip), Some(udp)) = (local_enr.ip4(), local_enr.udp4()) {
        discovery_addresses.push(format!("/ip4/{}/udp/{}/p2p/{}", ip, udp, peer_id_str));
    }
    if let (Some(ip), Some(udp)) = (local_enr.ip6(), local_enr.udp6()) {
        discovery_addresses.push(format!("/ip6/{}/udp/{}/p2p/{}", ip, udp, peer_id_str));
    }

    let identity = Identity {
        peer_id: peer_id_str.to_string(),
        enr: local_enr.to_base64(),
        p2p_addresses,
        discovery_addresses,
        metadata: Metadata {
            seq_number: local_enr.seq().to_string(),
            attnets: format!("0x{}", hex::encode(local_enr.attnets().unwrap_or([0u8; 8]))),
            syncnets: format!("0x{:02x}", local_enr.syncnets().unwrap_or(0)),
            custody_group_count: local_enr.cgc().unwrap_or(4).to_string(),
        },
    };

    let body = serde_json::to_string(&IdentityResponse { data: &identity }).unwrap();
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

fn next(current: &mut Token) -> Token {
    let tok = Token(current.0);
    let n = current.0.wrapping_add(1);
    // Skip Token(0) == LISTENER on wrap to avoid aliasing the accept socket.
    current.0 = if n == LISTENER.0 { LISTENER.0 + 1 } else { n };
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
    use silver_common::{Enr, Identify, Keypair};

    use super::*;

    fn get_req(path: &str, version: &str) -> Vec<u8> {
        format!("GET {path} {version}\r\nHost: localhost\r\n\r\n").into_bytes()
    }

    #[test]
    fn parse_http11_defaults_keep_alive() {
        let req = get_req("/eth/v1/node/identity", "HTTP/1.1");
        let (_, r) = try_parse_request(&req).unwrap();
        assert_eq!(r.path, "/eth/v1/node/identity");
        assert!(r.keep_alive);
    }

    #[test]
    fn parse_http11_connection_close() {
        let req = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        let (_, r) = try_parse_request(req).unwrap();
        assert_eq!(r.path, "/metrics");
        assert!(!r.keep_alive);
    }

    #[test]
    fn parse_http10_defaults_close() {
        let req = get_req("/", "HTTP/1.0");
        let (_, r) = try_parse_request(&req).unwrap();
        assert!(!r.keep_alive);
    }

    #[test]
    fn parse_partial_returns_none() {
        assert!(try_parse_request(b"GET /eth/v1/node/identity HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn parse_query_string_split() {
        let req = get_req("/eth/v1/beacon/states/head/validators?status=active", "HTTP/1.1");
        let (_, r) = try_parse_request(&req).unwrap();
        assert_eq!(r.path, "/eth/v1/beacon/states/head/validators");
        assert_eq!(r.query, "status=active");
    }

    #[test]
    fn parse_post_body_buffered() {
        let body = b"{\"slot\":\"1\"}";
        let req = format!(
            "POST /eth/v1/beacon/blocks HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut buf = req.into_bytes();
        // incomplete — body not yet arrived
        assert!(try_parse_request(&buf).is_none());
        buf.extend_from_slice(body);
        let (consumed, r) = try_parse_request(&buf).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.body, body.as_ref());
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn parse_returns_consumed_byte_count() {
        let req1 = b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let req2 = b"GET /eth/v1/node/identity HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let mut buf = req1.to_vec();
        buf.extend_from_slice(req2);
        let (consumed, r) = try_parse_request(&buf).unwrap();
        assert_eq!(r.path, "/metrics");
        assert_eq!(consumed, req1.len());
        let (_, r2) = try_parse_request(&buf[consumed..]).unwrap();
        assert_eq!(r2.path, "/eth/v1/node/identity");
    }

    #[test]
    fn metrics_response_valid_prometheus_format() {
        let mut out = Vec::new();
        handle_metrics(&mut out);
        let s = std::str::from_utf8(&out).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("text/plain; version=0.0.4; charset=utf-8"));
        let body_start = s.find("\r\n\r\n").unwrap() + 4;
        assert_eq!(&s[body_start..], "");
    }

    #[test]
    fn unknown_path_returns_404() {
        let mut out = Vec::new();
        handle_unknown("/not/real", &mut out);
        assert!(out.starts_with(b"HTTP/1.1 404"));
    }

    #[test]
    fn identity_response_content_length_matches_body() {
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().build(kp.secret_key()).unwrap();
        let resp = build_identity_response(&kp, &enr, &Identify::default());
        let s = std::str::from_utf8(&resp).unwrap();
        let header_end = s.find("\r\n\r\n").unwrap();
        let body = &s[header_end + 4..];
        let cl: usize = s[..header_end]
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
            .unwrap()
            .split(':')
            .nth(1)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(cl, body.len());
    }

    #[test]
    fn identity_response_json_fields_present() {
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().build(kp.secret_key()).unwrap();
        let resp = build_identity_response(&kp, &enr, &Identify::default());
        let s = std::str::from_utf8(&resp).unwrap();
        let body = &s[s.find("\r\n\r\n").unwrap() + 4..];
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        let data = &v["data"];
        assert!(data["peer_id"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(data["enr"].as_str().is_some_and(|s| s.starts_with("enr:")));
        assert!(data["metadata"]["seq_number"].as_str().is_some());
        assert!(data["metadata"]["attnets"].as_str().is_some_and(|s| s.starts_with("0x")));
        assert!(data["metadata"]["syncnets"].as_str().is_some_and(|s| s.starts_with("0x")));
    }

    #[test]
    fn identity_response_p2p_address_format() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let kp = Keypair::from_secret(&[1u8; 32]).unwrap();
        let enr = Enr::builder().build(kp.secret_key()).unwrap();
        let mut identify = Identify::default();
        identify.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 9000));
        let resp = build_identity_response(&kp, &enr, &identify);
        let s = std::str::from_utf8(&resp).unwrap();
        let body = &s[s.find("\r\n\r\n").unwrap() + 4..];
        let v: serde_json::Value = serde_json::from_str(body).unwrap();
        let addrs = v["data"]["p2p_addresses"].as_array().unwrap();
        assert_eq!(addrs.len(), 1);
        let addr = addrs[0].as_str().unwrap();
        assert!(addr.starts_with("/ip4/1.2.3.4/tcp/9000/p2p/"), "bad format: {addr}");
    }

    #[test]
    fn parse_invalid_content_length_returns_none() {
        let req = b"POST /foo HTTP/1.1\r\nHost: localhost\r\nContent-Length: abc\r\n\r\n";
        assert!(try_parse_request(req).is_none());
    }

    #[test]
    fn dispatch_http10_writes_version_not_supported() {
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = std_listener.local_addr().unwrap();
        let _client = std::net::TcpStream::connect(addr).unwrap();
        let (server, _) = std_listener.accept().unwrap();
        server.set_nonblocking(true).unwrap();

        let poll = Poll::new().unwrap();
        let token = Token(1);
        let mut stream = mio::net::TcpStream::from_std(server);
        poll.registry().register(&mut stream, token, Interest::READABLE).unwrap();

        let mut conn = HttpConnection::new(stream);
        let req = b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n";
        conn.read_buf[..req.len()].copy_from_slice(req);
        conn.read_end = req.len();

        dispatch(poll.registry(), &mut conn, token, &|_, out| {
            out.extend_from_slice(b"should not appear");
        })
        .unwrap();

        assert!(
            conn.write_buf.starts_with(b"HTTP/1.1 505"),
            "expected 505, got: {:?}",
            String::from_utf8_lossy(&conn.write_buf)
        );
    }

    #[test]
    fn token_wrap_skips_listener() {
        let mut cur = Token(usize::MAX);
        let assigned = next(&mut cur);
        assert_ne!(assigned, LISTENER, "returned token must not alias LISTENER");
        assert_ne!(cur, LISTENER, "next token must not alias LISTENER after wrap");
        assert_eq!(cur.0, LISTENER.0 + 1);
    }
}
