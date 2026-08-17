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
use silver_httpcore::{AfterResponse, ParsedRequest, ServerConnection, frame_response};

const LISTENER: Token = Token(0);
const IDENTITY_PATH: &str = "/eth/v1/node/identity";
const METRICS_PATH: &str = "/metrics";
const METRICS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

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

struct Connection {
    stream: TcpStream,
    http: ServerConnection,
}

pub struct BeaconApiTile {
    poll: Poll,
    events: Events,
    listener: TcpListener,
    current_token: Token,
    connections: HashMap<Token, Connection>,
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
                    self.connections
                        .insert(token, Connection { stream, http: ServerConnection::new() });
                }
                token => {
                    // TODO: path routing here is exact-match only. Most beacon
                    // API paths are parameterised
                    // (/eth/v1/beacon/states/{state_id}/...). Add
                    // prefix/pattern matching before implementing any
                    // parameterised routes.
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
    frame_response(out, "200 OK", Some(METRICS_CONTENT_TYPE), b"");
}

fn handle_unknown(path: &str, out: &mut Vec<u8>) {
    tracing::warn!("unknown path: {path}");
    frame_response(out, "404 Not Found", None, b"");
}

fn handle_event<F: Fn(&ParsedRequest<'_>, &mut Vec<u8>)>(
    registry: &mio::Registry,
    conn: &mut Connection,
    event: &mio::event::Event,
    request_handler: &F,
) -> io::Result<bool> {
    if event.is_readable() {
        loop {
            let space = conn.http.read_space()?;
            match conn.stream.read(space) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Ok(n) => conn.http.commit_read(n),
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
    let mut response = Vec::new();
    frame_response(&mut response, "200 OK", Some("application/json"), body.as_bytes());
    response
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
    fn token_wrap_skips_listener() {
        let mut cur = Token(usize::MAX);
        let assigned = next(&mut cur);
        assert_ne!(assigned, LISTENER, "returned token must not alias LISTENER");
        assert_ne!(cur, LISTENER, "next token must not alias LISTENER after wrap");
        assert_eq!(cur.0, LISTENER.0 + 1);
    }
}
