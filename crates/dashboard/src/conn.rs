//! One browser connection: a single HTTP request, then either a static reply
//! and close, or a WebSocket upgrade. A WebSocket connection is send-only: it
//! holds one cursor per instance ring and frames datagrams out as the socket
//! drains. Inbound bytes are read and dropped; EOF closes.

use std::{
    io::{self, Read, Write},
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD};
use mio::net::TcpStream;
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};

use crate::relay::Instance;

const REQUEST_MAX: usize = 8 << 10;
/// Queued-but-unsent bytes per client. Replay is paced by the socket against
/// this cap, so a long ring never sits in memory twice.
const OUT_CAP: usize = 256 << 10;
/// A client that accepts no bytes for this long is dropped.
const STALL: Duration = Duration::from_secs(30);
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const ASSETS: &[(&str, &str, &[u8])] = &[
    ("/", "text/html; charset=utf-8", include_bytes!("../web/index.html")),
    ("/app.js", "text/javascript", include_bytes!("../web/app.js")),
    ("/wire.js", "text/javascript", include_bytes!("../web/wire.js")),
    ("/state.js", "text/javascript", include_bytes!("../web/state.js")),
    ("/tcaches.js", "text/javascript", include_bytes!("../web/tcaches.js")),
    ("/peers.js", "text/javascript", include_bytes!("../web/peers.js")),
    ("/gossip.js", "text/javascript", include_bytes!("../web/gossip.js")),
    ("/events.js", "text/javascript", include_bytes!("../web/events.js")),
    ("/slot_charts.js", "text/javascript", include_bytes!("../web/slot_charts.js")),
    ("/trace.js", "text/javascript", include_bytes!("../web/trace.js")),
    ("/chart.js", "text/javascript", include_bytes!("../web/chart.js")),
    ("/flow.js", "text/javascript", include_bytes!("../web/flow.js")),
    ("/flow_layout.js", "text/javascript", include_bytes!("../web/flow_layout.js")),
    ("/flow_queues.js", "text/javascript", include_bytes!("../web/flow_queues.js")),
    ("/flow_tcaches.js", "text/javascript", include_bytes!("../web/flow_tcaches.js")),
    (
        "/vendor/uPlot.iife.min.js",
        "text/javascript",
        include_bytes!("../web/vendor/uPlot.iife.min.js"),
    ),
    ("/vendor/uPlot.min.css", "text/css", include_bytes!("../web/vendor/uPlot.min.css")),
    ("/view.js", "text/javascript", include_bytes!("../web/view.js")),
];

enum Phase {
    Request {
        buf: Vec<u8>,
    },
    /// Reply queued; close once it is written.
    Reply,
    WebSocket {
        cursors: Vec<u64>,
        lapped: u64,
    },
}

pub enum Progress {
    Open,
    Closed,
}

pub struct Conn {
    pub stream: TcpStream,
    phase: Phase,
    out: Vec<u8>,
    out_pos: usize,
    /// Set while unsent bytes are queued; reset on write progress.
    waiting_since: Option<Instant>,
}

impl Conn {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            phase: Phase::Request { buf: Vec::new() },
            out: Vec::with_capacity(OUT_CAP),
            out_pos: 0,
            waiting_since: None,
        }
    }

    pub fn wants_write(&self) -> bool {
        self.out_pos < self.out.len()
    }

    pub fn stalled(&self, now: Instant) -> bool {
        self.waiting_since.is_some_and(|t| now.duration_since(t) > STALL)
    }

    pub fn lapped(&self) -> u64 {
        match self.phase {
            Phase::WebSocket { lapped, .. } => lapped,
            _ => 0,
        }
    }

    pub fn on_readable(&mut self, instances: &[Instance]) -> Progress {
        let mut scratch = [0u8; 4096];
        loop {
            match self.stream.read(&mut scratch) {
                Ok(0) => return Progress::Closed,
                Ok(n) => {
                    if let Phase::Request { buf } = &mut self.phase {
                        buf.extend_from_slice(&scratch[..n]);
                        if buf.len() > REQUEST_MAX {
                            return Progress::Closed;
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Progress::Closed,
            }
        }
        if let Phase::Request { buf } = &mut self.phase {
            let buf = std::mem::take(buf);
            match self.respond(&buf, instances) {
                Some(phase) => self.phase = phase,
                None => {
                    self.phase = Phase::Request { buf };
                    return Progress::Open;
                }
            }
        }
        self.on_writable(instances)
    }

    /// `None` while the request head is incomplete.
    fn respond(&mut self, buf: &[u8], instances: &[Instance]) -> Option<Phase> {
        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut req = httparse::Request::new(&mut headers);
        match req.parse(buf) {
            Ok(httparse::Status::Partial) => return None,
            Ok(httparse::Status::Complete(_)) => {}
            Err(_) => return Some(self.reply("400 Bad Request", "text/plain", b"")),
        }
        if req.method != Some("GET") {
            return Some(self.reply("405 Method Not Allowed", "text/plain", b""));
        }
        let path = req.path.unwrap_or("/").split('?').next().unwrap_or("/");
        let header = |name: &str| {
            req.headers.iter().find(|h| h.name.eq_ignore_ascii_case(name)).map(|h| h.value)
        };

        if path == "/ws" {
            let upgrade = header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case(b"websocket"));
            let version_13 = header("sec-websocket-version") == Some(b"13");
            return Some(match header("sec-websocket-key") {
                Some(key) if upgrade && version_13 => self.upgrade(key, instances),
                _ => self.reply("400 Bad Request", "text/plain", b"websocket upgrade expected"),
            });
        }
        Some(match ASSETS.iter().find(|(p, ..)| *p == path) {
            Some((_, content_type, body)) => self.reply("200 OK", content_type, body),
            None => self.reply("404 Not Found", "text/plain", b""),
        })
    }

    fn reply(&mut self, status: &str, content_type: &str, body: &[u8]) -> Phase {
        write!(
            self.out,
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Cache-Control: no-cache\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        self.out.extend_from_slice(body);
        Phase::Reply
    }

    /// RFC 6455 §4.2.2: no Content-Length on a 101.
    fn upgrade(&mut self, key: &[u8], instances: &[Instance]) -> Phase {
        let accept = STANDARD.encode(digest(&SHA1_FOR_LEGACY_USE_ONLY, &[key, WS_GUID].concat()));
        write!(
            self.out,
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .unwrap();
        Phase::WebSocket { cursors: instances.iter().map(|i| i.ring.first()).collect(), lapped: 0 }
    }

    pub fn on_writable(&mut self, instances: &[Instance]) -> Progress {
        loop {
            self.fill(instances);
            if !self.wants_write() {
                return match self.phase {
                    Phase::Reply => Progress::Closed,
                    _ => Progress::Open,
                };
            }
            match self.stream.write(&self.out[self.out_pos..]) {
                Ok(0) => return Progress::Closed,
                Ok(n) => {
                    self.out_pos += n;
                    self.waiting_since = Some(Instant::now());
                    if self.out_pos == self.out.len() {
                        self.out.clear();
                        self.out_pos = 0;
                        self.waiting_since = None;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Progress::Open,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Progress::Closed,
            }
        }
    }

    /// Round-robin across instances so one busy ring cannot starve the rest
    /// during replay.
    fn fill(&mut self, instances: &[Instance]) {
        let Phase::WebSocket { cursors, lapped } = &mut self.phase else { return };
        if self.out_pos > 0 && self.out.len() + 1500 > OUT_CAP {
            self.out.drain(..self.out_pos);
            self.out_pos = 0;
        }
        cursors.resize_with(instances.len(), || 0);
        loop {
            let mut framed = false;
            for (cursor, instance) in cursors.iter_mut().zip(instances) {
                if self.out.len() - self.out_pos >= OUT_CAP {
                    return;
                }
                let ring = &instance.ring;
                if *cursor < ring.first() {
                    *lapped += ring.first() - *cursor;
                    *cursor = ring.first();
                }
                let Some(dgram) = ring.get(*cursor) else { continue };
                frame_binary(&mut self.out, dgram);
                *cursor += 1;
                framed = true;
            }
            if !framed {
                break;
            }
        }
        if self.wants_write() && self.waiting_since.is_none() {
            self.waiting_since = Some(Instant::now());
        }
    }
}

/// Server frames are unmasked (RFC 6455 §5.1).
fn frame_binary(out: &mut Vec<u8>, payload: &[u8]) {
    const FIN_BINARY: u8 = 0x82;
    match payload.len() {
        len @ 0..=125 => out.extend_from_slice(&[FIN_BINARY, len as u8]),
        len @ 126..=0xFFFF => {
            out.extend_from_slice(&[FIN_BINARY, 126]);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        len => {
            out.extend_from_slice(&[FIN_BINARY, 127]);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6455 §1.3 sample handshake.
    #[test]
    fn accept_key_matches_rfc_example() {
        let accept = STANDARD.encode(digest(
            &SHA1_FOR_LEGACY_USE_ONLY,
            &[b"dGhlIHNhbXBsZSBub25jZQ==".as_slice(), WS_GUID].concat(),
        ));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn frame_lengths_use_the_shortest_encoding() {
        let mut out = Vec::new();
        frame_binary(&mut out, &[7; 125]);
        assert_eq!(&out[..2], &[0x82, 125]);
        out.clear();
        frame_binary(&mut out, &[7; 1400]);
        assert_eq!(&out[..4], &[0x82, 126, 0x05, 0x78]);
        assert_eq!(out.len(), 4 + 1400);
    }
}
