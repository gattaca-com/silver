mod collector;
mod exposition;

use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use mio::{
    Interest, Registry,
    net::{TcpListener, TcpStream},
};
use silver_httpcore::{Readiness, ServerConnection, TokenRange, frame_response};

use self::{collector::Collector, exposition::Snapshot};

const CLIENTS: usize = 8;
pub(super) const SOCKETS: usize = CLIENTS + 1;
const TOKENS: TokenRange = TokenRange::share(6, super::TENANTS);
const BUDGET: Duration = Duration::from_micros(100);
const TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUEST: usize = 8192;
const WRITE_CHUNK: usize = 16 * 1024;

struct Client {
    stream: TcpStream,
    http: ServerConnection,
    body: Option<Arc<Snapshot>>,
    part: usize,
    offset: usize,
    received: usize,
    writing: bool,
    ready: bool,
    expires: Instant,
}

impl Client {
    fn new(stream: TcpStream, now: Instant) -> Self {
        Self {
            stream,
            http: ServerConnection::new(),
            body: None,
            part: 0,
            offset: 0,
            received: 0,
            writing: false,
            ready: true,
            expires: now + TIMEOUT,
        }
    }

    fn step(&mut self, snapshot: Option<&Arc<Snapshot>>) -> io::Result<bool> {
        if !self.writing {
            let buf = self.http.read_space()?;
            let len = buf.len().min(MAX_REQUEST - self.received);
            let n = self.stream.read(&mut buf[..len])?;
            if n == 0 {
                return Ok(false);
            }
            self.received += n;
            self.http.commit_read(n);
            self.writing = self.http.dispatch(&mut |req, out| {
                if req.path != "/metrics" {
                    frame_response(out, "404 Not Found", None, b"");
                } else if req.method != "GET" {
                    frame_response(out, "405 Method Not Allowed", None, b"");
                } else if let Some(snapshot) = snapshot {
                    self.body = Some(Arc::clone(snapshot));
                    write!(out, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", snapshot.len).unwrap();
                } else {
                    frame_response(out, "503 Service Unavailable", None, b"");
                }
            });
            if !self.writing && self.received == MAX_REQUEST {
                frame_response(
                    self.http.write_buf_mut(),
                    "431 Request Header Fields Too Large",
                    None,
                    b"",
                );
                self.writing = true;
            }
            return Ok(true);
        }

        let head = self.http.pending_write();
        if !head.is_empty() {
            let n = self.stream.write(head)?;
            self.http.commit_write(n);
            return Ok(n != 0);
        }
        let Some(body) = &self.body else { return Ok(false) };
        while body.parts.get(self.part).is_some_and(String::is_empty) {
            self.part += 1;
        }
        let Some(part) = body.parts.get(self.part) else { return Ok(false) };
        let end = (self.offset + WRITE_CHUNK).min(part.len());
        let n = self.stream.write(&part.as_bytes()[self.offset..end])?;
        self.offset += n;
        if self.offset == part.len() {
            self.part += 1;
            self.offset = 0;
        }
        Ok(n != 0)
    }
}

pub(super) struct MetricsEndpoint {
    listener: TcpListener,
    accepting: bool,
    clients: [Option<Client>; CLIENTS],
    next: usize,
    sources: Collector,
}

impl MetricsEndpoint {
    pub fn bind(addr: SocketAddr, sources: PathBuf, registry: &Registry) -> io::Result<Self> {
        let mut listener = TcpListener::bind(addr)?;
        registry.register(&mut listener, TOKENS.at(0), Interest::READABLE)?;
        Ok(Self {
            listener,
            accepting: false,
            clients: std::array::from_fn(|_| None),
            next: 0,
            sources: Collector::new(sources),
        })
    }

    pub fn discover_sources(&mut self, epoch: u64) {
        self.sources.discover(epoch);
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    fn accept_one(&mut self, registry: &Registry, now: Instant) {
        match self.listener.accept() {
            Ok((mut stream, _)) => {
                if let Some((i, slot)) =
                    self.clients.iter_mut().enumerate().find(|(_, c)| c.is_none()) &&
                    registry
                        .register(
                            &mut stream,
                            TOKENS.at(i + 1),
                            Interest::READABLE | Interest::WRITABLE,
                        )
                        .is_ok()
                {
                    *slot = Some(Client::new(stream, now));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => self.accepting = false,
        }
    }

    pub fn pump(&mut self, readiness: &Readiness) -> bool {
        let now = Instant::now();
        let deadline = now + BUDGET;
        for event in readiness.events() {
            match TOKENS.offset_of(event.token()) {
                Some(0) => self.accepting = true,
                Some(n @ 1..=CLIENTS) => {
                    if let Some(c) = &mut self.clients[n - 1] {
                        c.ready = true;
                    }
                }
                _ => {}
            }
        }
        if self.accepting {
            self.accept_one(readiness.registry(), now);
        }
        for _ in 0..CLIENTS {
            let slot = &mut self.clients[self.next];
            self.next = (self.next + 1) % CLIENTS;
            if let Some(c) = slot {
                if now >= c.expires {
                    *slot = None;
                } else if c.ready {
                    match c.step(self.sources.snapshot.as_ref()) {
                        Ok(false) => *slot = None,
                        Ok(true) => {}
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => c.ready = false,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(_) => *slot = None,
                    }
                }
            }
            if Instant::now() >= now + BUDGET / 2 {
                break;
            }
        }
        self.sources.pump(now, deadline) ||
            self.accepting ||
            self.clients.iter().flatten().any(|c| c.ready)
    }
}

#[cfg(test)]
mod tests;
