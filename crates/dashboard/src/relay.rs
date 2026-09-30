use std::{
    io,
    net::SocketAddr,
    time::{Duration, Instant},
};

use mio::{
    Events, Interest, Poll, Token,
    net::{TcpListener, UdpSocket},
};
use silver_log::{info, warn};
use silver_observe_wire::{HEADER_LEN, Header, Kind, MAX_DATAGRAM};
use slab::Slab;

use crate::{
    conn::{Conn, Progress},
    ring::DatagramRing,
};

const UDP: Token = Token(0);
const LISTENER: Token = Token(1);
const CONN_BASE: usize = 2;
/// Every instance costs a full ring; senders past this are dropped.
const MAX_INSTANCES: usize = 64;
const STATS: Duration = Duration::from_secs(10);

pub struct Instance {
    pub ring: DatagramRing,
    id: u64,
    label: String,
    boot_id: u64,
    next_seq: u64,
    lost: u64,
}

impl Instance {
    fn record(&mut self, header: &Header, dgram: &[u8]) {
        if header.boot_id != self.boot_id {
            self.boot_id = header.boot_id;
            self.next_seq = header.seq;
        }
        if header.seq > self.next_seq {
            self.lost += header.seq - self.next_seq;
        }
        self.next_seq = self.next_seq.max(header.seq + 1);
        if header.kind == Kind::Instance {
            self.label = String::from_utf8_lossy(&dgram[HEADER_LEN..]).into_owned();
        }
        self.ring.push(dgram);
    }

    fn retained(&self) -> Duration {
        let ts = |d: Option<&[u8]>| d.and_then(Header::parse).map_or(0, |h| h.ts_ns);
        Duration::from_nanos(ts(self.ring.newest()).saturating_sub(ts(self.ring.oldest())))
    }
}

struct Client {
    conn: Conn,
    write_registered: bool,
}

pub struct Relay {
    poll: Poll,
    udp: UdpSocket,
    listener: TcpListener,
    instances: Vec<Instance>,
    clients: Slab<Client>,
    ring_budget: usize,
    rejected: u64,
}

impl Relay {
    pub fn bind(
        udp_addr: SocketAddr,
        http_addr: SocketAddr,
        ring_budget: usize,
    ) -> io::Result<Self> {
        let poll = Poll::new()?;
        let mut udp = UdpSocket::bind(udp_addr)?;
        let mut listener = TcpListener::bind(http_addr)?;
        poll.registry().register(&mut udp, UDP, Interest::READABLE)?;
        poll.registry().register(&mut listener, LISTENER, Interest::READABLE)?;
        info!(%udp_addr, %http_addr, ring_budget, "dashboard listening");
        Ok(Self {
            poll,
            udp,
            listener,
            instances: Vec::new(),
            clients: Slab::new(),
            ring_budget,
            rejected: 0,
        })
    }

    pub fn run(mut self) -> io::Result<()> {
        let mut events = Events::with_capacity(256);
        let mut next_stats = Instant::now() + STATS;
        loop {
            match self.poll.poll(&mut events, Some(Duration::from_secs(1))) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
            for event in &events {
                match event.token() {
                    UDP => self.ingest(),
                    LISTENER => self.accept(),
                    Token(t) => {
                        let key = t - CONN_BASE;
                        let Some(client) = self.clients.get_mut(key) else { continue };
                        let progress = if event.is_readable() || event.is_read_closed() {
                            client.conn.on_readable(&self.instances)
                        } else {
                            client.conn.on_writable(&self.instances)
                        };
                        self.settle(key, progress);
                    }
                }
            }

            let now = Instant::now();
            let stalled: Vec<_> =
                self.clients.iter().filter(|(_, c)| c.conn.stalled(now)).map(|(k, _)| k).collect();
            for key in stalled {
                warn!(key, "client stalled, dropping");
                self.settle(key, Progress::Closed);
            }
            if now >= next_stats {
                self.log_stats();
                next_stats = now + STATS;
            }
        }
    }

    /// Drains the socket, then pushes the new tail to every WebSocket client.
    fn ingest(&mut self) {
        let mut buf = [0u8; MAX_DATAGRAM + 1];
        loop {
            let n = match self.udp.recv_from(&mut buf) {
                Ok((n, _)) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    warn!(%e, "udp recv");
                    break;
                }
            };
            let dgram = &buf[..n];
            let Some(header) = Header::parse(dgram) else {
                self.rejected += 1;
                continue;
            };
            let idx = match self.instances.iter().position(|i| i.id == header.instance_id) {
                Some(idx) => idx,
                None if self.instances.len() < MAX_INSTANCES => {
                    info!(instance_id = header.instance_id, "new instance");
                    self.instances.push(Instance {
                        ring: DatagramRing::new(self.ring_budget),
                        id: header.instance_id,
                        label: String::new(),
                        boot_id: header.boot_id,
                        next_seq: header.seq,
                        lost: 0,
                    });
                    self.instances.len() - 1
                }
                None => {
                    self.rejected += 1;
                    continue;
                }
            };
            self.instances[idx].record(&header, dgram);
        }

        let keys: Vec<_> = self.clients.iter().map(|(k, _)| k).collect();
        for key in keys {
            let progress = self.clients[key].conn.on_writable(&self.instances);
            self.settle(key, progress);
        }
    }

    fn accept(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    let entry = self.clients.vacant_entry();
                    let token = Token(entry.key() + CONN_BASE);
                    if let Err(e) =
                        self.poll.registry().register(&mut stream, token, Interest::READABLE)
                    {
                        warn!(%e, "register client");
                        continue;
                    }
                    entry.insert(Client { conn: Conn::new(stream), write_registered: false });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => {
                    warn!(%e, "accept");
                    break;
                }
            }
        }
    }

    /// Closes a finished connection, or matches its registration to whether
    /// it still has bytes queued.
    fn settle(&mut self, key: usize, progress: Progress) {
        let Some(client) = self.clients.get_mut(key) else { return };
        if let Progress::Closed = progress {
            let mut client = self.clients.remove(key);
            let _ = self.poll.registry().deregister(&mut client.conn.stream);
            return;
        }
        let want = client.conn.wants_write();
        if want == client.write_registered {
            return;
        }
        let interest =
            if want { Interest::READABLE | Interest::WRITABLE } else { Interest::READABLE };
        let token = Token(key + CONN_BASE);
        match self.poll.registry().reregister(&mut client.conn.stream, token, interest) {
            Ok(()) => client.write_registered = want,
            Err(e) => {
                warn!(%e, "reregister client");
                self.settle(key, Progress::Closed);
            }
        }
    }

    fn log_stats(&self) {
        for i in &self.instances {
            info!(
                label = i.label,
                instance_id = i.id,
                entries = i.ring.len(),
                bytes = i.ring.bytes(),
                retained_s = i.retained().as_secs(),
                lost = i.lost,
                "instance"
            );
        }
        let lapped: u64 = self.clients.iter().map(|(_, c)| c.conn.lapped()).sum();
        info!(clients = self.clients.len(), lapped, rejected = self.rejected, "relay");
    }
}
