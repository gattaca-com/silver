use std::{
    io, mem,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use crate::Stream;

/// Where a pool connects. A host name resolves on its own thread, as
/// `getaddrinfo` blocks for as long as DNS takes.
pub(crate) enum Address {
    Uds(PathBuf),
    /// An IP literal, never looked up.
    Tcp(SocketAddr),
    Unresolved(String),
    Resolving {
        host_port: String,
        answer: Receiver<io::Result<SocketAddr>>,
    },
    Resolved {
        host_port: String,
        addr: SocketAddr,
    },
}

impl Address {
    pub(crate) fn of_host_port(host_port: String) -> Self {
        match host_port.parse() {
            Ok(addr) => Self::Tcp(addr),
            Err(_) => Self::Unresolved(host_port),
        }
    }

    /// `None` while the host name resolves.
    pub(crate) fn connect(&mut self) -> Option<io::Result<Stream>> {
        match self {
            Self::Uds(path) => Some(Stream::connect_uds(path)),
            Self::Tcp(addr) | Self::Resolved { addr, .. } => Some(Stream::connect_tcp(*addr)),
            Self::Resolving { .. } => None,
            Self::Unresolved(host_port) => {
                let host_port = mem::take(host_port);
                let (sender, answer) = mpsc::channel();
                let resolver = host_port.clone();
                let spawned = thread::Builder::new().name("http-resolve".into()).spawn(move || {
                    let _ = sender.send(resolve(&resolver));
                });
                if let Err(error) = spawned {
                    *self = Self::Unresolved(host_port);
                    return Some(Err(error));
                }
                *self = Self::Resolving { host_port, answer };
                None
            }
        }
    }

    /// The resolution's outcome once, when it finishes; a failure leaves the
    /// name to resolve again on the next connect.
    pub(crate) fn poll_resolved(&mut self) -> Option<io::Result<()>> {
        let Self::Resolving { host_port, answer } = self else { return None };
        let resolved = match answer.try_recv() {
            Ok(resolved) => resolved,
            Err(TryRecvError::Empty) => return None,
            Err(TryRecvError::Disconnected) => Err(io::Error::other("resolver thread died")),
        };
        match resolved {
            Ok(addr) => *self = Self::Resolved { host_port: mem::take(host_port), addr },
            Err(error) => {
                *self = Self::Unresolved(mem::take(host_port));
                return Some(Err(error));
            }
        }
        Some(Ok(()))
    }

    /// After a failed connect: the host may have moved, so the next connect
    /// looks its name up again.
    pub(crate) fn forget_resolved(&mut self) {
        if let Self::Resolved { host_port, addr } = self {
            silver_log::info!(host_port, %addr, "connect failed; resolving again");
            *self = Self::Unresolved(mem::take(host_port));
        }
    }
}

fn resolve(host_port: &str) -> io::Result<SocketAddr> {
    host_port
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no address resolved"))
}
