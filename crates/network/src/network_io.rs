mod mio_io;
mod rx_pool_metrics;
#[cfg(test)]
mod tests;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub(crate) mod uring_io;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
mod uring_ring;

use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bytes::BytesMut;
use mio_io::MioIo;
use quinn_proto::Transmit;
use rx_pool_metrics::RxPoolMetrics;
use silver_config::NetworkConfig;
#[cfg(all(target_os = "linux", feature = "io-uring"))]
use uring_io::UringIo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketId {
    Quic,
    Discovery,
}

pub(crate) enum NetworkIo {
    Mio(Box<MioIo>),
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    Uring(Box<UringIo>),
}

impl NetworkIo {
    pub(crate) fn new(
        quic_addr: SocketAddr,
        discovery_addr: SocketAddr,
        config: &NetworkConfig,
    ) -> io::Result<Self> {
        match config {
            NetworkConfig::Mio => {
                let io = MioIo::new(quic_addr, discovery_addr)?;
                for socket in [SocketId::Quic, SocketId::Discovery] {
                    RxPoolMetrics::new(socket, 0).publish(0);
                }
                Ok(Self::Mio(Box::new(io)))
            }
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            NetworkConfig::IoUring(config) => {
                let mut io = UringIo::new(config, quic_addr, discovery_addr)?;
                io.register_spine_waker();
                Ok(Self::Uring(Box::new(io)))
            }
            #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
            NetworkConfig::IoUring(_) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "network io_uring requires Linux and a build with --features io-uring",
            )),
        }
    }

    #[cfg(feature = "thread_park")]
    pub(crate) fn register_spine_waker(&mut self) -> io::Result<()> {
        match self {
            Self::Mio(io) => io.register_spine_waker(),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => {
                io.register_spine_waker();
                Ok(())
            }
        }
    }

    pub(crate) fn start_loop(&mut self) {
        #[cfg(all(target_os = "linux", feature = "io-uring", feature = "thread_park"))]
        if let Self::Uring(io) = self {
            io.start_loop();
        }
    }

    pub(crate) fn wait(&mut self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Mio(io) => io.poll(timeout),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => io.wait_for_completions(timeout),
        }
    }

    pub(crate) fn recv<F>(&mut self, receive: F) -> io::Result<()>
    where
        F: FnMut(SocketId, BytesMut, SocketAddr, &mut Vec<u8>) -> Option<Transmit>,
    {
        match self {
            Self::Mio(io) => {
                io.poll(Duration::ZERO)?;
                io.recv(receive);
                Ok(())
            }
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => io.poll_with_response(Duration::ZERO, receive).map(|_| ()),
        }
    }

    pub(crate) fn is_blocked(&self, socket: SocketId) -> bool {
        match self {
            Self::Mio(io) => io.is_blocked(socket),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => io.is_blocked(socket),
        }
    }

    pub(crate) fn flush(&mut self, socket: SocketId) -> bool {
        match self {
            Self::Mio(io) => io.flush(socket),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => match io.flush() {
                Ok(()) => !io.is_blocked(socket),
                Err(error) => {
                    silver_log::error!(?error, "network io_uring submission failed");
                    false
                }
            },
        }
    }

    /// The producer is called only after a transmit buffer is available.
    pub(crate) fn send<F>(&mut self, socket: SocketId, produce: F) -> bool
    where
        F: FnOnce(&mut Vec<u8>) -> Option<Transmit>,
    {
        match self {
            Self::Mio(io) => io.send(socket, produce),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => match io.send(socket, produce) {
                Ok(sent) => sent,
                Err(error) => {
                    silver_log::error!(?error, ?socket, "network io_uring send failed");
                    false
                }
            },
        }
    }

    pub(crate) fn ban(&mut self, ip: IpAddr) {
        match self {
            Self::Mio(io) => io.ban(ip),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => io.ban(ip),
        }
    }

    pub(crate) fn unban(&mut self, ip: IpAddr) {
        match self {
            Self::Mio(io) => io.unban(ip),
            #[cfg(all(target_os = "linux", feature = "io-uring"))]
            Self::Uring(io) => io.unban(ip),
        }
    }
}
