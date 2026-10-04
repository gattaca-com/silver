#[cfg(feature = "thread_park")]
mod futex_wake;
mod provided_buffers;
#[cfg(test)]
mod tests;
mod tx_pool;

use std::{
    io,
    mem::ManuallyDrop,
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

use bytes::BytesMut;
#[cfg(feature = "thread_park")]
use flux::park::SIGNAL;
#[cfg(feature = "thread_park")]
use futex_wake::{FUTEX_TAG, FutexWake};
use fxhash::FxHasher;
use io_uring::{IoUring, cqueue, opcode, types};
use provided_buffers::{NAME_SPACE, ProvidedBuffers};
use quinn_proto::Transmit;
use silver_common::WitherFilter;
use silver_config::UringConfig;
use tx_pool::{TX_TAG, TxPool};

use super::{SocketId, uring_ring};
use crate::socket::{RX_BUF_SIZE, bind_udp};

const SOCKETS: [SocketId; 2] = [SocketId::Quic, SocketId::Discovery];
const CANCEL_TAG: u64 = 2;

pub struct UringIo {
    ring: IoUring,
    sockets: [UdpSocket; 2],
    // Retain kernel-visible memory if cancellation or unregistration fails during Drop.
    pools: ManuallyDrop<[ProvidedBuffers; 2]>,
    header: ManuallyDrop<Box<libc::msghdr>>,
    tx: ManuallyDrop<[TxPool; 2]>,
    active: [bool; 2],
    files_registered: bool,
    next_tx_socket: usize,
    enabled: bool,
    stopped: bool,
    scratch: Vec<u8>,
    banned_ips: WitherFilter<IpAddr, FxHasher, 1024>,
    #[cfg(feature = "thread_park")]
    wake: Option<FutexWake>,
}

// SAFETY: kernel pointers refer to stable heap storage. All application access
// requires &mut self.
unsafe impl Send for UringIo {}

impl UringIo {
    /// The ring is enabled on the first flush or poll, which binds it to that
    /// thread as its single issuer. Construction may happen on another thread;
    /// shutdown and drop must run on the issuer.
    pub fn new(
        config: &UringConfig,
        quic_addr: SocketAddr,
        discovery_addr: SocketAddr,
    ) -> io::Result<Self> {
        let ring = uring_ring::build(config)?;
        let sockets = [bind_udp(quic_addr)?, bind_udp(discovery_addr)?];
        ring.submitter().register_files(&[sockets[0].as_raw_fd(), sockets[1].as_raw_fd()])?;
        let pools = [
            ProvidedBuffers::new(SocketId::Quic, config.quic_rx_buffers)?,
            ProvidedBuffers::new(SocketId::Discovery, config.discovery_rx_buffers)?,
        ];
        // SAFETY: null pointers and zero lengths are valid; multishot reads only the
        // reserved lengths.
        let mut header: Box<libc::msghdr> = Box::new(unsafe { std::mem::zeroed() });
        header.msg_namelen = NAME_SPACE as _;
        let mut receiver = Self {
            ring,
            sockets,
            pools: ManuallyDrop::new(pools),
            header: ManuallyDrop::new(header),
            tx: ManuallyDrop::new([
                TxPool::new(SocketId::Quic, config.quic_tx_buffers, config.send_zc_min_size),
                TxPool::new(
                    SocketId::Discovery,
                    config.discovery_tx_buffers,
                    config.send_zc_min_size,
                ),
            ]),
            active: [false; 2],
            files_registered: true,
            next_tx_socket: 0,
            enabled: false,
            stopped: false,
            scratch: Vec::with_capacity(RX_BUF_SIZE),
            banned_ips: WitherFilter::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            #[cfg(feature = "thread_park")]
            wake: None,
        };
        for pool in receiver.pools.iter_mut() {
            pool.register(&receiver.ring)?;
        }
        Ok(receiver)
    }

    pub fn local_addr(&self, socket: SocketId) -> io::Result<SocketAddr> {
        self.sockets[socket as usize].local_addr()
    }

    pub(crate) fn register_spine_waker(&mut self) {
        #[cfg(feature = "thread_park")]
        self.wake.get_or_insert_with(|| FutexWake::new(&SIGNAL));
    }

    #[cfg(feature = "thread_park")]
    pub(crate) fn start_loop(&mut self) {
        if let Some(wake) = &mut self.wake {
            wake.snapshot();
        }
    }

    pub(crate) fn ban(&mut self, ip: IpAddr) {
        self.banned_ips.insert(ip);
    }

    pub(crate) fn unban(&mut self, ip: IpAddr) {
        self.banned_ips.remove(&ip);
    }

    pub fn is_blocked(&self, socket: SocketId) -> bool {
        self.tx[socket as usize].is_blocked()
    }

    /// Calls the producer only when a slot is available. Accepted packets are
    /// submitted by flush or poll.
    pub fn send<F>(&mut self, socket: SocketId, produce: F) -> io::Result<bool>
    where
        F: FnOnce(&mut Vec<u8>) -> Option<Transmit>,
    {
        self.tx[socket as usize].enqueue(produce)
    }

    /// Publishes queued work. Transmit slots remain reserved until poll
    /// processes their completions.
    #[timed]
    pub fn flush(&mut self) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "io_uring is stopped"));
        }
        if !self.enabled {
            self.ring.submitter().register_enable_rings()?;
            self.enabled = true;
        }
        self.rearm();
        for index in [self.next_tx_socket, self.next_tx_socket ^ 1] {
            self.tx[index].submit(&mut self.ring);
        }
        self.next_tx_socket ^= 1;
        let pending = {
            let submission = self.ring.submission();
            !submission.is_empty() || submission.cq_overflow() || submission.taskrun()
        };
        if pending {
            self.ring.submit()?;
        }
        Ok(())
    }

    /// Retained packets keep their pool slots until a later call can reclaim
    /// their storage.
    pub fn poll<F>(&mut self, timeout: Duration, mut receive: F) -> io::Result<usize>
    where
        F: FnMut(SocketId, BytesMut, SocketAddr),
    {
        self.poll_with_response(timeout, |socket, data, remote, _| {
            receive(socket, data, remote);
            None
        })
    }

    pub(crate) fn wait_for_completions(&mut self, timeout: Duration) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "io_uring is stopped"));
        }
        self.recycle();
        // The caller has run since the last poll, so buffers still retained here
        // are pinned by unread data rather than in transit.
        for pool in self.pools.iter_mut() {
            pool.replace_if_exhausted();
        }
        #[cfg(feature = "thread_park")]
        if !timeout.is_zero() &&
            let Some(wake) = &mut self.wake
        {
            if !wake.arm(&mut self.ring) {
                // A full SQ must not allow a sleep without a spine wakeup.
                self.flush()?;
                return Ok(());
            }
        }
        self.flush()?;
        if self.ring.completion().is_empty() && !timeout.is_zero() {
            self.wait(timeout)?;
        }
        Ok(())
    }

    pub(crate) fn poll_with_response<F>(
        &mut self,
        timeout: Duration,
        mut receive: F,
    ) -> io::Result<usize>
    where
        F: FnMut(SocketId, BytesMut, SocketAddr, &mut Vec<u8>) -> Option<Transmit>,
    {
        if self.stopped {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "io_uring is stopped"));
        }
        self.wait_for_completions(timeout)?;

        let mut received = 0;
        for completion in &mut self.ring.completion() {
            let user_data = completion.user_data();
            #[cfg(feature = "thread_park")]
            if user_data == FUTEX_TAG {
                self.wake
                    .as_mut()
                    .ok_or_else(|| io::Error::other("unregistered futex wake"))?
                    .complete(completion.result())?;
                continue;
            }
            if user_data & TX_TAG != 0 {
                let index = (user_data & 1) as usize;
                if let Err(error) =
                    self.tx[index].complete(user_data, completion.result(), completion.flags())
                {
                    if error.kind() == io::ErrorKind::InvalidData {
                        return Err(error);
                    }
                    silver_log::warn!(?error, socket = ?SOCKETS[index], "network io_uring send failed");
                }
                continue;
            }
            let socket = match user_data {
                0 => SocketId::Quic,
                1 => SocketId::Discovery,
                _ => return Err(io::Error::other("unexpected receive completion tag")),
            };
            let index = socket as usize;
            let flags = completion.flags();
            if !cqueue::more(flags) {
                self.active[index] = false;
            }
            if cqueue::buffer_more(flags) {
                return Err(io::Error::other("unexpected incremental receive buffer"));
            }
            let result = completion.result();
            if result == -libc::ENOBUFS {
                self.pools[index].no_buffers();
            }
            let packet = match cqueue::buffer_select(flags) {
                Some(id) => self.pools[index].take(id, result, &self.header)?,
                None if result < 0 => None,
                None => return Err(io::Error::other("receive completion has no buffer ID")),
            };
            if result < 0 && !matches!(-result, libc::ENOBUFS | libc::EAGAIN | libc::EINTR) {
                return Err(io::Error::from_raw_os_error(-result));
            }
            if let Some((data, remote)) = packet {
                if self.banned_ips.contains(&remote.ip()) {
                    continue;
                }
                received += 1;
                self.scratch.clear();
                if let Some(response) = receive(socket, data, remote, &mut self.scratch) {
                    if response.size > self.scratch.len() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "response exceeds scratch buffer",
                        ));
                    }
                    if let Err(error) = self.tx[index].enqueue(|buffer| {
                        buffer.extend_from_slice(&self.scratch[..response.size]);
                        Some(response)
                    }) {
                        silver_log::warn!(?error, ?socket, "network io_uring response dropped");
                    }
                }
            }
        }

        self.recycle();
        self.flush()?;
        Ok(received)
    }

    fn recycle(&mut self) {
        for pool in self.pools.iter_mut() {
            pool.recycle();
        }
    }

    fn rearm(&mut self) {
        for socket in SOCKETS {
            let index = socket as usize;
            if self.active[index] || !self.pools[index].has_buffers() {
                continue;
            }
            let entry =
                opcode::RecvMsgMulti::new(types::Fixed(index as u32), &**self.header, index as u16)
                    .build()
                    .user_data(index as u64);
            // SAFETY: sockets, header, and pools stay alive until the terminal receive CQEs
            // arrive.
            if unsafe { self.ring.submission().push(&entry) }.is_err() {
                break;
            }
            self.active[index] = true;
        }
    }

    fn wait(&self, timeout: Duration) -> io::Result<()> {
        let timeout = types::Timespec::from(timeout);
        let args = types::SubmitArgs::new().timespec(&timeout);
        match self.ring.submitter().submit_with_args(1, &args) {
            Ok(_) => Ok(()),
            Err(error) if matches!(error.raw_os_error(), Some(libc::ETIME | libc::EINTR)) => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn has_in_flight(&self) -> bool {
        #[cfg(feature = "thread_park")]
        if self.wake.as_ref().is_some_and(FutexWake::is_active) {
            return true;
        }
        self.active.iter().any(|active| *active) || self.tx.iter().any(TxPool::has_in_flight)
    }

    /// Discards unsubmitted sends, cancels pending I/O, and drains zero-copy
    /// notifications before releasing memory.
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.stopped = true;
        for pool in self.tx.iter_mut() {
            pool.stop();
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut cancelling = false;
        while self.has_in_flight() {
            if !cancelling {
                let entry = opcode::AsyncCancel2::new(types::CancelBuilder::any())
                    .build()
                    .user_data(CANCEL_TAG);
                // SAFETY: cancellation carries no pointers; all I/O resources remain owned
                // here.
                cancelling = unsafe { self.ring.submission().push(&entry) }.is_ok();
            }
            self.ring.submit()?;
            for completion in &mut self.ring.completion() {
                if completion.user_data() & TX_TAG != 0 {
                    let index = (completion.user_data() & 1) as usize;
                    if let Err(error) = self.tx[index].complete(
                        completion.user_data(),
                        completion.result(),
                        completion.flags(),
                    ) {
                        if error.kind() == io::ErrorKind::InvalidData {
                            return Err(error);
                        }
                        if error.raw_os_error() != Some(libc::ECANCELED) {
                            silver_log::debug!(
                                ?error,
                                "send completed with an error during shutdown"
                            );
                        }
                    }
                    continue;
                }
                match completion.user_data() {
                    #[cfg(feature = "thread_park")]
                    FUTEX_TAG => {
                        self.wake
                            .as_mut()
                            .ok_or_else(|| io::Error::other("unregistered futex wake"))?
                            .complete(completion.result())?;
                    }
                    0 | 1 => {
                        let index = completion.user_data() as usize;
                        if completion.result() == -libc::ENOBUFS {
                            self.pools[index].no_buffers();
                        }
                        if let Some(id) = cqueue::buffer_select(completion.flags()) {
                            self.pools[index].take(id, -libc::ECANCELED, &self.header)?;
                        }
                        if !cqueue::more(completion.flags()) {
                            self.active[index] = false;
                        }
                    }
                    CANCEL_TAG => {
                        cancelling = false;
                        let result = completion.result();
                        if result < 0 && !matches!(-result, libc::ENOENT | libc::EALREADY) {
                            return Err(io::Error::from_raw_os_error(-result));
                        }
                    }
                    _ => return Err(io::Error::other("unexpected shutdown completion tag")),
                }
            }
            if self.has_in_flight() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "io_uring cancellation deadline",
                    ));
                }
                // A short wait also retries cancellations that raced SQPOLL submission.
                self.wait(remaining.min(Duration::from_millis(10)))?;
            }
        }
        for pool in self.pools.iter_mut() {
            pool.unregister(&self.ring)?;
        }
        if self.files_registered {
            self.ring.submitter().unregister_files()?;
            self.files_registered = false;
        }
        Ok(())
    }
}

impl Drop for UringIo {
    fn drop(&mut self) {
        match self.shutdown() {
            Ok(()) => {
                // SAFETY: all sends, notifications, and receives completed; both buffer rings
                // are unregistered.
                unsafe {
                    ManuallyDrop::drop(&mut self.pools);
                    ManuallyDrop::drop(&mut self.header);
                    ManuallyDrop::drop(&mut self.tx);
                }
            }
            Err(error) => {
                silver_log::error!(
                    ?error,
                    "io_uring shutdown failed; retaining kernel-visible allocations"
                );
            }
        }
    }
}
