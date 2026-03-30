use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    os::fd::AsRawFd as _,
};

use flux::tracing;
use mio::net::UdpSocket;

pub(crate) const RX_BATCH_MAX: usize = 32;
const RX_BUF_SIZE: usize = 2048;
/// Index of the scratch buffer used for poll_transmit.
pub(crate) const SCRATCH: usize = RX_BATCH_MAX;
const TX_BATCH_MAX: usize = 256;
const MAX_GSO_SEGMENTS: usize = 10;
const CMSG_BUF_SIZE: usize = 64;

// --- RxBatch ----------------------------------------------------------------

pub(crate) struct RxBatch {
    /// Per-datagram buffers. Indices 0..RX_BATCH_MAX are receive slots,
    /// index SCRATCH is a spare buffer for poll_transmit.
    pub(crate) bufs: Vec<Vec<u8>>,
    addrs: Vec<libc::sockaddr_storage>,
    iovecs: Vec<libc::iovec>,
    hdrs: Vec<libc::mmsghdr>,
    count: usize,
}

// SAFETY: Raw pointers in iovecs/hdrs point into self's own heap buffers and
// are only dereferenced during syscalls within a single thread.
unsafe impl Send for RxBatch {}

impl RxBatch {
    pub(crate) fn new() -> Self {
        let bufs = (0..RX_BATCH_MAX + 1).map(|_| vec![0u8; RX_BUF_SIZE]).collect();
        Self {
            bufs,
            addrs: vec![unsafe { std::mem::zeroed() }; RX_BATCH_MAX],
            iovecs: vec![unsafe { std::mem::zeroed() }; RX_BATCH_MAX],
            hdrs: vec![unsafe { std::mem::zeroed() }; RX_BATCH_MAX],
            count: 0,
        }
    }

    /// Batch-receive datagrams via recvmmsg. Returns number received.
    pub(crate) fn recv(&mut self, socket: &UdpSocket) -> usize {
        let fd = socket.as_raw_fd();

        for i in 0..RX_BATCH_MAX {
            self.iovecs[i].iov_base = self.bufs[i].as_mut_ptr() as *mut _;
            self.iovecs[i].iov_len = RX_BUF_SIZE;

            self.hdrs[i].msg_hdr.msg_name = &mut self.addrs[i] as *mut _ as *mut _;
            self.hdrs[i].msg_hdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as u32;
            self.hdrs[i].msg_hdr.msg_iov = &mut self.iovecs[i] as *mut _;
            self.hdrs[i].msg_hdr.msg_iovlen = 1;
            self.hdrs[i].msg_hdr.msg_control = std::ptr::null_mut();
            self.hdrs[i].msg_hdr.msg_controllen = 0;
            self.hdrs[i].msg_hdr.msg_flags = 0;
            self.hdrs[i].msg_len = 0;
        }

        let ret = unsafe {
            libc::recvmmsg(
                fd,
                self.hdrs.as_mut_ptr(),
                RX_BATCH_MAX as u32,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::WouldBlock {
                tracing::error!(error=?err, "recvmmsg");
            }
            self.count = 0;
            return 0;
        }

        self.count = ret as usize;
        self.count
    }

    /// Get the i-th received datagram as (data, source_addr).
    pub(crate) fn get(&self, i: usize) -> (&[u8], SocketAddr) {
        let len = self.hdrs[i].msg_len as usize;
        let data = &self.bufs[i][..len];
        let addr = sockaddr_to_std(&self.addrs[i]);
        (data, addr)
    }
}

// --- TxBatch ----------------------------------------------------------------

pub(crate) struct TxEntry {
    buf_idx: usize,
    size: usize,
    segment_size: Option<usize>,
    dst: SocketAddr,
}

pub(crate) struct TxBatch {
    pub(crate) bufs: Vec<Vec<u8>>,
    pub(crate) entries: Vec<TxEntry>,
    iovecs: Vec<libc::iovec>,
    addrs: Vec<libc::sockaddr_storage>,
    cmsgs: Vec<[u8; CMSG_BUF_SIZE]>,
    hdrs: Vec<libc::mmsghdr>,
    send_idx: usize,
    prepared: bool,
}

// SAFETY: Same as RxBatch — pointers are internal and single-threaded.
unsafe impl Send for TxBatch {}

impl TxBatch {
    pub(crate) fn new() -> Self {
        let bufs = (0..TX_BATCH_MAX).map(|_| Vec::with_capacity(MAX_GSO_SEGMENTS * 1500)).collect();
        Self {
            bufs,
            entries: Vec::with_capacity(TX_BATCH_MAX),
            iovecs: Vec::with_capacity(TX_BATCH_MAX),
            addrs: Vec::with_capacity(TX_BATCH_MAX),
            cmsgs: Vec::with_capacity(TX_BATCH_MAX),
            hdrs: Vec::with_capacity(TX_BATCH_MAX),
            send_idx: 0,
            prepared: false,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.send_idx = 0;
        self.prepared = false;
    }

    pub(crate) fn is_full(&self) -> bool {
        self.entries.len() >= TX_BATCH_MAX
    }

    pub(crate) fn has_pending(&self) -> bool {
        self.prepared && self.send_idx < self.hdrs.len()
    }

    /// Record a transmit after poll_transmit wrote into bufs[entries.len()].
    pub(crate) fn commit(&mut self, tx: &quinn_proto::Transmit) {
        let buf_idx = self.entries.len();
        self.entries.push(TxEntry {
            buf_idx,
            size: tx.size,
            segment_size: tx.segment_size,
            dst: tx.destination,
        });
    }

    /// Build sendmmsg headers from entries (if not already built), then send.
    /// Returns true if all messages were sent.
    pub(crate) fn flush(&mut self, socket: &UdpSocket) -> bool {
        if self.entries.is_empty() {
            return true;
        }
        
        if !self.prepared {
            self.prepare();
        }

        self.do_send(socket)
    }

    fn prepare(&mut self) {
        self.iovecs.clear();
        self.addrs.clear();
        self.cmsgs.clear();
        self.hdrs.clear();
        self.send_idx = 0;

        for entry in &self.entries {
            self.iovecs.push(libc::iovec {
                iov_base: self.bufs[entry.buf_idx].as_ptr() as *mut _,
                iov_len: entry.size,
            });
            self.addrs.push(sockaddr_from(entry.dst));
            self.cmsgs.push([0u8; CMSG_BUF_SIZE]);
        }

        for (i, entry) in self.entries.iter().enumerate() {
            let mut hdr: libc::msghdr = unsafe { std::mem::zeroed() };
            hdr.msg_name = &mut self.addrs[i] as *mut _ as *mut _;
            hdr.msg_namelen = sockaddr_len(entry.dst);
            hdr.msg_iov = &mut self.iovecs[i] as *mut _;
            hdr.msg_iovlen = 1;

            if let Some(segment_size) = entry.segment_size {
                let cmsg_buf = &mut self.cmsgs[i];
                hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
                hdr.msg_controllen =
                    unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as _ };
                unsafe {
                    let cmsg = libc::CMSG_FIRSTHDR(&hdr);
                    (*cmsg).cmsg_level = libc::SOL_UDP;
                    (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                    (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
                    *(libc::CMSG_DATA(cmsg) as *mut u16) = segment_size as u16;
                }
            }

            self.hdrs.push(libc::mmsghdr { msg_hdr: hdr, msg_len: 0 });
        }

        self.prepared = true;
    }

    fn do_send(&mut self, socket: &UdpSocket) -> bool {
        let fd = socket.as_raw_fd();

        while self.send_idx < self.hdrs.len() {
            let remaining = (self.hdrs.len() - self.send_idx) as u32;
            let ret = unsafe {
                libc::sendmmsg(fd, self.hdrs[self.send_idx..].as_mut_ptr(), remaining, 0)
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return false;
                }
                tracing::error!(error=?err, "sendmmsg");
                return false;
            }
            self.send_idx += ret as usize;
        }

        true
    }
}

// --- sockaddr helpers -------------------------------------------------------

fn sockaddr_from(addr: SocketAddr) -> libc::sockaddr_storage {
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sa = &mut storage as *mut _ as *mut libc::sockaddr_in;
            unsafe {
                (*sa).sin_family = libc::AF_INET as u16;
                (*sa).sin_port = v4.port().to_be();
                (*sa).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
        }
        SocketAddr::V6(v6) => {
            let sa = &mut storage as *mut _ as *mut libc::sockaddr_in6;
            unsafe {
                (*sa).sin6_family = libc::AF_INET6 as u16;
                (*sa).sin6_port = v6.port().to_be();
                (*sa).sin6_addr.s6_addr = v6.ip().octets();
                (*sa).sin6_flowinfo = v6.flowinfo();
                (*sa).sin6_scope_id = v6.scope_id();
            }
        }
    }
    storage
}

fn sockaddr_to_std(storage: &libc::sockaddr_storage) -> SocketAddr {
    match storage.ss_family as i32 {
        libc::AF_INET => {
            let sa = storage as *const _ as *const libc::sockaddr_in;
            unsafe {
                let ip = Ipv4Addr::from(u32::from_be((*sa).sin_addr.s_addr));
                let port = u16::from_be((*sa).sin_port);
                SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
        }
        libc::AF_INET6 => {
            let sa = storage as *const _ as *const libc::sockaddr_in6;
            unsafe {
                let ip = Ipv6Addr::from((*sa).sin6_addr.s6_addr);
                let port = u16::from_be((*sa).sin6_port);
                SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    (*sa).sin6_flowinfo,
                    (*sa).sin6_scope_id,
                ))
            }
        }
        family => {
            tracing::error!(family, "unexpected sockaddr family");
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        }
    }
}

fn sockaddr_len(addr: SocketAddr) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(_) => std::mem::size_of::<libc::sockaddr_in>() as _,
        SocketAddr::V6(_) => std::mem::size_of::<libc::sockaddr_in6>() as _,
    }
}
