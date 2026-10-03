use std::{
    io,
    mem::{size_of, size_of_val, zeroed},
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr,
};

use quinn_proto::Transmit;
use socket2::SockAddr;

use crate::socket::MAX_GSO_SEGMENTS;

pub(super) struct TxMessage {
    pub(super) header: libc::msghdr,
    iovec: libc::iovec,
    address: SockAddr,
    // cmsghdr needs native-word alignment. Space covers GSO, ECN, and source-address control
    // messages.
    control: [usize; 16],
}

impl TxMessage {
    pub(super) fn new() -> Self {
        Self {
            // SAFETY: zero lengths and null pointers are valid before preparation.
            header: unsafe { zeroed() },
            // SAFETY: zero length and a null pointer are valid before preparation.
            iovec: unsafe { zeroed() },
            address: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into(),
            control: [0; 16],
        }
    }

    pub(super) fn prepare(&mut self, buffer: &[u8], transmit: &Transmit) -> io::Result<()> {
        if transmit.size > buffer.len() || transmit.size > i32::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid transmit size"));
        }
        if let Some(segment_size) = transmit.segment_size {
            if segment_size == 0 ||
                segment_size > u16::MAX as usize ||
                transmit.size.div_ceil(segment_size) > MAX_GSO_SEGMENTS
            {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP segmentation"));
            }
        }
        let destination = match transmit.destination {
            SocketAddr::V4(addr) => {
                SocketAddrV6::new(addr.ip().to_ipv6_mapped(), addr.port(), 0, 0)
            }
            SocketAddr::V6(addr) => addr,
        };
        let ipv4 = destination.ip().to_ipv4_mapped().is_some();
        self.address = SocketAddr::V6(destination).into();
        self.iovec = libc::iovec { iov_base: buffer.as_ptr() as *mut _, iov_len: transmit.size };
        self.header.msg_name = self.address.as_ptr() as *mut _;
        self.header.msg_namelen = self.address.len();
        self.header.msg_iov = &mut self.iovec;
        self.header.msg_iovlen = 1;
        self.header.msg_control = self.control.as_mut_ptr().cast();
        self.header.msg_controllen = 0;

        if let Some(segment_size) = transmit.segment_size {
            self.push_control(libc::SOL_UDP, libc::UDP_SEGMENT, segment_size as u16);
        }
        if let Some(ecn) = transmit.ecn {
            let (level, kind) = if ipv4 {
                (libc::IPPROTO_IP, libc::IP_TOS)
            } else {
                (libc::IPPROTO_IPV6, libc::IPV6_TCLASS)
            };
            self.push_control(level, kind, ecn as libc::c_int);
        }
        if let Some(source) = transmit.src_ip {
            let source = match source {
                IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source),
                _ => source,
            };
            match source {
                IpAddr::V4(ip) if ipv4 => {
                    self.push_control(libc::IPPROTO_IP, libc::IP_PKTINFO, libc::in_pktinfo {
                        ipi_ifindex: 0,
                        ipi_spec_dst: libc::in_addr { s_addr: u32::from_ne_bytes(ip.octets()) },
                        ipi_addr: libc::in_addr { s_addr: 0 },
                    })
                }
                IpAddr::V6(ip) if !ipv4 => {
                    self.push_control(libc::IPPROTO_IPV6, libc::IPV6_PKTINFO, libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr { s6_addr: ip.octets() },
                        ipi6_ifindex: destination.scope_id(),
                    })
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "transmit source and destination address families differ",
                    ))
                }
            }
        }
        Ok(())
    }

    fn push_control<T: Copy>(&mut self, level: i32, kind: i32, value: T) {
        // SAFETY: the small, fixed control payload types fit CMSG_SPACE's input domain.
        let space = unsafe { libc::CMSG_SPACE(size_of::<T>() as u32) } as usize;
        let offset = self.header.msg_controllen;
        assert!(offset + space <= size_of_val(&self.control));
        // SAFETY: the native-word-aligned control buffer has room for this header and
        // payload.
        unsafe {
            let header = self.control.as_mut_ptr().cast::<u8>().add(offset).cast::<libc::cmsghdr>();
            header.write(libc::cmsghdr {
                cmsg_len: libc::CMSG_LEN(size_of::<T>() as u32) as _,
                cmsg_level: level,
                cmsg_type: kind,
            });
            ptr::write_unaligned(libc::CMSG_DATA(header).cast::<T>(), value);
        }
        self.header.msg_controllen += space;
    }
}
