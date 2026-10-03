#[cfg(test)]
mod tests;

use std::{
    io,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    ptr::{self, NonNull},
    sync::atomic::{AtomicU16, Ordering},
};

use bytes::{Buf, BytesMut};
use io_uring::{
    IoUring,
    types::{BufRingEntry, RecvMsgOut},
};

use crate::{
    network_io::{SocketId, rx_pool_metrics::RxPoolMetrics},
    socket::RX_BUF_SIZE,
};

// io_uring_recvmsg_out has four u32 fields, followed by the reserved sockaddr
// space.
const PAYLOAD_OFFSET: usize = 4 * size_of::<u32>() + size_of::<libc::sockaddr_storage>();
const BUFFER_SIZE: usize = PAYLOAD_OFFSET + RX_BUF_SIZE;

pub(super) struct ProvidedBuffers {
    descriptors: NonNull<BufRingEntry>,
    group: u16,
    entries: u16,
    tail: u16,
    registered: bool,
    buffers: Vec<BytesMut>,
    provided: Vec<bool>,
    retired: Vec<u16>,
    metrics: RxPoolMetrics,
}

impl ProvidedBuffers {
    pub(super) fn new(socket: SocketId, entries: u16) -> io::Result<Self> {
        assert!(entries.is_power_of_two() && entries <= 32768);
        // SAFETY: anonymous mmap returns page-aligned, zero-initialized descriptor
        // storage.
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                usize::from(entries) * size_of::<BufRingEntry>(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptors: NonNull::new(mapping.cast()).expect("null buffer ring mapping"),
            group: socket as u16,
            entries,
            tail: 0,
            registered: false,
            buffers: (0..entries).map(|_| BytesMut::zeroed(BUFFER_SIZE)).collect(),
            provided: vec![false; usize::from(entries)],
            retired: Vec::with_capacity(usize::from(entries)),
            metrics: RxPoolMetrics::new(socket, entries),
        })
    }

    pub(super) fn register(&mut self, ring: &IoUring) -> io::Result<()> {
        // SAFETY: the owner unregisters this mapping before dropping it, or retains it
        // on failure.
        unsafe {
            ring.submitter().register_buf_ring_with_flags(
                self.descriptors.as_ptr() as u64,
                self.entries,
                self.group,
                0,
            )?;
        }
        self.registered = true;
        for id in 0..self.entries {
            self.provide(id);
        }
        self.publish();
        self.metrics.publish(0);
        Ok(())
    }

    pub(super) fn unregister(&mut self, ring: &IoUring) -> io::Result<()> {
        if self.registered {
            ring.submitter().unregister_buf_ring(self.group)?;
            self.registered = false;
            self.metrics.close();
        }
        Ok(())
    }

    fn provide(&mut self, id: u16) {
        assert!(!self.provided[usize::from(id)]);
        // SAFETY: all-zero descriptor fields are valid.
        let mut descriptor: BufRingEntry = unsafe { std::mem::zeroed() };
        descriptor.set_addr(self.buffers[usize::from(id)].as_mut_ptr() as u64);
        descriptor.set_len(BUFFER_SIZE as u32);
        descriptor.set_bid(id);
        let slot = usize::from(self.tail & (self.entries - 1));
        // SAFETY: this slot was consumed before its buffer became recyclable.
        // Exclude the reserved field: entry zero aliases the shared atomic tail there.
        unsafe {
            ptr::copy_nonoverlapping(
                (&descriptor as *const BufRingEntry).cast::<u8>(),
                self.descriptors.as_ptr().add(slot).cast::<u8>(),
                size_of::<BufRingEntry>() - size_of::<u16>(),
            );
        }
        self.tail = self.tail.wrapping_add(1);
        self.provided[usize::from(id)] = true;
    }

    fn publish(&self) {
        // SAFETY: the mmap is live and page-aligned; the tail is aligned for AtomicU16.
        let tail = unsafe { &*BufRingEntry::tail(self.descriptors.as_ptr()).cast::<AtomicU16>() };
        tail.store(self.tail, Ordering::Release);
    }

    pub(super) fn recycle(&mut self) {
        let old_tail = self.tail;
        let retired = self.retired.len();
        let mut index = 0;
        while index < self.retired.len() {
            let id = self.retired[index];
            let buffer = &mut self.buffers[usize::from(id)];
            buffer.clear();
            if buffer.try_reclaim(BUFFER_SIZE) {
                // SAFETY: this entire allocation was initialized at creation and is exclusively
                // owned again.
                unsafe { buffer.set_len(BUFFER_SIZE) };
                self.provide(id);
                self.retired.swap_remove(index);
            } else {
                index += 1;
            }
        }
        if self.tail != old_tail {
            self.publish();
        }
        self.metrics.recycled(retired - self.retired.len());
        self.metrics.publish(self.retired.len());
    }

    pub(super) fn no_buffers(&mut self) {
        self.metrics.no_buffers();
    }

    pub(super) fn has_buffers(&self) -> bool {
        self.retired.len() < usize::from(self.entries)
    }

    pub(super) fn take(
        &mut self,
        id: u16,
        result: i32,
        header: &libc::msghdr,
    ) -> io::Result<Option<(BytesMut, SocketAddr)>> {
        let provided = self
            .provided
            .get_mut(usize::from(id))
            .ok_or_else(|| io::Error::other("receive selected an invalid buffer ID"))?;
        if !*provided {
            return Err(io::Error::other(
                "receive selected a buffer still owned by the application",
            ));
        }
        *provided = false;
        self.retired.push(id);
        self.metrics.consumed(self.retired.len());
        if result < 0 {
            return Ok(None);
        }

        let buffer = &mut self.buffers[usize::from(id)];
        let received = buffer
            .get(..result as usize)
            .ok_or_else(|| io::Error::other("receive completion exceeds buffer capacity"))?;
        let output = RecvMsgOut::parse(received, header)
            .map_err(|_| io::Error::other("invalid multishot receive layout"))?;
        if output.is_payload_truncated() ||
            output.is_name_data_truncated() ||
            output.is_control_data_truncated() ||
            output.incoming_payload_len() as usize != output.payload_data().len()
        {
            return Ok(None);
        }
        let remote = Self::remote_address(output.name_data())?;
        let payload_len = output.payload_data().len();
        // Keep an empty handle at the allocation's end, so reclamation requires
        // exclusive ownership.
        let mut packet = buffer.split_to(BUFFER_SIZE);
        packet.advance(PAYLOAD_OFFSET);
        packet.truncate(payload_len);
        Ok(Some((packet, remote)))
    }

    fn remote_address(name: &[u8]) -> io::Result<SocketAddr> {
        let family = name
            .get(..size_of::<u16>())
            .map(|bytes| u16::from_ne_bytes([bytes[0], bytes[1]]) as i32);
        match family {
            Some(libc::AF_INET) if name.len() >= size_of::<libc::sockaddr_in>() => {
                // SAFETY: the checked slice contains the full sockaddr; its alignment is
                // unrestricted.
                let addr = unsafe { name.as_ptr().cast::<libc::sockaddr_in>().read_unaligned() };
                Ok((
                    Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()),
                    u16::from_be(addr.sin_port),
                )
                    .into())
            }
            Some(libc::AF_INET6) if name.len() >= size_of::<libc::sockaddr_in6>() => {
                // SAFETY: the checked slice contains the full sockaddr; its alignment is
                // unrestricted.
                let addr = unsafe { name.as_ptr().cast::<libc::sockaddr_in6>().read_unaligned() };
                let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let port = u16::from_be(addr.sin6_port);
                Ok(match ip.to_ipv4_mapped() {
                    Some(ip) => SocketAddr::from((ip, port)),
                    None => {
                        SocketAddrV6::new(ip, port, addr.sin6_flowinfo, addr.sin6_scope_id).into()
                    }
                })
            }
            _ => Err(io::Error::other("invalid UDP source address")),
        }
    }
}

impl Drop for ProvidedBuffers {
    fn drop(&mut self) {
        assert!(!self.registered, "dropping a registered buffer ring");
        // SAFETY: the mapping is no longer registered and has no outstanding kernel
        // users.
        unsafe {
            libc::munmap(
                self.descriptors.as_ptr().cast(),
                usize::from(self.entries) * size_of::<BufRingEntry>(),
            );
        }
    }
}
