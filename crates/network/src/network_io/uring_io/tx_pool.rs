#[cfg(test)]
mod tests;
mod tx_message;

use std::{collections::VecDeque, io, os::fd::RawFd};

use io_uring::{IoUring, cqueue, opcode, types};
use quinn_proto::Transmit;
use tx_message::TxMessage;

use super::SocketId;
use crate::socket::MAX_GSO_SEGMENTS;

pub(super) const TX_TAG: u64 = 1 << 63;
const GENERATION_SHIFT: u32 = 17;

enum State {
    Free,
    Queued,
    InFlight { result: Option<i32>, more: bool, notified: bool },
}

struct Slot {
    buffer: Vec<u8>,
    message: Box<TxMessage>,
    state: State,
    tag: u64,
    size: usize,
    zero_copy: bool,
}

pub(super) struct TxPool {
    slots: Box<[Slot]>,
    free: Vec<u16>,
    queued: VecDeque<u16>,
    in_flight: usize,
    zero_copy_min_size: usize,
    stopped: bool,
}

impl TxPool {
    pub(super) fn new(socket: SocketId, entries: u16, zero_copy_min_size: usize) -> Self {
        assert!(entries > 0);
        Self {
            slots: (0..entries)
                .map(|id| Slot {
                    buffer: Vec::with_capacity(MAX_GSO_SEGMENTS * 1500),
                    message: Box::new(TxMessage::new()),
                    state: State::Free,
                    tag: TX_TAG | (u64::from(id) << 1) | socket as u64,
                    size: 0,
                    zero_copy: false,
                })
                .collect(),
            free: (0..entries).rev().collect(),
            queued: VecDeque::with_capacity(usize::from(entries)),
            in_flight: 0,
            zero_copy_min_size,
            stopped: false,
        }
    }

    pub(super) fn is_blocked(&self) -> bool {
        self.stopped || self.free.is_empty()
    }

    pub(super) fn enqueue<F>(&mut self, produce: F) -> io::Result<bool>
    where
        F: FnOnce(&mut Vec<u8>) -> Option<Transmit>,
    {
        if self.stopped {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "transmit pool is stopped"));
        }
        let Some(&id) = self.free.last() else { return Ok(false) };
        let slot = &mut self.slots[usize::from(id)];
        slot.buffer.clear();
        let Some(transmit) = produce(&mut slot.buffer) else { return Ok(false) };
        slot.message.prepare(&slot.buffer, &transmit)?;
        slot.size = transmit.size;
        slot.zero_copy = transmit.size >= self.zero_copy_min_size;
        slot.state = State::Queued;
        self.free.pop();
        self.queued.push_back(id);
        Ok(true)
    }

    pub(super) fn submit(&mut self, ring: &mut IoUring, fd: RawFd) {
        let mut submission = ring.submission();
        while let Some(&id) = self.queued.front() {
            if submission.is_full() {
                break;
            }
            let slot = &mut self.slots[usize::from(id)];
            let generation = (slot.tag >> GENERATION_SHIFT) as u32;
            slot.tag = TX_TAG |
                (u64::from(generation.wrapping_add(1)) << GENERATION_SHIFT) |
                (slot.tag & ((1 << GENERATION_SHIFT) - 1));
            let entry = if slot.zero_copy {
                opcode::SendMsgZc::new(types::Fd(fd), &slot.message.header)
                    .flags(libc::MSG_NOSIGNAL as u32)
                    .build()
            } else {
                opcode::SendMsg::new(types::Fd(fd), &slot.message.header)
                    .flags(libc::MSG_NOSIGNAL as u32)
                    .build()
            }
            .user_data(slot.tag);
            // SAFETY: each message and payload stays fixed until its send and required
            // notification complete.
            unsafe { submission.push(&entry).expect("checked SQ capacity") };
            slot.state = State::InFlight { result: None, more: false, notified: false };
            self.in_flight += 1;
            self.queued.pop_front();
        }
    }

    pub(super) fn complete(&mut self, tag: u64, result: i32, flags: u32) -> io::Result<()> {
        let id = ((tag >> 1) & u64::from(u16::MAX)) as u16;
        let slot = self.slots.get_mut(usize::from(id)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid transmit slot ID")
        })?;
        if slot.tag != tag {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "stale transmit completion"));
        }
        let State::InFlight { result: send_result, more, notified } = &mut slot.state else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "completion for an inactive transmit",
            ));
        };
        let notification = cqueue::notif(flags);
        if notification {
            if !slot.zero_copy || *notified || cqueue::more(flags) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid transmit notification",
                ));
            }
            *notified = true;
        } else {
            if send_result.is_some() || (!slot.zero_copy && cqueue::more(flags)) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid transmit completion",
                ));
            }
            *send_result = Some(result);
            *more = cqueue::more(flags);
        }

        let error = if !notification && result >= 0 && result as usize != slot.size {
            Some(io::Error::new(io::ErrorKind::WriteZero, "partial UDP transmit"))
        } else if !notification && result < 0 && !matches!(-result, libc::EAGAIN | libc::EINTR) {
            Some(io::Error::from_raw_os_error(-result))
        } else {
            None
        };
        if let Some(result) = *send_result {
            if !*more || *notified {
                self.in_flight -= 1;
                if !self.stopped && (result == -libc::EAGAIN || result == -libc::EINTR) {
                    slot.state = State::Queued;
                    self.queued.push_back(id);
                } else {
                    slot.state = State::Free;
                    self.free.push(id);
                }
            }
        }
        error.map_or(Ok(()), Err)
    }

    pub(super) fn has_in_flight(&self) -> bool {
        self.in_flight != 0
    }

    pub(super) fn stop(&mut self) {
        self.stopped = true;
        for id in self.queued.drain(..) {
            self.slots[usize::from(id)].state = State::Free;
            self.free.push(id);
        }
    }
}
