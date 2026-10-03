use std::io;

use flux::park::Signal;
use io_uring::{IoUring, opcode};

pub(super) const FUTEX_TAG: u64 = 3;
// Linux FUTEX2_SIZE_U32; shared waits match Flux's FUTEX_WAKE from any thread.
const FUTEX2_SIZE_U32: u32 = 2;

pub(super) struct FutexWake {
    signal: &'static Signal,
    expected: u32,
    active: bool,
}

impl FutexWake {
    pub(super) fn new(signal: &'static Signal) -> Self {
        Self { signal, expected: signal.read_counter(), active: false }
    }

    pub(super) fn snapshot(&mut self) {
        self.expected = self.signal.read_counter();
    }

    pub(super) fn is_active(&self) -> bool {
        self.active
    }

    pub(super) fn arm(&mut self, ring: &mut IoUring) -> bool {
        if self.active {
            return true;
        }
        let entry = opcode::FutexWait::new(
            self.signal.futex_ptr(),
            u64::from(self.expected),
            u64::from(u32::MAX),
            FUTEX2_SIZE_U32,
        )
        .build()
        .user_data(FUTEX_TAG);
        // SAFETY: the signal has static storage, including if ring teardown fails.
        self.active = unsafe { ring.submission().push(&entry) }.is_ok();
        self.active
    }

    pub(super) fn complete(&mut self, result: i32) -> io::Result<()> {
        if !self.active {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected futex completion"));
        }
        self.active = false;
        match result {
            0 => Ok(()),
            result if matches!(-result, libc::EAGAIN | libc::EINTR | libc::ECANCELED) => Ok(()),
            result if result < 0 => Err(io::Error::from_raw_os_error(-result)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidData, "invalid futex completion")),
        }
    }
}
