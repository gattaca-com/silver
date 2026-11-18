use std::{
    io::{Error, ErrorKind},
    os::fd::{AsRawFd, RawFd},
    path::{Path, PathBuf},
};

use flux_disk::{DiskEvent, DiskIo, FileToken, OpenOptions};
use silver_common::{TCacheProducer, TCacheRead, TProducer, TReservation};

pub(super) enum ReadOutcome {
    Sent(TCacheRead),
    Missing,
    Failed(Error),
}

enum State {
    Sizing,
    /// Waiting for tcache room.
    Reserving(usize),
    /// The kernel is filling the reservation, so it must not drop yet.
    Reading(TReservation, usize),
    Done(ReadOutcome),
}

struct Read<T> {
    path: PathBuf,
    file: Option<FileToken>,
    tag: T,
    state: State,
}

/// Reads whole files straight into tcache payloads without blocking: open,
/// size, reserve, read into the reservation, close. Reads finish in the order
/// the disk completes them and hand the caller's tag back.
pub(super) struct FileReader<T> {
    // Drops first: its drop waits for the kernel to finish writing into the
    // reservations `reads` still holds.
    disk: DiskIo,
    reads: Vec<Read<T>>,
}

impl<T> FileReader<T> {
    pub(super) fn new() -> Result<Self, Error> {
        Ok(Self { disk: super::disk_ring()?, reads: Vec::new() })
    }

    pub(super) fn in_flight(&self) -> usize {
        self.reads.len()
    }

    pub(super) fn ring_fd(&mut self) -> RawFd {
        self.disk.submit();
        self.disk.as_raw_fd()
    }

    pub(super) fn tags(&self) -> impl Iterator<Item = &T> {
        self.reads.iter().map(|read| &read.tag)
    }

    /// Paths are built one way, so bytes compare exactly.
    pub(super) fn busy_with(&self, path: &Path) -> bool {
        self.reads.iter().any(|read| read.path.as_os_str() == path.as_os_str())
    }

    pub(super) fn start(&mut self, path: PathBuf, tag: T) {
        let (file, state) = match self.disk.open(&path, OpenOptions::new().read(true)) {
            Ok(file) if self.disk.file_len(file) => (Some(file), State::Sizing),
            Ok(file) => {
                let error = Error::other("file closed before its length was read");
                (Some(file), State::Done(ReadOutcome::Failed(error)))
            }
            Err(error) => (None, State::Done(ReadOutcome::Failed(error))),
        };
        self.reads.push(Read { path, file, tag, state });
    }

    /// Reaps completions and hands each finished read to `done`. A read that
    /// does not fit in `producer` yet waits for a later step.
    pub(super) fn step(&mut self, producer: &mut TProducer, mut done: impl FnMut(T, ReadOutcome)) {
        let reads = &mut self.reads;
        self.disk.poll_with(|event| {
            let file = match &event {
                DiskEvent::FileLen { file, .. } |
                DiskEvent::ReadInto { file, .. } |
                DiskEvent::Failed { file, .. } => *file,
                _ => return,
            };
            if let Some(read) = reads.iter_mut().find(|read| read.file == Some(file)) {
                read.state = std::mem::replace(&mut read.state, State::Sizing).after(event);
            }
        });

        let mut index = 0;
        while index < self.reads.len() {
            let read = &mut self.reads[index];
            if let State::Reserving(len) = read.state {
                if len > producer.cache_ref().max_payload_len() {
                    let error = Error::other(format!("{len} bytes exceed the tcache"));
                    read.state = State::Done(ReadOutcome::Failed(error));
                } else if let Some(reservation) = producer.reserve(len, true) {
                    let file = read.file.expect("a sized read has a file");
                    read.state = fill(&mut self.disk, file, reservation, len);
                }
            }
            if !matches!(read.state, State::Done(_)) {
                index += 1;
                continue;
            }
            let read = self.reads.swap_remove(index);
            if let Some(file) = read.file {
                self.disk.close(file);
            }
            let State::Done(outcome) = read.state else { unreachable!("matched above") };
            done(read.tag, outcome);
        }
    }
}

impl State {
    fn after(self, event: DiskEvent) -> Self {
        match (self, event) {
            (Self::Sizing, DiskEvent::FileLen { len, .. }) => Self::Reserving(len as usize),
            (Self::Sizing, DiskEvent::Failed { error, .. })
                if error.kind() == ErrorKind::NotFound =>
            {
                Self::Done(ReadOutcome::Missing)
            }
            (Self::Sizing, DiskEvent::Failed { error, .. }) => {
                Self::Done(ReadOutcome::Failed(error))
            }
            (Self::Reading(mut reservation, expected), DiskEvent::ReadInto { len, .. })
                if len == expected =>
            {
                reservation.increment_offset(len);
                Self::Done(ReadOutcome::Sent(reservation.read()))
            }
            (Self::Reading(_, expected), DiskEvent::ReadInto { len, .. }) => {
                let error = Error::other(format!("read {len} of {expected} bytes"));
                Self::Done(ReadOutcome::Failed(error))
            }
            (Self::Reading(..), DiskEvent::Failed { error, .. }) => {
                Self::Done(ReadOutcome::Failed(error))
            }
            (state, _) => state,
        }
    }
}

fn fill(disk: &mut DiskIo, file: FileToken, mut reservation: TReservation, len: usize) -> State {
    let target = match reservation.buffer() {
        Ok(buffer) => buffer.as_mut_ptr(),
        Err(error) => return State::Done(ReadOutcome::Failed(error)),
    };
    if len == 0 {
        reservation.increment_offset(0);
        return State::Done(ReadOutcome::Sent(reservation.read()));
    }
    // SAFETY: the reservation's `len` bytes stay valid and untouched: it is
    // held in `State::Reading` until the completion, and `disk` drops first.
    if !unsafe { disk.read_at_into(file, 0, target, len) } {
        return State::Done(ReadOutcome::Failed(Error::other("file closed before its read")));
    }
    State::Reading(reservation, len)
}
