use std::{
    io::{Error, ErrorKind},
    path::Path,
};

use flux_disk::{DiskEvent, DiskIo, FailedOp, FileToken, OpenOptions};
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

enum Update {
    Len(usize),
    Read(usize, Option<Error>),
    Failed(Error),
}

struct Read<T> {
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

    pub(super) fn tags(&self) -> impl Iterator<Item = &T> {
        self.reads.iter().map(|read| &read.tag)
    }

    pub(super) fn start(&mut self, path: &Path, tag: T) {
        let read = match self.disk.open(path, OpenOptions::new().read(true)) {
            Ok(file) => {
                self.disk.file_len(file);
                Read { file: Some(file), tag, state: State::Sizing }
            }
            Err(error) => Read { file: None, tag, state: State::Done(ReadOutcome::Failed(error)) },
        };
        self.reads.push(read);
    }

    /// Reaps completions and hands each finished read to `done`. A read that
    /// does not fit in `producer` yet waits for a later step.
    pub(super) fn step(&mut self, producer: &mut TProducer, mut done: impl FnMut(T, ReadOutcome)) {
        let reads = &mut self.reads;
        self.disk.poll_with(|event| {
            let (file, update) = match event {
                DiskEvent::FileLen { file, len } => (file, Update::Len(len as usize)),
                DiskEvent::ReadInto { file, len, error, .. } => (file, Update::Read(len, error)),
                DiskEvent::Failed {
                    file, op: FailedOp::Open | FailedOp::FileLen, error, ..
                } => (file, Update::Failed(error)),
                _ => return,
            };
            if let Some(read) = reads.iter_mut().find(|read| read.file == Some(file)) {
                read.state = read.state_after(update);
            }
        });

        let mut index = 0;
        while index < self.reads.len() {
            let read = &mut self.reads[index];
            if let State::Reserving(len) = read.state &&
                let Some(reservation) = producer.reserve(len, true)
            {
                read.state = fill(&mut self.disk, read.file, reservation, len);
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

impl<T> Read<T> {
    fn state_after(&mut self, update: Update) -> State {
        match (std::mem::replace(&mut self.state, State::Sizing), update) {
            (State::Sizing, Update::Len(len)) => State::Reserving(len),
            (State::Sizing, Update::Failed(error)) if error.kind() == ErrorKind::NotFound => {
                State::Done(ReadOutcome::Missing)
            }
            (State::Sizing, Update::Failed(error)) => State::Done(ReadOutcome::Failed(error)),
            (State::Reading(mut reservation, expected), Update::Read(len, None))
                if len == expected =>
            {
                reservation.increment_offset(len);
                State::Done(ReadOutcome::Sent(reservation.read()))
            }
            (State::Reading(_, expected), Update::Read(len, error)) => {
                State::Done(ReadOutcome::Failed(
                    error
                        .unwrap_or_else(|| Error::other(format!("read {len} of {expected} bytes"))),
                ))
            }
            (state, _) => state,
        }
    }
}

fn fill(
    disk: &mut DiskIo,
    file: Option<FileToken>,
    mut reservation: TReservation,
    len: usize,
) -> State {
    let target = match reservation.buffer() {
        Ok(buffer) => buffer.as_mut_ptr(),
        Err(error) => return State::Done(ReadOutcome::Failed(error)),
    };
    if len == 0 {
        reservation.increment_offset(0);
        return State::Done(ReadOutcome::Sent(reservation.read()));
    }
    let Some(file) = file else { return State::Done(ReadOutcome::Failed(Error::other("no file"))) };
    // SAFETY: the reservation's `len` bytes stay valid and untouched: it is
    // held in `State::Reading` until the completion, and `disk` drops first.
    if !unsafe { disk.read_at_into(file, 0, target, len) } {
        return State::Done(ReadOutcome::Failed(Error::other("file closed before its read")));
    }
    State::Reading(reservation, len)
}
