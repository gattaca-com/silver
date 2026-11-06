use std::{
    io::{Error, ErrorKind},
    path::Path,
};

use flux_disk::{DiskEvent, DiskIo, FailedOp, FileToken, OpenOptions};
use silver_common::{TCacheProducer, TCacheRead, TProducer};

pub(super) enum ReadOutcome {
    Sent(TCacheRead),
    Missing,
    Failed(Error),
}

struct Read<T> {
    file: Option<FileToken>,
    tag: T,
    result: Option<Result<Vec<u8>, Error>>,
}

/// Reads whole files into tcache payloads without blocking: open, read to
/// end, close. Reads finish in the order the disk completes them and hand
/// the caller's tag back.
pub(super) struct FileReader<T> {
    disk: DiskIo,
    reads: Vec<Read<T>>,
    buffers: Vec<Vec<u8>>,
}

impl<T> FileReader<T> {
    pub(super) fn new() -> Result<Self, Error> {
        Ok(Self { disk: super::disk_ring()?, reads: Vec::new(), buffers: Vec::new() })
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
                let buf = self.buffers.pop().unwrap_or_default();
                let queued = self.disk.read_to_end_owned(file, 0, buf);
                self.disk.close(file);
                match queued {
                    Ok(()) => Read { file: Some(file), tag, result: None },
                    Err(buf) => {
                        self.buffers.push(buf);
                        Read { file: None, tag, result: Some(Err(Error::other("file closed"))) }
                    }
                }
            }
            Err(error) => Read { file: None, tag, result: Some(Err(error)) },
        };
        self.reads.push(read);
    }

    /// Reaps completions and hands each finished read to `done`. A read
    /// whose bytes do not fit in `producer` yet waits for a later step.
    pub(super) fn step(&mut self, producer: &mut TProducer, mut done: impl FnMut(T, ReadOutcome)) {
        let (reads, buffers) = (&mut self.reads, &mut self.buffers);
        self.disk.poll_with(|event| {
            let (file, result) = match event {
                DiskEvent::Failed { file, op: FailedOp::Open, error, .. } => (file, Err(error)),
                DiskEvent::ReadOwned { file, buf, error: None, .. } => (file, Ok(buf)),
                DiskEvent::ReadOwned { file, buf, error: Some(error), .. } => {
                    buffers.push(buf);
                    (file, Err(error))
                }
                _ => return,
            };
            // A failed open is reported before the read queued behind it.
            match reads.iter_mut().find(|read| read.file == Some(file)) {
                Some(read) if read.result.is_none() => read.result = Some(result),
                _ => {
                    if let Ok(buf) = result {
                        buffers.push(buf);
                    }
                }
            }
        });

        let mut index = 0;
        while index < self.reads.len() {
            let read = &mut self.reads[index];
            let outcome = match read.result.take() {
                None => {
                    index += 1;
                    continue;
                }
                Some(Ok(bytes)) => {
                    let Some(mut reservation) = producer.reserve(bytes.len(), true) else {
                        read.result = Some(Ok(bytes));
                        index += 1;
                        continue;
                    };
                    let outcome = match reservation.buffer() {
                        Ok(target) => {
                            target[..bytes.len()].copy_from_slice(&bytes);
                            reservation.increment_offset(bytes.len());
                            ReadOutcome::Sent(reservation.read())
                        }
                        Err(error) => ReadOutcome::Failed(Error::other(error)),
                    };
                    self.buffers.push(bytes);
                    outcome
                }
                Some(Err(error)) if error.kind() == ErrorKind::NotFound => ReadOutcome::Missing,
                Some(Err(error)) => ReadOutcome::Failed(error),
            };
            done(self.reads.swap_remove(index).tag, outcome);
        }
    }
}
