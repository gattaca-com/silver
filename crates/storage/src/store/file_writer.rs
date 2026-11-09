use std::{
    io::Error,
    path::{Path, PathBuf},
};

use flux_disk::{DiskEvent, DiskIo, FileToken, OpenOptions, OperationId};
use fxhash::FxHashSet;

pub(super) enum WriteOp<'a> {
    /// Written in place from memory the caller keeps valid until the
    /// completion; see [`FileWriter::start`].
    Create {
        path: PathBuf,
        source: *const u8,
        len: usize,
    },
    /// Copied into a pooled buffer, so `bytes` may go once `start` returns.
    Append {
        path: PathBuf,
        bytes: &'a [u8],
    },
    /// Writes `staged` from a pooled copy of `bytes`, then renames it over
    /// `path`.
    Replace {
        path: PathBuf,
        staged: PathBuf,
        bytes: &'a [u8],
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    Unlink {
        path: PathBuf,
    },
}

impl WriteOp<'_> {
    /// The file the op changes; ops on one file run one at a time.
    pub(super) fn key(&self) -> &Path {
        match self {
            Self::Create { path, .. } |
            Self::Append { path, .. } |
            Self::Replace { path, .. } |
            Self::Unlink { path } => path,
            Self::Rename { from, .. } => from,
        }
    }
}

enum Stage {
    Busy,
    /// An append's file length arrived; its write goes at that offset.
    Sized(u64),
    /// A replace's staged bytes are down; the rename comes next.
    Staged,
    Done(Result<(), Error>),
}

struct Write<T> {
    key: PathBuf,
    file: Option<FileToken>,
    operation: Option<OperationId>,
    /// An append's pooled copy, written once the file length is known.
    bytes: Option<Vec<u8>>,
    /// A replace's `(staged, path)`, renamed once the staged bytes are down.
    rename: Option<(PathBuf, PathBuf)>,
    tag: T,
    stage: Stage,
}

/// Creates, appends, replaces, renames and unlinks files without blocking.
/// Ops on different files overlap; [`Self::busy_with`] lets the caller keep
/// ops on one file in order. Writes finish in completion order and hand the
/// caller's tag back.
pub(super) struct FileWriter<T> {
    // Drops first: its drop waits for the kernel to finish reading the
    // caller memory `Create` ops point into.
    disk: DiskIo,
    order: FileToken,
    writes: Vec<Write<T>>,
    keys: FxHashSet<PathBuf>,
    buffers: Vec<Vec<u8>>,
}

impl<T> FileWriter<T> {
    pub(super) fn new(store_dir: &str) -> Result<Self, Error> {
        let mut disk = super::disk_ring()?;
        Ok(Self {
            order: disk.open_directory(store_dir)?,
            disk,
            writes: Vec::new(),
            keys: FxHashSet::default(),
            buffers: Vec::new(),
        })
    }

    pub(super) fn in_flight(&self) -> usize {
        self.writes.len()
    }

    pub(super) fn busy_with(&self, path: &Path) -> bool {
        self.keys.contains(path)
    }

    /// # Safety
    ///
    /// For [`WriteOp::Create`], `source..source + len` must stay valid and
    /// unchanged until `tag` comes back from [`Self::step`]; holding the
    /// owner of those bytes in `tag` does that.
    pub(super) unsafe fn start(&mut self, op: WriteOp, tag: T) {
        let key = op.key().to_path_buf();
        let mut write = Write {
            key,
            file: None,
            operation: None,
            bytes: None,
            rename: None,
            tag,
            stage: Stage::Busy,
        };
        let started = match op {
            WriteOp::Create { path, source, len } => self.open(&path, true).map(|file| {
                write.file = Some(file);
                // SAFETY: forwarded from this function's contract.
                let queued = unsafe { self.disk.write_at_from(file, 0, source, len) };
                if !queued {
                    write.stage = Stage::Done(Ok(()));
                }
            }),
            WriteOp::Append { path, bytes } => self.open(&path, false).map(|file| {
                write.file = Some(file);
                write.bytes = Some(self.pooled_copy(bytes));
                self.disk.file_len(file);
            }),
            WriteOp::Replace { path, staged, bytes } => self.open(&staged, true).map(|file| {
                write.file = Some(file);
                let copy = self.pooled_copy(bytes);
                let queued = self.disk.write_at_owned(file, 0, copy).is_ok();
                write.rename = Some((staged, path));
                if !queued {
                    write.stage = Stage::Done(Err(Error::other("replace's file closed")));
                }
            }),
            WriteOp::Rename { from, to } => {
                self.disk.rename_path(self.order, from, to).map(|id| write.operation = id)
            }
            WriteOp::Unlink { path } => {
                self.disk.unlink(self.order, path).map(|id| write.operation = id)
            }
        };
        if let Err(error) = started {
            write.stage = Stage::Done(Err(error));
        }
        self.keys.insert(write.key.clone());
        self.writes.push(write);
    }

    fn pooled_copy(&mut self, bytes: &[u8]) -> Vec<u8> {
        let mut buffer = self.buffers.pop().unwrap_or_default();
        buffer.clear();
        buffer.extend_from_slice(bytes);
        buffer
    }

    fn open(&mut self, path: &Path, truncate: bool) -> Result<FileToken, Error> {
        let options = OpenOptions::new().write(true).create(true).truncate(truncate);
        self.disk.open(path, options)
    }

    /// Reaps completions, starts the next stage of appends and replaces, and
    /// hands each finished write to `done`.
    pub(super) fn step(&mut self, mut done: impl FnMut(T, Result<(), Error>)) {
        let (writes, buffers) = (&mut self.writes, &mut self.buffers);
        self.disk.poll_with(|event| {
            let (by_file, by_operation, stage) = match event {
                DiskEvent::WrittenFrom { file, error, .. } => (Some(file), None, finished(error)),
                DiskEvent::FileLen { file, len } => (Some(file), None, Stage::Sized(len)),
                DiskEvent::WrittenOwned { file, buf, error, .. } => {
                    buffers.push(buf);
                    let stage = if error.is_none() { Stage::Staged } else { finished(error) };
                    (Some(file), None, stage)
                }
                DiskEvent::Renamed { operation_id, .. } |
                DiskEvent::Unlinked { operation_id, .. } => {
                    (None, Some(operation_id), Stage::Done(Ok(())))
                }
                DiskEvent::Failed { file, operation_id, error, .. } => {
                    (Some(file), operation_id, Stage::Done(Err(error)))
                }
                _ => return,
            };
            let write = writes.iter_mut().find(|write| {
                by_operation.is_some_and(|id| write.operation == Some(id)) ||
                    (by_operation.is_none() && write.file == by_file)
            });
            if let Some(write) = write &&
                !matches!(write.stage, Stage::Done(_))
            {
                write.stage = stage;
            }
        });

        let mut index = 0;
        while index < self.writes.len() {
            let write = &mut self.writes[index];
            match write.stage {
                Stage::Sized(len) => {
                    let (file, bytes) = (write.file.expect("an open file"), write.bytes.take());
                    write.stage =
                        match bytes.map(|bytes| self.disk.write_at_owned(file, len, bytes)) {
                            Some(Ok(())) => Stage::Busy,
                            Some(Err(buffer)) => {
                                self.buffers.push(buffer);
                                Stage::Done(Err(Error::other("append's file closed")))
                            }
                            None => Stage::Done(Err(Error::other("append without bytes"))),
                        };
                }
                Stage::Staged if write.rename.is_some() => {
                    let file = write.file.expect("an open file");
                    let (staged, path) = write.rename.take().expect("checked above");
                    write.stage = match self.disk.rename_path(file, staged, path) {
                        Ok(Some(id)) => {
                            write.operation = Some(id);
                            Stage::Busy
                        }
                        Ok(None) => Stage::Done(Err(Error::other("replace's file closed"))),
                        Err(error) => Stage::Done(Err(error)),
                    };
                }
                Stage::Staged => write.stage = Stage::Done(Ok(())),
                Stage::Busy | Stage::Done(_) => {}
            }
            if !matches!(self.writes[index].stage, Stage::Done(_)) {
                index += 1;
                continue;
            }
            let write = self.writes.swap_remove(index);
            if let Some(file) = write.file {
                self.disk.close(file);
            }
            self.keys.remove(&write.key);
            let Stage::Done(result) = write.stage else { unreachable!("matched above") };
            done(write.tag, result);
        }
    }
}

fn finished(error: Option<Error>) -> Stage {
    Stage::Done(error.map_or(Ok(()), Err))
}
