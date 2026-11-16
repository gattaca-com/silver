use std::{
    io::Error,
    path::{Path, PathBuf},
};

use flux_disk::{DiskEvent, DiskIo, FileToken, OpenOptions, OperationId};

const DIRECTORY_TOKENS: usize = 4;

/// Open handles on one directory, taken in turn: a rename or unlink on a
/// token runs only once the one before it on that token has completed.
pub(super) struct DirectoryTokens {
    tokens: [FileToken; DIRECTORY_TOKENS],
    next: usize,
}

impl DirectoryTokens {
    pub(super) fn open(disk: &mut DiskIo, directory: &str) -> Result<Self, Error> {
        let mut tokens = [disk.open_directory(directory)?; DIRECTORY_TOKENS];
        for token in &mut tokens[1..] {
            *token = disk.open_directory(directory)?;
        }
        Ok(Self { tokens, next: 0 })
    }

    pub(super) fn next(&mut self) -> FileToken {
        self.next = (self.next + 1) % DIRECTORY_TOKENS;
        self.tokens[self.next]
    }
}

/// `bytes` point into memory the write's tag keeps alive; see
/// [`FileWriter::start`].
pub(super) enum WriteOp {
    Create {
        path: PathBuf,
        bytes: *const [u8],
    },
    /// Written at the file's length, so appends to one file must not overlap.
    Append {
        path: PathBuf,
        bytes: *const [u8],
    },
    /// Written to `staged`, which is then renamed over `path`. Once `staged`
    /// opens, the rename follows even a failed write.
    Replace {
        path: PathBuf,
        staged: PathBuf,
        bytes: *const [u8],
    },
    Rename {
        from: PathBuf,
        to: PathBuf,
    },
    Unlink {
        path: PathBuf,
    },
}

impl WriteOp {
    /// The file the op changes; ops on one file run one at a time.
    fn key(&self) -> &Path {
        match self {
            Self::Create { path, .. } |
            Self::Append { path, .. } |
            Self::Replace { path, .. } |
            Self::Unlink { path } => path,
            Self::Rename { from, .. } => from,
        }
    }
}

struct Write<T> {
    key: PathBuf,
    /// A rename changes its destination as well.
    renamed_to: Option<PathBuf>,
    file: Option<FileToken>,
    /// Finishes the write when set; otherwise its data write does.
    finishing_op: Option<OperationId>,
    /// An append's bytes, written once its file length arrives.
    append: Option<*const [u8]>,
    error: Option<Error>,
    finished: bool,
    tag: T,
}

// SAFETY: `append` points into memory `tag` keeps alive, and moves with it.
unsafe impl<T: Send> Send for Write<T> {}

/// Creates, appends, replaces, renames and unlinks files without blocking.
/// Ops on different files overlap; [`Self::conflicts_with`] lets the caller
/// keep ops on one file in order. [`Self::next_finished`] hands each finished
/// write's tag back, in no particular order.
pub(super) struct FileWriter<T> {
    // Drops first: its drop waits for the kernel to finish reading the
    // memory the writes point into.
    pub(super) disk: DiskIo,
    directory: DirectoryTokens,
    writes: Vec<Write<T>>,
    // Append lengths a poll reaped; their writes are queued after it.
    lengths: Vec<(FileToken, u64)>,
}

impl<T> FileWriter<T> {
    pub(super) fn new(store_dir: &str) -> Result<Self, Error> {
        let mut disk = super::disk_ring()?;
        Ok(Self {
            directory: DirectoryTokens::open(&mut disk, store_dir)?,
            disk,
            writes: Vec::new(),
            lengths: Vec::new(),
        })
    }

    pub(super) fn in_flight(&self) -> usize {
        self.writes.len()
    }

    pub(super) fn busy_with(&self, path: &Path) -> bool {
        // Paths are built one way, so bytes compare exactly and skip the
        // per-component parse `Path` equality does.
        let path = path.as_os_str();
        self.writes.iter().any(|write| {
            write.key.as_os_str() == path ||
                write.renamed_to.as_ref().is_some_and(|to| to.as_os_str() == path)
        })
    }

    pub(super) fn conflicts_with(&self, op: &WriteOp) -> bool {
        let renamed_to = match op {
            WriteOp::Rename { to, .. } => Some(to),
            _ => None,
        };
        self.busy_with(op.key()) || renamed_to.is_some_and(|to| self.busy_with(to))
    }

    /// # Safety
    ///
    /// The op's `bytes` must stay valid and unchanged until `tag` comes back
    /// from [`Self::step`]; holding their owner in `tag` does that.
    pub(super) unsafe fn start(&mut self, op: WriteOp, tag: T) {
        let mut write = Write {
            key: PathBuf::new(),
            renamed_to: None,
            file: None,
            finishing_op: None,
            append: None,
            error: None,
            finished: false,
            tag,
        };
        let started = match op {
            WriteOp::Create { path, bytes } => {
                // SAFETY: forwarded from this function's contract.
                let started = unsafe { self.create(&path, bytes, &mut write) };
                write.key = path;
                started
            }
            WriteOp::Append { path, bytes } => {
                let started = self.open(&path, false, &mut write).and_then(|file| {
                    self.disk.file_len(file).then_some(()).ok_or_else(file_closed)
                });
                write.append = Some(bytes);
                write.key = path;
                started
            }
            WriteOp::Replace { path, staged, bytes } => {
                // SAFETY: forwarded from this function's contract.
                let started = unsafe { self.create(&staged, bytes, &mut write) }.and_then(|()| {
                    let file = write.file.expect("created above");
                    queued(self.disk.rename(file, &path))
                });
                write.key = path;
                started.map(|id| write.finishing_op = Some(id))
            }
            WriteOp::Rename { from, to } => {
                let started = queued(self.disk.rename_path(self.directory.next(), &from, &to));
                write.key = from;
                write.renamed_to = Some(to);
                started.map(|id| write.finishing_op = Some(id))
            }
            WriteOp::Unlink { path } => {
                let started = queued(self.disk.unlink(self.directory.next(), &path));
                write.key = path;
                started.map(|id| write.finishing_op = Some(id))
            }
        };
        if let Err(error) = started {
            write.error = Some(error);
            write.finished = true;
        }
        self.writes.push(write);
    }

    /// # Safety
    ///
    /// As [`Self::start`].
    unsafe fn create(
        &mut self,
        path: &Path,
        bytes: *const [u8],
        write: &mut Write<T>,
    ) -> Result<(), Error> {
        let file = self.open(path, true, write)?;
        // SAFETY: forwarded from this function's contract.
        unsafe { write_at(&mut self.disk, file, 0, bytes) }
    }

    fn open(
        &mut self,
        path: &Path,
        truncate: bool,
        write: &mut Write<T>,
    ) -> Result<FileToken, Error> {
        let options = OpenOptions::new().write(true).create(true).truncate(truncate);
        let file = self.disk.open(path, options)?;
        write.file = Some(file);
        Ok(file)
    }

    /// Reaps completions and queues the writes of appends whose length
    /// arrived.
    pub(super) fn step(&mut self) {
        let (writes, lengths) = (&mut self.writes, &mut self.lengths);
        self.disk.poll_with(|event| {
            let (file, operation, error) = match event {
                DiskEvent::FileLen { file, len } => return lengths.push((file, len)),
                DiskEvent::Written { file, .. } => (Some(file), None, None),
                DiskEvent::Renamed { operation_id, .. } |
                DiskEvent::Unlinked { operation_id, .. } => (None, Some(operation_id), None),
                DiskEvent::Failed { file, operation_id, error, .. } => {
                    (Some(file), operation_id, Some(error))
                }
                _ => return,
            };
            let Some(write) = writes.iter_mut().find(|write| match operation {
                Some(id) => write.finishing_op == Some(id),
                None => write.file == file,
            }) else {
                return;
            };
            if let Some(error) = error {
                write.error.get_or_insert(error);
            }
            write.finished |= operation.is_some() || write.finishing_op.is_none();
        });

        self.write_appends();
    }

    fn write_appends(&mut self) {
        for (file, len) in self.lengths.drain(..) {
            let Some(write) = self.writes.iter_mut().find(|write| write.file == Some(file)) else {
                continue;
            };
            let bytes = write.append.take().expect("only appends ask for a length");
            // SAFETY: forwarded from `start`'s contract.
            if let Err(error) = unsafe { write_at(&mut self.disk, file, len, bytes) } {
                write.error.get_or_insert(error);
                write.finished = true;
            }
        }
    }

    pub(super) fn next_finished(&mut self) -> Option<(T, Result<(), Error>)> {
        let index = self.writes.iter().position(|write| write.finished)?;
        let write = self.writes.swap_remove(index);
        if let Some(file) = write.file {
            self.disk.close(file);
        }
        Some((write.tag, write.error.map_or(Ok(()), Err)))
    }
}

/// # Safety
///
/// As [`FileWriter::start`].
unsafe fn write_at(
    disk: &mut DiskIo,
    file: FileToken,
    offset: u64,
    bytes: *const [u8],
) -> Result<(), Error> {
    // SAFETY: forwarded from this function's contract.
    if unsafe { disk.write_at_from(file, offset, bytes.cast(), bytes.len()) } {
        Ok(())
    } else {
        Err(Error::other("empty write or closed file"))
    }
}

fn queued(id: Result<Option<OperationId>, Error>) -> Result<OperationId, Error> {
    id?.ok_or_else(file_closed)
}

fn file_closed() -> Error {
    Error::other("file closed")
}
