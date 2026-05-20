use std::{
    collections::VecDeque,
    fs::File,
    io::{Error, ErrorKind, Read, Write},
    os::fd::{FromRawFd, IntoRawFd},
    path::{Path, PathBuf},
};

use fxhash::FxHashMap;
use libc::{F_GETFL, F_SETFL, O_NONBLOCK, fcntl};
use silver_common::{
    P2pSend, P2pStreamId, RpcOutbound, RpcRequestInbound, RpcResponse, RpcResponseOutbound,
    TCacheProducer, TMultiProducer, TRandomAccess, TRead,
    ssz_view::{DataColumnSidecarsByRangeRequestView, DataColumnsByRootIdentifierView},
};

const MAX_WRITES_PER_LOOP: usize = 10;
const MAX_READS_PER_LOOP: usize = 10;

enum PendingWrite {
    Index { block_root: [u8; 32], slot: u64 },
    Column { slot: u64, column: u64, ssz: TRead },
}

/// Data columns disk store.
/// TODO: backfill.
pub(super) struct Store {
    store_dir: String,
    // Mapping of block roots to slots.
    root_index: FxHashMap<[u8; 32], u64>,

    // Data columns for the current slot indexed by the block root.
    // TODO alternative to vec values? 
    current_slot: FxHashMap<[u8; 32], Vec<(u64, TRead)>>,
    write_queue: VecDeque<PendingWrite>,
    query_queue: VecDeque<(P2pStreamId, u64, u64)>,
}

impl Store {
    pub(super) fn load(store_dir: String) -> Result<Self, Error> {
        let mut root_index = FxHashMap::default();

        // Try to create dirs if they do not exist.
        if !std::fs::exists(&store_dir)? {
            std::fs::create_dir_all(&store_dir)?;
        }

        for sub_dir in std::fs::read_dir(&store_dir)? {
            let index_path = sub_dir?.path().join("block_index.bin");
            if let Ok(mut index_file) = open_file_read_non_blocking(index_path) {
                let mut buffer = [0u8; 40];
                while index_file.read_exact(&mut buffer).is_ok() {
                    let block_root: [u8; 32] = buffer[..32].try_into().unwrap();
                    let slot = u64::from_le_bytes(buffer[32..].try_into().unwrap());
                    root_index.insert(block_root, slot);
                }
            }
        }

        Ok(Self {
            store_dir,
            root_index,
            current_slot: Default::default(),
            write_queue: Default::default(),
            query_queue: Default::default(),
        })
    }

    pub(super) fn add(
        &mut self,
        block_root: [u8; 32],
        column_index: u64,
        sidecar_ssz: TRead,
        slot: u64,
        backfilling: bool,
    ) {
        if backfilling {
            self.write_queue.push_back(PendingWrite::Column {
                slot,
                column: column_index,
                ssz: sidecar_ssz,
            });
            self.write_queue.push_back(PendingWrite::Index { block_root, slot });
        } else {
            self.current_slot
                .entry(block_root)
                .and_modify(|v| v.push((column_index, sidecar_ssz.clone())))
                .or_insert_with(|| vec![(column_index, sidecar_ssz)]);
        }
    }

    pub(super) fn set_canonical(&mut self, slot: u64, canonical_root: [u8; 32]) {
        if let Some(columns) = self.current_slot.remove(&canonical_root) {
            self.root_index.insert(canonical_root, slot);
            for (column, ssz) in columns {
                self.write_queue.push_back(PendingWrite::Column { slot, column, ssz });
            }
            self.write_queue.push_back(PendingWrite::Index { block_root: canonical_root, slot });
        }
        self.current_slot.clear();
    }

    pub(super) fn rpc_request(
        &mut self,
        rpc_consumer: &mut TRandomAccess,
        request: RpcRequestInbound,
    ) {
        match request.request {
            silver_common::RpcRequest::DataColumnsByRange { ssz, len } => {
                if DataColumnSidecarsByRangeRequestView::check_size(&ssz[..len]) {
                    let start = DataColumnSidecarsByRangeRequestView::start_slot(&ssz[..len]);
                    let count = DataColumnSidecarsByRangeRequestView::count(&ssz[..len]);
                    let columns = DataColumnSidecarsByRangeRequestView::columns(&ssz[..len])
                        .chunks_exact(8)
                        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()));

                    for column in columns {
                        for slot in start..start + count {
                            self.query_queue.push_back((request.stream_id, slot, column));
                        }
                    }
                }
            }
            silver_common::RpcRequest::DataColumnsByRoot(tcache_read) => {
                let read = rpc_consumer.acquire(tcache_read);
                if let Ok((buf, _)) = read.buffer() {
                    if DataColumnsByRootIdentifierView::check_size(buf) {
                        let root = DataColumnsByRootIdentifierView::block_root(buf);
                        match self.root_index.get(root) {
                            Some(slot) => {
                                for column in DataColumnsByRootIdentifierView::columns(buf)
                                    .chunks_exact(8)
                                    .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                                {
                                    self.query_queue.push_back((request.stream_id, *slot, column));
                                }
                            }
                            None => todo!("return unavailable resource"),
                        }
                    }
                }
            }
            _ => {}
        }
    }

    pub(super) fn file_io<F>(
        &mut self,
        fork_digest: &[u8; 4],
        producer: &mut TMultiProducer,
        emit: &mut F,
    ) -> Result<(), Error>
    where
        F: FnMut(P2pSend),
    {
        // pending writes
        let mut writes = 0;
        while writes < MAX_WRITES_PER_LOOP &&
            let Some(pending) = self.write_queue.front()
        {
            writes += 1;

            match pending {
                PendingWrite::Index { block_root, slot } => {
                    let path = self.slot_dir(*slot).join("block_index.bin");
                    let mut file = open_file_write_non_blocking(path, true)?;
                    match file.write(block_root).and(file.write(&slot.to_le_bytes())) {
                        Ok(n) if n == block_root.len() + 8 => {
                            self.write_queue.pop_front();
                        }
                        Ok(_) => break,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
                PendingWrite::Column { slot, column, ssz } => {
                    let path = self.slot_dir(*slot).join(format!("{slot}_{column}.ssz"));
                    let mut file = open_file_write_non_blocking(path, false)?;
                    let (buffer, _) = ssz.buffer().map_err(Error::other)?;
                    match file.write(buffer) {
                        Ok(n) if n == buffer.len() => {
                            self.write_queue.pop_front();
                        }
                        Ok(_) => break,
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
        }

        // pending reads
        let mut reads = 0;
        while reads < MAX_READS_PER_LOOP &&
            let Some((stream_id, slot, column)) = self.query_queue.front()
        {
            reads += 1;

            let path = self.slot_dir(*slot).join(format!("{slot}_{column}.ssz"));
            if let Ok(mut file) = open_file_read_non_blocking(path) {
                let ssz_len = file.metadata()?.len();
                let reservation =
                    producer.reserve(ssz_len as usize, true).ok_or(ErrorKind::StorageFull)?;
                match file.read(reservation.buffer()?) {
                    Ok(read) if read == ssz_len as usize => {
                        emit(P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                            stream_id: *stream_id,
                            response: RpcResponse::DataColumnSidecar {
                                fork_digest: *fork_digest,
                                ssz: reservation.read(),
                            },
                        })));
                        self.query_queue.pop_front();
                    }
                    Ok(_) => break,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(())
    }

    fn slot_dir(&self, slot: u64) -> PathBuf {
        let group_dir = slot & !1023;
        PathBuf::new().join(&self.store_dir).join(group_dir.to_string())
    }
}

fn open_file_read_non_blocking<P: AsRef<Path>>(path: P) -> Result<File, Error> {
    let f = std::fs::File::open(path)?;
    let fd = f.into_raw_fd();
    let flags = unsafe { fcntl(fd, F_GETFL, 0) };
    if flags < 0 {
        return Err(Error::last_os_error());
    }

    let flags = flags | O_NONBLOCK;
    let res = unsafe { fcntl(fd, F_SETFL, flags) };
    if res != 0 {
        return Err(Error::last_os_error());
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

fn open_file_write_non_blocking<P: AsRef<Path>>(path: P, append: bool) -> Result<File, Error> {
    let f = if append {
        std::fs::File::options().append(true).create(true).open(path)?
    } else {
        std::fs::File::options().write(true).create(true).truncate(true).open(path)?
    };
    let fd = f.into_raw_fd();
    let flags = unsafe { fcntl(fd, F_GETFL, 0) };
    if flags < 0 {
        return Err(Error::last_os_error());
    }

    let flags = flags | O_NONBLOCK;
    let res = unsafe { fcntl(fd, F_SETFL, flags) };
    if res != 0 {
        return Err(Error::last_os_error());
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use std::{
        io::{ErrorKind, Read, Write},
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn non_blocking_file() {
        let _ = std::fs::remove_file("/tmp/test.txt");
        let mut file = super::open_file_write_non_blocking("/tmp/test.txt", false).unwrap();

        let mut handles = vec![];
        for i in 0..10 {
            let h = thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1));
                let start = Instant::now();
                let mut file = super::open_file_read_non_blocking("/tmp/test.txt").unwrap();
                let mut data = vec![0u8; 128 * 1024];
                let mut read = 0;
                for _ in 0..400 {
                    match file.read(&mut data) {
                        Ok(wrote) if wrote == data.len() => {
                            read += wrote;
                        }
                        Ok(n) => {
                            read += n;
                            //println!("read {n }/{}", data.len());
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            println!("would block!");
                        }
                        Err(e) => panic!("{e:?}"),
                    }
                }
                println!("{i} read {read} in {:?}", start.elapsed());
            });
            handles.push(h);
        }
        let data = vec![0u8; 128 * 1024];
        for _ in 0..400 {
            match file.write(&data) {
                Ok(wrote) if wrote == data.len() => {}
                Ok(n) => {
                    println!("wrote {n }/{}", data.len());
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    println!("would block!");
                }
                Err(e) => panic!("{e:?}"),
            }
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
