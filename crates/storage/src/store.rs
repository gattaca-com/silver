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
    ssz_view::{
        BeaconBlocksByRangeRequestView, BeaconBlocksByRootRequestView,
        DataColumnSidecarsByRangeRequestView, DataColumnsByRootIdentifierView,
    },
};

const MAX_WRITES_PER_LOOP: usize = 10;
const MAX_READS_PER_LOOP: usize = 10;

enum PendingWrite {
    Index { block_root: [u8; 32], slot: u64 },
    Column { slot: u64, column: u64, ssz: TRead },
    Block { slot: u64, ssz: TRead },
}

#[derive(Clone, Copy, Debug)]
enum PendingQuery {
    Column { stream_id: P2pStreamId, slot: u64, column: u64 },
    Block { stream_id: P2pStreamId, slot: u64 },
    Complete { stream_id: P2pStreamId },
}

/// Unified blocks and data columns disk store.
pub(super) struct Store {
    store_dir: String,
    // Mapping of block roots to slots.
    root_index: FxHashMap<[u8; 32], u64>,

    // Data columns for the current slot indexed by the block root.
    current_slot: FxHashMap<[u8; 32], Vec<(u64, TRead)>>,
    write_queue: VecDeque<PendingWrite>,
    query_queue: VecDeque<PendingQuery>,
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
            if !self.root_index.contains_key(&block_root) {
                self.root_index.insert(block_root, slot);
                self.write_queue.push_back(PendingWrite::Index { block_root, slot });
            }
        } else {
            self.current_slot
                .entry(block_root)
                .and_modify(|v| v.push((column_index, sidecar_ssz.clone())))
                .or_insert_with(|| vec![(column_index, sidecar_ssz)]);
        }
    }

    pub(super) fn add_block(&mut self, block_root: [u8; 32], block_ssz: TRead, slot: u64) {
        self.write_queue.push_back(PendingWrite::Block { slot, ssz: block_ssz });
        if !self.root_index.contains_key(&block_root) {
            self.root_index.insert(block_root, slot);
            self.write_queue.push_back(PendingWrite::Index { block_root, slot });
        }
    }

    pub(super) fn set_canonical(&mut self, slot: u64, canonical_root: [u8; 32]) {
        if let Some(columns) = self.current_slot.remove(&canonical_root) {
            if !self.root_index.contains_key(&canonical_root) {
                self.root_index.insert(canonical_root, slot);
                self.write_queue.push_back(PendingWrite::Index { block_root: canonical_root, slot });
            }
            for (column, ssz) in columns {
                self.write_queue.push_back(PendingWrite::Column { slot, column, ssz });
            }
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
                            self.query_queue.push_back(PendingQuery::Column {
                                stream_id: request.stream_id,
                                slot,
                                column,
                            });
                        }
                    }
                }
                self.query_queue.push_back(PendingQuery::Complete {
                    stream_id: request.stream_id,
                });
            }
            silver_common::RpcRequest::DataColumnsByRoot(tcache_read) => {
                let read = rpc_consumer.acquire(tcache_read);
                if let Ok((buf, _)) = read.buffer() {
                    if DataColumnsByRootIdentifierView::check_size(buf) {
                        let root = DataColumnsByRootIdentifierView::block_root(buf);
                        if let Some(slot) = self.root_index.get(root) {
                            for column in DataColumnsByRootIdentifierView::columns(buf)
                                .chunks_exact(8)
                                .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
                            {
                                self.query_queue.push_back(PendingQuery::Column {
                                    stream_id: request.stream_id,
                                    slot: *slot,
                                    column,
                                });
                            }
                        }
                    }
                }
                self.query_queue.push_back(PendingQuery::Complete {
                    stream_id: request.stream_id,
                });
            }
            silver_common::RpcRequest::BlocksByRange(req_bytes) => {
                let start = BeaconBlocksByRangeRequestView::start_slot(&req_bytes);
                let count = BeaconBlocksByRangeRequestView::count(&req_bytes);
                for slot in start..start + count {
                    self.query_queue.push_back(PendingQuery::Block {
                        stream_id: request.stream_id,
                        slot,
                    });
                }
                self.query_queue.push_back(PendingQuery::Complete {
                    stream_id: request.stream_id,
                });
            }
            silver_common::RpcRequest::BlockByRoot(tcache_read) => {
                let read = rpc_consumer.acquire(tcache_read);
                if let Ok((buf, _)) = read.buffer() {
                    if BeaconBlocksByRootRequestView::check_size(buf) {
                        let count = BeaconBlocksByRootRequestView::count(buf);
                        for i in 0..count {
                            let root = BeaconBlocksByRootRequestView::root(buf, i);
                            if let Some(slot) = self.root_index.get(root) {
                                self.query_queue.push_back(PendingQuery::Block {
                                    stream_id: request.stream_id,
                                    slot: *slot,
                                });
                            }
                        }
                    }
                }
                self.query_queue.push_back(PendingQuery::Complete {
                    stream_id: request.stream_id,
                });
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
                    let dir = self.slot_dir(*slot);
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                    }
                    let path = dir.join("block_index.bin");
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
                    let dir = self.slot_dir(*slot);
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                    }
                    let path = dir.join(format!("{slot}_{column}.ssz"));
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
                PendingWrite::Block { slot, ssz } => {
                    let dir = self.slot_dir(*slot);
                    if !dir.exists() {
                        std::fs::create_dir_all(&dir)?;
                    }
                    let path = dir.join(format!("{slot}_block.ssz"));
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
            let Some(pending_query) = self.query_queue.front()
        {
            reads += 1;

            match pending_query {
                PendingQuery::Column { stream_id, slot, column } => {
                    let path = self.slot_dir(*slot).join(format!("{slot}_{column}.ssz"));
                    match open_file_read_non_blocking(path) {
                        Ok(mut file) => {
                            let ssz_len = file.metadata()?.len();
                            let mut reservation =
                                producer.reserve(ssz_len as usize, true).ok_or(ErrorKind::StorageFull)?;
                            match file.read(reservation.buffer()?) {
                                Ok(read) if read == ssz_len as usize => {
                                    reservation.increment_offset(read);
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
                        Err(e) if e.kind() == ErrorKind::NotFound => {
                            self.query_queue.pop_front();
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
                PendingQuery::Block { stream_id, slot } => {
                    let path = self.slot_dir(*slot).join(format!("{slot}_block.ssz"));
                    match open_file_read_non_blocking(path) {
                        Ok(mut file) => {
                            let ssz_len = file.metadata()?.len();
                            let mut reservation =
                                producer.reserve(ssz_len as usize, true).ok_or(ErrorKind::StorageFull)?;
                            match file.read(reservation.buffer()?) {
                                Ok(read) if read == ssz_len as usize => {
                                    reservation.increment_offset(read);
                                    emit(P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                                        stream_id: *stream_id,
                                        response: RpcResponse::BeaconBlock {
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
                        Err(e) if e.kind() == ErrorKind::NotFound => {
                            self.query_queue.pop_front();
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
                PendingQuery::Complete { stream_id } => {
                    emit(P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
                        stream_id: *stream_id,
                        response: RpcResponse::Complete,
                    })));
                    self.query_queue.pop_front();
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

    #[test]
    fn test_store_block_persistence_and_queries() {
        use silver_common::{
            P2pSend, P2pStreamId, RpcOutbound, RpcRequest, RpcRequestInbound, RpcResponse,
            RpcResponseOutbound, StreamProtocol, TCache, TCacheProducer,
        };

        let store_path = format!("/tmp/test_store_blocks_{}", rand::random::<u32>());
        let _ = std::fs::remove_dir_all(&store_path);

        let mut store = super::Store::load(store_path.clone()).unwrap();

        // 1. Prepare block data in TCache
        let mut producer = TCache::producer("test_rpc_out", 1024 * 1024);
        let mut reservation = producer.reserve(100, true).unwrap();
        let block_bytes = [7u8; 100];
        reservation.write_all(&block_bytes).unwrap();
        reservation.flush().unwrap();
        let block_ssz = reservation.read();

        let mut rpc_consumer = producer.cache_ref().random_access("test_rpc", true).unwrap();
        let block_read = rpc_consumer.acquire(block_ssz);

        // 2. Add block
        let block_root = [0xAA; 32];
        let slot = 42;
        store.add_block(block_root, block_read, slot);

        // Check index state
        assert_eq!(store.root_index.get(&block_root), Some(&slot));

        // 3. Run file I/O to flush writes
        let fork_digest = [1, 2, 3, 4];
        let rpc_producer_cache = TCache::multi_producer("test_rpc_in", 1024 * 1024);
        let mut rpc_producer = rpc_producer_cache.clone();
        let mut emitted_sends = vec![];
        store
            .file_io(&fork_digest, &mut rpc_producer, &mut |send| {
                emitted_sends.push(send);
            })
            .unwrap();

        // Check that the block file was created
        let block_file_path = store.slot_dir(slot).join(format!("{slot}_block.ssz"));
        assert!(block_file_path.exists());
        println!("Block file created at: {:?} with len: {:?}", block_file_path, std::fs::metadata(&block_file_path).unwrap().len());

        // 4. Request block by range via RPC
        let mut req_bytes = [0u8; 24];
        req_bytes[0..8].copy_from_slice(&slot.to_le_bytes()); // start_slot
        req_bytes[8..16].copy_from_slice(&1u64.to_le_bytes()); // count
        req_bytes[16..24].copy_from_slice(&1u64.to_le_bytes()); // step

        let stream_id = P2pStreamId::new(1234, 1, StreamProtocol::BeaconBlocksByRange, false);
        let inbound_req = RpcRequestInbound {
            stream_id,
            request: RpcRequest::BlocksByRange(req_bytes),
        };

        let rpc_req_cache = TCache::producer("test_rpc_req", 1024 * 1024);
        let mut rpc_consumer = rpc_req_cache.cache_ref().random_access("test_cons", true).unwrap();
        store.rpc_request(&mut rpc_consumer, inbound_req);

        // 5. Run file I/O to read and emit responses
        let mut emitted_responses = vec![];
        store
            .file_io(&fork_digest, &mut rpc_producer, &mut |send| {
                emitted_responses.push(send);
            })
            .unwrap();

        // We expect two responses: 1 BeaconBlock and 1 Complete response
        assert_eq!(emitted_responses.len(), 2);

        // Check the BeaconBlock chunk
        if let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            stream_id: out_stream_id,
            response,
        })) = &emitted_responses[0]
        {
            assert_eq!(out_stream_id.stream_id(), stream_id.stream_id());
            if let RpcResponse::BeaconBlock { fork_digest: out_digest, ssz } = response {
                assert_eq!(out_digest, &fork_digest);
                let acquired = rpc_producer_cache.cache_ref().random_access("test_read", true).unwrap().acquire(*ssz);
                let (buf, _) = acquired.buffer().unwrap();
                assert_eq!(buf, &block_bytes);
            } else {
                panic!("Expected BeaconBlock response");
            }
        } else {
            panic!("Expected RPC Response outbound send event");
        }

        // Check the Complete chunk
        if let P2pSend::Rpc(RpcOutbound::Response(RpcResponseOutbound {
            stream_id: out_stream_id,
            response,
        })) = &emitted_responses[1]
        {
            assert_eq!(out_stream_id.stream_id(), stream_id.stream_id());
            assert!(matches!(response, RpcResponse::Complete));
        } else {
            panic!("Expected Complete response outbound send event");
        }

        // 6. Reload store and verify index loading
        let reloaded_store = super::Store::load(store_path.clone()).unwrap();
        assert_eq!(reloaded_store.root_index.get(&block_root), Some(&slot));

        // Clean up
        let _ = std::fs::remove_dir_all(&store_path);
    }
}
