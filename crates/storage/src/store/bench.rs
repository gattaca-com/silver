//! Storage workload benchmarks: the baseline the io_uring rewrite is measured
//! against. Each scenario drives `Store::file_io` the way the tile loop does
//! and reports per-call latency, throughput and CPU.
//!
//!   SILVER_BENCH_DIR=<dir on the data-store disk> \
//!   cargo test -p silver_storage --release storage_bench -- --ignored
//! --nocapture --test-threads 1
//!
//! `SILVER_BENCH_EPOCHS` (default 4) and `SILVER_BENCH_BLOBS` (default 21)
//! size the follow-tip workload. tmpfs understates every number.

use std::{
    io::Write,
    os::fd::AsRawFd,
    path::Path,
    time::{Duration, Instant},
};

use silver_beacon_state_data::SLOTS_PER_EPOCH;
use silver_common::{
    P2pStreamId, PayloadResolution, RpcRequest, RpcRequestInbound, StreamProtocol, SyncUpdate,
    TCache, TCacheId, TCacheProducer, TCacheReader, TProducer, TRead, TReadMode, block_root_fulu,
    ssz_view::DC_BY_RANGE_REQ_MAX, test_util::SynthBlock,
};
use tempfile::TempDir;

use super::{COLUMN_SLOTS_RETAINED, Payload, PendingWrite, SLOTS_PER_DIR, Store, column_path};

const COLUMNS: u64 = 128;
const CELL_BYTES: usize = 2048;
const COMMITMENT_BYTES: usize = 48;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn bench_dir() -> TempDir {
    let base = std::env::var("SILVER_BENCH_DIR")
        .unwrap_or_else(|_| std::env::temp_dir().display().to_string());
    TempDir::new_in(base).unwrap()
}

/// Index, column, commitments, proofs, signed header and inclusion proof.
fn column_sidecar_len(blobs: usize) -> usize {
    8 + blobs * (CELL_BYTES + 2 * COMMITMENT_BYTES) + 208 + 4 * 32 + 12
}

fn cpu(who: i32) -> Duration {
    let mut usage = unsafe { std::mem::zeroed::<libc::rusage>() };
    assert_eq!(unsafe { libc::getrusage(who, &mut usage) }, 0);
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    tv(usage.ru_utime) + tv(usage.ru_stime)
}

struct Sample {
    calls: Vec<Duration>,
    started: Instant,
    thread_cpu: Duration,
    process_cpu: Duration,
}

impl Sample {
    fn start() -> Self {
        Self {
            calls: Vec::new(),
            started: Instant::now(),
            thread_cpu: cpu(libc::RUSAGE_THREAD),
            process_cpu: cpu(libc::RUSAGE_SELF),
        }
    }

    fn file_io(&mut self, store: &mut Store, producer: &mut TProducer) {
        let t = Instant::now();
        store.file_io(|_| [0u8; 4], producer, &mut |_| {}).unwrap();
        self.calls.push(t.elapsed());
    }

    fn report(mut self, name: &str, objects: u64, bytes: u64) {
        let wall = self.started.elapsed();
        let thread_cpu = cpu(libc::RUSAGE_THREAD) - self.thread_cpu;
        let process_cpu = cpu(libc::RUSAGE_SELF) - self.process_cpu;
        self.calls.sort_unstable();
        let at = |q: f64| self.calls[((self.calls.len() - 1) as f64 * q) as usize];
        let busy: Duration = self.calls.iter().sum();
        println!(
            "{name}: {objects} objects, {} MiB, {} file_io calls\n  \
             file_io p50 {:?} p99 {:?} max {:?}, busy {busy:?}, wall {wall:?}\n  \
             {:.0} objects/s busy, {:.1} us busy/object, cpu thread {thread_cpu:?} process {process_cpu:?}",
            bytes >> 20,
            self.calls.len(),
            at(0.5),
            at(0.99),
            at(1.0),
            objects as f64 / busy.as_secs_f64(),
            busy.as_secs_f64() * 1e6 / objects as f64,
        );
    }
}

/// Payloads copied into a tcache and acquired the way the tile hands them on.
struct Stager {
    producer: TProducer,
    reader: TCacheReader,
}

impl Stager {
    fn new(name: &'static str) -> Self {
        let producer = TCache::producer(TCacheId::ControlProcessing, 1 << 28);
        let reader = TCacheReader::single(producer.cache_ref(), name, TReadMode::Sliding).unwrap();
        Self { producer, reader }
    }

    fn stage(&mut self, bytes: &[u8]) -> TRead {
        let mut reservation =
            self.producer.reserve(bytes.len(), true).expect("staging tcache full");
        reservation.write_all(bytes).unwrap();
        reservation.flush().unwrap();
        self.reader.acquire(reservation.read())
    }

    fn release(&mut self) {
        self.reader.free();
        self.producer.loop_start();
    }
}

fn drain(store: &mut Store, producer: &mut TProducer, sample: &mut Sample) {
    while !store.write_queue.is_empty() || store.writer.in_flight() > 0 {
        sample.file_io(store, producer);
    }
    sample.file_io(store, producer);
}

fn served_producer() -> TProducer {
    TCache::producer(TCacheId::NetworkProcessing, 1 << 27)
}

/// Supernode following the tip: per slot one block and 128 columns, with
/// finality two epochs behind promoting each finalized epoch.
fn follow_tip(store: &mut Store, epochs: u64, blobs: usize) {
    let commitments = vec![0u8; blobs * COMMITMENT_BYTES];
    let column = vec![0x5au8; column_sidecar_len(blobs)];
    let mut stager = Stager::new("bench_follow");
    let mut producer = served_producer();
    store.sync_update(SyncUpdate::Following);

    let mut roots = vec![[0x31u8; 32]];
    let (mut objects, mut bytes) = (0, 0);
    let mut sample = Sample::start();
    for slot in 1..=epochs * SLOTS_PER_EPOCH {
        let parent = *roots.last().unwrap();
        let block = SynthBlock::fulu(slot, &commitments).parent_root(parent).into_bytes();
        let root = block_root_fulu(&block);
        roots.push(root);
        store.add_block(root, stager.stage(&block), slot, parent);
        for index in 0..COLUMNS {
            store.add_data_column(root, index, stager.stage(&column), slot, false);
        }
        objects += 1 + COLUMNS;
        bytes += (block.len() + COLUMNS as usize * column.len()) as u64;

        let finalized = (slot % SLOTS_PER_EPOCH == 0 && slot > 2 * SLOTS_PER_EPOCH)
            .then(|| slot - 2 * SLOTS_PER_EPOCH);
        let (finalized_slot, finalized_root) =
            finalized.map_or((store.head.finalized_slot, store.head.finalized_root), |f| {
                objects += SLOTS_PER_EPOCH * (1 + COLUMNS);
                (f, roots[f as usize])
            });
        store.update_head(slot, root, PayloadResolution::Full, finalized_slot, finalized_root);
        drain(store, &mut producer, &mut sample);
        stager.release();
    }
    sample.report("W1 follow tip (writes + promotions)", objects, bytes);
}

fn by_range_requests(store: &mut Store, first_slot: u64, peers: usize) {
    let mut unused = Stager::new("bench_requests");
    for peer in 0..peers {
        let start = first_slot + (peer as u64 * 8) % (2 * SLOTS_PER_EPOCH);
        let mut blocks = [0u8; 24];
        blocks[0..8].copy_from_slice(&start.to_le_bytes());
        blocks[8..16].copy_from_slice(&64u64.to_le_bytes());
        blocks[16..24].copy_from_slice(&1u64.to_le_bytes());
        store.rpc_request(&mut unused.reader, RpcRequestInbound {
            stream_id: P2pStreamId::new(peer, 1, StreamProtocol::BeaconBlocksByRange, true),
            request: RpcRequest::BlocksByRange(blocks),
        });

        let mut columns = [0u8; DC_BY_RANGE_REQ_MAX];
        columns[0..8].copy_from_slice(&start.to_le_bytes());
        columns[8..16].copy_from_slice(&8u64.to_le_bytes());
        columns[16..20].copy_from_slice(&20u32.to_le_bytes());
        for index in 0..COLUMNS {
            let at = 20 + index as usize * 8;
            columns[at..at + 8].copy_from_slice(&index.to_le_bytes());
        }
        store.rpc_request(&mut unused.reader, RpcRequestInbound {
            stream_id: P2pStreamId::new(peer, 2, StreamProtocol::DataColumnSidecarsByRange, true),
            request: RpcRequest::DataColumnsByRange { ssz: columns, len: DC_BY_RANGE_REQ_MAX },
        });
    }
}

fn serve(name: &str, store: &mut Store, peers: usize) {
    by_range_requests(store, 1, peers);
    let units: usize = store.query_queue.iter().map(|q| q.units.len()).sum();
    let mut producer = served_producer();
    let mut sample = Sample::start();
    while !store.query_queue.is_empty() || store.reader.in_flight() > 0 {
        producer.loop_start();
        sample.file_io(store, &mut producer);
    }
    sample.report(name, units as u64, 0);
}

fn walk_files(dir: &Path, visit: &mut impl FnMut(&Path)) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk_files(&path, visit);
        } else {
            visit(&path);
        }
    }
}

/// Evicts the store's data pages. Dentries and inodes stay cached: dropping
/// those needs root.
fn evict_page_cache(store_dir: &str) {
    unsafe { libc::sync() };
    walk_files(Path::new(store_dir), &mut |path| {
        let file = std::fs::File::open(path).unwrap();
        assert_eq!(
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) },
            0
        );
    });
}

#[test]
#[ignore = "manual benchmark; writes GiBs to SILVER_BENCH_DIR"]
fn storage_bench_follow_and_serve() {
    let epochs = env_u64("SILVER_BENCH_EPOCHS", 4);
    let blobs = env_u64("SILVER_BENCH_BLOBS", 21) as usize;
    let dir = bench_dir();
    let store_dir = dir.path().to_str().unwrap().to_owned();
    let mut store = Store::load(store_dir.clone(), super::test_spec(u64::MAX), u128::MAX).unwrap();
    println!("column sidecar {} bytes, {epochs} epochs", column_sidecar_len(blobs));

    follow_tip(&mut store, epochs, blobs);
    serve("W3 serve by-range, warm (units)", &mut store, 16);
    evict_page_cache(&store_dir);
    serve("W4 serve by-range, cold data pages (units)", &mut store, 16);
}

/// Finalized column history arriving faster than it can be written.
#[test]
#[ignore = "manual benchmark; writes GiBs to SILVER_BENCH_DIR"]
fn storage_bench_backfill_columns() {
    let slots = env_u64("SILVER_BENCH_EPOCHS", 4) * SLOTS_PER_EPOCH;
    let blobs = env_u64("SILVER_BENCH_BLOBS", 21) as usize;
    let dir = bench_dir();
    let mut store =
        Store::load(dir.path().to_str().unwrap().to_owned(), super::test_spec(u64::MAX), u128::MAX)
            .unwrap();
    store.sync_update(SyncUpdate::Following);
    store.update_head(1 << 20, [1; 32], PayloadResolution::Full, 1 << 20, [1; 32]);
    let mut producer = served_producer();
    let mut sample = Sample::start();
    drain(&mut store, &mut producer, &mut sample);

    let column = vec![0x5au8; column_sidecar_len(blobs)];
    let mut stager = Stager::new("bench_backfill");
    let mut sample = Sample::start();
    for slot in (1 << 19)..(1 << 19) + slots {
        for index in 0..COLUMNS {
            store.add_data_column(
                [2; 32],
                index,
                stager.stage(&column),
                slot,
                index + 1 == COLUMNS,
            );
        }
        drain(&mut store, &mut producer, &mut sample);
        stager.release();
    }
    sample.report("W2 backfill columns", slots * COLUMNS, slots * COLUMNS * column.len() as u64);
}

/// Retained groups beside the removed one: block history on mainnet keeps
/// about this many, and every truncation lists them.
const RETAINED_GROUPS: u64 = 8192;

/// One retention step that drops a full group of finalized columns.
#[test]
#[ignore = "manual benchmark; writes GiBs to SILVER_BENCH_DIR"]
fn storage_bench_truncate_column_group() {
    let blobs = env_u64("SILVER_BENCH_BLOBS", 21) as usize;
    let dir = bench_dir();
    let store_dir = dir.path().to_str().unwrap().to_owned();
    let mut store = Store::load(store_dir.clone(), super::test_spec(u64::MAX), u128::MAX).unwrap();
    let column = vec![0x5au8; column_sidecar_len(blobs)];
    for slot in 0..SLOTS_PER_DIR {
        for index in 0..COLUMNS {
            let path = column_path(&store_dir, slot, index);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, &column).unwrap();
        }
    }
    for group in 1..=RETAINED_GROUPS {
        std::fs::create_dir(super::slot_dir(&store_dir, Payload::Column, group * SLOTS_PER_DIR))
            .unwrap();
    }
    unsafe { libc::sync() };

    // The first truncation of a run lists every group once; later ones only
    // derive the groups the floor passed. Measure a later one.
    let mut producer = served_producer();
    store.write_queue.push_back(PendingWrite::TruncateHistory {
        payload: Payload::Column,
        finalized_slot: COLUMN_SLOTS_RETAINED,
    });
    let first = Instant::now();
    store.file_io(|_| [0u8; 4], &mut producer, &mut |_| {}).unwrap();
    println!("first truncation of the run (lists {RETAINED_GROUPS} groups): {:?}", first.elapsed());

    let mut sample = Sample::start();
    store.write_queue.push_back(PendingWrite::TruncateHistory {
        payload: Payload::Column,
        finalized_slot: COLUMN_SLOTS_RETAINED + SLOTS_PER_DIR,
    });
    sample.file_io(&mut store, &mut producer);
    while !store.write_queue.is_empty() || !store.remover.is_idle() {
        sample.file_io(&mut store, &mut producer);
    }
    assert!(!super::slot_dir(&store_dir, Payload::Column, 0).exists());
    assert!(super::slot_dir(&store_dir, Payload::Column, SLOTS_PER_DIR).exists());
    sample.report("W5 truncate one column group (files)", SLOTS_PER_DIR * COLUMNS, 0);
}
