use std::{
    alloc::{self, Layout},
    array,
    ffi::c_void,
    ops::Deref,
    ptr::addr_of,
    slice,
    sync::atomic::{AtomicU64, Ordering},
};

pub use consumer::{AcquiredRead, Consumer, RandomAccessConsumer, TCacheRead};
use flux::{timing::Nanos, tracing};
pub use producer::{MultiProducer, Producer, Reservation, TCacheProducer};
use thiserror::Error;

use crate::spine::tcache::consumer::Buckets;

const MAGIC: [u8; 3] = [0xEA, 0x51, 0xEE];
const MAX_CONSUMERS: usize = 64;
const ALIGN: usize = size_of::<Slot>();

// TCacheHead (528 B) rounded up to Slot alignment (32 B).
const DATA_OFFSET: usize = const {
    let h = size_of::<TCacheHead>();
    let a = size_of::<Slot>();
    (h + a - 1) & !(a - 1)
};

mod consumer;
mod metrics;
mod producer;

use metrics::TCacheMetrics;

/// Single or multi producer, multi consumer cache buffer with a Tail
///
/// _     /)---(\
/// \\   (/ . . \)
///  \\__)-\(*)/
///  \_       (_
///  (___/-(____) _
pub struct TCache {
    name: &'static str,
    /// Flat buffer: [TCacheHead | padding | data…]
    /// Aligned to ALIGN. DATA_OFFSET bytes precede the data region.
    ptr: *mut u8,
    /// Data capacity (excludes the header).
    len: u32,
    backing: Backing,
    /// `None` when name is empty, or if mmap'ing the metrics file
    /// fails (tile continues to function without surfer visibility).
    metrics: Option<TCacheMetrics>,
}

unsafe impl Send for TCache {}
unsafe impl Sync for TCache {}

enum Backing {
    Heap {
        layout: Layout,
    },
    #[cfg(unix)]
    Shmem {
        fd: libc::c_int,
        total_len: usize,
        owner: bool,
        name: std::ffi::CString,
    },
}

impl Drop for TCache {
    fn drop(&mut self) {
        match &self.backing {
            Backing::Heap { layout } => unsafe {
                alloc::dealloc(self.ptr, *layout);
            },
            #[cfg(unix)]
            Backing::Shmem { fd, total_len, owner, name } => unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, *total_len);
                libc::close(*fd);
                if *owner {
                    libc::shm_unlink(name.as_ptr());
                }
            },
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TCacheRef {
    // SAFETY: take care when dereferencing
    cache: *const c_void,
}

unsafe impl Send for TCacheRef {}
unsafe impl Sync for TCacheRef {}

impl Deref for TCacheRef {
    type Target = TCache;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.cache as *const TCache) }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("missing magic bytes")]
    NoMagic,
    #[error("invalid seq: {slot}, expected: {expected}")]
    WrongSeq { expected: u64, slot: u64 },
    #[error("too many consumers")]
    MaxConsumers,
    #[error("Unexpected cache ref")]
    UnexpectedCacheRef,
    #[error("stale seq: {seq} < {tail}")]
    StaleSeq { name: &'static str, seq: u64, tail: u64 },
}

impl TCache {
    /// Create a single producer t-cache. `name` is a stable label
    /// (e.g. `"gossip_in"`); the metrics layer uses it to produce
    /// `counters-tcache-{name}`.
    pub fn producer(name: &'static str, n: usize) -> Producer {
        let tcache = Self::alloc_heap(name, n);
        let space = tcache.len;
        Producer { cache: Box::into_raw(tcache), seq: 0, space }
    }

    /// Create a multi-producer t-cache.
    pub fn multi_producer(name: &'static str, n: usize) -> MultiProducer {
        let tcache = Self::alloc_heap(name, n);
        let len = tcache.len;
        MultiProducer::new(Box::into_raw(tcache), len)
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Attach to a named shmem segment as a producer, creating it if needed.
    /// Either side (producer or consumer) may start first. `n` must be
    /// identical on both sides.
    #[cfg(unix)]
    pub fn shm_producer(name: &str, n: usize) -> Producer {
        let tcache = Self::attach_shmem(name, n);
        let space = tcache.len;
        Producer { cache: Box::into_raw(tcache), seq: 0, space }
    }

    /// Attach to a named shmem segment as a random-access consumer, creating
    /// it if needed. Either side (producer or consumer) may start first. `n`
    /// must be identical on both sides.
    #[cfg(unix)]
    pub fn shm_consumer(name: &str, n: usize) -> Result<RandomAccessConsumer, Error> {
        let tcache = Box::into_raw(Self::attach_shmem(name, n));
        // SAFETY: tcache is a valid Box-allocated TCache; we intentionally
        // leak it here (same pattern as producer/multi_producer).
        unsafe { (*tcache).random_access("", true) }
    }

    pub fn consumer(&self, name: &'static str) -> Result<Consumer, Error> {
        let seq = self.head().seq.load(Ordering::Acquire);

        let index = self
            .head()
            .tails
            .iter()
            .position(|t| {
                t.compare_exchange(u64::MAX, seq, Ordering::Release, Ordering::Relaxed).is_ok()
            })
            .ok_or(Error::MaxConsumers)?;

        // Publish a baseline tail so surfer's chart has a value to plot
        // before the consumer has actually called free.
        self.record_tail(index, seq);
        self.record_consumer_name(index, name);

        Ok(Consumer {
            cache: TCacheRef { cache: addr_of!(*self) as *const c_void },
            index,
            seq,
            next_seq: seq,
            timer: self.create_consumer_timer(name),
        })
    }

    pub fn random_access(
        &self,
        name: &'static str,
        auto_free: bool,
    ) -> Result<RandomAccessConsumer, Error> {
        let seq = self.head().seq.load(Ordering::Acquire);

        let index = self
            .head()
            .tails
            .iter()
            .position(|t| {
                t.compare_exchange(u64::MAX, seq, Ordering::Release, Ordering::Relaxed).is_ok()
            })
            .ok_or(Error::MaxConsumers)?;

        tracing::info!(name, index, "new random access consumer with tail seq {seq}");

        self.record_tail(index, seq);
        self.record_consumer_name(index, name);

        Ok(RandomAccessConsumer {
            cache: TCacheRef { cache: addr_of!(*self) as *const c_void },
            index,
            name,
            active: Buckets::new(32 * 1024, self.len as u64),
            auto_free,
            timer: self.create_consumer_timer(name),
        })
    }

    #[inline]
    fn record_consumer_name(&self, idx: usize, name: &'static str) {
        if let Some(m) = &self.metrics {
            m.set_consumer_name(idx, name);
        }
    }

    /// Build a per-consumer flux Timer named
    /// `tcache-{tcache_name}-{consumer_name}`. Result file paths are
    /// `timing-tcache-{tcache_name}-{consumer_name}` and
    /// `latency-tcache-{tcache_name}-{consumer_name}` under flux's
    /// `shmem/queues` directory — surfer picks up the latency queue
    /// via the existing timings discovery.
    ///
    /// Returns `None` when this TCache has no metrics (unnamed or
    /// metrics file open failed) so the consumer's read path is a
    /// no-op for latency.
    fn create_consumer_timer(&self, consumer_name: &'static str) -> Option<flux::Timer> {
        self.metrics.as_ref()?;
        let label = format!("tcache-{}-{}", self.name, consumer_name);
        Some(flux::Timer::new("silver", &label))
    }

    fn index(&self, seq: u64) -> usize {
        (seq & (self.len - 1) as u64) as usize
    }

    fn space(&self, head_seq: u64) -> u32 {
        let min_tail = self.min_tail(head_seq);
        debug_assert!(
            head_seq - min_tail <= self.len as u64,
            "{head_seq} - {min_tail} > {}",
            self.len
        );
        self.len - ((head_seq - min_tail) as u32)
    }

    fn min_tail(&self, seq: u64) -> u64 {
        let mut min = seq;
        for tail in &self.head().tails {
            min = min.min(tail.load(Ordering::Acquire));
        }
        min
    }

    fn read(&self, seq: u64) -> Result<(&[u8], u64, Nanos), Error> {
        let idx = self.index(seq);
        let slot: &Slot = self.slot_at(idx);
        if slot.magic != MAGIC {
            return Err(Error::NoMagic);
        }

        let slot_seq = slot.seq.load(Ordering::Acquire);
        if slot_seq != seq {
            return Err(Error::WrongSeq { expected: seq, slot: slot_seq });
        }
        if slot.skip != 0 {
            return Ok((&[], slot.reservation_len as u64, slot.reserve_ns));
        }

        Ok((
            unsafe {
                slice::from_raw_parts(
                    self.data_ptr().add(slot.data_start as usize),
                    slot.data_end as usize - slot.data_start as usize,
                )
            },
            slot.reservation_len as u64,
            slot.reserve_ns,
        ))
    }

    fn slot_ts(&self, seq: u64) -> Result<Nanos, Error> {
        let idx = self.index(seq);
        let slot: &Slot = self.slot_at(idx);
        if slot.magic != MAGIC {
            return Err(Error::NoMagic);
        }

        let slot_seq = slot.seq.load(Ordering::Acquire);
        if slot_seq != seq {
            return Err(Error::WrongSeq { expected: seq, slot: slot_seq });
        }
        Ok(slot.reserve_ns)
    }

    fn reserve_len(&self, seq: u64, requested_len: usize) -> usize {
        let mut data_len = requested_len + size_of::<Slot>();

        let idx = self.index(seq);

        if idx + data_len > self.len as usize {
            let offset = self.len as usize - idx;
            data_len += offset;
        }

        align::<ALIGN>(data_len)
    }

    fn reserve(&self, seq: u64, space: u32, len: u32) -> Option<(u64, usize)> {
        let mut data_len = len as usize + size_of::<Slot>();

        let reserve_seq = seq;
        let idx = self.index(reserve_seq);

        let data_offset = if idx + data_len > self.len as usize {
            let offset = self.len as usize - idx;
            data_len += offset;
            offset
        } else {
            size_of::<Slot>()
        };

        let reserve_len = align::<ALIGN>(data_len);

        (space >= reserve_len as u32).then(|| {
            let start = self.index((idx + data_offset) as u64);
            let end = start + len as usize;

            let slot: &mut Slot = unsafe {
                let mut_ptr = self.data_ptr().add(idx);
                slice::from_raw_parts_mut(mut_ptr, size_of::<Slot>()).into()
            };

            slot.seq = AtomicU64::new(u64::MAX);
            slot.reservation_len = reserve_len as u32;
            slot.reserve_ns = Nanos::now();
            slot.data_start = start as u32;
            slot.data_end = end as u32;
            slot.skip = 1;
            slot.magic = MAGIC;

            (reserve_seq, reserve_len)
        })
    }

    /// SAFETY: This must only be called by a single `Reservation` owner for a
    /// given `seq`.
    #[allow(clippy::mut_from_ref)]
    fn write(&self, seq: u64) -> Result<&mut [u8], Error> {
        let idx = self.index(seq);
        let slot: &Slot = self.slot_at(idx);
        if slot.magic != MAGIC {
            return Err(Error::NoMagic);
        }

        let slot_seq = slot.seq.load(Ordering::Acquire);
        if slot_seq != u64::MAX {
            return Err(Error::WrongSeq { expected: seq, slot: slot_seq });
        }

        unsafe {
            let ptr = self.data_ptr().add(slot.data_start as usize);
            Ok(slice::from_raw_parts_mut(ptr, slot.data_end as usize - slot.data_start as usize))
        }
    }

    fn commit(&self, seq: u64, success: bool) {
        let idx = self.index(seq);

        let slot: &mut Slot = unsafe {
            let mut_ptr = self.data_ptr().add(idx);
            slice::from_raw_parts_mut(mut_ptr, size_of::<Slot>()).into()
        };
        if success {
            slot.skip = 0;
        }
        let new_head = seq + slot.reservation_len as u64;
        slot.seq = AtomicU64::new(seq);
        // Track the producer's actual progress for the metrics layer.
        // `head.seq` (visible to joining consumers) is only updated by
        // `publish_head` on out-of-space, but surfer wants the live
        // production cursor.
        self.record_head(new_head);
    }

    // --- backing accessors ---

    #[inline]
    pub(super) fn head(&self) -> &TCacheHead {
        // SAFETY: ptr is always valid and aligned; TCacheHead is at offset 0.
        unsafe { &*(self.ptr as *const TCacheHead) }
    }

    #[inline]
    fn data_ptr(&self) -> *mut u8 {
        // SAFETY: ptr + DATA_OFFSET is within the allocated buffer.
        unsafe { self.ptr.add(DATA_OFFSET) }
    }

    #[inline]
    fn slot_at(&self, idx: usize) -> &Slot {
        unsafe {
            let ptr = self.data_ptr().add(idx);
            &*(slice::from_raw_parts(ptr, size_of::<Slot>()).as_ptr() as *const Slot)
        }
    }

    // --- allocators ---

    fn alloc_heap(name: &'static str, size: usize) -> Box<Self> {
        assert!(
            size.is_power_of_two() && size.is_multiple_of(ALIGN),
            "n must be a power-of-two multiple of {ALIGN}"
        );
        let total = DATA_OFFSET + size;
        let layout = Layout::from_size_align(total, ALIGN).unwrap();
        let metrics = if name.is_empty() {
            None
        } else {
            TCacheMetrics::new(name, MAX_CONSUMERS, size as u64)
                .map_err(|e| tracing::warn!(?name, ?e, "TCacheMetrics::new failed"))
                .ok()
        };
        let ptr = unsafe {
            let p = alloc::alloc_zeroed(layout);
            if p.is_null() {
                alloc::handle_alloc_error(layout);
            }
            p
        };
        Self::init_head(ptr);
        Box::new(Self { name, ptr, len: size as u32, backing: Backing::Heap { layout }, metrics })
    }

    /// Attach to a named shmem segment, creating it if it doesn't exist yet.
    /// Safe to call from multiple processes concurrently: `O_CREAT | O_EXCL`
    /// is the atomic gate — exactly one caller becomes the creator (sizes +
    /// inits the segment), all others wait until it is ready.
    ///
    /// Readiness is signalled by `ready == u64::MAX`, set as the last
    /// store in `init_head`.
    #[cfg(unix)]
    fn attach_shmem(name: &str, size: usize) -> Box<Self> {
        use std::ffi::CString;
        assert!(
            size.is_power_of_two() && size.is_multiple_of(ALIGN),
            "n must be a power-of-two multiple of {ALIGN}"
        );
        let total = DATA_OFFSET + size;
        let cname = CString::new(name).expect("shmem name must not contain null bytes");

        // Race to create. Exactly one caller wins O_EXCL; losers open existing.
        let fd = unsafe {
            libc::shm_open(cname.as_ptr(), libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600)
        };

        if fd >= 0 {
            // Creator: size the segment, map it, init.
            // On any failure, unlink so joiners don't spin forever on a zombie segment.
            struct Cleanup(i32, *const libc::c_char);
            impl Drop for Cleanup {
                fn drop(&mut self) {
                    unsafe { libc::shm_unlink(self.1) };
                    unsafe { libc::close(self.0) };
                }
            }
            let cleanup = Cleanup(fd, cname.as_ptr());

            let rc = unsafe { libc::ftruncate(fd, total as libc::off_t) };
            assert_eq!(rc, 0, "ftruncate({name}): {}", std::io::Error::last_os_error());

            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    total,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            assert_ne!(ptr, libc::MAP_FAILED, "mmap({name}): {}", std::io::Error::last_os_error());

            let ptr = ptr as *mut u8;
            // Sets ready = u64::MAX as the last store (release) in init_head.
            Self::init_head(ptr);
            std::mem::forget(cleanup); // init complete, segment is valid
            Box::new(Self {
                name: "",
                ptr,
                len: size as u32,
                backing: Backing::Shmem { fd, total_len: total, owner: true, name: cname },
                metrics: None,
            })
        } else {
            // Joiner: open existing, wait for creator to finish sizing + init.
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EEXIST),
                "shm_open({name}): {}",
                std::io::Error::last_os_error(),
            );

            let fd = loop {
                let fd = unsafe { libc::shm_open(cname.as_ptr(), libc::O_RDWR, 0) };
                if fd >= 0 {
                    break fd;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            };

            // Wait for ftruncate.
            loop {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                unsafe { libc::fstat(fd, &mut st) };
                if st.st_size as usize >= total {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(1));
            }

            let ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    total,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    fd,
                    0,
                )
            };
            assert_ne!(ptr, libc::MAP_FAILED, "mmap({name}): {}", std::io::Error::last_os_error());

            // Wait for init_head (acquire load pairs with creator's release store on
            // ready).
            let head = unsafe { &*(ptr as *const TCacheHead) };
            while head.ready.load(Ordering::Acquire) != u64::MAX {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }

            Box::new(Self {
                name: "",
                ptr: ptr as *mut u8,
                len: size as u32,
                backing: Backing::Shmem { fd, total_len: total, owner: false, name: cname },
                metrics: None,
            })
        }
    }

    fn init_head(ptr: *mut u8) {
        // SAFETY: ptr is freshly allocated/mapped with at least DATA_OFFSET bytes.
        unsafe {
            let head = &mut *(ptr as *mut TCacheHead);
            head.seq = AtomicU64::new(0);
            head.tails = array::from_fn(|_| AtomicU64::new(u64::MAX));
            // Release store — pairs with the joiner's acquire load on ready.
            head.ready.store(u64::MAX, Ordering::Release);
        }
    }

    #[inline]
    pub(super) fn record_head(&self, seq: u64) {
        if let Some(m) = &self.metrics {
            m.set_head_seq(seq);
        }
    }

    /// Record a consumer's tail seq into the per-tcache metrics slot.
    /// A seq of 0 is interpreted as "no real progress" and is mapped
    /// to the `u64::MAX` sentinel — surfer then treats it as
    /// "tail == head" rather than dragging `min_tail` to 0. The
    /// in-memory `head.tails[idx]` is unaffected; this is purely the
    /// metrics view.
    #[inline]
    pub(super) fn record_tail(&self, idx: usize, seq: u64) {
        if let Some(m) = &self.metrics {
            let v = if seq == 0 { u64::MAX } else { seq };
            m.set_tail_seq(idx, v);
        }
    }
}

#[repr(C)]
pub(super) struct TCacheHead {
    seq: AtomicU64,
    tails: [AtomicU64; MAX_CONSUMERS],
    /// Written last in init_head as the readiness signal; never modified after
    /// init.
    ready: AtomicU64,
}

#[repr(C)]
struct Slot {
    seq: AtomicU64,
    reserve_ns: Nanos,
    data_start: u32,
    data_end: u32,
    reservation_len: u32,
    skip: u8,
    magic: [u8; 3],
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            seq: AtomicU64::new(0),
            reserve_ns: Nanos::now(),
            data_start: 0,
            data_end: 0,
            reservation_len: 0,
            skip: 0,
            magic: MAGIC,
        }
    }
}

impl Clone for Slot {
    fn clone(&self) -> Self {
        Self {
            seq: AtomicU64::new(self.seq.load(Ordering::Relaxed)),
            data_start: self.data_start,
            data_end: self.data_end,
            reserve_ns: self.reserve_ns,
            reservation_len: self.reservation_len,
            skip: self.skip,
            magic: MAGIC,
        }
    }
}

impl AsRef<[u8]> for Slot {
    fn as_ref(&self) -> &[u8] {
        let ptr = addr_of!(*self) as *const u8;
        unsafe { slice::from_raw_parts(ptr, size_of::<Slot>()) }
    }
}

impl From<&[u8]> for &Slot {
    fn from(value: &[u8]) -> Self {
        let slot = value.as_ptr() as *const Slot;
        unsafe { &*slot }
    }
}

impl From<&mut [u8]> for &mut Slot {
    fn from(value: &mut [u8]) -> Self {
        let slot = value.as_mut_ptr() as *mut Slot;
        unsafe { &mut *slot }
    }
}

#[inline]
fn align<const A: usize>(val: usize) -> usize {
    debug_assert!(A.is_power_of_two());
    let d = val & (A - 1);
    if d == 0 { val } else { val + A - d }
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering as AOrdering},
        },
        thread,
        time::{Duration, Instant},
    };

    use rand::Rng;

    use super::*;
    use crate::spine::tcache::producer::TCacheProducer;

    // ---- multi-producer / multi-consumer integrity helpers ----

    /// 12-byte header on every test message: [producer_id u32 LE]
    /// [seq_in_producer u32 LE] [checksum u32 LE]. Followed by random
    /// payload bytes. Lets each consumer verify per-producer monotonic
    /// ordering and detect torn writes.
    const HEADER_LEN: usize = 12;

    fn checksum(buf: &[u8]) -> u32 {
        // Cheap deterministic 32-bit hash. Multiplicative + LCG-ish; good
        // enough to catch any non-trivial corruption (not a security
        // primitive).
        let mut h: u32 = 0x12345678;
        for &b in buf {
            h = h.wrapping_mul(31).wrapping_add(b as u32);
        }
        h
    }

    /// Read all available messages from `consumer` until `done` is signalled
    /// AND no more readable bytes remain at our seq. Returns
    /// (per-producer-count, per-producer-max-seq, total bytes consumed).
    /// Asserts checksum integrity + per-producer monotonic seq inline.
    fn drain_consumer(
        consumer: &mut Consumer,
        done: &AtomicBool,
        producers: usize,
    ) -> (Vec<u32>, Vec<u32>, usize) {
        let mut count = vec![0u32; producers];
        let mut max_seq = vec![0u32; producers];
        let mut have_seen = vec![false; producers];
        let mut total_bytes = 0usize;
        let deadline = Instant::now() + Duration::from_secs(30);

        loop {
            match consumer.read() {
                Ok((buf, _)) => {
                    if !buf.is_empty() {
                        assert!(
                            buf.len() >= HEADER_LEN,
                            "msg shorter than header ({} < {HEADER_LEN})",
                            buf.len()
                        );
                        let pid = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
                        let seq = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                        let csum = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                        let payload = &buf[HEADER_LEN..];
                        assert!(pid < producers, "producer_id {pid} out of range");
                        assert_eq!(
                            checksum(payload),
                            csum,
                            "checksum mismatch p={pid} seq={seq} payload_len={}",
                            payload.len()
                        );
                        if have_seen[pid] {
                            assert!(
                                max_seq[pid] < seq,
                                "non-monotonic per-producer: p={pid} prev={} cur={seq}",
                                max_seq[pid]
                            );
                        }
                        have_seen[pid] = true;
                        max_seq[pid] = seq;
                        count[pid] += 1;
                        total_bytes += buf.len();
                    }
                    consumer.free();
                }
                Err(_) => {
                    // No data ready. If producers are done and no further
                    // bytes will arrive, exit; otherwise yield + retry.
                    if done.load(AOrdering::Acquire) {
                        // One more drain pass then bail — producers may
                        // have committed bytes after we last polled.
                        let mut empty_polls = 0;
                        while empty_polls < 64 {
                            match consumer.read() {
                                Ok((buf, _)) if !buf.is_empty() => {
                                    let pid =
                                        u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
                                    let seq = u32::from_le_bytes(buf[4..8].try_into().unwrap());
                                    let csum = u32::from_le_bytes(buf[8..12].try_into().unwrap());
                                    let payload = &buf[HEADER_LEN..];
                                    assert_eq!(checksum(payload), csum);
                                    if have_seen[pid] {
                                        assert!(max_seq[pid] < seq);
                                    }
                                    have_seen[pid] = true;
                                    max_seq[pid] = seq;
                                    count[pid] += 1;
                                    total_bytes += buf.len();
                                    empty_polls = 0;
                                }
                                Ok(_) => {
                                    empty_polls += 1;
                                }
                                Err(_) => {
                                    empty_polls += 1;
                                    thread::yield_now();
                                }
                            }
                            consumer.free();
                        }
                        return (count, max_seq, total_bytes);
                    }
                    if Instant::now() > deadline {
                        panic!("consumer deadline exceeded; counts so far: {:?}", count);
                    }
                    thread::yield_now();
                }
            }
        }
    }

    fn drive_producer<F>(
        msgs_per_producer: u32,
        producer_id: u32,
        rng_seed: u64,
        mut reserve_one: F,
    ) -> usize
    where
        F: FnMut(usize, bool) -> Reservation,
    {
        use rand::{SeedableRng, rngs::StdRng};
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let mut total = 0usize;

        for seq_in_p in 0..msgs_per_producer {
            // Payload length chosen to mix small + slot-spanning sizes.
            // Picking 64..=1024 ensures no single request exceeds the
            // 4 KB tcache used in the multi-producer wrap test, while
            // total writes (4 producers * 4096 msgs * ~544B avg ≈ 8 MB)
            // are well above the buffer size → buffer wraps many times.
            let payload_len = rng.gen_range(64..=1024);
            let total_len = HEADER_LEN + payload_len;

            let mut reservation = reserve_one(total_len, true);

            // Build the message in-place inside a scoped borrow so the
            // mutable slice ref drops before we call increment_offset.
            {
                let buf = reservation.buffer().expect("reservation buffer");
                buf[0..4].copy_from_slice(&producer_id.to_le_bytes());
                buf[4..8].copy_from_slice(&seq_in_p.to_le_bytes());
                // Random payload first so we can checksum it before
                // writing the header's checksum slot.
                for b in &mut buf[HEADER_LEN..] {
                    *b = rng.r#gen::<u8>();
                }
                let csum = checksum(&buf[HEADER_LEN..]);
                buf[8..12].copy_from_slice(&csum.to_le_bytes());
            }
            reservation.increment_offset(total_len);
            total += total_len;
        }
        total
    }

    /// Single producer + multiple consumers + buffer wrapping. Establishes
    /// the test machinery (header / checksum / drain) on the simple-path
    /// `Producer` so failures in the multi-producer test are unambiguously
    /// `MultiProducer`-specific.
    #[test]
    fn single_producer_multi_consumer_wraps_buffer() {
        const TCACHE_SIZE: usize = 1 << 14; // 16 KB — small enough to wrap many times
        const CONSUMERS: usize = 4;
        const MSGS: u32 = 4096;

        let mut producer = TCache::producer("test_tcache", TCACHE_SIZE);
        let mut consumers: Vec<Consumer> =
            (0..CONSUMERS).map(|_| producer.cache_ref().consumer("test").unwrap()).collect();

        let done = Arc::new(AtomicBool::new(false));

        let consumer_threads: Vec<_> = consumers
            .drain(..)
            .enumerate()
            .map(|(i, mut c)| {
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    let r = drain_consumer(&mut c, &done, 1);
                    (i, r)
                })
            })
            .collect();

        let total_written = drive_producer(MSGS, 0, 0xC0FFEE, |len, ac| {
            // Block-wait for space; the existing Producer returns None when
            // the ring is full, signal of slow consumer.
            loop {
                if let Some(r) = producer.reserve(len, ac) {
                    return r;
                }
                thread::yield_now();
            }
        });
        producer.publish_head();
        done.store(true, AOrdering::Release);

        for h in consumer_threads {
            let (i, (count, max_seq, total)) = h.join().unwrap();
            assert_eq!(count[0], MSGS, "consumer {i}: expected {MSGS} msgs, got {}", count[0]);
            assert_eq!(max_seq[0], MSGS - 1);
            assert_eq!(total, total_written, "consumer {i}: byte total mismatch");
        }
    }

    /// `MultiProducer`: N producer threads cloning a shared multi-producer,
    /// M consumer threads, buffer sized small enough to force many wraps.
    /// Verifies:
    ///   - Each consumer sees every message from every producer.
    ///   - Per-producer messages arrive in monotonic order.
    ///   - Payload checksums survive concurrent writes (no torn slots).
    ///   - Total bytes seen per consumer == total bytes written across all
    ///     producers.
    #[test]
    fn multi_producer_multi_consumer_wraps_buffer() {
        const TCACHE_SIZE: usize = 1 << 14; // 16 KB — small to force wraps
        const PRODUCERS: u32 = 4;
        const CONSUMERS: usize = 4;
        const MSGS_PER_PRODUCER: u32 = 4096;

        let mp = TCache::multi_producer("test_mp", TCACHE_SIZE);
        let mut consumers: Vec<Consumer> =
            (0..CONSUMERS).map(|_| mp.cache_ref().consumer("test").unwrap()).collect();

        // Spawn consumers BEFORE producers so they observe the full stream
        // from seq 0 and don't miss early commits.
        let done = Arc::new(AtomicBool::new(false));
        let consumer_threads: Vec<_> = consumers
            .drain(..)
            .enumerate()
            .map(|(i, mut c)| {
                let done = Arc::clone(&done);
                thread::spawn(move || {
                    let r = drain_consumer(&mut c, &done, PRODUCERS as usize);
                    (i, r)
                })
            })
            .collect();

        // Spawn producer threads, each with its own clone of the
        // MultiProducer (Arc<Seqlock<...>>-backed; multiple writers
        // coordinate seq+space).
        let producer_threads: Vec<_> = (0..PRODUCERS)
            .map(|p| {
                let mut mp_clone = mp.clone();
                thread::spawn(move || {
                    drive_producer(MSGS_PER_PRODUCER, p, 0xC0FFEE ^ (p as u64), |len, ac| {
                        loop {
                            if let Some(r) = mp_clone.reserve(len, ac) {
                                return r;
                            }
                            thread::yield_now();
                        }
                    })
                })
            })
            .collect();

        let total_written: usize = producer_threads.into_iter().map(|h| h.join().unwrap()).sum();
        mp.publish_head();
        done.store(true, AOrdering::Release);

        for h in consumer_threads {
            let (i, (count, max_seq, total)) = h.join().unwrap();
            for p in 0..PRODUCERS as usize {
                assert_eq!(
                    count[p], MSGS_PER_PRODUCER,
                    "consumer {i}: producer {p} count {} != {MSGS_PER_PRODUCER}",
                    count[p]
                );
                assert_eq!(
                    max_seq[p],
                    MSGS_PER_PRODUCER - 1,
                    "consumer {i}: producer {p} max_seq {}",
                    max_seq[p]
                );
            }
            assert_eq!(total, total_written, "consumer {i}: byte total mismatch");
        }
    }

    #[test]
    fn produce_consume() {
        let mut producer = TCache::producer("test_buckets", 2 << 14);
        let mut consumer = producer.cache_ref().consumer("test").unwrap();

        let prod = std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut total = 0;
            let start = Instant::now();
            while total < (2 << 32) {
                if let Some(mut buffer) = producer.reserve(rng.gen_range(512..8192), true) {
                    let remaining = buffer.remaining().unwrap();
                    total += remaining;
                    buffer.flush().unwrap();
                    //println!("wrote: {remaining} / {total} {buffer:?}");
                }
                std::thread::yield_now();
            }
            println!("production latency: {:?}", start.elapsed());
            total
        });

        let mut total = consumer.seq as usize;
        while total < (2 << 32) {
            match consumer.read() {
                Ok((buf, _)) => {
                    total += buf.len();
                    //println!("Read: {} / {total} @ {seq_was}", buf.len());
                    assert!(buf.len() > 0);
                }
                _ => {}
            }
            consumer.free();
        }

        let prod_total = prod.join().unwrap();
        assert_eq!(prod_total, total);
    }
}
