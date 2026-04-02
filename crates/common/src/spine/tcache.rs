use std::{
    alloc::{self, Layout},
    array,
    ops::Deref,
    ptr::addr_of,
    slice,
    sync::atomic::{AtomicU64, Ordering},
};

pub use consumer::{Consumer, RandomAccessConsumer, TCacheRead};
pub use producer::{Producer, Reservation};
use thiserror::Error;

const MAGIC: [u8; 3] = [0xEA, 0x51, 0xEE];
const MAX_CONSUMERS: usize = 64;
const ALIGN: usize = size_of::<Slot>();

mod consumer;
mod producer;

/// Single producer, multi consumer cache buffer with a Tail
///
/// _     /)---(\       
/// \\   (/ . . \)    
///  \\__)-\(*)/       
///  \_       (_     
///  (___/-(____) _    
///               
pub struct TCache {
    head: TCacheHead,
    len: u32,
    data: Box<[u8]>,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct TCacheRef {
    cache: *const TCache,
}

unsafe impl Send for TCacheRef {}
unsafe impl Sync for TCacheRef {}

impl Deref for TCacheRef {
    type Target = TCache;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.cache }
    }
}

impl TCacheRef {
    pub fn consumer(&self) -> Result<Consumer, Error> {
        self.deref().consumer()
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
    StaleSeq { seq: u64, tail: u64 },
}

impl TCache {
    pub fn producer(n: usize) -> Producer {
        assert!(n.is_power_of_two() && n.is_multiple_of(ALIGN));
        let layout = Layout::from_size_align(n, ALIGN).unwrap();
        let tcache = unsafe {
            let ptr = alloc::alloc_zeroed(layout);
            if ptr.is_null() {
                alloc::handle_alloc_error(layout);
            }
            let data = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, n));
            Box::new(Self {
                head: TCacheHead {
                    seq: AtomicU64::new(0),
                    tails: array::from_fn(|_| AtomicU64::new(u64::MAX)),
                },
                len: data.len() as u32,
                data,
            })
        };
        let space = tcache.len;
        Producer { cache: Box::into_raw(tcache), seq: 0, space }
    }

    pub fn consumer(&self) -> Result<Consumer, Error> {
        // find start seq
        let seq = self.head.seq.load(Ordering::Acquire);

        let index = self
            .head
            .tails
            .iter()
            .position(|t| {
                t.compare_exchange(u64::MAX, seq, Ordering::Release, Ordering::Relaxed).is_ok()
            })
            .ok_or(Error::MaxConsumers)?;

        Ok(Consumer { cache: TCacheRef { cache: addr_of!(*self) }, index, seq, next_seq: seq })
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
        for tail in &self.head.tails {
            min = min.min(tail.load(Ordering::Acquire));
        }
        min
    }

    fn read(&self, seq: u64) -> Result<(&[u8], u64), Error> {
        let idx = self.index(seq);
        let slot: &Slot = (&self.data[idx..]).into();
        if slot.magic != MAGIC {
            return Err(Error::NoMagic);
        }

        let slot_seq = slot.seq.load(Ordering::Acquire);
        if slot_seq != seq {
            return Err(Error::WrongSeq { expected: seq, slot: slot_seq });
        }
        if slot.skip != 0 {
            return Ok((&[], slot.reservation_len as u64));
        }

        Ok((&self.data[slot.data_start..slot.data_end], slot.reservation_len as u64))
    }

    fn reserve(&self, producer: &mut Producer, len: u32) -> Option<(u64, usize)> {
        let mut data_len = len as usize + size_of::<Slot>();

        let reserve_seq = producer.seq;
        let idx = self.index(reserve_seq);

        let data_offset = if idx + data_len > self.len as usize {
            // would wrap, allocate at start of buffer to return contiguous slice
            let offset = self.len as usize - idx;
            data_len += offset;
            offset
        } else {
            size_of::<Slot>()
        };

        // Aligned so that contiguous `size_of::<Slot>()` always available
        let reserve_len = align::<ALIGN>(data_len);

        (producer.space >= reserve_len as u32).then(|| {
            let start = self.index((idx + data_offset) as u64);
            let end = start + len as usize;

            let slot: &mut Slot = unsafe {
                let mut_ptr = self.data[idx..idx + size_of::<Slot>()].as_ptr() as *mut u8;
                slice::from_raw_parts_mut(mut_ptr, size_of::<Slot>()).into()
            };

            slot.seq = AtomicU64::new(u64::MAX);
            slot.reservation_len = reserve_len as u32;
            slot.data_start = start;
            slot.data_end = end;
            slot.skip = 1;
            slot.magic = MAGIC;

            (reserve_seq, reserve_len)
        })
    }

    /// SAFETY: This must only calleded by a single `Reservation` owner for a
    /// given `seq`.
    #[allow(clippy::mut_from_ref)]
    fn write(&self, seq: u64) -> Result<&mut [u8], Error> {
        let idx = self.index(seq);
        let slot: &Slot = (&self.data[idx..]).into();
        if slot.magic != MAGIC {
            return Err(Error::NoMagic);
        }

        let slot_seq = slot.seq.load(Ordering::Acquire);
        if slot_seq != u64::MAX {
            return Err(Error::WrongSeq { expected: seq, slot: slot_seq });
        }

        unsafe {
            let mut_ptr = self.data[slot.data_start..slot.data_end].as_ptr() as *mut u8;
            Ok(slice::from_raw_parts_mut(mut_ptr, slot.data_end - slot.data_start))
        }
    }

    fn commit(&self, seq: u64, success: bool) {
        let idx = self.index(seq);

        let slot: &mut Slot = unsafe {
            let mut_ptr = self.data[idx..idx + size_of::<Slot>()].as_ptr() as *mut u8;
            slice::from_raw_parts_mut(mut_ptr, size_of::<Slot>()).into()
        };
        if success {
            slot.skip = 0;
        }
        slot.seq = AtomicU64::new(seq);
    }
}

struct TCacheHead {
    seq: AtomicU64,
    tails: [AtomicU64; MAX_CONSUMERS],
}

#[repr(C)]
struct Slot {
    seq: AtomicU64,
    data_start: usize,
    data_end: usize,
    reservation_len: u32,
    skip: u8,
    magic: [u8; 3],
}

impl Default for Slot {
    fn default() -> Self {
        Self {
            seq: AtomicU64::new(0),
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
    use std::{io::Write, time::Instant};

    use rand::Rng;

    use super::*;

    #[test]
    fn produce_consume() {
        let mut producer = TCache::producer(2 << 14);
        let mut consumer = producer.cache_ref().consumer().unwrap();

        let prod = std::thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut total = 0;
            let start = Instant::now();
            while total < (2 << 32) {
                if let Some(mut buffer) = producer.reserve(rng.gen_range(512..8192)) {
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
                Ok(buf) => {
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
