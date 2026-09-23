use std::sync::atomic::Ordering;

use super::{AcquiredRead, Error, RandomAccessConsumer, TCacheId, TCacheRead, TCacheRef};

#[derive(Copy, Clone, Default)]
pub struct TCacheTable([Option<TCacheRef>; TCacheId::COUNT]);

impl TCacheTable {
    pub fn set(&mut self, cache: TCacheRef) {
        self.0[cache.id() as usize] = Some(cache);
    }

    pub fn get(&self, id: TCacheId) -> Result<TCacheRef, Error> {
        self.0[id as usize].ok_or(Error::Unregistered(id))
    }
}

impl FromIterator<TCacheRef> for TCacheTable {
    fn from_iter<I: IntoIterator<Item = TCacheRef>>(caches: I) -> Self {
        let mut table = Self::default();
        caches.into_iter().for_each(|cache| table.set(cache));
        table
    }
}

#[derive(Copy, Clone, Debug)]
pub enum ReadMode {
    Sliding,
    /// Tail published only on explicit `free`, not on every read drop.
    SlidingManualFree,
    /// Never force-reset on idle, so a stalled consumer blocks the producer.
    /// Only for high-throughput consumers.
    Strict,
    /// Strict, with a fixed retention boundary moved by `advance_retention`.
    Retained,
}

/// The only way to read a TCache: one consumer per id, routed by
/// `TCacheRead::id`. Consumers live inline and `AcquiredRead` points at them,
/// so the reader must not move while reads are held (box it if it must).
pub struct TCacheReader {
    tcaches: TCacheTable,
    consumers: [Option<RandomAccessConsumer>; TCacheId::COUNT],
}

impl TCacheReader {
    pub fn new(tcaches: TCacheTable) -> Self {
        Self { tcaches, consumers: [const { None }; TCacheId::COUNT] }
    }

    /// A reader over one cache, opened.
    pub fn single(cache: TCacheRef, name: &'static str, mode: ReadMode) -> Result<Self, Error> {
        let mut reader = Self::new(TCacheTable::from_iter([cache]));
        reader.open(cache.id(), name, mode)?;
        Ok(reader)
    }

    /// The tail is claimed one ring behind the published head, so everything
    /// still in the ring at open stays readable; before the first wrap that
    /// is seq 0. The producer blocks until this consumer's first free if its
    /// unpublished progress puts the head further ahead than that.
    pub fn open(&mut self, id: TCacheId, name: &'static str, mode: ReadMode) -> Result<(), Error> {
        let cache = self.tcaches.get(id)?;
        let slot = &mut self.consumers[id as usize];
        assert!(slot.is_none(), "{name}: {id:?} already open");
        let head = cache.head().seq.load(Ordering::Acquire);
        let tail = head.saturating_sub(cache.capacity() as u64);
        let consumer = match mode {
            ReadMode::Sliding => cache.ra_consumer_from(tail, name, true, false)?,
            ReadMode::SlidingManualFree => cache.ra_consumer_from(tail, name, false, false)?,
            ReadMode::Strict => cache.ra_consumer_from(tail, name, true, true)?,
            ReadMode::Retained => {
                let mut consumer = cache.ra_consumer_from(tail, name, true, true)?;
                consumer.retain();
                consumer
            }
        };
        *slot = Some(consumer);
        Ok(())
    }

    pub fn is_open(&self, id: TCacheId) -> bool {
        self.consumers[id as usize].is_some()
    }

    pub fn close(&mut self, id: TCacheId) {
        self.consumers[id as usize] = None;
    }

    #[inline]
    pub(super) fn get(&mut self, id: TCacheId) -> Option<&mut RandomAccessConsumer> {
        self.consumers[id as usize].as_mut()
    }

    #[inline]
    pub(super) fn consumer(&mut self, id: TCacheId) -> &mut RandomAccessConsumer {
        self.get(id).unwrap_or_else(|| panic!("tcache {id:?} not open"))
    }

    /// False when `id` is not open.
    pub fn is_strict(&self, id: TCacheId) -> bool {
        self.consumers[id as usize].as_ref().is_some_and(RandomAccessConsumer::is_strict)
    }

    /// False when `id` is not open.
    pub fn is_retained(&self, id: TCacheId) -> bool {
        self.consumers[id as usize].as_ref().is_some_and(RandomAccessConsumer::is_retained)
    }

    pub fn advance_retention(&mut self, id: TCacheId, seq: u64) {
        self.consumer(id).advance_retention(seq);
    }

    #[cfg(test)]
    pub(super) fn active_count(&self, id: TCacheId) -> usize {
        self.consumers[id as usize].as_ref().map_or(0, RandomAccessConsumer::active_count)
    }

    #[inline]
    pub fn acquire(&mut self, read: TCacheRead) -> AcquiredRead {
        self.consumer(read.id).acquire(read)
    }

    #[inline]
    pub fn acquire_strict(&mut self, read: TCacheRead) -> Option<AcquiredRead> {
        self.consumer(read.id).acquire_strict(read)
    }

    pub fn table(&self) -> &TCacheTable {
        &self.tcaches
    }

    pub fn free(&mut self) {
        for consumer in self.consumers.iter_mut().flatten() {
            consumer.free();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spine::tcache::{PRODUCER_EMITTER, TCache, TCacheProducer};

    fn write(producer: &mut impl TCacheProducer, bytes: &[u8]) -> TCacheRead {
        let mut reservation = producer.reserve(bytes.len(), true).unwrap();
        let read = reservation.read();
        reservation.buffer().unwrap().copy_from_slice(bytes);
        reservation.increment_offset(bytes.len());
        read
    }

    #[test]
    fn routes_by_id_and_reads_before_open() {
        let mut gossip = TCache::producer(TCacheId::ControlProcessing, 1 << 16);
        let mut rpc = TCache::producer(TCacheId::NetworkProcessing, 1 << 16);
        let early = write(&mut gossip, b"early");

        let table = TCacheTable::from_iter([gossip.cache_ref(), rpc.cache_ref()]);
        let mut reader = TCacheReader::new(table);
        reader.open(TCacheId::ControlProcessing, "g", ReadMode::Sliding).unwrap();
        reader.open(TCacheId::NetworkProcessing, "r", ReadMode::Strict).unwrap();
        assert!(matches!(
            reader.open(TCacheId::ControlRpc, "x", ReadMode::Strict),
            Err(Error::Unregistered(TCacheId::ControlRpc))
        ));

        let late = write(&mut rpc, b"rpc");
        assert_eq!(reader.acquire(early).buffer().unwrap().0, b"early");
        assert_eq!(reader.acquire_strict(late).unwrap().buffer().unwrap().0, b"rpc");
        assert!(reader.is_strict(TCacheId::NetworkProcessing));
        assert!(
            !reader.is_strict(TCacheId::ControlProcessing) &&
                !reader.is_strict(TCacheId::ControlSlot)
        );
        reader.free();
    }

    /// The stamp is the pinning consumer's slot and tail; identity ignores it.
    #[test]
    fn to_read_stamps_the_pinning_consumer() {
        let mut gossip = TCache::producer(TCacheId::ControlProcessing, 1 << 18);
        let table = TCacheTable::from_iter([gossip.cache_ref()]);
        let mut first = TCacheReader::new(table);
        let mut second = TCacheReader::new(table);
        first.open(TCacheId::ControlProcessing, "first", ReadMode::Sliding).unwrap();
        second.open(TCacheId::ControlProcessing, "second", ReadMode::Sliding).unwrap();

        let produced = write(&mut gossip, b"x");
        assert_eq!(produced.emitter, PRODUCER_EMITTER);
        let pinned = second.acquire(produced);
        let forwarded = pinned.to_read();
        assert_eq!(forwarded, produced);
        assert_eq!((forwarded.id, forwarded.seq), (produced.id, produced.seq));
        assert_eq!(forwarded.emitter, 1);
        assert_eq!(forwarded.floor, 0);
        drop(pinned);

        // Release everything behind, wrap past the guard, and the floor follows the
        // tail.
        let big = vec![0u8; 1 << 15];
        let mut last = write(&mut gossip, &big);
        for _ in 0..5 {
            drop(second.acquire(last));
            second.free();
            last = write(&mut gossip, &big);
        }
        let pinned = second.acquire(last);
        let forwarded = pinned.to_read();
        assert!(0 < forwarded.floor && forwarded.floor <= forwarded.seq, "{forwarded:?}");
        drop(pinned);
        first.free();
        second.free();
    }

    #[test]
    #[should_panic(expected = "not open")]
    fn acquire_on_unopened_id_panics() {
        let mut gossip = TCache::producer(TCacheId::ControlProcessing, 1 << 16);
        let read = write(&mut gossip, b"x");
        let mut reader = TCacheReader::new(TCacheTable::default());
        reader.acquire(read);
    }
}
