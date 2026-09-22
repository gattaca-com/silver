use std::io::Write;

use super::{
    AcquiredRead, Producer, SubReservationError, SubReservationRef, TCacheProducer, TCacheRead,
    TCacheReader,
};

const ENTRY_BYTES: usize = 16;

// Only typed, same-cache descriptors enter this in-process format, never
// network bytes.
#[derive(Clone, Copy, Debug)]
pub struct SubReservationList {
    read: TCacheRead,
    count: usize,
}

impl SubReservationList {
    pub fn write<T: Into<Option<SubReservationRef>>>(
        producer: &mut Producer,
        entries: impl ExactSizeIterator<Item = T>,
    ) -> Result<Self, SubReservationError> {
        let count = entries.len();
        if count == 0 || count > 128 {
            return Err(SubReservationError::InvalidLayout);
        }
        let mut reservation =
            producer.reserve(count * ENTRY_BYTES, false).ok_or(SubReservationError::CacheFull)?;
        let bytes = reservation.buffer().map_err(|_| SubReservationError::Stale)?;
        let mut written = 0;
        for (index, entry) in entries.enumerate() {
            let entry = entry.into().ok_or(SubReservationError::InvalidLayout)?;
            if index >= count || entry.read.id != producer.cache_ref().id() {
                return Err(SubReservationError::WrongProducer);
            }
            let out = &mut bytes[index * ENTRY_BYTES..(index + 1) * ENTRY_BYTES];
            out[..8].copy_from_slice(&entry.read.seq.to_le_bytes());
            out[8..].copy_from_slice(&(entry.header_bytes as u64).to_le_bytes());
            written += 1;
        }
        if written != count {
            return Err(SubReservationError::InvalidLayout);
        }
        reservation.flush().map_err(|_| SubReservationError::Stale)?;
        Ok(Self { read: reservation.read(), count })
    }

    pub fn read(self) -> TCacheRead {
        self.read
    }

    pub fn acquire(
        self,
        reader: &mut TCacheReader,
    ) -> Result<AcquiredSubReservationList, SubReservationError> {
        let consumer = reader
            .get(self.read.id)
            .filter(|consumer| consumer.strict)
            .ok_or(SubReservationError::WrongConsumer)?;
        let read = consumer.acquire_strict(self.read).ok_or(SubReservationError::Stale)?;
        if read.buffer().map_err(|_| SubReservationError::Stale)?.0.len() !=
            self.count * ENTRY_BYTES
        {
            return Err(SubReservationError::InvalidLayout);
        }
        Ok(AcquiredSubReservationList { read, list: self })
    }

    pub fn view(
        self,
        producer: &Producer,
    ) -> Result<impl ExactSizeIterator<Item = SubReservationRef> + '_, SubReservationError> {
        let bytes = producer.read_buffer(self.read).map_err(|_| SubReservationError::Stale)?;
        Ok(self.entries(bytes))
    }

    fn entries(self, bytes: &[u8]) -> impl ExactSizeIterator<Item = SubReservationRef> + '_ {
        bytes.chunks_exact(ENTRY_BYTES).map(move |entry| SubReservationRef {
            read: TCacheRead {
                id: self.read.id,
                seq: u64::from_le_bytes(entry[..8].try_into().unwrap()),
            },
            header_bytes: u64::from_le_bytes(entry[8..].try_into().unwrap()) as usize,
        })
    }
}

pub struct AcquiredSubReservationList {
    read: AcquiredRead,
    list: SubReservationList,
}

impl AcquiredSubReservationList {
    pub fn entries(&self) -> impl ExactSizeIterator<Item = SubReservationRef> + '_ {
        self.list.entries(self.read.buffer().expect("acquired reservation list").0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SubLayout, TCache, TCacheId, TCacheReader, TReadMode};

    #[test]
    fn list_keeps_descriptors_in_one_cache_and_requires_live_strict_reads() {
        let mut producer = TCache::producer(TCacheId::DataColumns, 1 << 16);
        let mut consumer =
            Box::new(TCacheReader::single(producer.cache_ref(), "", TReadMode::Retained).unwrap());
        let layout = SubLayout { parts: 1, first_len: 4, second_len: 2 };
        let first = producer.sub_reservation(layout, b"", b"").unwrap();
        let second = producer.sub_reservation(layout, b"", b"").unwrap();
        let list = SubReservationList::write(&mut producer, [first, second].into_iter()).unwrap();
        let acquired = list.acquire(&mut consumer).unwrap();
        let sequences: Vec<_> = acquired.entries().map(|r| r.read().seq()).collect();
        assert_eq!(sequences, [first.read().seq(), second.read().seq()]);
        assert_eq!(list.view(&producer).unwrap().len(), 2);

        let mut other = TCache::producer(TCacheId::SszGossip, 1 << 16);
        let mut wrong =
            Box::new(TCacheReader::single(other.cache_ref(), "", TReadMode::Retained).unwrap());
        assert!(matches!(list.acquire(&mut wrong), Err(SubReservationError::WrongConsumer)));
        assert!(SubReservationList::write(&mut other, [first].into_iter()).is_err());
        assert!(
            SubReservationList::write(&mut producer, std::iter::empty::<SubReservationRef>())
                .is_err()
        );
        assert!(SubReservationList::write(&mut producer, [first; 129].into_iter()).is_err());

        producer.view_sub_reservation(first).unwrap().close();
        producer.view_sub_reservation(second).unwrap().close();
        let mut padding = producer.reserve(32 * 1024, false).unwrap();
        padding.buffer().unwrap().fill(0);
        padding.flush().unwrap();
        consumer.advance_retention(TCacheId::DataColumns, producer.next_seq());
        assert_eq!(acquired.entries().len(), 2);
        drop(acquired);
        consumer.free();
        assert!(matches!(list.acquire(&mut consumer), Err(SubReservationError::Stale)));
    }
}
