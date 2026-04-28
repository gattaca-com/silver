//! Per-protocol SSZ encoders for outgoing RPC payloads. Output is the
//! raw SSZ-encoded payload bytes — chunk framing (varint length, snappy
//! frames, optional response result-code byte) is handled by the network
//! tile when it actually writes to the libp2p stream.
//!
//! Each encoder uses the same pattern as the gossip-protocol encoders in
//! `crates/gossip/src/control.rs`: single-pass into a TCache reservation,
//! no intermediate `Vec`.
//!
//! Response chunks for `BeaconBlocksByRange/Root` and the data-column
//! variants are not emitted here — they require full SSZ encoding of
//! `SignedBeaconBlock` / `DataColumnSidecar` containers, which is the
//! responsibility of whichever beacon-state subsystem produces those
//! bodies.

use silver_common::{
    Error, TCacheProducer, TCacheRead,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, GOODBYE_SIZE, METADATA_SIZE, PING_SIZE, STATUS_V1_SIZE,
        STATUS_V2_SIZE,
    },
};

/// Encode a `Ping` request or `Pong` response (uint64 seq, 8 bytes LE).
pub fn encode_ping<P: TCacheProducer>(producer: &mut P, seq: u64) -> Result<TCacheRead, Error> {
    encode_u64(producer, seq, PING_SIZE)
}

/// Encode a `Goodbye` request (uint64 reason, 8 bytes LE). Same wire shape
/// as Ping; kept distinct for caller clarity.
pub fn encode_goodbye<P: TCacheProducer>(
    producer: &mut P,
    reason: u64,
) -> Result<TCacheRead, Error> {
    encode_u64(producer, reason, GOODBYE_SIZE)
}

/// Encode a v1 Status payload (84 bytes). Use `encode_status_v2` if the
/// peer negotiated the v2 protocol — wire shapes differ by 8 bytes.
pub fn encode_status<P: TCacheProducer>(
    producer: &mut P,
    fork_digest: &[u8; 4],
    finalized_root: &[u8; 32],
    finalized_epoch: u64,
    head_root: &[u8; 32],
    head_slot: u64,
) -> Result<TCacheRead, Error> {
    let mut reservation = producer.reserve(STATUS_V1_SIZE, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    fill_status(
        &mut out[..STATUS_V1_SIZE],
        fork_digest,
        finalized_root,
        finalized_epoch,
        head_root,
        head_slot,
    );
    reservation.increment_offset(STATUS_V1_SIZE);
    Ok(reservation.read())
}

/// Encode a v2 Status payload (92 bytes — adds `earliest_available_slot`).
#[allow(clippy::too_many_arguments)]
pub fn encode_status_v2<P: TCacheProducer>(
    producer: &mut P,
    fork_digest: &[u8; 4],
    finalized_root: &[u8; 32],
    finalized_epoch: u64,
    head_root: &[u8; 32],
    head_slot: u64,
    earliest_available_slot: u64,
) -> Result<TCacheRead, Error> {
    let mut reservation = producer.reserve(STATUS_V2_SIZE, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    fill_status(
        &mut out[..STATUS_V1_SIZE],
        fork_digest,
        finalized_root,
        finalized_epoch,
        head_root,
        head_slot,
    );
    out[84..92].copy_from_slice(&earliest_available_slot.to_le_bytes());
    reservation.increment_offset(STATUS_V2_SIZE);
    Ok(reservation.read())
}

/// Encode a v3 MetaData response payload (25 bytes).
pub fn encode_metadata<P: TCacheProducer>(
    producer: &mut P,
    seq_number: u64,
    attnets: &[u8; 8],
    syncnets: u8,
    custody_group_count: u64,
) -> Result<TCacheRead, Error> {
    let mut reservation = producer.reserve(METADATA_SIZE, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    out[0..8].copy_from_slice(&seq_number.to_le_bytes());
    out[8..16].copy_from_slice(attnets);
    out[16] = syncnets;
    out[17..25].copy_from_slice(&custody_group_count.to_le_bytes());
    reservation.increment_offset(METADATA_SIZE);
    Ok(reservation.read())
}

/// Encode a v2 `BeaconBlocksByRange` request (24 bytes: start_slot, count,
/// step — step is deprecated and must be 1 per the spec).
pub fn encode_blocks_by_range_request<P: TCacheProducer>(
    producer: &mut P,
    start_slot: u64,
    count: u64,
    step: u64,
) -> Result<TCacheRead, Error> {
    let mut reservation =
        producer.reserve(BLOCKS_BY_RANGE_REQ_SIZE, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    out[0..8].copy_from_slice(&start_slot.to_le_bytes());
    out[8..16].copy_from_slice(&count.to_le_bytes());
    out[16..24].copy_from_slice(&step.to_le_bytes());
    reservation.increment_offset(BLOCKS_BY_RANGE_REQ_SIZE);
    Ok(reservation.read())
}

/// Encode a v2 `BeaconBlocksByRoot` request: SSZ List[Root, MAX] of 32-byte
/// block roots, packed contiguously (32B per element, no length prefix —
/// list length is recovered from total payload length).
pub fn encode_blocks_by_root_request<P: TCacheProducer>(
    producer: &mut P,
    roots: &[[u8; 32]],
) -> Result<TCacheRead, Error> {
    let total = roots.len() * 32;
    let mut reservation = producer.reserve(total, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    for (i, root) in roots.iter().enumerate() {
        out[i * 32..(i + 1) * 32].copy_from_slice(root);
    }
    reservation.increment_offset(total);
    Ok(reservation.read())
}

#[inline]
fn encode_u64<P: TCacheProducer>(
    producer: &mut P,
    value: u64,
    size: usize,
) -> Result<TCacheRead, Error> {
    debug_assert_eq!(size, 8);
    let mut reservation = producer.reserve(size, true).ok_or(Error::BufferTooSmall)?;
    let out = producer.reservation_buffer(&mut reservation)?;
    out[..8].copy_from_slice(&value.to_le_bytes());
    reservation.increment_offset(size);
    Ok(reservation.read())
}

#[inline]
fn fill_status(
    out: &mut [u8],
    fork_digest: &[u8; 4],
    finalized_root: &[u8; 32],
    finalized_epoch: u64,
    head_root: &[u8; 32],
    head_slot: u64,
) {
    out[0..4].copy_from_slice(fork_digest);
    out[4..36].copy_from_slice(finalized_root);
    out[36..44].copy_from_slice(&finalized_epoch.to_le_bytes());
    out[44..76].copy_from_slice(head_root);
    out[76..84].copy_from_slice(&head_slot.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use silver_common::{
        TCache,
        ssz_view::{
            BeaconBlocksByRangeRequestView, GoodbyeView, MetadataView, PingView, StatusView,
        },
    };

    use super::*;

    fn read(producer: &silver_common::TProducer, tc: TCacheRead) -> Vec<u8> {
        let consumer = producer.cache_ref().random_access().unwrap();
        let (bytes, _) = consumer.read_at(tc.seq()).unwrap();
        bytes.to_vec()
    }

    #[test]
    fn ping_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let tc = encode_ping(&mut producer, 0xDEADBEEF_u64).unwrap();
        let bytes = read(&producer, tc);
        assert_eq!(bytes.len(), PING_SIZE);
        let arr: &[u8; PING_SIZE] = bytes.as_slice().try_into().unwrap();
        assert_eq!(PingView::seq_number(arr), 0xDEADBEEF);
    }

    #[test]
    fn goodbye_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let tc = encode_goodbye(&mut producer, 1).unwrap(); // 1 = client shutdown
        let bytes = read(&producer, tc);
        let arr: &[u8; GOODBYE_SIZE] = bytes.as_slice().try_into().unwrap();
        assert_eq!(GoodbyeView::reason(arr), 1);
    }

    #[test]
    fn status_v1_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let fork_digest = [0xAA, 0xBB, 0xCC, 0xDD];
        let finalized_root = [0x11; 32];
        let head_root = [0x22; 32];
        let tc = encode_status(&mut producer, &fork_digest, &finalized_root, 42, &head_root, 1000)
            .unwrap();
        let bytes = read(&producer, tc);
        assert!(StatusView::check_size(&bytes));
        assert_eq!(bytes.len(), STATUS_V1_SIZE);
        assert_eq!(StatusView::fork_digest(&bytes), &fork_digest);
        assert_eq!(StatusView::finalized_root(&bytes), &finalized_root);
        assert_eq!(StatusView::finalized_epoch(&bytes), 42);
        assert_eq!(StatusView::head_root(&bytes), &head_root);
        assert_eq!(StatusView::head_slot(&bytes), 1000);
        assert_eq!(StatusView::earliest_available_slot(&bytes), None);
    }

    #[test]
    fn status_v2_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let tc = encode_status_v2(&mut producer, &[1, 2, 3, 4], &[5; 32], 10, &[6; 32], 20, 999)
            .unwrap();
        let bytes = read(&producer, tc);
        assert_eq!(bytes.len(), STATUS_V2_SIZE);
        assert!(StatusView::check_size(&bytes));
        assert_eq!(StatusView::earliest_available_slot(&bytes), Some(999));
    }

    #[test]
    fn metadata_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let attnets = [0xFF, 0x00, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78];
        let tc = encode_metadata(&mut producer, 7, &attnets, 0x0F, 64).unwrap();
        let bytes = read(&producer, tc);
        assert_eq!(bytes.len(), METADATA_SIZE);
        let arr: &[u8; METADATA_SIZE] = bytes.as_slice().try_into().unwrap();
        assert_eq!(MetadataView::seq_number(arr), 7);
        assert_eq!(MetadataView::attnets(arr), &attnets);
        assert_eq!(MetadataView::syncnets(arr), 0x0F);
        assert_eq!(MetadataView::custody_group_count(arr), 64);
    }

    #[test]
    fn blocks_by_range_request_round_trip() {
        let mut producer = TCache::producer(1 << 14);
        let tc = encode_blocks_by_range_request(&mut producer, 100, 32, 1).unwrap();
        let bytes = read(&producer, tc);
        let arr: &[u8; BLOCKS_BY_RANGE_REQ_SIZE] = bytes.as_slice().try_into().unwrap();
        assert_eq!(BeaconBlocksByRangeRequestView::start_slot(arr), 100);
        assert_eq!(BeaconBlocksByRangeRequestView::count(arr), 32);
        assert_eq!(BeaconBlocksByRangeRequestView::step(arr), 1);
    }

    #[test]
    fn blocks_by_root_request_packs_contiguous_roots() {
        let mut producer = TCache::producer(1 << 14);
        let roots = [[0x11; 32], [0x22; 32], [0x33; 32]];
        let tc = encode_blocks_by_root_request(&mut producer, &roots).unwrap();
        let bytes = read(&producer, tc);
        assert_eq!(bytes.len(), 96);
        assert_eq!(&bytes[0..32], &roots[0]);
        assert_eq!(&bytes[32..64], &roots[1]);
        assert_eq!(&bytes[64..96], &roots[2]);
    }
}
