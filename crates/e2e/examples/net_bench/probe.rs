//! Probe payload carried in a gossip publish frame. The payload is an
//! uncompressed snappy literal, so its fields sit at a fixed offset inside the
//! frame and can be read or patched without decompression.

use buffa::encoding::{decode_varint, encode_varint, varint_len};
use silver_common::{P2pStreamId, TCacheProducer, TCacheRead, TProducer};
use silver_e2e::inject::{InjectError, build_publish_frame};

pub const PROBE_LEN: usize = 3 * size_of::<u64>();
const SEQ: usize = 0;
const SCHEDULED: usize = 8;
const TURNAROUND: usize = 16;
// RPC.publish and Message.data are both field 2, length-delimited.
const PUBLISH_TAG: u8 = 2 << 3 | 2;
const DATA_TAG: u8 = 2 << 3 | 2;

#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub seq: u64,
    pub scheduled_ns: u64,
    pub turnaround_ns: u64,
}

impl Probe {
    fn read(payload: &[u8]) -> Self {
        let field = |at: usize| u64::from_le_bytes(payload[at..at + 8].try_into().unwrap());
        Self { seq: field(SEQ), scheduled_ns: field(SCHEDULED), turnaround_ns: field(TURNAROUND) }
    }
}

/// Reusable snappy-literal payload: `varint(len) | literal tag | payload`.
pub struct ProbeEncoder {
    snappy: Vec<u8>,
    payload_at: usize,
    wire_topic: String,
}

impl ProbeEncoder {
    pub fn new(payload_size: usize, wire_topic: String) -> Self {
        assert!(payload_size >= PROBE_LEN, "payload must hold the probe fields");
        let mut snappy = Vec::with_capacity(payload_size + 16);
        encode_varint(payload_size as u64, &mut snappy);
        let literal_len = payload_size - 1;
        match literal_len {
            0..60 => snappy.push((literal_len as u8) << 2),
            _ => {
                let bytes = (literal_len.ilog2() / 8 + 1) as usize;
                snappy.push((59 + bytes as u8) << 2);
                snappy.extend_from_slice(&literal_len.to_le_bytes()[..bytes]);
            }
        }
        let payload_at = snappy.len();
        snappy.resize(payload_at + payload_size, 0);
        Self { snappy, payload_at, wire_topic }
    }

    pub fn publish(
        &mut self,
        outbound: &mut TProducer,
        seq: u64,
        scheduled_ns: u64,
    ) -> Result<TCacheRead, InjectError> {
        let payload = &mut self.snappy[self.payload_at..];
        payload[SEQ..SEQ + 8].copy_from_slice(&seq.to_le_bytes());
        payload[SCHEDULED..SCHEDULED + 8].copy_from_slice(&scheduled_ns.to_le_bytes());
        payload[TURNAROUND..TURNAROUND + 8].fill(0);
        build_publish_frame(outbound, &self.wire_topic, &self.snappy)
    }
}

/// An inbound NetworkIngress frame: `P2pStreamId | RPC`.
pub struct InboundFrame<'a> {
    rpc: &'a [u8],
    payload_at: usize,
}

impl<'a> InboundFrame<'a> {
    pub fn parse(frame: &'a [u8]) -> Option<Self> {
        let rpc = frame.get(size_of::<P2pStreamId>()..)?;
        let payload_at = probe_offset(rpc)?;
        (rpc.len() >= payload_at + PROBE_LEN).then_some(Self { rpc, payload_at })
    }

    pub fn probe(&self) -> Probe {
        Probe::read(&self.rpc[self.payload_at..])
    }

    /// Copies the RPC body into `outbound` with the turnaround field set.
    pub fn echo(
        &self,
        outbound: &mut TProducer,
        turnaround_ns: u64,
    ) -> Result<TCacheRead, InjectError> {
        let len = self.rpc.len();
        let mut reservation = outbound.reserve(len, true).ok_or(InjectError::ReserveFailed)?;
        let out = &mut outbound.reservation_buffer(&mut reservation)?[..len];
        out.copy_from_slice(self.rpc);
        let at = self.payload_at + TURNAROUND;
        out[at..at + 8].copy_from_slice(&turnaround_ns.to_le_bytes());
        reservation.increment_offset(len);
        Ok(reservation.read())
    }
}

/// Offset of the literal payload within an RPC holding one publish.
fn probe_offset(rpc: &[u8]) -> Option<usize> {
    let mut cursor = rpc.strip_prefix(&[PUBLISH_TAG])?;
    let message_len = usize::try_from(decode_varint(&mut cursor).ok()?).ok()?;
    let mut message = cursor.get(..message_len)?;
    let data = loop {
        let (&tag, rest) = message.split_first()?;
        message = rest;
        let len = usize::try_from(decode_varint(&mut message).ok()?).ok()?;
        let (field, rest) = message.split_at_checked(len)?;
        if tag == DATA_TAG {
            break field;
        }
        message = rest;
    };
    let mut snappy = data;
    let payload_len = decode_varint(&mut snappy).ok()?;
    let (&literal, _) = snappy.split_first()?;
    // Literal tags carry kind 0; tags 60..=63 append 1..=4 length bytes.
    if literal & 3 != 0 {
        return None;
    }
    let extra = (literal >> 2).saturating_sub(59) as usize;
    let header = varint_len(payload_len) + 1 + extra;
    Some(data.as_ptr() as usize - rpc.as_ptr() as usize + header)
}

#[cfg(test)]
mod tests {
    use silver_common::{TCache, TCacheId, TCacheReader, TReadMode};

    use super::*;

    #[test]
    fn frames_round_trip_and_echo_patches_only_the_turnaround() {
        for payload_size in [PROBE_LEN, 59, 60, 300, 70_000] {
            let mut outbound = TCache::producer(TCacheId::ControlGossip, 1 << 20);
            let mut reader =
                TCacheReader::single(outbound.cache_ref(), "test", TReadMode::Sliding).unwrap();
            let mut encoder = ProbeEncoder::new(payload_size, "/eth2/abcd1234/x/ssz_snappy".into());
            let read = encoder.publish(&mut outbound, 7, 1234).unwrap();
            let acquired = reader.acquire(read);
            let (rpc, _) = acquired.buffer().unwrap();
            let mut frame = vec![0; size_of::<P2pStreamId>()];
            frame.extend_from_slice(rpc);

            let inbound = InboundFrame::parse(&frame).unwrap();
            let probe = inbound.probe();
            assert_eq!((probe.seq, probe.scheduled_ns, probe.turnaround_ns), (7, 1234, 0));
            let data = snap::raw::Decoder::new().decompress_vec(&encoder.snappy).unwrap();
            assert_eq!(data.len(), payload_size);

            let echoed = inbound.echo(&mut outbound, 99).unwrap();
            let acquired = reader.acquire(echoed);
            let (rpc, _) = acquired.buffer().unwrap();
            let mut frame = vec![0; size_of::<P2pStreamId>()];
            frame.extend_from_slice(rpc);
            let probe = InboundFrame::parse(&frame).unwrap().probe();
            assert_eq!((probe.seq, probe.scheduled_ns, probe.turnaround_ns), (7, 1234, 99));
        }
    }
}
