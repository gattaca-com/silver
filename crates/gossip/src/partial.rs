use std::{iter, time::Instant};

use buffa::{
    bytes::BufMut,
    encoding::{Tag, WireType, encode_varint, varint_len},
    types::{encode_bytes, encode_string, string_encoded_len},
};
use silver_common::{
    GossipFrameError, GossipFrameRef, GossipSegment, TProducer,
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_PROOF,
        partial_column::{PartialSidecarPlan, parts_metadata_len, write_parts_metadata},
    },
};

// Tags, varints, topic, group id, metadata field, and the SSZ
// offsets-plus-bitmap prefix; every piece is small and bounded.
const MAX_PARTIAL_FRAMING: usize = 256;

/// Row masks for a `partsMetadata` field; both bitlists carry exactly
/// `n_rows` bits.
pub struct PartsMetadata {
    pub available: u128,
    pub requests: u128,
    pub n_rows: usize,
}

impl PartsMetadata {
    fn encodable(&self) -> bool {
        self.n_rows <= 128 &&
            (self.n_rows == 128 ||
                (self.available >> self.n_rows == 0 && self.requests >> self.n_rows == 0))
    }
}

/// One outbound partial-column RPC frame: `RPC.partial` carrying a
/// `PartialMessagesExtension` for a single `(topic, group)` pair. The
/// fork identity is fixed by `plan` and `group_id` at construction and
/// never rewritten. Cell and proof payloads stay in their retained
/// records; only framing bytes are prepared here.
pub struct PartialFrame<'a> {
    /// Full topic name (the protobuf `topic_id`).
    pub topic: &'a str,
    pub group_id: &'a [u8],
    /// `None` omits `partialMessage`: a metadata-only frame.
    pub plan: Option<PartialSidecarPlan>,
    /// Fulu eager push only; the segment length must equal the plan's
    /// `header_bytes`.
    pub header: Option<GossipSegment>,
    pub metadata: Option<PartsMetadata>,
}

impl PartialFrame<'_> {
    /// Write the frame descriptor into the outgoing gossip cache.
    /// `cells` and `proofs` are the selected rows' ranges in ascending
    /// row order; counts and lengths must match the plan.
    pub fn write(
        &self,
        producer: &mut TProducer,
        cells: impl ExactSizeIterator<Item = GossipSegment> + Clone,
        proofs: impl ExactSizeIterator<Item = GossipSegment> + Clone,
        expires: Instant,
    ) -> Result<GossipFrameRef, GossipFrameError> {
        let k = self.plan.map_or(0, |plan| plan.cell_count());
        let header_bytes = self.plan.map_or(0, |plan| plan.header_bytes());
        // Range lengths back the declared varints; a mismatch would emit
        // corrupt protobuf, so reject it here rather than on the wire.
        // Metadata row counts must match the payload's and stay encodable.
        if (self.plan.is_none() && self.metadata.is_none()) ||
            cells.len() != k ||
            proofs.len() != k ||
            cells.clone().any(|cell| segment_len(cell) != BYTES_PER_CELL) ||
            proofs.clone().any(|proof| segment_len(proof) != BYTES_PER_KZG_PROOF) ||
            self.header.map_or(0, segment_len) != header_bytes ||
            self.metadata.as_ref().is_some_and(|meta| {
                !meta.encodable() || self.plan.is_some_and(|plan| plan.n_rows() != meta.n_rows)
            })
        {
            return Err(GossipFrameError::InvalidDescriptor);
        }

        let ssz_len = self.plan.map_or(0, |plan| plan.ssz_len());
        let meta_len = self.metadata.as_ref().map(|meta| parts_metadata_len(meta.n_rows));
        let fields_len = 1 +
            string_encoded_len(self.topic) +
            1 +
            varint_len(self.group_id.len() as u64) +
            self.group_id.len() +
            self.plan.map_or(0, |_| 1 + varint_len(ssz_len as u64));
        let tail = meta_len.map_or(0, |m| 1 + varint_len(m as u64) + m);
        let ext_len = fields_len + ssz_len + tail;

        // Framing layout: [lead | header list prefix | metadata field].
        let lead = 1 +
            varint_len(ext_len as u64) +
            fields_len +
            self.plan.map_or(0, |plan| plan.prefix_len());
        let mid = if header_bytes > 0 { 4 } else { 0 };
        let framing_len = lead + mid + tail;
        if framing_len > MAX_PARTIAL_FRAMING {
            return Err(GossipFrameError::TooLarge);
        }

        let mut buf = [0u8; MAX_PARTIAL_FRAMING];
        let mut cursor: &mut [u8] = &mut buf[..framing_len];
        Tag::new(10, WireType::LengthDelimited).encode(&mut cursor);
        encode_varint(ext_len as u64, &mut cursor);
        Tag::new(1, WireType::LengthDelimited).encode(&mut cursor);
        encode_string(self.topic, &mut cursor);
        Tag::new(2, WireType::LengthDelimited).encode(&mut cursor);
        encode_bytes(self.group_id, &mut cursor);
        if let Some(plan) = self.plan {
            Tag::new(3, WireType::LengthDelimited).encode(&mut cursor);
            encode_varint(ssz_len as u64, &mut cursor);
            let mut prefix = [0u8; 33];
            let prefix = &mut prefix[..plan.prefix_len()];
            plan.write_prefix(prefix);
            cursor.put_slice(prefix);
        }
        debug_assert_eq!(cursor.len(), mid + tail);
        if header_bytes > 0 {
            cursor.put_slice(&PartialSidecarPlan::HEADER_LIST_PREFIX);
        }
        if let Some(meta) = &self.metadata {
            let mut buf = [0u8; parts_metadata_len(128)];
            let bytes = &mut buf[..meta_len.unwrap()];
            write_parts_metadata(meta.available, meta.requests, meta.n_rows, bytes);
            Tag::new(4, WireType::LengthDelimited).encode(&mut cursor);
            encode_bytes(bytes, &mut cursor);
        }
        debug_assert!(cursor.is_empty());

        let header_prefix =
            (header_bytes > 0).then_some(GossipSegment::Framing { offset: lead, length: 4 });
        let metadata_framing =
            (tail > 0).then_some(GossipSegment::Framing { offset: lead + mid, length: tail });
        let count = 1 +
            2 * k +
            usize::from(header_prefix.is_some()) * 2 +
            usize::from(metadata_framing.is_some());
        GossipFrameRef::write(producer, expires, &buf[..framing_len], WithLen {
            len: count,
            inner: iter::once(GossipSegment::Framing { offset: 0, length: lead })
                .chain(cells)
                .chain(proofs)
                .chain(header_prefix)
                .chain(self.header)
                .chain(metadata_framing),
        })
    }
}

// `Chain` drops `ExactSizeIterator`; the segment count is known exactly.
struct WithLen<I> {
    inner: I,
    len: usize,
}

impl<I: Iterator> Iterator for WithLen<I> {
    type Item = I::Item;

    fn next(&mut self) -> Option<I::Item> {
        self.len = self.len.saturating_sub(1);
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}

impl<I: Iterator> ExactSizeIterator for WithLen<I> {}

fn segment_len(segment: GossipSegment) -> usize {
    match segment {
        GossipSegment::Framing { length, .. } |
        GossipSegment::Gossip { length, .. } |
        GossipSegment::DataColumns { length, .. } |
        GossipSegment::Shared { length, .. } => length,
    }
}

#[cfg(test)]
mod tests {
    use buffa::{Message, MessageField, MessageView};

    use crate::generated::{
        ControlExtensions, ControlMessage, PartialMessagesExtension, RPC, RPCView, rpc::SubOpts,
    };

    /// Registry wire numbers: SubOpts.requestsPartial=3,
    /// supportsSendingPartial=4, ControlMessage.extensions=6,
    /// ControlExtensions.partialMessages=10, RPC.partial=10.
    #[test]
    fn partial_fields_round_trip() {
        let rpc = RPC {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some("col_topic".into()),
                requests_partial: Some(true),
                supports_sending_partial: None,
                ..Default::default()
            }],
            control: MessageField::some(ControlMessage {
                extensions: MessageField::some(ControlExtensions {
                    partial_messages: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            partial: MessageField::some(PartialMessagesExtension {
                topic_id: Some(b"col_topic".to_vec()),
                group_id: Some(vec![0u8; 33]),
                partial_message: Some(vec![0xab; 64]),
                parts_metadata: None,
                ..Default::default()
            }),
            ..Default::default()
        };

        let bytes = rpc.encode_to_vec();
        let view = RPCView::decode_view(&bytes).unwrap();

        let sub = view.subscriptions.iter().next().unwrap();
        assert_eq!(sub.requests_partial, Some(true));
        // requestsPartial implies sending support; the flag itself stays
        // absent on the wire and normalization happens at the consumer.
        assert_eq!(sub.supports_sending_partial, None);

        assert_eq!(
            view.control.as_option().unwrap().extensions.as_option().unwrap().partial_messages,
            Some(true)
        );

        let partial = view.partial.as_option().unwrap();
        assert_eq!(partial.topic_id, Some(&b"col_topic"[..]));
        assert_eq!(partial.group_id.unwrap().len(), 33);
        assert_eq!(partial.partial_message, Some(&[0xab; 64][..]));
        assert_eq!(partial.parts_metadata, None);
    }

    #[test]
    fn legacy_frames_decode_with_partial_fields_unset() {
        let rpc = RPC {
            subscriptions: vec![SubOpts {
                subscribe: Some(true),
                topic_id: Some("t".into()),
                ..Default::default()
            }],
            control: MessageField::some(ControlMessage::default()),
            ..Default::default()
        };

        let bytes = rpc.encode_to_vec();
        let view = RPCView::decode_view(&bytes).unwrap();

        let sub = view.subscriptions.iter().next().unwrap();
        assert_eq!(sub.requests_partial, None);
        assert_eq!(sub.supports_sending_partial, None);
        assert!(!view.control.as_option().unwrap().extensions.is_set());
        assert!(!view.partial.is_set());
    }

    use std::time::{Duration, Instant};

    use silver_common::{
        GossipFrameError, GossipFrameRef, GossipSegment, TCache, TCacheProducer, TProducer,
        TRandomAccess,
        ssz_view::{
            BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF,
            partial_column::{
                PARTIAL_HEADER_FIXED, PartialLayout, PartialSidecarPlan, fulu_group_id,
                gloas_group_id, parts_metadata_len, write_parts_metadata,
            },
        },
    };

    use super::{PartialFrame, PartsMetadata};

    const TOPIC: &str = "/eth2/aabbccdd/data_column_sidecar_7/ssz_snappy";

    /// Reference bytes from buffa's own encoder over the same content.
    fn reference_rpc(group_id: &[u8], ssz: Vec<u8>, metadata: Option<Vec<u8>>) -> Vec<u8> {
        RPC {
            partial: MessageField::some(PartialMessagesExtension {
                topic_id: Some(TOPIC.as_bytes().to_vec()),
                group_id: Some(group_id.to_vec()),
                partial_message: Some(ssz),
                parts_metadata: metadata,
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn reassemble(frame: GossipFrameRef, consumer: &mut TRandomAccess, now: Instant) -> Vec<u8> {
        let view = frame.acquire(consumer, now).unwrap();
        let descriptor = view.descriptor_range();
        let mut wire = Vec::new();
        for segment in view.segments() {
            if let Some(range) = segment.framing_range() {
                wire.extend_from_slice(&descriptor.as_ref()[range]);
            } else {
                wire.extend_from_slice(segment.acquire(consumer, None).unwrap().as_ref());
            }
        }
        assert_eq!(wire.len(), view.wire_len());
        wire
    }

    /// One source record holding k cells, k proofs, and `header_bytes`
    /// of header SSZ; returns per-region segments.
    fn source_record(
        producer: &mut TProducer,
        k: usize,
        header_bytes: usize,
    ) -> (Vec<GossipSegment>, Vec<GossipSegment>, Option<GossipSegment>, Vec<u8>) {
        let len = k * (BYTES_PER_CELL + BYTES_PER_KZG_PROOF) + header_bytes;
        let mut reservation = producer.reserve(len, true).unwrap();
        let read = reservation.read();
        {
            let buf = reservation.buffer().unwrap();
            for (i, byte) in buf.iter_mut().enumerate() {
                *byte = (i % 251) as u8;
            }
            if header_bytes > 0 {
                let header = &mut buf[len - header_bytes..];
                header[0..4].copy_from_slice(&(PARTIAL_HEADER_FIXED as u32).to_le_bytes());
            }
        }
        let bytes = reservation.buffer().unwrap().to_vec();
        reservation.increment_offset(len);

        let cells = (0..k)
            .map(|i| GossipSegment::Gossip {
                read,
                offset: i * BYTES_PER_CELL,
                length: BYTES_PER_CELL,
            })
            .collect();
        let proofs = (0..k)
            .map(|i| GossipSegment::Gossip {
                read,
                offset: k * BYTES_PER_CELL + i * BYTES_PER_KZG_PROOF,
                length: BYTES_PER_KZG_PROOF,
            })
            .collect();
        let header = (header_bytes > 0).then_some(GossipSegment::Gossip {
            read,
            offset: len - header_bytes,
            length: header_bytes,
        });
        (cells, proofs, header, bytes)
    }

    fn reference_ssz(plan: &PartialSidecarPlan, source: &[u8], header_bytes: usize) -> Vec<u8> {
        let mut ssz = vec![0u8; plan.prefix_len()];
        plan.write_prefix(&mut ssz);
        ssz.extend_from_slice(&source[..source.len() - header_bytes]);
        if header_bytes > 0 {
            ssz.extend_from_slice(&PartialSidecarPlan::HEADER_LIST_PREFIX);
            ssz.extend_from_slice(&source[source.len() - header_bytes..]);
        }
        assert_eq!(ssz.len(), plan.ssz_len());
        ssz
    }

    #[test]
    fn fulu_frame_matches_buffa_reference_encoding() {
        let mut producer = TCache::producer("", 1 << 18);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let now = Instant::now();
        let header_bytes = PARTIAL_HEADER_FIXED + 3 * BYTES_PER_KZG_COMMITMENT;
        let (cells, proofs, header, source) = source_record(&mut producer, 2, header_bytes);

        let group = fulu_group_id(&[0xab; 32]);
        let plan = PartialSidecarPlan::new(PartialLayout::Fulu { header_bytes }, 0b101, 3).unwrap();
        let frame = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: Some(plan),
            header,
            metadata: Some(PartsMetadata { available: 0b101, requests: 0b010, n_rows: 3 }),
        }
        .write(
            &mut producer,
            cells.iter().copied(),
            proofs.iter().copied(),
            now + Duration::from_secs(1),
        )
        .unwrap();

        let mut metadata = vec![0u8; parts_metadata_len(3)];
        write_parts_metadata(0b101, 0b010, 3, &mut metadata);
        let reference =
            reference_rpc(&group, reference_ssz(&plan, &source, header_bytes), Some(metadata));

        assert_eq!(reassemble(frame, &mut consumer, now), reference);
    }

    #[test]
    fn gloas_frame_matches_buffa_reference_encoding() {
        let mut producer = TCache::producer("", 1 << 18);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let now = Instant::now();
        let (cells, proofs, header, source) = source_record(&mut producer, 1, 0);
        assert!(header.is_none());

        let group = gloas_group_id(&[0xcd; 32], 123_456);
        let plan = PartialSidecarPlan::new(PartialLayout::Gloas, 0b10, 2).unwrap();
        let frame = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: Some(plan),
            header: None,
            metadata: None,
        }
        .write(
            &mut producer,
            cells.iter().copied(),
            proofs.iter().copied(),
            now + Duration::from_secs(1),
        )
        .unwrap();

        let reference = reference_rpc(&group, reference_ssz(&plan, &source, 0), None);
        assert_eq!(reassemble(frame, &mut consumer, now), reference);
    }

    #[test]
    fn frame_rejects_count_and_header_mismatches() {
        let mut producer = TCache::producer("", 1 << 18);
        let now = Instant::now();
        let (cells, proofs, _, _) = source_record(&mut producer, 2, 0);

        let group = fulu_group_id(&[0xab; 32]);
        let plan =
            PartialSidecarPlan::new(PartialLayout::Fulu { header_bytes: 0 }, 0b11, 2).unwrap();
        let missing_proof = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: Some(plan),
            header: None,
            metadata: None,
        }
        .write(
            &mut producer,
            cells.iter().copied(),
            proofs.iter().copied().take(1),
            now + Duration::from_secs(1),
        );
        assert!(matches!(missing_proof, Err(GossipFrameError::InvalidDescriptor)));

        let with_header = PartialSidecarPlan::new(
            PartialLayout::Fulu { header_bytes: PARTIAL_HEADER_FIXED },
            0b11,
            2,
        )
        .unwrap();
        let missing_header = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: Some(with_header),
            header: None,
            metadata: None,
        }
        .write(
            &mut producer,
            cells.iter().copied(),
            proofs.iter().copied(),
            now + Duration::from_secs(1),
        );
        assert!(matches!(missing_header, Err(GossipFrameError::InvalidDescriptor)));

        let mismatched_rows = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: Some(plan),
            header: None,
            metadata: Some(PartsMetadata { available: 0, requests: 0b1, n_rows: 3 }),
        }
        .write(
            &mut producer,
            cells.iter().copied(),
            proofs.iter().copied(),
            now + Duration::from_secs(1),
        );
        assert!(matches!(mismatched_rows, Err(GossipFrameError::InvalidDescriptor)));
    }

    #[test]
    fn metadata_only_frame_matches_buffa_reference_encoding() {
        let mut producer = TCache::producer("", 1 << 16);
        let mut consumer = producer.cache_ref().strict_random_access("", true).unwrap();
        let now = Instant::now();

        let group = fulu_group_id(&[0xee; 32]);
        let frame = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: None,
            header: None,
            metadata: Some(PartsMetadata { available: 0b11, requests: 0b100, n_rows: 4 }),
        }
        .write(&mut producer, std::iter::empty(), std::iter::empty(), now + Duration::from_secs(1))
        .unwrap();

        let mut metadata = vec![0u8; parts_metadata_len(4)];
        write_parts_metadata(0b11, 0b100, 4, &mut metadata);
        let reference = RPC {
            partial: MessageField::some(PartialMessagesExtension {
                topic_id: Some(TOPIC.as_bytes().to_vec()),
                group_id: Some(group.to_vec()),
                partial_message: None,
                parts_metadata: Some(metadata),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        assert_eq!(reassemble(frame, &mut consumer, now), reference);

        // Neither payload nor metadata: nothing to send.
        let empty = PartialFrame {
            topic: TOPIC,
            group_id: &group,
            plan: None,
            header: None,
            metadata: None,
        }
        .write(
            &mut producer,
            std::iter::empty(),
            std::iter::empty(),
            now + Duration::from_secs(1),
        );
        assert!(matches!(empty, Err(GossipFrameError::InvalidDescriptor)));
    }
}
