use super::{MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol};

/// Multistream-select negotiation state for a single QUIC stream.
pub(crate) enum NegotiateState {
    /// Outbound: writing multistream header + protocol proposal.
    OutWriting { protocol: StreamProtocol, written: usize },
    /// Outbound: reading back multistream header + protocol echo.
    OutReading { protocol: StreamProtocol, buf: [u8; 96], read: usize },
    /// Inbound: reading multistream header (fixed size).
    InReadingHeader { buf: [u8; 20], read: usize },
    /// Inbound: header matched, reading protocol varint + string.
    InReadingProtocol { buf: [u8; 68], read: usize },
    /// Inbound: matched protocol, writing multistream header + protocol echo.
    InWriting { protocol: StreamProtocol, written: usize },
    /// Inbound: unrecognized protocol, writing reject (header + na).
    InWritingReject { written: usize },
    /// Negotiation complete.
    Done(StreamProtocol),
    /// Negotiation failed.
    Failed,
}

/// Result of a single drive step.
#[derive(Debug)]
pub(crate) enum NegotiateAction {
    /// Need to write `data[offset..]` to the quinn send_stream.
    Write,
    /// Need to read more bytes from the quinn recv_stream.
    Read,
    /// Negotiation complete.
    Done(StreamProtocol),
    /// Negotiation failed (protocol mismatch or bad header).
    Failed,
}

impl NegotiateState {
    /// Create state for an outbound stream (we are the dialer).
    pub(crate) fn new_outbound(protocol: StreamProtocol) -> Self {
        Self::OutWriting { protocol, written: 0 }
    }

    /// Create state for an inbound stream (we are the listener).
    pub(crate) fn new_inbound() -> Self {
        Self::InReadingHeader { buf: [0u8; 20], read: 0 }
    }

    /// Bytes to write for current state, if any. Returns (buf, offset).
    pub(crate) fn pending_write(&self) -> Option<(&[u8], usize)> {
        match self {
            Self::OutWriting { protocol, written } => {
                // Write MULTISTREAM_V1 ++ protocol.multiselect() in one go.
                // Caller must handle the boundary between the two slices.
                Some((MULTISTREAM_V1, *written))
            }
            Self::InWriting { protocol, written } => Some((MULTISTREAM_V1, *written)),
            Self::InWritingReject { written } => Some((REJECT_RESPONSE, *written)),
            _ => None,
        }
    }

    /// Drive the write side. Call after successfully writing bytes to
    /// send_stream. `wrote`: number of bytes written this call.
    pub(crate) fn advance_write(&mut self, wrote: usize) -> NegotiateAction {
        match self {
            Self::OutWriting { protocol, written } => {
                *written += wrote;
                let total = MULTISTREAM_V1.len() + protocol.multiselect().len();
                if *written >= total {
                    let proto = *protocol;
                    *self = Self::OutReading { protocol: proto, buf: [0u8; 96], read: 0 };
                    NegotiateAction::Read
                } else {
                    NegotiateAction::Write
                }
            }
            Self::InWriting { protocol, written } => {
                *written += wrote;
                let total = MULTISTREAM_V1.len() + protocol.multiselect().len();
                if *written >= total {
                    let proto = *protocol;
                    *self = Self::Done(proto);
                    NegotiateAction::Done(proto)
                } else {
                    NegotiateAction::Write
                }
            }
            Self::InWritingReject { written } => {
                *written += wrote;
                if *written >= REJECT_RESPONSE.len() {
                    *self = Self::Failed;
                    NegotiateAction::Failed
                } else {
                    NegotiateAction::Write
                }
            }
            _ => NegotiateAction::Read,
        }
    }

    /// Feed received bytes into the state machine.
    /// Returns the action the caller should take next.
    pub(crate) fn feed_read(&mut self, data: &[u8]) -> NegotiateAction {
        match self {
            Self::OutReading { protocol, buf, read } => {
                let expected_len = MULTISTREAM_V1.len() + protocol.multiselect().len();
                let take = data.len().min(expected_len - *read);
                buf[*read..*read + take].copy_from_slice(&data[..take]);
                *read += take;

                if *read < expected_len {
                    return NegotiateAction::Read;
                }

                // Verify: first MULTISTREAM_V1, then protocol echo.
                if &buf[..MULTISTREAM_V1.len()] != MULTISTREAM_V1 {
                    *self = Self::Failed;
                    return NegotiateAction::Failed;
                }
                let proto_bytes = &buf[MULTISTREAM_V1.len()..expected_len];
                if proto_bytes != protocol.multiselect() {
                    *self = Self::Failed;
                    return NegotiateAction::Failed;
                }

                let proto = *protocol;
                *self = Self::Done(proto);
                NegotiateAction::Done(proto)
            }

            Self::InReadingHeader { buf, read } => {
                let take = data.len().min(buf.len() - *read);
                buf[*read..*read + take].copy_from_slice(&data[..take]);
                *read += take;

                if *read < buf.len() {
                    return NegotiateAction::Read;
                }

                if buf[..] != MULTISTREAM_V1[..] {
                    *self = Self::Failed;
                    return NegotiateAction::Failed;
                }

                *self = Self::InReadingProtocol { buf: [0u8; 68], read: 0 };
                let remaining = &data[take..];
                if remaining.is_empty() { NegotiateAction::Read } else { self.feed_read(remaining) }
            }

            Self::InReadingProtocol { buf, read } => {
                // First byte is varint length prefix. For all our protocols
                // this fits in one byte (max protocol string is ~66 bytes).
                if *read == 0 && data.is_empty() {
                    return NegotiateAction::Read;
                }

                let take = if *read == 0 {
                    // First byte: varint length. Copy it + as much payload as available.
                    let take = data.len().min(buf.len());
                    buf[..take].copy_from_slice(&data[..take]);
                    take
                } else {
                    let take = data.len().min(buf.len() - *read);
                    buf[*read..*read + take].copy_from_slice(&data[..take]);
                    take
                };
                *read += take;

                if *read == 0 {
                    return NegotiateAction::Read;
                }

                // varint length is buf[0] (single byte for all our protocols).
                let proto_total = buf[0] as usize + 1; // +1 for the varint byte itself
                if proto_total > buf.len() {
                    *self = Self::InWritingReject { written: 0 };
                    return NegotiateAction::Write;
                }

                if *read < proto_total {
                    return NegotiateAction::Read;
                }

                // Match against known protocols.
                let proto_line = &buf[..proto_total];
                if let Some(protocol) = StreamProtocol::from_multiselect(proto_line) {
                    *self = Self::InWriting { protocol, written: 0 };
                    NegotiateAction::Write
                } else {
                    *self = Self::InWritingReject { written: 0 };
                    NegotiateAction::Write
                }
            }

            _ => NegotiateAction::Read,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::stream::{ALL_PROTOCOLS, MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol};

    /// Feed data one byte at a time, collecting write outputs and action
    /// transitions.
    fn feed_byte_by_byte(neg: &mut NegotiateState, data: &[u8]) -> Vec<NegotiateAction> {
        let mut actions = Vec::new();
        for &b in data {
            actions.push(neg.feed_read(&[b]));
        }
        actions
    }

    /// Simulate the full outbound handshake: write header+proto, then read
    /// echo. Feed the echo one byte at a time.
    fn outbound_byte_by_byte(protocol: StreamProtocol) -> NegotiateState {
        let mut neg = NegotiateState::new_outbound(protocol);

        // Advance writes until we transition to reading.
        let total_write = MULTISTREAM_V1.len() + protocol.multiselect().len();
        let action = neg.advance_write(total_write);
        assert!(matches!(action, NegotiateAction::Read));

        // Build the expected echo: MULTISTREAM_V1 + protocol.multiselect()
        let mut echo = Vec::new();
        echo.extend_from_slice(MULTISTREAM_V1);
        echo.extend_from_slice(protocol.multiselect());

        // Feed one byte at a time.
        for (i, &b) in echo.iter().enumerate() {
            let action = neg.feed_read(&[b]);
            if i < echo.len() - 1 {
                assert!(
                    matches!(action, NegotiateAction::Read),
                    "expected Read at byte {i}, got {action:?}"
                );
            } else {
                assert!(
                    matches!(action, NegotiateAction::Done(_)),
                    "expected Done at final byte, got {action:?}"
                );
            }
        }
        neg
    }

    #[test]
    fn outbound_all_protocols() {
        for &proto in ALL_PROTOCOLS {
            let neg = outbound_byte_by_byte(proto);
            assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        }
    }

    #[test]
    fn outbound_bad_echo_fails() {
        let mut neg = NegotiateState::new_outbound(StreamProtocol::Ping);
        let total_write = MULTISTREAM_V1.len() + StreamProtocol::Ping.multiselect().len();
        neg.advance_write(total_write);

        // Feed correct header then wrong protocol.
        for &b in MULTISTREAM_V1 {
            neg.feed_read(&[b]);
        }
        // Feed garbage instead of protocol echo.
        let garbage = vec![0xffu8; StreamProtocol::Ping.multiselect().len()];
        let action = neg.feed_read(&garbage);
        assert!(matches!(action, NegotiateAction::Failed));
    }

    #[test]
    fn outbound_bulk_feed() {
        let proto = StreamProtocol::StatusV2;
        let mut neg = NegotiateState::new_outbound(proto);
        let total_write = MULTISTREAM_V1.len() + proto.multiselect().len();
        neg.advance_write(total_write);

        // Feed entire echo at once.
        let mut echo = Vec::new();
        echo.extend_from_slice(MULTISTREAM_V1);
        echo.extend_from_slice(proto.multiselect());
        let action = neg.feed_read(&echo);
        assert!(matches!(action, NegotiateAction::Done(p) if p == proto));
    }

    /// Simulate the full inbound handshake byte-by-byte.
    fn inbound_byte_by_byte(protocol: StreamProtocol) -> NegotiateState {
        let mut neg = NegotiateState::new_inbound();

        // Feed MULTISTREAM_V1 header byte-by-byte.
        for (i, &b) in MULTISTREAM_V1.iter().enumerate() {
            let action = neg.feed_read(&[b]);
            if i < MULTISTREAM_V1.len() - 1 {
                assert!(
                    matches!(action, NegotiateAction::Read),
                    "header: expected Read at byte {i}, got {action:?}"
                );
            } else {
                // Last byte of header → transitions to InReadingProtocol.
                assert!(
                    matches!(action, NegotiateAction::Read),
                    "header: expected Read after last byte, got {action:?}"
                );
            }
        }

        // Feed protocol line byte-by-byte.
        let proto_bytes = protocol.multiselect();
        for (i, &b) in proto_bytes.iter().enumerate() {
            let action = neg.feed_read(&[b]);
            if i < proto_bytes.len() - 1 {
                assert!(
                    matches!(action, NegotiateAction::Read),
                    "proto: expected Read at byte {i}, got {action:?}"
                );
            } else {
                // Last byte → matched protocol, transitions to InWriting.
                assert!(
                    matches!(action, NegotiateAction::Write),
                    "proto: expected Write at final byte, got {action:?}"
                );
            }
        }

        // Advance write of confirmation (MULTISTREAM_V1 + protocol echo).
        let confirm_len = MULTISTREAM_V1.len() + proto_bytes.len();
        let action = neg.advance_write(confirm_len);
        assert!(matches!(action, NegotiateAction::Done(_)));
        neg
    }

    #[test]
    fn inbound_all_protocols() {
        for &proto in ALL_PROTOCOLS {
            let neg = inbound_byte_by_byte(proto);
            assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        }
    }

    #[test]
    fn inbound_bad_header_fails() {
        let mut neg = NegotiateState::new_inbound();
        let mut bad_header = MULTISTREAM_V1.to_vec();
        *bad_header.last_mut().unwrap() ^= 0xff; // corrupt last byte
        let actions = feed_byte_by_byte(&mut neg, &bad_header);
        assert!(matches!(actions.last(), Some(NegotiateAction::Failed)));
    }

    #[test]
    fn inbound_unknown_protocol_rejects() {
        let mut neg = NegotiateState::new_inbound();

        // Feed valid header.
        for &b in MULTISTREAM_V1 {
            neg.feed_read(&[b]);
        }

        // Feed an unknown protocol line. 0x0d = 13 = len("/unknown/1.0\n").
        let unknown = b"\x0d/unknown/1.0\n";
        let actions = feed_byte_by_byte(&mut neg, unknown);

        // Should transition to InWritingReject → Write action.
        assert!(
            matches!(actions.last(), Some(NegotiateAction::Write)),
            "expected Write (reject) for unknown protocol"
        );

        // Advance the reject write.
        let action = neg.advance_write(REJECT_RESPONSE.len());
        assert!(matches!(action, NegotiateAction::Failed));
    }

    #[test]
    fn inbound_bulk_feed() {
        let proto = StreamProtocol::DataColumnSidecarsByRoot;
        let mut neg = NegotiateState::new_inbound();

        // Feed header + protocol all at once.
        let mut input = Vec::new();
        input.extend_from_slice(MULTISTREAM_V1);
        input.extend_from_slice(proto.multiselect());
        let action = neg.feed_read(&input);

        // Should want to write confirmation.
        assert!(matches!(action, NegotiateAction::Write));

        let confirm_len = MULTISTREAM_V1.len() + proto.multiselect().len();
        let action = neg.advance_write(confirm_len);
        assert!(matches!(action, NegotiateAction::Done(p) if p == proto));
    }

    #[test]
    fn inbound_partial_write_advance() {
        let proto = StreamProtocol::Goodbye;
        let mut neg = NegotiateState::new_inbound();

        let mut input = Vec::new();
        input.extend_from_slice(MULTISTREAM_V1);
        input.extend_from_slice(proto.multiselect());
        neg.feed_read(&input);

        // Advance write one byte at a time.
        let confirm_len = MULTISTREAM_V1.len() + proto.multiselect().len();
        for i in 0..confirm_len {
            let action = neg.advance_write(1);
            if i < confirm_len - 1 {
                assert!(matches!(action, NegotiateAction::Write));
            } else {
                assert!(matches!(action, NegotiateAction::Done(p) if p == proto));
            }
        }
    }
}
