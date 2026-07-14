use quinn_proto::StreamId;
use silver_common::{MULTISTREAM_V1, REJECT_RESPONSE, StreamProtocol};

use super::StreamError;
use crate::p2p::streams::StreamIo;

const MAX_RETRY: usize = 2;

/// The multistream header goes on the wire exactly once per direction: the
/// first inbound response (echo or reject) carries it, later ones start
/// `written` past it. `REJECT_RESPONSE` and the `InWriting` sequence both
/// lay out header-then-line, so the offset skips the header for count > 0.
fn header_written(rejects: usize) -> usize {
    if rejects == 0 { 0 } else { MULTISTREAM_V1.len() }
}

/// Multistream-select negotiation state for a single QUIC stream.
#[derive(Debug)]
pub(crate) enum NegotiateState {
    /// Outbound: writing multistream header + protocol proposal. `header`
    /// is false on reject-retry rounds — the header is exchanged only once
    /// per stream, in both directions.
    OutWriting { protocol: StreamProtocol, written: usize, header: bool },
    /// Outbound: reading back multistream header + protocol echo.
    OutReading { protocol: StreamProtocol, buf: [u8; 96], read: usize, header: bool },
    /// Inbound: reading multistream header (fixed size).
    InReadingHeader { buf: [u8; 20], read: usize },
    /// Inbound: header matched, reading protocol varint + string. Sized for
    /// the longest protocol line (`execution_payload_envelopes_by_range`, 74B).
    InReadingProtocol { buf: [u8; 96], read: usize, count: usize },
    /// Inbound: matched protocol, writing multistream header + protocol echo.
    InWriting { protocol: StreamProtocol, written: usize },
    /// Inbound: unrecognized protocol, writing reject (header + na).
    InWritingReject { written: usize, count: usize },
    /// Negotiation complete.
    Done(StreamProtocol),
}

enum Spin {
    Ok(NegotiateState),
    Next(NegotiateState),
}

impl NegotiateState {
    /// Create state for an outbound stream (we are the dialer).
    pub(crate) fn new_outbound(protocol: StreamProtocol) -> Self {
        Self::OutWriting { protocol, written: 0, header: true }
    }

    /// Create state for an inbound stream (we are the listener).
    pub(crate) fn new_inbound() -> Self {
        Self::InReadingHeader { buf: [0u8; 20], read: 0 }
    }

    /// Loops until negotiate is blocked or complete or errors.
    pub(crate) fn spin<S: StreamIo>(
        mut self,
        id: StreamId,
        io: &mut S,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(id, io)? {
                Spin::Ok(negotiate_state) => return Ok(negotiate_state),
                Spin::Next(negotiate_state) => {
                    self = negotiate_state;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(self, id: StreamId, io: &mut S) -> Result<Spin, StreamError> {
        match self {
            NegotiateState::OutWriting { protocol, mut written, header } => {
                // try to write any remaining negotiate bytes: MULTISELECT_V1 ++
                // protocol.multiselect()
                let before = written;
                if written < MULTISTREAM_V1.len() {
                    written += io.write_to_stream(id, &MULTISTREAM_V1[written..])?;
                } else {
                    let data = protocol.multiselect();
                    let offset = written - MULTISTREAM_V1.len();
                    written += io.write_to_stream(id, &data[offset..])?;

                    if written >= MULTISTREAM_V1.len() + data.len() {
                        return Ok(Spin::Next(Self::OutReading {
                            protocol,
                            buf: [0u8; 96],
                            read: 0,
                            header,
                        }));
                    }
                }
                // Park only on zero progress (quinn write-blocked, Writable
                // armed); a completed header write must continue to the
                // proposal in this spin — no event fires for it.
                let next = Self::OutWriting { protocol, written, header };
                Ok(if written > before { Spin::Next(next) } else { Spin::Ok(next) })
            }
            NegotiateState::OutReading { protocol, mut buf, mut read, header } => {
                // The responder sends the multistream header once per
                // stream; reject-retry responses carry only the echo or
                // another na.
                let hdr_len = if header { MULTISTREAM_V1.len() } else { 0 };
                let total = hdr_len + protocol.multiselect().len();
                // Cap read at `total` so we don't consume bytes that
                // belong to the next protocol (e.g. an identify varint
                // arriving in the same packet as the multistream
                // response). Quinn buffers the surplus internally for
                // the protocol-specific state to read.
                read += io.read_from_stream(id, &mut buf[read..total])?;

                // check for reject
                if read >= hdr_len + REJECT_RESPONSE.len() {
                    if header && &buf[..hdr_len] != MULTISTREAM_V1 {
                        return Err(StreamError::InvalidMultiStreamHeader);
                    }
                    if &buf[hdr_len..hdr_len + REJECT_RESPONSE.len()] == REJECT_RESPONSE {
                        match protocol.next() {
                            Some(next_protocol) => {
                                return Ok(Spin::Next(Self::OutWriting {
                                    protocol: next_protocol,
                                    written: MULTISTREAM_V1.len(),
                                    header: false,
                                }));
                            }
                            None => return Err(StreamError::StreamRejected),
                        }
                    }
                }

                if read >= total {
                    if header && &buf[..hdr_len] != MULTISTREAM_V1 {
                        return Err(StreamError::InvalidMultiStreamHeader);
                    }
                    if &buf[hdr_len..total] != protocol.multiselect() {
                        return Err(StreamError::InvalidMultiStreamProtocol);
                    }
                    return Ok(Spin::Ok(Self::Done(protocol)));
                }

                Ok(Spin::Ok(Self::OutReading { protocol, buf, read, header }))
            }
            NegotiateState::InReadingHeader { mut buf, mut read } => {
                read += io.read_from_stream(id, &mut buf[read..])?;

                if read == buf.len() {
                    if buf[..] != MULTISTREAM_V1[..] {
                        return Err(StreamError::InvalidMultiStreamHeader);
                    }
                    return Ok(Spin::Next(Self::InReadingProtocol {
                        buf: [0u8; 96],
                        read: 0,
                        count: 0,
                    }));
                }

                Ok(Spin::Ok(Self::InReadingHeader { buf, read }))
            }
            NegotiateState::InReadingProtocol { mut buf, mut read, count } => {
                if read == 0 {
                    read += io.read_from_stream(id, &mut buf[..1])?;
                    if read == 0 {
                        return Ok(Spin::Ok(Self::InReadingProtocol { buf, read, count }));
                    }
                }
                let total = buf[0] as usize + 1; // +1 for length byte itself.
                if total > buf.len() {
                    tracing::error!(total, "multiselect len > buffer len");
                    return Ok(Spin::Next(Self::InWritingReject {
                        written: header_written(count),
                        count,
                    }));
                }
                if read < total {
                    read += io.read_from_stream(id, &mut buf[read..total])?;
                }
                if read >= total {
                    match StreamProtocol::from_multiselect(&buf[..total]) {
                        Some(protocol) => {
                            return Ok(Spin::Next(Self::InWriting {
                                protocol,
                                written: header_written(count),
                            }));
                        }
                        None => {
                            tracing::error!(protocol=?str::from_utf8(&buf[..total]),"unrecognized negotiate protocol");
                            return Ok(Spin::Next(Self::InWritingReject {
                                written: header_written(count),
                                count,
                            }));
                        }
                    }
                }

                Ok(Spin::Ok(Self::InReadingProtocol { buf, read, count }))
            }
            NegotiateState::InWriting { protocol, mut written } => {
                let before = written;
                if written < MULTISTREAM_V1.len() {
                    written += io.write_to_stream(id, &MULTISTREAM_V1[written..])?;
                } else {
                    let data = protocol.multiselect();
                    let offset = written - MULTISTREAM_V1.len();
                    written += io.write_to_stream(id, &data[offset..])?;

                    if written >= MULTISTREAM_V1.len() + data.len() {
                        return Ok(Spin::Ok(Self::Done(protocol)));
                    }
                }
                // As `OutWriting`: header-complete must roll into the echo
                // write in this spin; park only when write-blocked.
                let next = Self::InWriting { protocol, written };
                Ok(if written > before { Spin::Next(next) } else { Spin::Ok(next) })
            }
            NegotiateState::InWritingReject { mut written, count } => {
                written += io.write_to_stream(id, &REJECT_RESPONSE[written..])?;
                if written >= REJECT_RESPONSE.len() {
                    if count >= MAX_RETRY {
                        return Err(StreamError::StreamRejected);
                    } else {
                        return Ok(Spin::Next(Self::InReadingProtocol {
                            buf: [0u8; 96],
                            read: 0,
                            count: count + 1,
                        }));
                    }
                }
                Ok(Spin::Ok(Self::InWritingReject { written, count }))
            }
            NegotiateState::Done(protocol) => Ok(Spin::Ok(NegotiateState::Done(protocol))),
        }
    }
}

#[cfg(test)]
mod tests {
    use quinn_proto::{Dir, Side};
    use silver_common::ALL_PROTOCOLS;

    use super::*;
    use crate::p2p::streams::AcquiredRpcOutbound;

    /// In-memory `StreamIo` for driving the negotiation state machine.
    struct MockIo {
        in_buf: Vec<u8>,
        out_buf: Vec<u8>,
        /// If set, cap each write call to this many bytes.
        write_chunk: Option<usize>,
        /// If set, cap each read call to this many bytes.
        read_chunk: Option<usize>,
    }

    impl MockIo {
        fn new() -> Self {
            Self { in_buf: Vec::new(), out_buf: Vec::new(), write_chunk: None, read_chunk: None }
        }

        fn with_input(data: &[u8]) -> Self {
            let mut io = Self::new();
            io.in_buf.extend_from_slice(data);
            io
        }
    }

    impl StreamIo for MockIo {
        fn write_to_stream(&mut self, _id: StreamId, data: &[u8]) -> Result<usize, StreamError> {
            let cap = self.write_chunk.unwrap_or(usize::MAX);
            let n = data.len().min(cap);
            self.out_buf.extend_from_slice(&data[..n]);
            Ok(n)
        }

        fn read_from_stream(
            &mut self,
            _id: StreamId,
            data: &mut [u8],
        ) -> Result<usize, StreamError> {
            let cap = self.read_chunk.unwrap_or(usize::MAX);
            let n = self.in_buf.len().min(data.len()).min(cap);
            data[..n].copy_from_slice(&self.in_buf[..n]);
            self.in_buf.drain(..n);
            Ok(n)
        }

        fn close_write(&mut self, _id: StreamId) -> Result<(), StreamError> {
            Ok(())
        }

        fn rpc_next(&mut self) -> Option<AcquiredRpcOutbound> {
            None
        }

        fn gossip_next(&mut self) -> Option<silver_common::TRead> {
            None
        }
        fn remote_addr(&self) -> std::net::SocketAddr {
            "127.0.0.1:12345".parse().unwrap()
        }
    }

    fn sid() -> StreamId {
        StreamId::new(Side::Client, Dir::Bi, 0)
    }

    /// Drive `spin` until either Done is reached, the negotiation errors, or
    /// progress stalls (state unchanged with no new I/O activity — guards
    /// against infinite loops).
    fn drive(mut state: NegotiateState, io: &mut MockIo) -> Result<NegotiateState, StreamError> {
        for _ in 0..1024 {
            let before_in = io.in_buf.len();
            let before_out = io.out_buf.len();
            state = state.spin(sid(), io)?;
            if matches!(state, NegotiateState::Done(_)) {
                return Ok(state);
            }
            if io.in_buf.len() == before_in && io.out_buf.len() == before_out {
                // No progress — caller is expected to feed more bytes.
                return Ok(state);
            }
        }
        panic!("drive exceeded iteration cap")
    }

    fn echo_for(protocol: StreamProtocol) -> Vec<u8> {
        let mut v = Vec::with_capacity(MULTISTREAM_V1.len() + protocol.multiselect().len());
        v.extend_from_slice(MULTISTREAM_V1);
        v.extend_from_slice(protocol.multiselect());
        v
    }

    #[test]
    fn outbound_all_protocols() {
        for &proto in ALL_PROTOCOLS {
            let mut io = MockIo::with_input(&echo_for(proto));
            let neg = drive(NegotiateState::new_outbound(proto), &mut io).unwrap();
            assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
            assert_eq!(io.out_buf, echo_for(proto));
        }
    }

    #[test]
    fn outbound_bulk_feed() {
        let proto = StreamProtocol::StatusV2;
        let mut io = MockIo::with_input(&echo_for(proto));
        let neg = drive(NegotiateState::new_outbound(proto), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
    }

    #[test]
    fn outbound_byte_by_byte() {
        let proto = StreamProtocol::Ping;
        let mut io = MockIo::with_input(&echo_for(proto));
        io.read_chunk = Some(1);
        io.write_chunk = Some(1);
        let neg = drive(NegotiateState::new_outbound(proto), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        assert_eq!(io.out_buf, echo_for(proto));
    }

    fn expect_err(result: Result<NegotiateState, StreamError>) -> StreamError {
        match result {
            Ok(_) => panic!("expected error, got Ok"),
            Err(e) => e,
        }
    }

    #[test]
    fn outbound_bad_echo_fails() {
        let proto = StreamProtocol::Ping;
        let mut input = Vec::new();
        input.extend_from_slice(MULTISTREAM_V1);
        input.extend(std::iter::repeat_n(0xffu8, proto.multiselect().len()));
        let mut io = MockIo::with_input(&input);
        let err = expect_err(drive(NegotiateState::new_outbound(proto), &mut io));
        assert!(matches!(err, StreamError::InvalidMultiStreamProtocol));
    }

    #[test]
    fn outbound_bad_header_fails() {
        let proto = StreamProtocol::Ping;
        let mut input = MULTISTREAM_V1.to_vec();
        *input.last_mut().unwrap() ^= 0xff;
        input.extend_from_slice(proto.multiselect());
        let mut io = MockIo::with_input(&input);
        let err = expect_err(drive(NegotiateState::new_outbound(proto), &mut io));
        assert!(matches!(err, StreamError::InvalidMultiStreamHeader));
    }

    #[test]
    fn outbound_status_v2_falls_back_to_v1() {
        // Server rejects StatusV2 → state machine retries with StatusV1.
        let mut input = Vec::new();
        input.extend_from_slice(MULTISTREAM_V1);
        input.extend_from_slice(REJECT_RESPONSE);
        let mut io = MockIo::with_input(&input);
        let mut state = drive(NegotiateState::new_outbound(StreamProtocol::StatusV2), &mut io)
            .unwrap_or_else(|_| panic!("expected fallback path, not error"));

        // After fallback the dialler proposes StatusV1; the responder echoes
        // only the protocol — the multistream header is sent once per stream.
        io.in_buf.extend_from_slice(StreamProtocol::StatusV1.multiselect());
        state = drive(state, &mut io).unwrap();
        assert!(matches!(state, NegotiateState::Done(p) if p == StreamProtocol::StatusV1));
    }

    #[test]
    fn outbound_reject_on_retry_fails() {
        let mut input = Vec::new();
        input.extend_from_slice(MULTISTREAM_V1);
        input.extend_from_slice(REJECT_RESPONSE);
        let mut io = MockIo::with_input(&input);
        let state = drive(NegotiateState::new_outbound(StreamProtocol::StatusV2), &mut io)
            .unwrap_or_else(|_| panic!("expected fallback path, not error"));

        // Second reject is a bare na — no header, no protocols left.
        io.in_buf.extend_from_slice(REJECT_RESPONSE);
        let err = expect_err(drive(state, &mut io));
        assert!(matches!(err, StreamError::StreamRejected));
    }

    #[test]
    fn inbound_all_protocols() {
        for &proto in ALL_PROTOCOLS {
            let mut input = MULTISTREAM_V1.to_vec();
            input.extend_from_slice(proto.multiselect());
            let mut io = MockIo::with_input(&input);
            let neg = drive(NegotiateState::new_inbound(), &mut io).unwrap();
            assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
            assert_eq!(io.out_buf, echo_for(proto));
        }
    }

    #[test]
    fn inbound_bulk_feed() {
        let proto = StreamProtocol::DataColumnSidecarsByRoot;
        let mut input = MULTISTREAM_V1.to_vec();
        input.extend_from_slice(proto.multiselect());
        let mut io = MockIo::with_input(&input);
        let neg = drive(NegotiateState::new_inbound(), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        assert_eq!(io.out_buf, echo_for(proto));
    }

    #[test]
    fn inbound_byte_by_byte() {
        let proto = StreamProtocol::Goodbye;
        let mut input = MULTISTREAM_V1.to_vec();
        input.extend_from_slice(proto.multiselect());
        let mut io = MockIo::with_input(&input);
        io.read_chunk = Some(1);
        io.write_chunk = Some(1);
        let neg = drive(NegotiateState::new_inbound(), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        assert_eq!(io.out_buf, echo_for(proto));
    }

    #[test]
    fn inbound_bad_header_fails() {
        let mut input = MULTISTREAM_V1.to_vec();
        *input.last_mut().unwrap() ^= 0xff;
        let mut io = MockIo::with_input(&input);
        let err = expect_err(drive(NegotiateState::new_inbound(), &mut io));
        assert!(matches!(err, StreamError::InvalidMultiStreamHeader));
    }

    #[test]
    fn inbound_unknown_protocol_rejects() {
        let mut input = MULTISTREAM_V1.to_vec();
        // \x0d = 13 = len("/unknown/1.0\n")
        input.extend_from_slice(b"\x0d/unknown/1.0\n");
        let mut io = MockIo::with_input(&input);
        // One unknown proposal: na goes out, the stream stays open awaiting
        // the dialer's next proposal.
        let neg = drive(NegotiateState::new_inbound(), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::InReadingProtocol { .. }));
        assert_eq!(io.out_buf, REJECT_RESPONSE);
    }

    /// The version-fallback walk: dialer proposes an unsupported version,
    /// gets na, proposes a supported one on the same stream. The responder
    /// header goes out exactly once (with the na), the echo is bare.
    #[test]
    fn inbound_unknown_then_known_negotiates() {
        let proto = StreamProtocol::GossipSub;
        let mut input = MULTISTREAM_V1.to_vec();
        input.extend_from_slice(b"\x0f/meshsub/1.3.0\n");
        input.extend_from_slice(proto.multiselect());
        let mut io = MockIo::with_input(&input);
        let neg = drive(NegotiateState::new_inbound(), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        let mut expected = REJECT_RESPONSE.to_vec();
        expected.extend_from_slice(proto.multiselect());
        assert_eq!(io.out_buf, expected);
    }

    /// Rejects are capped: MAX_RETRY re-reads after the first, then the
    /// stream errors. Later nas carry no header.
    #[test]
    fn inbound_reject_cap_errors() {
        let mut input = MULTISTREAM_V1.to_vec();
        for _ in 0..=MAX_RETRY {
            input.extend_from_slice(b"\x0d/unknown/1.0\n");
        }
        let mut io = MockIo::with_input(&input);
        let err = expect_err(drive(NegotiateState::new_inbound(), &mut io));
        assert!(matches!(err, StreamError::StreamRejected));
        let na = &REJECT_RESPONSE[MULTISTREAM_V1.len()..];
        let mut expected = REJECT_RESPONSE.to_vec();
        for _ in 0..MAX_RETRY {
            expected.extend_from_slice(na);
        }
        assert_eq!(io.out_buf, expected);
    }

    #[test]
    fn inbound_partial_write_advance() {
        let proto = StreamProtocol::Goodbye;
        let mut input = MULTISTREAM_V1.to_vec();
        input.extend_from_slice(proto.multiselect());
        let mut io = MockIo::with_input(&input);
        io.write_chunk = Some(1);
        let neg = drive(NegotiateState::new_inbound(), &mut io).unwrap();
        assert!(matches!(neg, NegotiateState::Done(p) if p == proto));
        assert_eq!(io.out_buf, echo_for(proto));
    }
}
