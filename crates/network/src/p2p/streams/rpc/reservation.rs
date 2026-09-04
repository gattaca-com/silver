use std::{
    io::{Error, ErrorKind},
    ops::RangeInclusive,
};

use silver_common::{
    P2pStreamId, RpcRequest, RpcResponse, StreamProtocol, TCacheProducer, TProducer, TReservation,
    ssz_view::{
        BLOCKS_BY_RANGE_REQ_SIZE, BLOCKS_BY_ROOT_REQ_MAX, DATA_COLUMN_SIDECAR_GLOAS_MIN,
        DATA_COLUMN_SIDECAR_MAX, DC_BY_RANGE_REQ_MAX, DC_BY_RANGE_REQ_MIN, DC_BY_ROOT_SINGLE_SIZE,
        EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE, EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_REQ_MAX,
        GOODBYE_SIZE, MAX_PAYLOAD_SIZE, METADATA_SIZE, PING_SIZE, SIGNED_BEACON_BLOCK_MAX,
        SIGNED_BEACON_BLOCK_MIN, SIGNED_EXECUTION_PAYLOAD_ENVELOPE_MIN, STATUS_V1_SIZE,
        STATUS_V2_SIZE,
    },
};

fn payload_bounds(id: &P2pStreamId) -> RangeInclusive<usize> {
    let exact = |n: usize| n..=n;
    if id.is_incoming() {
        // Requests.
        match id.protocol() {
            StreamProtocol::StatusV1 => exact(STATUS_V1_SIZE),
            StreamProtocol::StatusV2 => exact(STATUS_V2_SIZE),
            StreamProtocol::Ping => exact(PING_SIZE),
            StreamProtocol::Goodbye => exact(GOODBYE_SIZE),
            StreamProtocol::Metadata => 0..=0,
            StreamProtocol::BeaconBlocksByRange => exact(BLOCKS_BY_RANGE_REQ_SIZE),
            StreamProtocol::ExecutionPayloadEnvelopesByRange => {
                exact(EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE)
            }
            StreamProtocol::DataColumnSidecarsByRange => DC_BY_RANGE_REQ_MIN..=DC_BY_RANGE_REQ_MAX,
            StreamProtocol::BeaconBlocksByRoot => 32..=BLOCKS_BY_ROOT_REQ_MAX,
            StreamProtocol::ExecutionPayloadEnvelopesByRoot => {
                32..=EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_REQ_MAX
            }
            // Variable-size identifiers, so only the tcache caps the total.
            StreamProtocol::DataColumnSidecarsByRoot => DC_BY_ROOT_SINGLE_SIZE..=MAX_PAYLOAD_SIZE,
            _ => 0..=0,
        }
    } else {
        // Responses.
        match id.protocol() {
            StreamProtocol::StatusV1 => exact(STATUS_V1_SIZE),
            StreamProtocol::StatusV2 => exact(STATUS_V2_SIZE),
            StreamProtocol::Ping => exact(PING_SIZE),
            StreamProtocol::Metadata => exact(METADATA_SIZE),
            StreamProtocol::BeaconBlocksByRange | StreamProtocol::BeaconBlocksByRoot => {
                SIGNED_BEACON_BLOCK_MIN..=SIGNED_BEACON_BLOCK_MAX
            }
            // Both sidecar layouts share the protocol; gloas is the shorter.
            StreamProtocol::DataColumnSidecarsByRange |
            StreamProtocol::DataColumnSidecarsByRoot => {
                DATA_COLUMN_SIDECAR_GLOAS_MIN..=DATA_COLUMN_SIDECAR_MAX
            }
            StreamProtocol::ExecutionPayloadEnvelopesByRange |
            StreamProtocol::ExecutionPayloadEnvelopesByRoot => {
                SIGNED_EXECUTION_PAYLOAD_ENVELOPE_MIN..=MAX_PAYLOAD_SIZE
            }
            _ => 0..=0,
        }
    }
}

/// Requests that are a `List[Root, _]`: the length must be whole roots.
fn is_root_list_request(id: &P2pStreamId) -> bool {
    id.is_incoming() &&
        matches!(
            id.protocol(),
            StreamProtocol::BeaconBlocksByRoot | StreamProtocol::ExecutionPayloadEnvelopesByRoot
        )
}

pub fn alloc_incoming_rpc(
    rpc_in: &mut TProducer,
    id: &P2pStreamId,
    len: usize,
) -> Result<RpcReservation, Error> {
    let bounds = payload_bounds(id);
    if !bounds.contains(&len) || (is_root_list_request(id) && !len.is_multiple_of(32)) {
        tracing::warn!(
            ?id,
            len,
            min = bounds.start(),
            max = bounds.end(),
            "rpc chunk length outside the protocol's bounds"
        );
        return Err(ErrorKind::InvalidData.into());
    }
    let (inbound, tcache) = if id.is_incoming() {
        // incoming rpc = request
        match id.protocol() {
            StreamProtocol::StatusV1 => {
                (Rpc::Request(RpcRequest::StatusV1([0u8; STATUS_V1_SIZE])), None)
            }
            StreamProtocol::StatusV2 => {
                (Rpc::Request(RpcRequest::StatusV2([0u8; STATUS_V2_SIZE])), None)
            }
            StreamProtocol::Ping => (Rpc::Request(RpcRequest::Ping([0u8; PING_SIZE])), None),
            StreamProtocol::Goodbye => {
                (Rpc::Request(RpcRequest::Goodbye([0u8; GOODBYE_SIZE])), None)
            }
            StreamProtocol::Metadata => (Rpc::Request(RpcRequest::MetaData), None),
            StreamProtocol::BeaconBlocksByRange => {
                (Rpc::Request(RpcRequest::BlocksByRange([0u8; BLOCKS_BY_RANGE_REQ_SIZE])), None)
            }
            StreamProtocol::BeaconBlocksByRoot => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (Rpc::Request(RpcRequest::BlockByRoot(tcache)), Some(reservation))
            }
            StreamProtocol::DataColumnSidecarsByRange => (
                Rpc::Request(RpcRequest::DataColumnsByRange {
                    ssz: [0u8; DC_BY_RANGE_REQ_MAX],
                    len,
                }),
                None,
            ),
            StreamProtocol::DataColumnSidecarsByRoot => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (Rpc::Request(RpcRequest::DataColumnsByRoot(tcache)), Some(reservation))
            }
            StreamProtocol::ExecutionPayloadEnvelopesByRange => (
                Rpc::Request(RpcRequest::ExecutionPayloadEnvelopesByRange(
                    [0u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE],
                )),
                None,
            ),
            StreamProtocol::ExecutionPayloadEnvelopesByRoot => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (
                    Rpc::Request(RpcRequest::ExecutionPayloadEnvelopesByRoot(tcache)),
                    Some(reservation),
                )
            }
            _ => return Err(ErrorKind::InvalidInput.into()),
        }
    } else {
        match id.protocol() {
            StreamProtocol::StatusV1 => {
                (Rpc::Response(RpcResponse::StatusV1([0u8; STATUS_V1_SIZE])), None)
            }
            StreamProtocol::StatusV2 => {
                (Rpc::Response(RpcResponse::StatusV2([0u8; STATUS_V2_SIZE])), None)
            }
            StreamProtocol::Ping => (Rpc::Response(RpcResponse::Ping([0u8; PING_SIZE])), None),
            StreamProtocol::Metadata => {
                (Rpc::Response(RpcResponse::MetaData([0u8; METADATA_SIZE])), None)
            }
            StreamProtocol::BeaconBlocksByRange => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (
                    Rpc::Response(RpcResponse::BeaconBlock { fork_digest: [0u8; 4], ssz: tcache }),
                    Some(reservation),
                )
            }
            StreamProtocol::BeaconBlocksByRoot => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (
                    Rpc::Response(RpcResponse::BeaconBlock { fork_digest: [0u8; 4], ssz: tcache }),
                    Some(reservation),
                )
            }
            StreamProtocol::DataColumnSidecarsByRange => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (
                    Rpc::Response(RpcResponse::DataColumnSidecar {
                        fork_digest: [0u8; 4],
                        ssz: tcache,
                    }),
                    Some(reservation),
                )
            }
            StreamProtocol::DataColumnSidecarsByRoot => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (
                    Rpc::Response(RpcResponse::DataColumnSidecar {
                        fork_digest: [0u8; 4],
                        ssz: tcache,
                    }),
                    Some(reservation),
                )
            }
            StreamProtocol::ExecutionPayloadEnvelopesByRange |
            StreamProtocol::ExecutionPayloadEnvelopesByRoot => {
                let reservation = rpc_in.reserve(len, true).ok_or(ErrorKind::FileTooLarge)?;
                let tcache = reservation.read();
                (
                    Rpc::Response(RpcResponse::ExecutionPayloadEnvelope {
                        fork_digest: [0u8; 4],
                        ssz: tcache,
                    }),
                    Some(reservation),
                )
            }
            _ => return Err(ErrorKind::InvalidInput.into()),
        }
    };

    Ok(RpcReservation { inbound, offset: 0, tcache })
}

/// `length` is the chunk's varint payload length — the decoded error
/// message lands in `msg`, capped at the spec's 256-byte ErrorMessage
/// limit.
pub fn alloc_error_response(error: u8, length: usize) -> RpcReservation {
    RpcReservation {
        inbound: Rpc::Response(RpcResponse::Error { error, msg: [0u8; 256], len: length.min(256) }),
        offset: 0,
        tcache: None,
    }
}

pub fn rpc_response_context_length(protocol: StreamProtocol) -> usize {
    match protocol {
        StreamProtocol::BeaconBlocksByRange |
        StreamProtocol::BeaconBlocksByRoot |
        StreamProtocol::DataColumnSidecarsByRange |
        StreamProtocol::DataColumnSidecarsByRoot |
        StreamProtocol::ExecutionPayloadEnvelopesByRange |
        StreamProtocol::ExecutionPayloadEnvelopesByRoot => 4,
        _ => 0,
    }
}

#[derive(Debug)]
pub struct RpcReservation {
    inbound: Rpc,
    offset: usize,
    tcache: Option<TReservation>,
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum Rpc {
    Request(RpcRequest),
    Response(RpcResponse),
}

impl RpcReservation {
    pub fn remaining_buffer(&mut self) -> Result<&mut [u8], Error> {
        let buffer = match &mut self.inbound {
            Rpc::Request(req) => match req {
                RpcRequest::StatusV1(s) => &mut s[self.offset..],
                RpcRequest::StatusV2(s) => &mut s[self.offset..],
                RpcRequest::Ping(p) => &mut p[self.offset..],
                RpcRequest::Goodbye(g) => &mut g[self.offset..],
                RpcRequest::MetaData => &mut [],
                RpcRequest::BlocksByRange(b) => &mut b[self.offset..],
                RpcRequest::BlockByRoot(_) => match &mut self.tcache {
                    Some(reservation) => reservation.remaining_buffer()?,
                    None => return Err(ErrorKind::InvalidData.into()), // uses reservation
                },
                RpcRequest::DataColumnsByRange { ssz, len } => &mut ssz[self.offset..*len],
                RpcRequest::DataColumnsByRoot(_) => match &mut self.tcache {
                    Some(reservation) => reservation.remaining_buffer()?,
                    None => return Err(ErrorKind::InvalidData.into()), // uses reservation
                },
                RpcRequest::ExecutionPayloadEnvelopesByRange(b) => &mut b[self.offset..],
                RpcRequest::ExecutionPayloadEnvelopesByRoot(_) => match &mut self.tcache {
                    Some(reservation) => reservation.remaining_buffer()?,
                    None => return Err(ErrorKind::InvalidData.into()), // uses reservation
                },
            },
            Rpc::Response(rsp) => match rsp {
                RpcResponse::StatusV1(s) => &mut s[self.offset..],
                RpcResponse::StatusV2(s) => &mut s[self.offset..],
                RpcResponse::Ping(p) => &mut p[self.offset..],
                RpcResponse::MetaData(m) => &mut m[self.offset..],
                RpcResponse::BeaconBlock { fork_digest, ssz: _ } |
                RpcResponse::DataColumnSidecar { fork_digest, ssz: _ } |
                RpcResponse::ExecutionPayloadEnvelope { fork_digest, ssz: _ } => {
                    if self.offset < fork_digest.len() {
                        &mut fork_digest[self.offset..]
                    } else {
                        match &mut self.tcache {
                            Some(reservation) => reservation.remaining_buffer()?,
                            None => return Err(ErrorKind::InvalidData.into()), // uses reservation
                        }
                    }
                }
                RpcResponse::Error { error: _, msg, len } => &mut msg[self.offset..*len],
                RpcResponse::Complete => return Err(ErrorKind::InvalidData.into()), /* no reservation for Complete */
            },
        };

        Ok(buffer)
    }

    /// Returns whether or not the write is complete.
    pub fn increment_offset(&mut self, written: usize) -> Result<bool, Error> {
        match &mut self.inbound {
            Rpc::Request(_) => match &mut self.tcache {
                Some(reservation) => reservation.increment_offset(written),
                None => self.offset += written,
            },
            Rpc::Response(rsp) => match rsp {
                RpcResponse::BeaconBlock { .. } |
                RpcResponse::DataColumnSidecar { .. } |
                RpcResponse::ExecutionPayloadEnvelope { .. } => {
                    if self.offset < 4 {
                        self.offset += written;
                        debug_assert!(self.offset <= 4);
                    } else {
                        match &mut self.tcache {
                            Some(reservation) => reservation.increment_offset(written),
                            None => return Err(ErrorKind::InvalidData.into()), // uses reservation
                        }
                    }
                }
                _ => self.offset += written,
            },
        }
        // The tcache reservation auto-commits when its offset hits the
        // buffer length; after that the slot's seq is set and any
        // further `cache.write()` call (including via `remaining_buffer`)
        // would error with `WrongSeq`. Treat post-commit as
        // write-complete and skip the probe.
        if let Some(res) = self.tcache.as_ref() &&
            res.is_committed()
        {
            return Ok(true);
        }
        self.remaining_buffer().map(|b| b.is_empty())
    }

    pub fn into_rpc(self) -> Rpc {
        self.inbound
    }
}
