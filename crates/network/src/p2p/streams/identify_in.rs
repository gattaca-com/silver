use silver_common::{P2pStreamId, encode_varint};

use crate::p2p::streams::{StreamError, StreamIo};

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum WriteIdentifyResponse {
    WritingLength { buf: [u8; 10], length: usize, written: usize, response: Vec<u8> },
    WritingResponse { response: Vec<u8>, written: usize },
    Done,
}

impl WriteIdentifyResponse {
    pub fn new(identify_protobuf: Vec<u8>) -> Result<Self, StreamError> {
        // let mut proto = ProtoIdentify::default();
        // proto.protocolVersion = Some(PROTOCOL_VERSION.to_owned());
        // proto.agentVersion = Some(AGENT_VERSION.to_owned());
        // proto.protocols = (0..32).filter_map(|bit| (response.protocols & (1 << bit)
        // == 1).then_some(bit)).map(|idx| {     // multiselect protocol string
        // is the bytes version withuot length prefix and newline suffix.
        //     let mut bytes = ALL_PROTOCOLS[idx].multiselect();
        //     bytes = &bytes[1..bytes.len() - 1];
        //     unsafe { String::from_utf8_unchecked(bytes) }
        // }).collect();
        // proto.listenAddrs = response.encode_listen_addrs(local_dialler);
        // proto.signedPeerRecord = Some(response.signed_peer_record(keypair, seq))

        let mut buf = [0u8; 10];
        let length = encode_varint(identify_protobuf.len() as u64, &mut buf)?;
        Ok(Self::WritingLength { buf, length, written: 0, response: identify_protobuf })
    }
}

enum Spin {
    Ok(WriteIdentifyResponse),
    Next(WriteIdentifyResponse),
}

impl WriteIdentifyResponse {
    pub fn spin<S: StreamIo>(mut self, id: &P2pStreamId, io: &mut S) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(id, io)? {
                Spin::Ok(write_response) => return Ok(write_response),
                Spin::Next(write_response) => {
                    self = write_response;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(self, id: &P2pStreamId, io: &mut S) -> Result<Spin, StreamError> {
        match self {
            WriteIdentifyResponse::WritingLength { buf, length, mut written, response } => {
                written += io.write_to_stream(id.stream_id(), &buf[written..length])?;
                if written == length {
                    Ok(Spin::Next(Self::WritingResponse { response, written: 0 }))
                } else {
                    Ok(Spin::Ok(Self::WritingLength { buf, length, written, response }))
                }
            }
            WriteIdentifyResponse::WritingResponse { response, mut written } => {
                written += io.write_to_stream(id.stream_id(), &response[written..])?;
                if written == response.len() {
                    Ok(Spin::Ok(Self::Done))
                } else {
                    Ok(Spin::Ok(Self::WritingResponse { response, written }))
                }
            }
            WriteIdentifyResponse::Done => Ok(Spin::Ok(Self::Done)),
        }
    }
}
