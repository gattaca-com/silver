use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use buffa::MessageView;
use silver_common::{
    Identify, P2pStreamId, PROTOCOL_VERSION, PeerId, StreamProtocol, decode_varint,
    parse_eth2_multiaddr,
};

use crate::p2p::{
    generated::IdentifyView,
    streams::{StreamError, StreamIo},
};

const MAX_MESSAGE_SIZE: u64 = 4096;

/// State machine for reading identift protobuf
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ReadIdentifyResponse {
    /// Reading the response varint length
    ReadingLength { buf: [u8; 10], read: usize },
    /// Reading protobuf bytes.
    ReadingBody { buffer: Vec<u8>, read: usize },
    /// Request read completed
    Complete { identify: Identify },
}

impl Default for ReadIdentifyResponse {
    fn default() -> Self {
        Self::ReadingLength { buf: [0; 10], read: 0 }
    }
}

enum Spin {
    Ok(ReadIdentifyResponse),
    Next(ReadIdentifyResponse),
}

impl ReadIdentifyResponse {
    pub fn spin<S: StreamIo>(
        mut self,
        io: &mut S,
        p2p_id: &P2pStreamId,
    ) -> Result<Self, StreamError> {
        loop {
            match self.spin_inner(io, p2p_id)? {
                Spin::Ok(read_state) => return Ok(read_state),
                Spin::Next(read_state) => {
                    self = read_state;
                }
            }
        }
    }

    fn spin_inner<S: StreamIo>(
        self,
        io: &mut S,
        p2p_id: &P2pStreamId,
    ) -> Result<Spin, StreamError> {
        match self {
            ReadIdentifyResponse::ReadingLength { mut buf, mut read } => {
                read += io.read_from_stream(p2p_id.stream_id(), &mut buf[read..])?;
                if read > 0 {
                    for pos in 0..read {
                        if buf[pos] & 0x80 == 0 {
                            // last byte of varint.
                            let (length, offset) = decode_varint(&buf[..read], 0)?;
                            if length > MAX_MESSAGE_SIZE {
                                return Err(StreamError::IdentifyTooBig);
                            }

                            let mut buffer = vec![0u8; length as usize];
                            if offset < read {
                                // copy remainder into the response buffer
                                buffer[..(read - offset)].copy_from_slice(&buf[offset..read]);
                            }

                            return Ok(Spin::Next(Self::ReadingBody {
                                buffer,
                                read: read - offset,
                            }));
                        }
                    }
                }
                Ok(Spin::Ok(Self::ReadingLength { buf, read }))
            }
            ReadIdentifyResponse::ReadingBody { mut buffer, mut read } => {
                read +=
                    io.read_from_stream(p2p_id.stream_id(), &mut buffer.as_mut_slice()[read..])?;

                if read == buffer.len() {
                    let view = IdentifyView::decode_view(&buffer)?;
                    Ok(Spin::Ok(Self::Complete { identify: to_identify(view)? }))
                } else {
                    Ok(Spin::Ok(Self::ReadingBody { buffer, read }))
                }
            }
            ReadIdentifyResponse::Complete { identify } => {
                Ok(Spin::Ok(Self::Complete { identify }))
            }
        }
    }
}

fn to_identify(view: IdentifyView<'_>) -> Result<Identify, StreamError> {
    view.protocolVersion
        .filter(|p| *p == PROTOCOL_VERSION)
        .ok_or(StreamError::InvalidIdentifyProtocol)?;
    let agent = view.agentVersion.ok_or(StreamError::MissingIdentifyAgent)?;

    let mut identify = Identify::default();
    let agent_bytes = agent.as_bytes();
    let len = identify.user_agent.len().min(agent_bytes.len());
    identify.user_agent[..len].copy_from_slice(&agent.as_bytes()[..len]);
    identify.user_agent_len = len;

    if let Some(peer_record) = view.signedPeerRecord {
        identify.verify_signed_record(peer_record)?;
    } else {
        let peer_id = view
            .publicKey
            .map(PeerId::from_protobuf_encoded)
            .ok_or(StreamError::MissingIdentifyPubkey)?;
        for addr in view.listenAddrs {
            match parse_eth2_multiaddr(addr).ok_or(StreamError::InvalidIdentifyMultiAddr)? {
                silver_common::Eth2Addr::TcpV4((ip, port)) => {
                    identify.tcp_ipv4 = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
                }
                silver_common::Eth2Addr::TcpV6((ip, port)) => {
                    identify.tcp_ipv6 = Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
                }
                silver_common::Eth2Addr::QuicV4((ip, port)) => {
                    identify.udp_ipv4 = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
                }
                silver_common::Eth2Addr::QuicV6((ip, port)) => {
                    identify.udp_ipv6 = Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
                }
                silver_common::Eth2Addr::PeerId(peer_id) => identify.peer_id = Some(peer_id),
            }
        }
    }

    for protocol in view.protocols {
        if let Some(stream_protocol) = StreamProtocol::from_multiselect_str(protocol) {
            identify.protocols |= 1 << stream_protocol.ordinal();
        }
    }

    if let Some(observed) = view.observedAddr {
        let addr =
            match parse_eth2_multiaddr(observed).ok_or(StreamError::InvalidIdentifyObservedAddr)? {
                silver_common::Eth2Addr::TcpV4((ip, port)) => {
                    SocketAddr::V4(SocketAddrV4::new(ip, port))
                }
                silver_common::Eth2Addr::TcpV6((ip, port)) => {
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
                }
                silver_common::Eth2Addr::QuicV4((ip, port)) => {
                    SocketAddr::V4(SocketAddrV4::new(ip, port))
                }
                silver_common::Eth2Addr::QuicV6((ip, port)) => {
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))
                }
                silver_common::Eth2Addr::PeerId(_) => {
                    return Err(StreamError::InvalidIdentifyObservedAddr)
                }
            };
        identify.observed = Some(addr);
    }

    Ok(identify)
}
