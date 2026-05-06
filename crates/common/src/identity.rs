use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use flux::timing::Nanos;
use secp256k1::{
    Message, PublicKey, SECP256K1,
    ecdsa::Signature,
    hashes::{Hash, sha256},
};

use crate::{
    ALL_PROTOCOLS, Error, Keypair, PeerId, ProtoIdentify, ProtoIdentifyView, StreamProtocol,
    decode_protobuf_pubkey, decode_varint, encode_secp256k1_protobuf,
};

pub const PROTOCOL_VERSION: &str = "eth2/1.0.0";
pub const AGENT_VERSION: &str = "silver/v0.0.1/x86_64-linux";

/// libp2p signed-envelope domain string for peer records.
/// <https://github.com/libp2p/specs/blob/master/RFC/0003-routing-records.md>
const PEER_RECORD_DOMAIN: &[u8] = b"libp2p-peer-record";

/// Multicodec identifying the inner payload as a libp2p PeerRecord (varint
/// 0x0301). Two raw bytes on the wire.
const PEER_RECORD_PAYLOAD_TYPE: &[u8] = &[0x03, 0x01];

/// Multiaddr protocol codes used by eth2.
const MA_IP4: u64 = 4;
const MA_IP6: u64 = 41;
const MA_TCP: u64 = 6;
const MA_UDP: u64 = 273;
const MA_QUIC_V1: u64 = 461;
const MA_P2P: u64 = 421;

/// secp256k1 KeyType in the libp2p PublicKey protobuf.
const KEY_TYPE_SECP256K1: u64 = 2;

#[derive(Clone, Copy, Debug)]
pub struct Identify {
    pub user_agent: [u8; 64],
    pub user_agent_len: usize,
    /// secp256k1 compressed public key (33 bytes).
    pub public_key: [u8; 33],
    /// Stream protocol bitset. Bits map to indices in ALL_PROTOCOLS.
    pub protocols: u32,
    /// p2p addresses
    pub tcp_ipv4: Option<SocketAddr>,
    pub tcp_ipv6: Option<SocketAddr>,
    pub udp_ipv4: Option<SocketAddr>,
    pub udp_ipv6: Option<SocketAddr>,
    /// Observed addr of peer.
    pub observed: Option<SocketAddr>,
    /// Peer id, present if the Identify response was sent by the connection
    /// dialler.
    pub peer_id: Option<PeerId>,
}

impl Default for Identify {
    fn default() -> Self {
        Self {
            user_agent: [0u8; 64],
            user_agent_len: 0,
            public_key: [0u8; 33],
            protocols: Default::default(),
            tcp_ipv4: Default::default(),
            tcp_ipv6: Default::default(),
            udp_ipv4: Default::default(),
            udp_ipv6: Default::default(),
            observed: Default::default(),
            peer_id: Default::default(),
        }
    }
}

impl Identify {
    /// Parse and verify a libp2p `signedPeerRecord` (Identify field 8),
    /// populating `public_key`, `peer_id`, and the v4/v6 tcp/udp address
    /// fields with whatever the inner `PeerRecord` advertises.
    ///
    /// On failure (bad protobuf shape, wrong payload type, signature
    /// mismatch, peer-id / public-key mismatch) returns an error and leaves
    /// `self` untouched. Non-eth2 multiaddrs (DNS, websocket, …) are
    /// silently dropped.
    pub fn verify_signed_record(&mut self, signed_peer_record: &[u8]) -> Result<(), Error> {
        let env = parse_envelope(signed_peer_record)?;

        if env.payload_type != PEER_RECORD_PAYLOAD_TYPE {
            return Err(Error::BadDer);
        }

        // Decode the libp2p PublicKey wrapper inside the envelope. Only
        // secp256k1 is in scope for eth2 peers.
        let (key_type, key_bytes) = decode_protobuf_pubkey(env.public_key)?;
        if key_type != KEY_TYPE_SECP256K1 || key_bytes.len() != 33 {
            return Err(Error::UnsupportedKeyType);
        }
        let pubkey = PublicKey::from_slice(&key_bytes).map_err(|_| Error::BadPublicKey)?;
        let mut compressed = [0u8; 33];
        compressed.copy_from_slice(&key_bytes);

        // Build the canonical signing payload and verify the secp256k1
        // ECDSA signature. SHA-256 prehash matches the libp2p convention
        // (and what `Keypair::sign` produces on our side).
        let canonical = canonical_signing_payload(env.payload_type, env.payload);
        let digest = sha256::Hash::hash(&canonical);
        let msg = Message::from_digest(digest.to_byte_array());
        let sig = Signature::from_der(env.signature).map_err(|_| Error::BadSignature)?;
        SECP256K1.verify_ecdsa(&msg, &sig, &pubkey).map_err(|_| Error::BadSignature)?;

        // Decode the inner PeerRecord and confirm its peer_id matches the
        // signing key — guards against an envelope whose `public_key` was
        // swapped to one the attacker controls but whose payload still
        // claims a different victim's PeerId.
        let record = parse_peer_record(env.payload)?;
        let derived_id = PeerId::from_secp256k1_pubkey(&compressed);
        if record.peer_id != derived_id.as_bytes() {
            return Err(Error::PeerIdMismatch);
        }

        // Verified. Populate.
        self.public_key = compressed;
        self.peer_id = Some(derived_id);
        for ma_bytes in &record.addresses {
            match parse_eth2_multiaddr(ma_bytes) {
                Some(Eth2Addr::TcpV4(s)) => {
                    self.tcp_ipv4.get_or_insert(SocketAddr::new(IpAddr::V4(s.0), s.1));
                }
                Some(Eth2Addr::TcpV6(s)) => {
                    self.tcp_ipv6.get_or_insert(SocketAddr::new(IpAddr::V6(s.0), s.1));
                }
                Some(Eth2Addr::QuicV4(s)) => {
                    self.udp_ipv4.get_or_insert(SocketAddr::new(IpAddr::V4(s.0), s.1));
                }
                Some(Eth2Addr::QuicV6(s)) => {
                    self.udp_ipv6.get_or_insert(SocketAddr::new(IpAddr::V6(s.0), s.1));
                }
                Some(Eth2Addr::PeerId(peer_id)) => {
                    // PeerId multiaddr should not appear in the signed record.
                    if peer_id != derived_id {
                        return Err(Error::PeerIdMismatch);
                    }
                }
                None => continue,
            }
        }

        Ok(())
    }

    /// Build a libp2p `signedPeerRecord` (Identify field 8) covering the
    /// tcp/udp address fields of `self`. `seq` is the monotonic sequence
    /// number embedded in the inner `PeerRecord` (typically wall-clock
    /// nanoseconds — newer records replace older ones at peers).
    ///
    /// The signing keypair determines the embedded public key and
    /// `peer_id` — `self.public_key` and `self.peer_id` are *not* read.
    pub fn signed_peer_record(&self, keypair: &Keypair, seq: u64) -> Vec<u8> {
        let mut record = Vec::with_capacity(96);
        // PeerRecord field 1: peer_id (multihash bytes).
        let pid = keypair.peer_id();
        write_protobuf_len_delim(&mut record, 1, pid.as_bytes());
        // PeerRecord field 2: seq (uint64 varint).
        write_protobuf_varint(&mut record, 2, seq);
        // PeerRecord field 3: addresses (repeated AddressInfo).
        let mut ma_buf = Vec::with_capacity(32);
        for ma in self.address_iter() {
            ma_buf.clear();
            encode_eth2_multiaddr(&ma, &mut ma_buf);
            // AddressInfo { multiaddr = 1 } sub-message.
            let mut inner = Vec::with_capacity(ma_buf.len() + 2);
            write_protobuf_len_delim(&mut inner, 1, &ma_buf);
            write_protobuf_len_delim(&mut record, 3, &inner);
        }

        // Sign over the canonical envelope-payload bytes.
        let canonical = canonical_signing_payload(PEER_RECORD_PAYLOAD_TYPE, &record);
        let signature = keypair.sign(&canonical);

        // Envelope { public_key=1, payload_type=2, payload=3, signature=5 }.
        let pubkey_pb = encode_secp256k1_protobuf(keypair.public_key_compressed());
        let mut env = Vec::with_capacity(pubkey_pb.len() + record.len() + signature.len() + 24);
        write_protobuf_len_delim(&mut env, 1, &pubkey_pb);
        write_protobuf_len_delim(&mut env, 2, PEER_RECORD_PAYLOAD_TYPE);
        write_protobuf_len_delim(&mut env, 3, &record);
        write_protobuf_len_delim(&mut env, 5, &signature);
        env
    }

    pub fn encode_listen_addrs(&self, as_dialler: bool) -> Vec<Vec<u8>> {
        let mut output = Vec::with_capacity(5);
        for addr in self.address_iter() {
            let mut buf = vec![];
            encode_eth2_multiaddr(&addr, &mut buf);
            output.push(buf);
        }
        if as_dialler && let Some(peer_id) = self.peer_id {
            let mut buf = vec![];
            encode_eth2_multiaddr(&Eth2Addr::PeerId(peer_id), &mut buf);
            output.push(buf);
        }
        output
    }

    pub fn as_protobuf(&self, keypair: &Keypair) -> ProtoIdentify {
        (self, keypair).into()
    }

    /// Walk the four eth2-shaped address fields, yielding one `Eth2Addr`
    /// per populated slot.
    fn address_iter(&self) -> impl Iterator<Item = Eth2Addr> + '_ {
        let tcp4 = self.tcp_ipv4.and_then(extract_v4).map(Eth2Addr::TcpV4);
        let tcp6 = self.tcp_ipv6.and_then(extract_v6).map(Eth2Addr::TcpV6);
        let udp4 = self.udp_ipv4.and_then(extract_v4).map(Eth2Addr::QuicV4);
        let udp6 = self.udp_ipv6.and_then(extract_v6).map(Eth2Addr::QuicV6);
        [tcp4, tcp6, udp4, udp6].into_iter().flatten()
    }
}

impl From<(&Identify, &Keypair)> for ProtoIdentify {
    #[allow(clippy::field_reassign_with_default)]
    fn from((identify, keypair): (&Identify, &Keypair)) -> Self {
        let mut proto = ProtoIdentify::default();
        proto.protocolVersion = Some(PROTOCOL_VERSION.to_owned());
        proto.agentVersion = Some(AGENT_VERSION.to_owned());
        // Iterate the protocol table directly so bit-position and array
        // index can't drift. Bit `p.ordinal()` is the canonical encoding.
        proto.protocols = ALL_PROTOCOLS
            .iter()
            .filter(|p| identify.protocols & (1u32 << p.ordinal()) != 0)
            .map(|p| {
                let bytes = p.multiselect();
                // Strip the leading varint length and trailing '\n' — both
                // are multistream-select framing, not part of the protocol
                // ID that goes into Identify's `protocols` field.
                let s =
                    std::str::from_utf8(&bytes[1..bytes.len() - 1]).expect("protocol id is ASCII");
                s.to_owned()
            })
            .collect();
        proto.listenAddrs = identify.encode_listen_addrs(true);
        proto.signedPeerRecord = Some(identify.signed_peer_record(keypair, Nanos::now().0));
        proto.publicKey = Some(encode_secp256k1_protobuf(keypair.public_key_compressed()));

        if let Some(observed) = &identify.observed {
            let vec = encode_observed_addr(observed);
            proto.observedAddr = Some(vec);
        }

        proto
    }
}

pub fn encode_observed_addr(observed: &SocketAddr) -> Vec<u8> {
    // TODO assuming quic p2p
    let addr = match observed.ip() {
        IpAddr::V4(ipv4_addr) => &Eth2Addr::QuicV4((ipv4_addr, observed.port())),
        IpAddr::V6(ipv6_addr) => &Eth2Addr::QuicV6((ipv6_addr, observed.port())),
    };
    let mut vec = vec![];
    encode_eth2_multiaddr(addr, &mut vec);
    vec
}

impl TryFrom<ProtoIdentifyView<'_>> for Identify {
    type Error = Error;

    fn try_from(view: ProtoIdentifyView<'_>) -> Result<Self, Self::Error> {
        view.protocolVersion
            .filter(|p| *p == PROTOCOL_VERSION)
            .ok_or(Error::IdentifyInvalidProtocol)?;
        let agent = view.agentVersion.ok_or(Error::IdentifyMissingAgent)?;

        let mut identify = Identify::default();
        let agent_bytes = agent.as_bytes();
        let len = identify.user_agent.len().min(agent_bytes.len());
        identify.user_agent[..len].copy_from_slice(&agent.as_bytes()[..len]);
        identify.user_agent_len = len;

        if let Some(peer_record) = view.signedPeerRecord {
            identify.verify_signed_record(peer_record)?;
        } else {
            // Fallback path: trust `publicKey` for both the compressed key
            // and the derived peer id. The unsigned `listenAddrs` field is
            // believed only for transport addresses — `/p2p/<id>` entries
            // there must agree with the pubkey-derived id (otherwise an
            // unauthenticated peer could redirect dials).
            let pubkey = view.publicKey.ok_or(Error::IdentifyMissingPubkey)?;
            let (key_type, key_bytes) = decode_protobuf_pubkey(pubkey)?;
            if key_type != KEY_TYPE_SECP256K1 || key_bytes.len() != 33 {
                return Err(Error::UnsupportedKeyType);
            }
            identify.public_key.copy_from_slice(&key_bytes);
            let derived_id = PeerId::from_secp256k1_pubkey(&identify.public_key);
            identify.peer_id = Some(derived_id);

            for addr in view.listenAddrs {
                match parse_eth2_multiaddr(addr).ok_or(Error::IdentifyInvalidMultiAddr)? {
                    Eth2Addr::TcpV4((ip, port)) => {
                        identify.tcp_ipv4 = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
                    }
                    Eth2Addr::TcpV6((ip, port)) => {
                        identify.tcp_ipv6 = Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
                    }
                    Eth2Addr::QuicV4((ip, port)) => {
                        identify.udp_ipv4 = Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
                    }
                    Eth2Addr::QuicV6((ip, port)) => {
                        identify.udp_ipv6 = Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
                    }
                    Eth2Addr::PeerId(peer_id) => {
                        if peer_id != derived_id {
                            return Err(Error::PeerIdMismatch);
                        }
                    }
                }
            }
        }

        for protocol in view.protocols {
            if let Some(stream_protocol) = StreamProtocol::from_multiselect_str(protocol) {
                identify.protocols |= 1 << stream_protocol.ordinal();
            }
        }

        if let Some(observed) = view.observedAddr {
            let addr = match parse_eth2_multiaddr(observed)
                .ok_or(Error::IdentifyInvalidObservedAddr)?
            {
                Eth2Addr::TcpV4((ip, port)) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                Eth2Addr::TcpV6((ip, port)) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                Eth2Addr::QuicV4((ip, port)) => SocketAddr::V4(SocketAddrV4::new(ip, port)),
                Eth2Addr::QuicV6((ip, port)) => SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)),
                Eth2Addr::PeerId(_) => return Err(Error::IdentifyInvalidObservedAddr),
            };
            identify.observed = Some(addr);
        }

        Ok(identify)
    }
}

fn extract_v4(s: SocketAddr) -> Option<(Ipv4Addr, u16)> {
    match s {
        SocketAddr::V4(v) => Some((*v.ip(), v.port())),
        SocketAddr::V6(_) => None,
    }
}

fn extract_v6(s: SocketAddr) -> Option<(Ipv6Addr, u16)> {
    match s {
        SocketAddr::V6(v) => Some((*v.ip(), v.port())),
        SocketAddr::V4(_) => None,
    }
}

fn write_protobuf_len_delim(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    let tag = ((field as u64) << 3) | 2;
    write_varint(out, tag);
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn write_protobuf_varint(out: &mut Vec<u8>, field: u32, value: u64) {
    let tag = (field as u64) << 3;
    write_varint(out, tag);
    write_varint(out, value);
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    let mut buf = [0u8; 10];
    let n = crate::encode_varint(value, &mut buf).expect("varint fits in 10 bytes");
    out.extend_from_slice(&buf[..n]);
}

fn encode_eth2_multiaddr(addr: &Eth2Addr, out: &mut Vec<u8>) {
    match addr {
        Eth2Addr::TcpV4((ip, port)) => {
            write_varint(out, MA_IP4);
            out.extend_from_slice(&ip.octets());
            write_varint(out, MA_TCP);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Eth2Addr::TcpV6((ip, port)) => {
            write_varint(out, MA_IP6);
            out.extend_from_slice(&ip.octets());
            write_varint(out, MA_TCP);
            out.extend_from_slice(&port.to_be_bytes());
        }
        Eth2Addr::QuicV4((ip, port)) => {
            write_varint(out, MA_IP4);
            out.extend_from_slice(&ip.octets());
            write_varint(out, MA_UDP);
            out.extend_from_slice(&port.to_be_bytes());
            write_varint(out, MA_QUIC_V1);
        }
        Eth2Addr::QuicV6((ip, port)) => {
            write_varint(out, MA_IP6);
            out.extend_from_slice(&ip.octets());
            write_varint(out, MA_UDP);
            out.extend_from_slice(&port.to_be_bytes());
            write_varint(out, MA_QUIC_V1);
        }
        Eth2Addr::PeerId(peer_id) => {
            // /p2p has wire-type "L" — multihash bytes are length-prefixed.
            let multihash = peer_id.as_bytes();
            write_varint(out, MA_P2P);
            write_varint(out, multihash.len() as u64);
            out.extend_from_slice(multihash);
        }
    }
}

/// Borrowed view of a parsed libp2p SignedEnvelope.
struct Envelope<'a> {
    public_key: &'a [u8],
    payload_type: &'a [u8],
    payload: &'a [u8],
    signature: &'a [u8],
}

/// Borrowed view of a parsed libp2p PeerRecord. `addresses` holds the raw
/// multiaddr bytes from each `AddressInfo` sub-message.
struct PeerRecord<'a> {
    peer_id: &'a [u8],
    addresses: Vec<&'a [u8]>,
}

fn parse_envelope(data: &[u8]) -> Result<Envelope<'_>, Error> {
    let mut public_key = None;
    let mut payload_type = None;
    let mut payload = None;
    let mut signature = None;
    let mut pos = 0;

    while pos < data.len() {
        let (field, wire, p) = read_tag(data, pos)?;
        pos = p;
        match (field, wire) {
            (1, 2) => public_key = Some(read_len_delim(data, &mut pos)?),
            (2, 2) => payload_type = Some(read_len_delim(data, &mut pos)?),
            (3, 2) => payload = Some(read_len_delim(data, &mut pos)?),
            (5, 2) => signature = Some(read_len_delim(data, &mut pos)?),
            _ => skip_field(data, &mut pos, wire)?,
        }
    }

    Ok(Envelope {
        public_key: public_key.ok_or(Error::BadDer)?,
        payload_type: payload_type.ok_or(Error::BadDer)?,
        payload: payload.ok_or(Error::BadDer)?,
        signature: signature.ok_or(Error::BadDer)?,
    })
}

fn parse_peer_record(data: &[u8]) -> Result<PeerRecord<'_>, Error> {
    let mut peer_id = None;
    let mut addresses = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let (field, wire, p) = read_tag(data, pos)?;
        pos = p;
        match (field, wire) {
            // peer_id
            (1, 2) => peer_id = Some(read_len_delim(data, &mut pos)?),
            // seq — ignored. We don't track freshness in this layer.
            (2, 0) => {
                let (_v, p) = decode_varint(data, pos)?;
                pos = p;
            }
            // addresses (repeated AddressInfo). Each AddressInfo has a
            // single `multiaddr` field 1 (length-delimited bytes).
            (3, 2) => {
                let inner = read_len_delim(data, &mut pos)?;
                if let Some(ma) = parse_address_info(inner)? {
                    addresses.push(ma);
                }
            }
            _ => skip_field(data, &mut pos, wire)?,
        }
    }

    Ok(PeerRecord { peer_id: peer_id.ok_or(Error::BadDer)?, addresses })
}

fn parse_address_info(data: &[u8]) -> Result<Option<&[u8]>, Error> {
    let mut multiaddr = None;
    let mut pos = 0;
    while pos < data.len() {
        let (field, wire, p) = read_tag(data, pos)?;
        pos = p;
        match (field, wire) {
            (1, 2) => multiaddr = Some(read_len_delim(data, &mut pos)?),
            _ => skip_field(data, &mut pos, wire)?,
        }
    }
    Ok(multiaddr)
}

/// Build the canonical bytes that the envelope signature covers:
/// `varint(len(domain)) || domain || varint(len(payload_type)) ||
/// payload_type || varint(len(payload)) || payload`.
fn canonical_signing_payload(payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        10 + PEER_RECORD_DOMAIN.len() + 10 + payload_type.len() + 10 + payload.len(),
    );
    write_len_prefixed(&mut out, PEER_RECORD_DOMAIN);
    write_len_prefixed(&mut out, payload_type);
    write_len_prefixed(&mut out, payload);
    out
}

fn write_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    let mut buf = [0u8; 10];
    let n = crate::encode_varint(bytes.len() as u64, &mut buf).expect("varint fits in 10 bytes");
    out.extend_from_slice(&buf[..n]);
    out.extend_from_slice(bytes);
}

fn read_tag(data: &[u8], pos: usize) -> Result<(u32, u8, usize), Error> {
    let (raw, p) = decode_varint(data, pos)?;
    let field = (raw >> 3) as u32;
    let wire = (raw & 0x07) as u8;
    Ok((field, wire, p))
}

fn read_len_delim<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], Error> {
    let (len, p) = decode_varint(data, *pos)?;
    let len = len as usize;
    if p + len > data.len() {
        return Err(Error::BadDer);
    }
    let slice = &data[p..p + len];
    *pos = p + len;
    Ok(slice)
}

fn skip_field(data: &[u8], pos: &mut usize, wire: u8) -> Result<(), Error> {
    match wire {
        // varint
        0 => {
            let (_, p) = decode_varint(data, *pos)?;
            *pos = p;
        }
        // 64-bit fixed
        1 => {
            if *pos + 8 > data.len() {
                return Err(Error::BadDer);
            }
            *pos += 8;
        }
        // length-delimited
        2 => {
            let _ = read_len_delim(data, pos)?;
        }
        // 32-bit fixed
        5 => {
            if *pos + 4 > data.len() {
                return Err(Error::BadDer);
            }
            *pos += 4;
        }
        // groups (deprecated) and unknown wire types
        _ => return Err(Error::BadDer),
    }
    Ok(())
}

pub enum Eth2Addr {
    TcpV4((Ipv4Addr, u16)),
    TcpV6((Ipv6Addr, u16)),
    QuicV4((Ipv4Addr, u16)),
    QuicV6((Ipv6Addr, u16)),
    PeerId(PeerId),
}

impl std::fmt::Display for Eth2Addr {
    /// Canonical multiaddr string. PeerId multihash uses base58btc per the
    /// multiaddr spec (e.g. `/p2p/16Uiu2HAm...`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TcpV4((ip, port)) => write!(f, "/ip4/{ip}/tcp/{port}"),
            Self::TcpV6((ip, port)) => write!(f, "/ip6/{ip}/tcp/{port}"),
            Self::QuicV4((ip, port)) => write!(f, "/ip4/{ip}/udp/{port}/quic-v1"),
            Self::QuicV6((ip, port)) => write!(f, "/ip6/{ip}/udp/{port}/quic-v1"),
            Self::PeerId(pid) => {
                f.write_str("/p2p/")?;
                write_base58btc(pid.as_bytes(), f)
            }
        }
    }
}

/// Bitcoin-flavoured base58 (excludes 0/O/I/l). PeerId multihashes are at
/// most 42 bytes, so the 256-byte stack scratch covers the worst case
/// (`ceil(42 * log(256)/log(58)) ≈ 58` digits) with margin.
fn write_base58btc(input: &[u8], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    // Repeated long division: feed each input byte (high → low), maintain
    // the partial-quotient digits little-endian in `digits[..len]`.
    let mut digits = [0u8; 256];
    let mut len = 0;
    for &b in input {
        let mut carry = b as u32;
        for d in digits.iter_mut().take(len) {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits[len] = (carry % 58) as u8;
            len += 1;
            carry /= 58;
        }
    }

    // Each leading 0x00 byte → one '1' character.
    for _ in input.iter().take_while(|&&b| b == 0) {
        f.write_str("1")?;
    }
    for i in (0..len).rev() {
        f.write_str(std::str::from_utf8(&[ALPHABET[digits[i] as usize]]).unwrap())?;
    }
    Ok(())
}

/// Match the eth2-supported multiaddr shapes:
/// `/ip4/<a>/tcp/<p>`, `/ip6/<a>/tcp/<p>`, `/ip4/<a>/udp/<p>/quic-v1`,
/// `/ip6/<a>/udp/<p>/quic-v1`. Returns `None` for anything else (DNS, ws,
/// legacy `/quic`, trailing `/p2p/...` etc. — caller drops them).
pub fn parse_eth2_multiaddr(data: &[u8]) -> Option<Eth2Addr> {
    let mut pos = 0;

    // First protocol: ip4 or ip6.
    let (proto, p) = decode_varint(data, pos).ok()?;
    pos = p;
    let ip = match proto {
        MA_IP4 => {
            if pos + 4 > data.len() {
                return None;
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&data[pos..pos + 4]);
            pos += 4;
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        MA_IP6 => {
            if pos + 16 > data.len() {
                return None;
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[pos..pos + 16]);
            pos += 16;
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        MA_P2P => {
            // /p2p value is a varint-length-prefixed multihash. Don't pass
            // the bytes through `from_protobuf_encoded` — those expect the
            // inner protobuf pubkey, not an already-formed multihash.
            let (len, p) = decode_varint(data, pos).ok()?;
            let len = len as usize;
            if p + len > data.len() {
                return None;
            }
            let peer_id = PeerId::from_multihash_bytes(&data[p..p + len])?;
            return Some(Eth2Addr::PeerId(peer_id));
        }
        _ => return None,
    };

    // Second protocol: tcp or udp + 2-byte port.
    let (proto, p) = decode_varint(data, pos).ok()?;
    pos = p;
    if proto != MA_TCP && proto != MA_UDP {
        return None;
    }
    if pos + 2 > data.len() {
        return None;
    }
    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;

    if proto == MA_TCP {
        // TCP terminates here (or has a /p2p/<peer-id> suffix we ignore).
        return match ip {
            IpAddr::V4(v4) => Some(Eth2Addr::TcpV4((v4, port))),
            IpAddr::V6(v6) => Some(Eth2Addr::TcpV6((v6, port))),
        };
    }

    // UDP must be followed by /quic-v1 for an eth2 multiaddr.
    let (proto, p) = decode_varint(data, pos).ok()?;
    pos = p;
    if proto != MA_QUIC_V1 {
        return None;
    }
    let _ = pos; // /p2p/... suffix permitted but ignored.

    match ip {
        IpAddr::V4(v4) => Some(Eth2Addr::QuicV4((v4, port))),
        IpAddr::V6(v6) => Some(Eth2Addr::QuicV6((v6, port))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Keypair, encode_secp256k1_protobuf};

    fn fresh_identify() -> Identify {
        Identify {
            user_agent: [0u8; 64],
            user_agent_len: 0,
            public_key: [0u8; 33],
            protocols: 0,
            tcp_ipv4: None,
            tcp_ipv6: None,
            udp_ipv4: None,
            udp_ipv6: None,
            observed: None,
            peer_id: None,
        }
    }

    /// Encode a varint into a Vec.
    fn vi(v: u64) -> Vec<u8> {
        let mut buf = [0u8; 10];
        let n = crate::encode_varint(v, &mut buf).unwrap();
        buf[..n].to_vec()
    }

    /// Length-prefixed bytes.
    fn lp(bytes: &[u8]) -> Vec<u8> {
        let mut out = vi(bytes.len() as u64);
        out.extend_from_slice(bytes);
        out
    }

    /// Field-tagged length-delimited entry.
    fn tag_lp(field: u32, bytes: &[u8]) -> Vec<u8> {
        let tag = (field << 3) | 2;
        let mut out = vi(tag as u64);
        out.extend(lp(bytes));
        out
    }

    /// Field-tagged varint entry.
    fn tag_vi(field: u32, v: u64) -> Vec<u8> {
        let tag = field << 3; // wire type 0
        let mut out = vi(tag as u64);
        out.extend(vi(v));
        out
    }

    fn encode_multiaddr_v4_quic(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(vi(MA_IP4));
        out.extend_from_slice(&ip);
        out.extend(vi(MA_UDP));
        out.extend_from_slice(&port.to_be_bytes());
        out.extend(vi(MA_QUIC_V1));
        out
    }

    fn encode_multiaddr_v4_tcp(ip: [u8; 4], port: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(vi(MA_IP4));
        out.extend_from_slice(&ip);
        out.extend(vi(MA_TCP));
        out.extend_from_slice(&port.to_be_bytes());
        out
    }

    /// Build a libp2p PeerRecord protobuf.
    fn encode_peer_record(peer_id: &[u8], seq: u64, addrs: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(tag_lp(1, peer_id));
        out.extend(tag_vi(2, seq));
        for ma in addrs {
            // AddressInfo { multiaddr = 1 } — embed as a sub-message.
            let inner = tag_lp(1, ma);
            out.extend(tag_lp(3, &inner));
        }
        out
    }

    /// Build an Envelope protobuf signed over the canonical payload.
    fn encode_envelope(kp: &Keypair, payload_type: &[u8], payload: &[u8]) -> Vec<u8> {
        let canonical = canonical_signing_payload(payload_type, payload);
        let signature = kp.sign(&canonical);
        let pubkey_pb = encode_secp256k1_protobuf(kp.public_key_compressed());
        let mut out = Vec::new();
        out.extend(tag_lp(1, &pubkey_pb));
        out.extend(tag_lp(2, payload_type));
        out.extend(tag_lp(3, payload));
        out.extend(tag_lp(5, &signature));
        out
    }

    #[test]
    fn verify_round_trip_populates_fields() {
        let kp = Keypair::from_secret(&[11u8; 32]).unwrap();
        let pid = kp.peer_id();
        let quic = encode_multiaddr_v4_quic([127, 0, 0, 1], 9000);
        let tcp = encode_multiaddr_v4_tcp([127, 0, 0, 1], 9001);
        let record = encode_peer_record(pid.as_bytes(), 42, &[quic, tcp]);
        let envelope = encode_envelope(&kp, PEER_RECORD_PAYLOAD_TYPE, &record);

        let mut id = fresh_identify();
        id.verify_signed_record(&envelope).expect("verify");

        assert_eq!(id.public_key, *kp.public_key_compressed());
        assert_eq!(id.peer_id, Some(pid));
        assert_eq!(id.udp_ipv4, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000)));
        assert_eq!(id.tcp_ipv4, Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9001)));
        assert!(id.udp_ipv6.is_none());
        assert!(id.tcp_ipv6.is_none());
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let kp = Keypair::from_secret(&[12u8; 32]).unwrap();
        let pid = kp.peer_id();
        let quic = encode_multiaddr_v4_quic([10, 0, 0, 1], 7777);
        let record = encode_peer_record(pid.as_bytes(), 1, &[quic]);
        let mut envelope = encode_envelope(&kp, PEER_RECORD_PAYLOAD_TYPE, &record);

        // Flip a byte inside the payload (PeerRecord). Signature now over
        // a different canonical message → verify must fail.
        let payload_offset =
            envelope.windows(record.len()).position(|w| w == record.as_slice()).unwrap();
        envelope[payload_offset] ^= 0xff;

        let mut id = fresh_identify();
        let err = id.verify_signed_record(&envelope).unwrap_err();
        assert!(matches!(err, Error::BadSignature), "unexpected err: {err:?}");
        // Untouched on failure.
        assert!(id.peer_id.is_none());
        assert!(id.udp_ipv4.is_none());
    }

    #[test]
    fn verify_rejects_wrong_payload_type() {
        let kp = Keypair::from_secret(&[13u8; 32]).unwrap();
        let pid = kp.peer_id();
        let record = encode_peer_record(pid.as_bytes(), 1, &[]);
        // Wrong multicodec — signature would be valid but parser rejects
        // before it reaches the signature check.
        let envelope = encode_envelope(&kp, &[0xaa, 0xbb], &record);

        let mut id = fresh_identify();
        let err = id.verify_signed_record(&envelope).unwrap_err();
        assert!(matches!(err, Error::BadDer), "unexpected err: {err:?}");
    }

    #[test]
    fn verify_rejects_peer_id_swap() {
        // Sign with kp_a but stuff kp_b's peer_id into the inner record.
        let kp_a = Keypair::from_secret(&[14u8; 32]).unwrap();
        let kp_b = Keypair::from_secret(&[15u8; 32]).unwrap();
        let record = encode_peer_record(kp_b.peer_id().as_bytes(), 1, &[]);
        let envelope = encode_envelope(&kp_a, PEER_RECORD_PAYLOAD_TYPE, &record);

        let mut id = fresh_identify();
        let err = id.verify_signed_record(&envelope).unwrap_err();
        assert!(matches!(err, Error::PeerIdMismatch), "unexpected err: {err:?}");
    }

    /// Encode → decode loop through both public methods only. Catches any
    /// drift between `signed_peer_record`'s emitted bytes and the spec
    /// shape `verify_signed_record` expects.
    #[test]
    fn signed_peer_record_round_trip() {
        let kp = Keypair::from_secret(&[16u8; 32]).unwrap();
        let pid = kp.peer_id();

        let mut src = fresh_identify();
        src.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7777));
        src.tcp_ipv6 =
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 7778));
        src.udp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000));
        src.udp_ipv6 =
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)), 9001));

        let bytes = src.signed_peer_record(&kp, 1234567890);

        let mut dst = fresh_identify();
        dst.verify_signed_record(&bytes).expect("verify");

        assert_eq!(dst.peer_id, Some(pid));
        assert_eq!(dst.public_key, *kp.public_key_compressed());
        assert_eq!(dst.tcp_ipv4, src.tcp_ipv4);
        assert_eq!(dst.tcp_ipv6, src.tcp_ipv6);
        assert_eq!(dst.udp_ipv4, src.udp_ipv4);
        assert_eq!(dst.udp_ipv6, src.udp_ipv6);
    }

    /// Empty Identify (no advertised addrs) must still produce a verifiable
    /// envelope — the `seq` and `peer_id` fields alone are sufficient.
    #[test]
    fn signed_peer_record_no_addresses() {
        let kp = Keypair::from_secret(&[17u8; 32]).unwrap();
        let src = fresh_identify();
        let bytes = src.signed_peer_record(&kp, 1);

        let mut dst = fresh_identify();
        dst.verify_signed_record(&bytes).expect("verify");
        assert_eq!(dst.peer_id, Some(kp.peer_id()));
        assert!(dst.tcp_ipv4.is_none());
        assert!(dst.tcp_ipv6.is_none());
        assert!(dst.udp_ipv4.is_none());
        assert!(dst.udp_ipv6.is_none());
    }

    #[test]
    fn eth2_addr_display_ip_variants() {
        let v4 = Ipv4Addr::new(127, 0, 0, 1);
        let v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        assert_eq!(Eth2Addr::TcpV4((v4, 9000)).to_string(), "/ip4/127.0.0.1/tcp/9000");
        assert_eq!(Eth2Addr::TcpV6((v6, 9001)).to_string(), "/ip6/fe80::1/tcp/9001");
        assert_eq!(Eth2Addr::QuicV4((v4, 9000)).to_string(), "/ip4/127.0.0.1/udp/9000/quic-v1");
        assert_eq!(Eth2Addr::QuicV6((v6, 9001)).to_string(), "/ip6/fe80::1/udp/9001/quic-v1");
    }

    #[test]
    fn eth2_addr_display_peer_id_round_trip() {
        // The base58btc output must round-trip via libp2p-identity's
        // canonical multihash-string parse — but since we don't pull that
        // dep, validate by checking known-prefix shape and length range.
        let kp = Keypair::from_secret(&[5u8; 32]).unwrap();
        let s = Eth2Addr::PeerId(kp.peer_id()).to_string();
        assert!(s.starts_with("/p2p/"), "expected /p2p/ prefix, got {s}");
        // secp256k1 PeerIds are identity-multihashes of a 37-byte protobuf,
        // hence 39-byte multihashes which encode to ~52–54 base58 chars.
        let id_part = &s["/p2p/".len()..];
        assert!(
            (50..=58).contains(&id_part.len()),
            "unexpected base58 length {} for {s}",
            id_part.len()
        );
        // Bitcoin alphabet excludes 0/O/I/l.
        assert!(
            id_part.chars().all(|c| !matches!(c, '0' | 'O' | 'I' | 'l')),
            "base58btc alphabet violation in {s}"
        );
        // Lighthouse-style prefix sanity: secp256k1 identity-multihash always
        // starts with the same two bytes (0x00 0x25), so the leading base58
        // chars are deterministic ("16U…").
        assert!(id_part.starts_with("16U"), "expected 16U prefix, got {s}");
    }

    /// Round-trip an `Eth2Addr::PeerId` through encode/parse. Also asserts
    /// the wire framing is `varint(421) || varint(len) || multihash` so we
    /// stay interoperable with libp2p.
    #[test]
    fn eth2_addr_peer_id_round_trip() {
        let kp = Keypair::from_secret(&[19u8; 32]).unwrap();
        let pid = kp.peer_id();

        let mut wire = Vec::new();
        encode_eth2_multiaddr(&Eth2Addr::PeerId(pid), &mut wire);

        // varint(421) = 0xA5 0x03 (LE); varint(39) = 0x27; then 39 bytes of
        // multihash.
        let multihash = pid.as_bytes();
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0xa5, 0x03]);
        expected.push(multihash.len() as u8);
        expected.extend_from_slice(multihash);
        assert_eq!(wire, expected);

        let parsed = parse_eth2_multiaddr(&wire).expect("parse");
        match parsed {
            Eth2Addr::PeerId(got) => {
                assert_eq!(got.as_bytes(), multihash);
                assert_eq!(got, pid);
            }
            other => panic!("unexpected variant: {:?}", std::mem::discriminant(&other)),
        }
    }

    /// `Identify` → `ProtoIdentify` → wire bytes → `ProtoIdentifyView`
    /// → `Identify`. Validates the full encoder/decoder pair, including
    /// the protocols-bitset round-trip and address-field preservation.
    #[test]
    fn identify_proto_round_trip() {
        use buffa::{Message, MessageView};

        let kp = Keypair::from_secret(&[23u8; 32]).unwrap();

        let mut src = Identify::default();
        src.tcp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 7777));
        src.udp_ipv4 = Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 9000));
        src.protocols = (1u32 << StreamProtocol::GossipSub.ordinal()) |
            (1u32 << StreamProtocol::StatusV2.ordinal()) |
            (1u32 << StreamProtocol::Ping.ordinal());

        // Encode to protobuf bytes.
        let proto = src.as_protobuf(&kp);
        let mut wire = Vec::new();
        proto.encode(&mut wire);

        // Decode back through the view.
        let view = ProtoIdentifyView::decode_view(&wire).expect("decode");
        let dst = Identify::try_from(view).expect("try_from");

        assert_eq!(dst.peer_id, Some(kp.peer_id()));
        assert_eq!(dst.public_key, *kp.public_key_compressed());
        assert_eq!(dst.tcp_ipv4, src.tcp_ipv4);
        assert_eq!(dst.udp_ipv4, src.udp_ipv4);
        assert_eq!(dst.protocols, src.protocols, "protocols bitset must round-trip");
    }

    #[test]
    fn base58btc_known_vectors() {
        // Known Bitcoin-Wiki vectors — sanity-check the base58 encoder.
        struct V(&'static [u8], &'static str);
        let cases = [
            V(b"", ""),
            V(&[0x00], "1"),
            V(&[0x00, 0x00, 0x01], "112"),
            V(b"Hello World!", "2NEpo7TZRRrLZSi2U"),
        ];
        for V(input, expected) in cases {
            let mut s = String::new();
            std::fmt::write(&mut s, format_args!("{}", DisplayBase58(input))).unwrap();
            assert_eq!(s, expected, "input={input:?}");
        }
    }

    /// Helper struct so we can exercise `write_base58btc` through `Display`
    /// without going via `Eth2Addr` (whose PeerId variant has a fixed
    /// 39-byte input).
    struct DisplayBase58<'a>(&'a [u8]);
    impl<'a> std::fmt::Display for DisplayBase58<'a> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            super::write_base58btc(self.0, f)
        }
    }
}
