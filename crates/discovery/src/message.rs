use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aes::cipher::{KeyIvInit, StreamCipher};
use alloy_rlp::{Decodable, Encodable, Header};
use bytes::BufMut;
use flux::utils::ArrayVec;
use silver_common::NodeId;

use crate::crypto::{MAX_PACKET_SIZE, SessionCipher, encrypt_message};

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

pub const IV_LENGTH: usize = 16;

/// 6 (protocol_id) + 2 (version) + 1 (flag) + 12 (nonce) + 2 (authdata-size).
pub const STATIC_HEADER_LENGTH: usize = 23;
const MIN_PACKET_SIZE: usize = IV_LENGTH + STATIC_HEADER_LENGTH + 24;

pub const ENR_RECORD_MAX: usize = 300;

const PROTOCOL_ID: [u8; 6] = *b"discv5";
const PROTOCOL_VERSION: [u8; 2] = [0x00, 0x01];

const FLAG_MSG: u8 = 0;
const FLAG_WHOAREYOU: u8 = 1;
const FLAG_HANDSHAKE: u8 = 2;

const MAX_HEADER_SIZE: usize = STATIC_HEADER_LENGTH + 131 + ENR_RECORD_MAX;

pub type Distances = ArrayVec<u64, 64>;

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum Message {
    Ping { request_id: u64, enr_seq: u64 },
    Pong { request_id: u64, enr_seq: u64, ip: IpAddr, port: u16 },
    FindNode { request_id: u64, distances: Distances },
    Nodes { request_id: u64, total: u8, nodes: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8> },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    #[error("packet exceeds max size ({MAX_PACKET_SIZE} bytes)")]
    TooLarge,
    #[error("packet below min size ({MIN_PACKET_SIZE} bytes)")]
    TooSmall,
    #[error("auth-data length mismatch for packet kind")]
    InvalidAuthDataSize,
    #[error("AES-CTR header decryption produced invalid protocol header")]
    HeaderDecryptionFailed,
    #[error("unknown packet flag")]
    UnknownPacket,
    #[error("invalid node ID in auth-data")]
    InvalidNodeId,
    #[error("unsupported protocol version {0:#06x}")]
    InvalidVersion(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum MessageKind {
    Message,
    WhoAreYou {
        id_nonce: [u8; 16],
        enr_seq: u64,
    },
    Handshake {
        id_nonce_sig: [u8; 64],
        ephem_pubkey: [u8; 33],
        enr_record: Option<ArrayVec<u8, ENR_RECORD_MAX>>,
    },
}

pub struct Packet<'a> {
    pub iv: u128,
    pub src_id: NodeId,
    pub nonce: [u8; 12],
    pub kind: MessageKind,
    pub message: &'a [u8],
}

impl Message {
    pub(crate) fn encode(&self, out: &mut dyn BufMut) {
        match self {
            Message::Ping { request_id, enr_seq } => {
                out.put_u8(0x01);
                Header { list: true, payload_length: request_id.length() + enr_seq.length() }
                    .encode(out);
                request_id.encode(out);
                enr_seq.encode(out);
            }
            Message::Pong { request_id, enr_seq, ip, port } => {
                let ip4_bytes;
                let ip6_bytes;
                let ip_bytes: &[u8] = match ip {
                    IpAddr::V4(a) => {
                        ip4_bytes = a.octets();
                        &ip4_bytes
                    }
                    IpAddr::V6(a) => {
                        ip6_bytes = a.octets();
                        &ip6_bytes
                    }
                };
                let payload_len = request_id.length() +
                    enr_seq.length() +
                    ip_bytes.length() +
                    (*port as u64).length();
                out.put_u8(0x02);
                Header { list: true, payload_length: payload_len }.encode(out);
                request_id.encode(out);
                enr_seq.encode(out);
                ip_bytes.encode(out);
                (*port as u64).encode(out);
            }
            Message::FindNode { request_id, distances } => {
                let dist_payload: usize = distances.iter().map(|d| d.length()).sum::<usize>();
                let dist_list_len =
                    Header { list: true, payload_length: dist_payload }.length() + dist_payload;
                let payload_len = request_id.length() + dist_list_len;
                out.put_u8(0x03);
                Header { list: true, payload_length: payload_len }.encode(out);
                request_id.encode(out);
                Header { list: true, payload_length: dist_payload }.encode(out);
                for &d in distances.iter() {
                    d.encode(out);
                }
            }
            Message::Nodes { request_id, total, nodes } => {
                let nodes_payload: usize = nodes.iter().map(|e| e.len()).sum();
                let nodes_list_len =
                    Header { list: true, payload_length: nodes_payload }.length() + nodes_payload;
                let payload_len = request_id.length() + (*total as u64).length() + nodes_list_len;

                out.put_u8(0x04);
                Header { list: true, payload_length: payload_len }.encode(out);
                request_id.encode(out);
                (*total as u64).encode(out);
                Header { list: true, payload_length: nodes_payload }.encode(out);
                for enr in nodes.iter() {
                    out.put_slice(enr.as_slice());
                }
            }
        }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let (&type_byte, rest) = data.split_first()?;
        let mut buf = rest;
        let h = Header::decode(&mut buf).ok()?;
        if !h.list {
            return None;
        }
        let mut payload = &buf[..h.payload_length];

        match type_byte {
            0x01 => {
                let request_id = u64::decode(&mut payload).ok()?;
                let enr_seq = u64::decode(&mut payload).ok()?;
                Some(Message::Ping { request_id, enr_seq })
            }
            0x02 => {
                let request_id = u64::decode(&mut payload).ok()?;
                let enr_seq = u64::decode(&mut payload).ok()?;
                let ip_bytes = bytes::Bytes::decode(&mut payload).ok()?;
                let ip = match ip_bytes.len() {
                    4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(ip_bytes.as_ref()).ok()?)),
                    16 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(ip_bytes.as_ref()).ok()?)),
                    _ => return None,
                };
                let port = u64::decode(&mut payload).ok()? as u16;
                Some(Message::Pong { request_id, enr_seq, ip, port })
            }
            0x03 => {
                let request_id = u64::decode(&mut payload).ok()?;
                let dh = Header::decode(&mut payload).ok()?;
                if !dh.list {
                    return None;
                }
                let mut dist_payload = &payload[..dh.payload_length];
                let mut distances = Distances::new();
                while !dist_payload.is_empty() && !distances.is_full() {
                    distances.push(u64::decode(&mut dist_payload).ok()?);
                }
                Some(Message::FindNode { request_id, distances })
            }
            0x04 => {
                let request_id = u64::decode(&mut payload).ok()?;
                let total = u64::decode(&mut payload).ok()? as u8;
                let nh = Header::decode(&mut payload).ok()?;
                if !nh.list {
                    return None;
                }
                let mut node_list = &payload[..nh.payload_length];
                let mut nodes: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8> = ArrayVec::new();
                while !node_list.is_empty() && !nodes.is_full() {
                    // Capture full raw ENR bytes (list header + payload) for later decode.
                    let before = node_list;
                    let eh = Header::decode(&mut node_list).ok()?;
                    if !eh.list {
                        return None;
                    }
                    if node_list.len() < eh.payload_length {
                        return None;
                    }
                    let hdr_len = before.len() - node_list.len();
                    let total_len = hdr_len + eh.payload_length;
                    if total_len > ENR_RECORD_MAX {
                        return None;
                    }
                    let mut av: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
                    av.extend(before[..total_len].iter().copied());
                    nodes.push(av);
                    node_list = &node_list[eh.payload_length..];
                }
                Some(Message::Nodes { request_id, total, nodes })
            }
            _ => None,
        }
    }
}

impl<'a> Packet<'a> {
    /// Returns `iv || static_header || auth_data` (unmasked) — the AAD /
    /// challenge data for AES-GCM decryption and HKDF session key derivation.
    pub fn authenticated_data(&self) -> ArrayVec<u8, 512> {
        let header = self.build_header();
        let mut ad: ArrayVec<u8, 512> = ArrayVec::new();
        ad.extend(self.iv.to_be_bytes().iter().copied());
        ad.extend(header.iter().copied());
        ad
    }

    pub fn encode(&self, dst_id: &NodeId) -> ArrayVec<u8, MAX_PACKET_SIZE> {
        let mut header = self.build_header();

        let mut key = [0u8; 16];
        key.copy_from_slice(&dst_id.raw()[..16]);
        let iv_arr: [u8; 16] = self.iv.to_be_bytes();
        let mut cipher = Aes128Ctr::new_from_slices(&key, &iv_arr).expect("key=16 iv=16");
        cipher.apply_keystream(header.as_mut_slice());

        let mut out: ArrayVec<u8, MAX_PACKET_SIZE> = ArrayVec::new();
        out.extend(self.iv.to_be_bytes().iter().copied());
        out.extend(header.iter().copied());
        out.extend(self.message.iter().copied());
        out
    }

    /// Encrypt `msg` with `cipher` and encode as a complete wire packet.
    /// Returns `None` only if AES-GCM encryption fails (should not happen with
    /// valid keys).
    pub fn encode_message(
        src_id: NodeId,
        dst_id: NodeId,
        cipher: &SessionCipher,
        msg: Message,
    ) -> Option<ArrayVec<u8, MAX_PACKET_SIZE>> {
        let rng_buf: [u8; 28] = rand::random();
        let nonce: [u8; 12] = rng_buf[..12].try_into().unwrap();
        let iv: u128 = u128::from_be_bytes(rng_buf[12..].try_into().unwrap());

        // max plaintext = MAX_PACKET_SIZE - IV(16) - header(23) - auth_data(32) - GCM
        // tag(16)
        let mut plain: ArrayVec<u8, 1193> = ArrayVec::new();
        msg.encode(&mut plain);
        let tmp = Packet { iv, src_id, nonce, kind: MessageKind::Message, message: &[] };
        let aad = tmp.authenticated_data();
        let ciphertext = encrypt_message(cipher, &nonce, &aad, &plain)?;
        Some(
            Packet { iv, src_id, nonce, kind: MessageKind::Message, message: &ciphertext }
                .encode(&dst_id),
        )
    }

    /// Decode a wire packet, unmasking the header with AES-128-CTR keyed on
    /// `dst_id` (the local node, i.e., masking-key = dest-id[:16]).
    ///
    /// Returns `(packet, authenticated_data)` where `authenticated_data` is
    /// the AAD for AES-GCM and the HKDF challenge_data input.
    pub fn decode(
        dst_id: &NodeId,
        data: &'a [u8],
    ) -> Result<(Self, ArrayVec<u8, 512>), PacketError> {
        if data.len() > MAX_PACKET_SIZE {
            return Err(PacketError::TooLarge);
        }
        if data.len() < MIN_PACKET_SIZE {
            return Err(PacketError::TooSmall);
        }

        let iv_bytes = &data[..IV_LENGTH];
        let mut key = [0u8; 16];
        key.copy_from_slice(&dst_id.raw()[..16]);
        let mut iv_arr = [0u8; IV_LENGTH];
        iv_arr.copy_from_slice(iv_bytes);
        let mut cipher = Aes128Ctr::new_from_slices(&key, &iv_arr).expect("key=16 iv=16");

        let mut static_header: [u8; STATIC_HEADER_LENGTH] =
            data[IV_LENGTH..IV_LENGTH + STATIC_HEADER_LENGTH].try_into().unwrap();
        cipher.apply_keystream(&mut static_header);

        if static_header[..6] != PROTOCOL_ID {
            return Err(PacketError::HeaderDecryptionFailed);
        }
        if static_header[6..8] != PROTOCOL_VERSION {
            let v = u16::from_be_bytes([static_header[6], static_header[7]]);
            return Err(PacketError::InvalidVersion(v));
        }

        let flag = static_header[8];
        let nonce: [u8; 12] = static_header[9..21].try_into().unwrap();
        let auth_data_size = u16::from_be_bytes([static_header[21], static_header[22]]) as usize;

        if auth_data_size > data.len() - (IV_LENGTH + STATIC_HEADER_LENGTH) {
            return Err(PacketError::InvalidAuthDataSize);
        }

        let ad_start = IV_LENGTH + STATIC_HEADER_LENGTH;
        let mut auth_data: ArrayVec<u8, 512> = ArrayVec::new();
        auth_data.extend(data[ad_start..ad_start + auth_data_size].iter().copied());
        cipher.apply_keystream(auth_data.as_mut_slice());

        let msg_start = ad_start + auth_data_size;
        let message = &data[msg_start..];

        let mut authenticated_data: ArrayVec<u8, 512> = ArrayVec::new();
        authenticated_data.extend(iv_bytes.iter().copied());
        authenticated_data.extend(static_header.iter().copied());
        authenticated_data.extend(auth_data.iter().copied());

        let iv = u128::from_be_bytes(iv_bytes.try_into().unwrap());

        let auth_data = auth_data.as_slice();
        let (src_id, kind) = match flag {
            FLAG_MSG => {
                if auth_data.len() != 32 {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                let id = NodeId::new(auth_data.try_into().map_err(|_| PacketError::InvalidNodeId)?);
                (id, MessageKind::Message)
            }
            FLAG_WHOAREYOU => {
                if auth_data.len() != 24 {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                if !message.is_empty() {
                    return Err(PacketError::UnknownPacket);
                }
                let id_nonce: [u8; 16] = auth_data[..16].try_into().unwrap();
                let enr_seq = u64::from_be_bytes(auth_data[16..24].try_into().unwrap());
                (NodeId::new(&[0; 32]), MessageKind::WhoAreYou { id_nonce, enr_seq })
            }
            FLAG_HANDSHAKE => {
                // 32 src_id + 1 sig_size + 1 key_size + 64 sig + 33 pubkey = 131
                if auth_data.len() < 131 {
                    return Err(PacketError::InvalidAuthDataSize);
                }
                let id = NodeId::new(
                    &auth_data[..32].try_into().map_err(|_| PacketError::InvalidNodeId)?,
                );
                let id_nonce_sig: [u8; 64] =
                    auth_data[34..98].try_into().map_err(|_| PacketError::InvalidAuthDataSize)?;
                let ephem_pubkey: [u8; 33] =
                    auth_data[98..131].try_into().map_err(|_| PacketError::InvalidAuthDataSize)?;
                let enr_record = if auth_data.len() > 131 {
                    let tail = &auth_data[131..];
                    if tail.len() > ENR_RECORD_MAX {
                        return Err(PacketError::InvalidAuthDataSize);
                    }
                    let mut av: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
                    av.extend(tail.iter().copied());
                    Some(av)
                } else {
                    None
                };
                (id, MessageKind::Handshake { id_nonce_sig, ephem_pubkey, enr_record })
            }
            _ => return Err(PacketError::UnknownPacket),
        };

        Ok((Packet { iv, src_id, nonce, kind, message }, authenticated_data))
    }

    fn build_header(&self) -> ArrayVec<u8, MAX_HEADER_SIZE> {
        let mut auth_data: ArrayVec<u8, MAX_HEADER_SIZE> = ArrayVec::new();
        let flag = match &self.kind {
            MessageKind::Message => {
                auth_data.extend(self.src_id.raw().iter().copied());
                FLAG_MSG
            }
            MessageKind::WhoAreYou { id_nonce, enr_seq } => {
                auth_data.extend(id_nonce.iter().copied());
                auth_data.extend(enr_seq.to_be_bytes().iter().copied());
                FLAG_WHOAREYOU
            }
            MessageKind::Handshake { id_nonce_sig, ephem_pubkey, enr_record } => {
                auth_data.extend(self.src_id.raw().iter().copied());
                auth_data.push(64u8);
                auth_data.push(33u8);
                auth_data.extend(id_nonce_sig.iter().copied());
                auth_data.extend(ephem_pubkey.iter().copied());
                if let Some(enr) = enr_record {
                    auth_data.extend(enr.iter().copied());
                }
                FLAG_HANDSHAKE
            }
        };

        let mut h: ArrayVec<u8, MAX_HEADER_SIZE> = ArrayVec::new();
        h.extend(PROTOCOL_ID.iter().copied());
        h.extend(PROTOCOL_VERSION.iter().copied());
        h.push(flag);
        h.extend(self.nonce.iter().copied());
        h.extend((auth_data.len() as u16).to_be_bytes().iter().copied());
        h.extend(auth_data.iter().copied());
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_decode(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    fn node_id_1() -> NodeId {
        let sk = k256::ecdsa::SigningKey::from_slice(&hex_decode(
            "eef77acb6c6a6eebc5b363a475ac583ec7eccdb42b6481424c60f59aa326547f",
        ))
        .unwrap();
        NodeId::from(*sk.verifying_key())
    }

    fn node_id_2() -> NodeId {
        let sk = k256::ecdsa::SigningKey::from_slice(&hex_decode(
            "66fb62bfbd66b9177a138c1e5cddbe4f7c30c343e94e68df8769459cb1cde628",
        ))
        .unwrap();
        NodeId::from(*sk.verifying_key())
    }

    #[test]
    fn packet_encode_random() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let iv = 11u128;
        let nonce = [12u8; 12];
        let message = [1u8; 12];

        let expected = hex_decode(
            "0000000000000000000000000000000b4f3ab1857252f96f758330a846b5d3d4a954d738dfcd6d1ed118ecc1d54f9b20fbf2be28db87805b23193e03c455d73d63ac71dfa91ffa010101010101010101010101",
        );

        let encoded = Packet { iv, src_id, nonce, kind: MessageKind::Message, message: &message }
            .encode(&dst_id);
        assert_eq!(encoded.as_slice(), expected.as_slice());
    }

    #[test]
    fn packet_ref_test_encode_whoareyou() {
        let dst_id = node_id_2();
        let nonce: [u8; 12] = hex_decode("0102030405060708090a0b0c").try_into().unwrap();
        let id_nonce: [u8; 16] = hex_decode("0102030405060708090a0b0c0d0e0f10").try_into().unwrap();
        let enr_seq = 0u64;
        let iv = 0u128;

        let expected = hex_decode(
            "00000000000000000000000000000000088b3d434277464933a1ccc59f5967ad1d6035f15e528627dde75cd68292f9e6c27d6b66c8100a873fcbaed4e16b8d",
        );

        let encoded = Packet {
            iv,
            src_id: NodeId::new(&[0; 32]),
            nonce,
            kind: MessageKind::WhoAreYou { id_nonce, enr_seq },
            message: &[],
        }
        .encode(&dst_id);
        assert_eq!(encoded.as_slice(), expected.as_slice());
    }

    #[test]
    fn packet_encode_handshake() {
        let src_id = NodeId::new(&[3; 32]);
        let dst_id = NodeId::new(&[4; 32]);
        let nonce = [52u8; 12];
        let id_nonce_sig = [5u8; 64];
        let ephem_pubkey = [6u8; 33];
        let iv = 0u128;

        let expected = hex_decode(
            "0000000000000000000000000000000035a14bcdb844ae25f36070f07e0b25e765ed72b4d69c99d5fe5a8d438a4b5b518dfead9d80200875c23e31d0acda6f1b2a6124a70e3dc1f2b8b0770f24d8da18605ff3f5b60b090c61515093a88ef4c02186f7d1b5c9a88fdb8cfae239f13e451758751561b439d8044e27cecdf646f2aa1c9ecbd5faf37eb67a4f6337f4b2a885391e631f72deb808c63bf0b0faed23d7117f7a2e1f98c28bd0",
        );

        let encoded = Packet {
            iv,
            src_id,
            nonce,
            kind: MessageKind::Handshake { id_nonce_sig, ephem_pubkey, enr_record: None },
            message: &[],
        }
        .encode(&dst_id);
        assert_eq!(encoded.as_slice(), expected.as_slice());
    }

    #[test]
    fn packet_encode_handshake_enr() {
        let src_id = node_id_1();
        let dst_id = NodeId::new(&[4; 32]);
        let nonce = [52u8; 12];
        let id_nonce_sig = [5u8; 64];
        let ephem_pubkey = [6u8; 33];
        let iv = 0u128;

        let enr: silver_common::Enr = "enr:-IS4QHXuNmr1vGEGVGDcy_sG2BZ7a3A7mbKS812BK_9rToQiF1Lfknsi5o0xKLnGJbTzBssJCzMcIj8SOiu1O9dnfZEBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMT0UIR4Ch7I2GhYViQqbUhIIBUbQoleuTP-Wz1NJksuYN0Y3CCIyg".parse().unwrap();
        let enr_bytes = alloy_rlp::encode(&enr);
        let mut enr_record: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
        enr_record.extend(enr_bytes.iter().copied());

        let expected = hex_decode(
            "0000000000000000000000000000000035a14bcdb844ae25f36070f07e0b25e765ed72b4d69d187c57dd97a97dd558d1d8e6e6b6fed699e55bb02b47d25562e0a6486ff2aba179f2b8b0770f24d8da18605ff3f5b60b090c61515093a88ef4c02186f7d1b5c9a88fdb8cfae239f13e451758751561b439d8044e27cecdf646f2aa1c9ecbd5faf37eb67a4f6337f4b2a885391e631f72deb808c63bf0b0faed23d7117f7a2e1f98c28bd0e9f1ce8b51cc89e592ed2efa671b8efd49e1ce8fd567fdb06ed308267d31f6bd75827812d21e8aa5a6c025e69b67faea57a15c1c9324d16938c4ebe71dba0bd5d7b00bb6de3e846ed37ef13a9d2e271f25233f5d97bbb026223dbe6595210f6a11cbee54589a0c0c20c7bb7c4c5bea46553480e1b7d4e83b2dd8305aac3b15",
        );

        let encoded = Packet {
            iv,
            src_id,
            nonce,
            kind: MessageKind::Handshake {
                id_nonce_sig,
                ephem_pubkey,
                enr_record: Some(enr_record),
            },
            message: &[],
        }
        .encode(&dst_id);
        assert_eq!(encoded.as_slice(), expected.as_slice());
    }

    #[test]
    fn packet_ref_test_encode_message() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let iv = 0u128;
        let nonce = [52u8; 12];
        let ciphertext = [23u8; 12];

        let expected = hex_decode(
            "00000000000000000000000000000000088b3d43427746493294faf2af68559e215d0bce6652be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da171717171717171717171717",
        );

        let encoded =
            Packet { iv, src_id, nonce, kind: MessageKind::Message, message: &ciphertext }
                .encode(&dst_id);
        assert_eq!(encoded.as_slice(), expected.as_slice());
    }

    #[test]
    fn packet_encode_decode_random() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let iv: u128 = rand::random();
        let nonce: [u8; 12] = rand::random();
        let message: Vec<u8> = (0..44).map(|_| rand::random::<u8>()).collect();

        let encoded = Packet { iv, src_id, nonce, kind: MessageKind::Message, message: &message }
            .encode(&dst_id);
        let (decoded, _) = Packet::decode(&dst_id, &encoded).unwrap();

        assert_eq!(decoded.iv, iv);
        assert_eq!(decoded.src_id, src_id);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.kind, MessageKind::Message);
        assert_eq!(decoded.message, message.as_slice());
    }

    #[test]
    fn packet_encode_decode_whoareyou() {
        let dst_id = node_id_2();
        let nonce: [u8; 12] = rand::random();
        let id_nonce: [u8; 16] = rand::random();
        let enr_seq: u64 = rand::random();
        let iv: u128 = rand::random();

        let encoded = Packet {
            iv,
            src_id: NodeId::new(&[0; 32]),
            nonce,
            kind: MessageKind::WhoAreYou { id_nonce, enr_seq },
            message: &[],
        }
        .encode(&dst_id);
        let (decoded, _) = Packet::decode(&dst_id, &encoded).unwrap();

        assert_eq!(decoded.iv, iv);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.kind, MessageKind::WhoAreYou { id_nonce, enr_seq });
        assert!(decoded.message.is_empty());
    }

    #[test]
    fn encode_decode_auth_packet() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let nonce: [u8; 12] = rand::random();
        let id_nonce_sig = [13u8; 64];
        let ephem_pubkey = [11u8; 33];
        let iv: u128 = rand::random();

        let encoded = Packet {
            iv,
            src_id,
            nonce,
            kind: MessageKind::Handshake { id_nonce_sig, ephem_pubkey, enr_record: None },
            message: &[],
        }
        .encode(&dst_id);
        let (decoded, _) = Packet::decode(&dst_id, &encoded).unwrap();

        assert_eq!(decoded.iv, iv);
        assert_eq!(decoded.src_id, src_id);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.kind, MessageKind::Handshake {
            id_nonce_sig,
            ephem_pubkey,
            enr_record: None
        });
        assert!(decoded.message.is_empty());
    }

    #[test]
    fn packet_decode_ref_ping() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let nonce: [u8; 12] = hex_decode("ffffffffffffffffffffffff").try_into().unwrap();
        let ciphertext = hex_decode("b84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc");

        let encoded = hex_decode(
            "00000000000000000000000000000000088b3d4342774649325f313964a39e55ea96c005ad52be8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08dab84102ed931f66d1492acb308fa1c6715b9d139b81acbdcc",
        );

        let (decoded, _) = Packet::decode(&dst_id, &encoded).unwrap();
        assert_eq!(decoded.iv, 0u128);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.kind, MessageKind::Message);
        assert_eq!(decoded.src_id, src_id);
        assert_eq!(decoded.message, ciphertext.as_slice());
    }

    #[test]
    fn packet_decode_ref_ping_handshake() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let nonce: [u8; 12] = hex_decode("ffffffffffffffffffffffff").try_into().unwrap();
        let id_nonce_sig: [u8; 64] = hex_decode("c0a04b36f276172afc66a62848eb0769800c670c4edbefab8f26785e7fda6b56506a3f27ca72a75b106edd392a2cbf8a69272f5c1785c36d1de9d98a0894b2db").try_into().unwrap();
        let ephem_pubkey: [u8; 33] =
            hex_decode("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5")
                .try_into()
                .unwrap();
        let message = hex_decode("f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8");

        let encoded = hex_decode(
            "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad521d8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb252012b2cba3f4f374a90a75cff91f142fa9be3e0a5f3ef268ccb9065aeecfd67a999e7fdc137e062b2ec4a0eb92947f0d9a74bfbf44dfba776b21301f8b65efd5796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524f1eadf5f0f4126b79336671cbcf7a885b1f8bd2a5d839cf8",
        );

        let (decoded, _) = Packet::decode(&dst_id, &encoded).unwrap();
        assert_eq!(decoded.iv, 0u128);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.src_id, src_id);
        assert_eq!(decoded.kind, MessageKind::Handshake {
            id_nonce_sig,
            ephem_pubkey,
            enr_record: None
        });
        assert_eq!(decoded.message, message.as_slice());
    }

    #[test]
    fn packet_decode_ref_ping_handshake_enr() {
        let src_id = node_id_1();
        let dst_id = node_id_2();
        let nonce: [u8; 12] = hex_decode("ffffffffffffffffffffffff").try_into().unwrap();
        let id_nonce_sig: [u8; 64] = hex_decode("a439e69918e3f53f555d8ca4838fbe8abeab56aa55b056a2ac4d49c157ee719240a93f56c9fccfe7742722a92b3f2dfa27a5452f5aca8adeeab8c4d5d87df555").try_into().unwrap();
        let ephem_pubkey: [u8; 33] =
            hex_decode("039a003ba6517b473fa0cd74aefe99dadfdb34627f90fec6362df85803908f53a5")
                .try_into()
                .unwrap();
        let enr: silver_common::Enr = "enr:-H24QBfhsHORjaMtZAZCx2LA4ngWmOSXH4qzmnd0atrYPwHnb_yHTFkkgIu-fFCJCILCuKASh6CwgxLR1ToX1Rf16ycBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQMT0UIR4Ch7I2GhYViQqbUhIIBUbQoleuTP-Wz1NJksuQ".parse().unwrap();
        let enr_bytes = alloy_rlp::encode(&enr);
        let mut enr_record_av: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
        enr_record_av.extend(enr_bytes.iter().copied());
        let message = hex_decode("08d65093ccab5aa596a34d7511401987662d8cf62b139471");

        let encoded = hex_decode(
            "00000000000000000000000000000000088b3d4342774649305f313964a39e55ea96c005ad539c8c7560413a7008f16c9e6d2f43bbea8814a546b7409ce783d34c4f53245d08da4bb23698868350aaad22e3ab8dd034f548a1c43cd246be98562fafa0a1fa86d8e7a3b95ae78cc2b988ded6a5b59eb83ad58097252188b902b21481e30e5e285f19735796706adff216ab862a9186875f9494150c4ae06fa4d1f0396c93f215fa4ef524e0ed04c3c21e39b1868e1ca8105e585ec17315e755e6cfc4dd6cb7fd8e1a1f55e49b4b5eb024221482105346f3c82b15fdaae36a3bb12a494683b4a3c7f2ae41306252fed84785e2bbff3b022812d0882f06978df84a80d443972213342d04b9048fc3b1d5fcb1df0f822152eced6da4d3f6df27e70e4539717307a0208cd208d65093ccab5aa596a34d7511401987662d8cf62b139471",
        );

        let (decoded, _) = Packet::decode(&dst_id, &encoded).unwrap();
        assert_eq!(decoded.iv, 0u128);
        assert_eq!(decoded.nonce, nonce);
        assert_eq!(decoded.src_id, src_id);
        assert_eq!(decoded.kind, MessageKind::Handshake {
            id_nonce_sig,
            ephem_pubkey,
            enr_record: Some(enr_record_av)
        });
        assert_eq!(decoded.message, message.as_slice());
    }

    #[test]
    fn packet_decode_invalid_packet_size() {
        let src_id = node_id_1();

        let data = [0u8; MAX_PACKET_SIZE + 1];
        assert!(matches!(Packet::decode(&src_id, &data), Err(PacketError::TooLarge)));

        let data = [0u8; MIN_PACKET_SIZE - 1];
        assert!(matches!(Packet::decode(&src_id, &data), Err(PacketError::TooSmall)));
    }

    #[test]
    fn test_ping_encode_decode() {
        let msg = Message::Ping { request_id: 42, enr_seq: 7 };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        match Message::decode(&buf).unwrap() {
            Message::Ping { request_id, enr_seq } => {
                assert_eq!(request_id, 42);
                assert_eq!(enr_seq, 7);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_pong_ipv4_encode_decode() {
        use std::net::{IpAddr, Ipv4Addr};
        let msg = Message::Pong {
            request_id: 1,
            enr_seq: 3,
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 9000,
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        match Message::decode(&buf).unwrap() {
            Message::Pong { request_id, enr_seq, ip, port } => {
                assert_eq!(request_id, 1);
                assert_eq!(enr_seq, 3);
                assert_eq!(ip, IpAddr::V4(Ipv4Addr::LOCALHOST));
                assert_eq!(port, 9000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_pong_ipv6_encode_decode() {
        use std::net::{IpAddr, Ipv6Addr};
        let msg = Message::Pong {
            request_id: 2,
            enr_seq: 0,
            ip: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 30303,
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        match Message::decode(&buf).unwrap() {
            Message::Pong { request_id, enr_seq, ip, port } => {
                assert_eq!(request_id, 2);
                assert_eq!(enr_seq, 0);
                assert_eq!(ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
                assert_eq!(port, 30303);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_findnode_encode_decode() {
        let mut distances = Distances::new();
        distances.push(256);
        distances.push(255);
        distances.push(1);
        let msg = Message::FindNode { request_id: 99, distances };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        match Message::decode(&buf).unwrap() {
            Message::FindNode { request_id, distances } => {
                assert_eq!(request_id, 99);
                assert_eq!(distances.as_slice(), &[256u64, 255, 1]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_nodes_encode_decode_enr_bytes() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let enr = silver_common::Enr::builder()
            .ip4(std::net::Ipv4Addr::LOCALHOST)
            .udp4(9000u16)
            .build(&key)
            .unwrap();
        let enr_bytes = alloy_rlp::encode(&enr);
        let mut enr_raw: ArrayVec<u8, ENR_RECORD_MAX> = ArrayVec::new();
        enr_raw.extend(enr_bytes.iter().copied());

        let mut nodes: ArrayVec<ArrayVec<u8, ENR_RECORD_MAX>, 8> = ArrayVec::new();
        nodes.push(enr_raw.clone());

        let msg = Message::Nodes { request_id: 5, total: 1, nodes };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        match Message::decode(&buf).unwrap() {
            Message::Nodes { request_id, total, nodes } => {
                assert_eq!(request_id, 5);
                assert_eq!(total, 1);
                assert_eq!(nodes.len(), 1);
                assert_eq!(nodes[0].as_slice(), enr_raw.as_slice());
            }
            _ => panic!("wrong variant"),
        }
    }
}
