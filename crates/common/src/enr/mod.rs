// Adapted from https://github.com/sigp/enr (MIT License)

mod builder;
mod keys;
mod node_id;

use std::{
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

use alloy_rlp::{Decodable, Encodable, Error as DecoderError, Header};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
pub use builder::Error;
use bytes::{Buf, BytesMut};
pub use keys::{EnrKey, EnrPublicKey};
pub use node_id::NodeId;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use sha3::{Digest, Keccak256};

pub const MAX_ENR_SIZE: usize = 300;

pub const ID_ENR_KEY: &[u8] = b"id";
pub const ENR_VERSION: &[u8] = b"v4";
pub const IP_ENR_KEY: &[u8] = b"ip";
pub const IP6_ENR_KEY: &[u8] = b"ip6";
pub const UDP_ENR_KEY: &[u8] = b"udp";
pub const UDP6_ENR_KEY: &[u8] = b"udp6";
pub const ETH2_ENR_KEY: &[u8] = b"eth2";
pub const ATTNETS_ENR_KEY: &[u8] = b"attnets";
pub const SYNCNETS_ENR_KEY: &[u8] = b"syncnets";

/// An ENR record with a verified signature.
///
/// Fields are the standard ENR fields relevant to discovery. TCP fields are
/// omitted; the p2p layer uses QUIC. Unknown fields from decoded records are
/// verified against the signature and then dropped.
pub struct Enr<K: EnrKey> {
    seq: u64,
    node_id: NodeId,
    ip4: Option<Ipv4Addr>,
    ip6: Option<Ipv6Addr>,
    udp4: Option<u16>,
    udp6: Option<u16>,
    /// SSZ-encoded ENRForkID: fork_digest[4] + next_fork_version[4] +
    /// next_fork_epoch[8].
    eth2: Option<[u8; 16]>,
    /// Attestation subnet bitfield (SSZ Bitvector[64]).
    attnets: Option<[u8; 8]>,
    /// Sync committee subnet bitfield (lower 4 bits, SSZ Bitvector[4]).
    syncnets: Option<u8>,
    public_key: K::PublicKey,
    signature: [u8; 64],
}

impl<K: EnrKey> Copy for Enr<K> where K::PublicKey: Copy {}

impl<K: EnrKey> Enr<K> {
    pub fn builder() -> builder::Builder<K> {
        builder::Builder::default()
    }

    pub fn empty(signing_key: &K) -> Result<Self, Error> {
        Self::builder().build(signing_key)
    }

    #[inline]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    #[inline]
    pub const fn seq(&self) -> u64 {
        self.seq
    }

    #[inline]
    pub fn ip4(&self) -> Option<Ipv4Addr> {
        self.ip4
    }

    #[inline]
    pub fn ip6(&self) -> Option<Ipv6Addr> {
        self.ip6
    }

    #[inline]
    pub fn udp4(&self) -> Option<u16> {
        self.udp4
    }

    #[inline]
    pub fn udp6(&self) -> Option<u16> {
        self.udp6
    }

    #[inline]
    pub fn udp4_socket(&self) -> Option<SocketAddrV4> {
        Some(SocketAddrV4::new(self.ip4?, self.udp4?))
    }

    #[inline]
    pub fn udp6_socket(&self) -> Option<SocketAddrV6> {
        Some(SocketAddrV6::new(self.ip6?, self.udp6?, 0, 0))
    }

    #[inline]
    pub fn eth2(&self) -> Option<[u8; 16]> {
        self.eth2
    }

    #[inline]
    pub fn attnets(&self) -> Option<[u8; 8]> {
        self.attnets
    }

    #[inline]
    pub fn syncnets(&self) -> Option<u8> {
        self.syncnets
    }

    pub fn set_eth2(&mut self, eth2: [u8; 16], key: &K) -> Result<(), Error> {
        self.apply(key, |enr| enr.eth2 = Some(eth2))
    }

    pub fn set_attnets(&mut self, attnets: [u8; 8], key: &K) -> Result<(), Error> {
        self.apply(key, |enr| enr.attnets = Some(attnets))
    }

    pub fn set_syncnets(&mut self, syncnets: u8, key: &K) -> Result<(), Error> {
        self.apply(key, |enr| enr.syncnets = Some(syncnets))
    }

    /// Always returns `Some("v4")` — this implementation only supports the v4
    /// identity scheme.
    #[inline]
    pub fn id(&self) -> Option<String> {
        Some(String::from_utf8_lossy(ENR_VERSION).into_owned())
    }

    #[inline]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    #[inline]
    pub fn public_key(&self) -> K::PublicKey {
        self.public_key.clone()
    }

    /// Returns true if the ENR's signature is valid against the stored public
    /// key and the fields in this struct.
    ///
    /// Note: this recomputes RLP from the known typed fields only. ENRs that
    /// were decoded from the wire and contained additional fields (e.g. tcp,
    /// custom keys) were verified at decode time; those fields are not present
    /// here and this method will return false for them.
    #[inline]
    pub fn verify(&self) -> bool {
        self.public_key.verify_v4(&self.rlp_content(), &self.signature)
    }

    #[inline]
    pub fn compare_content(&self, other: &Self) -> bool {
        self.rlp_content() == other.rlp_content()
    }

    #[inline]
    pub fn is_udp_reachable(&self) -> bool {
        self.udp4_socket().is_some() || self.udp6_socket().is_some()
    }

    #[inline]
    pub fn to_base64(&self) -> String {
        let mut out = BytesMut::new();
        self.encode(&mut out);
        format!("enr:{}", URL_SAFE_NO_PAD.encode(out))
    }

    #[inline]
    pub fn size(&self) -> usize {
        let mut out = BytesMut::new();
        self.encode(&mut out);
        out.len()
    }

    pub fn set_seq(&mut self, seq: u64, key: &K) -> Result<(), Error> {
        let prev_seq = self.seq;
        let prev_sig = self.signature;
        self.seq = seq;
        if let Err(e) = self.sign(key) {
            self.seq = prev_seq;
            return Err(e);
        }
        if self.size() > MAX_ENR_SIZE {
            self.seq = prev_seq;
            self.signature = prev_sig;
            return Err(Error::ExceedsMaxSize);
        }
        self.node_id = NodeId::from(key.public());
        Ok(())
    }

    pub fn set_ip(&mut self, ip: IpAddr, key: &K) -> Result<Option<IpAddr>, Error> {
        let prev = match ip {
            IpAddr::V4(_) => self.ip4.map(IpAddr::V4),
            IpAddr::V6(_) => self.ip6.map(IpAddr::V6),
        };
        self.apply(key, |enr| match ip {
            IpAddr::V4(addr) => enr.ip4 = Some(addr),
            IpAddr::V6(addr) => enr.ip6 = Some(addr),
        })?;
        Ok(prev)
    }

    pub fn set_udp4(&mut self, udp: u16, key: &K) -> Result<Option<u16>, Error> {
        let prev = self.udp4;
        self.apply(key, |enr| enr.udp4 = Some(udp))?;
        Ok(prev)
    }

    pub fn remove_udp4(&mut self, key: &K) -> Result<(), Error> {
        self.apply(key, |enr| enr.udp4 = None)
    }

    pub fn set_udp6(&mut self, udp: u16, key: &K) -> Result<Option<u16>, Error> {
        let prev = self.udp6;
        self.apply(key, |enr| enr.udp6 = Some(udp))?;
        Ok(prev)
    }

    pub fn remove_udp6(&mut self, key: &K) -> Result<(), Error> {
        self.apply(key, |enr| enr.udp6 = None)
    }

    pub fn set_udp_socket(&mut self, socket: SocketAddr, key: &K) -> Result<(), Error> {
        self.apply(key, |enr| match socket.ip() {
            IpAddr::V4(addr) => {
                enr.ip4 = Some(addr);
                enr.udp4 = Some(socket.port());
            }
            IpAddr::V6(addr) => {
                enr.ip6 = Some(addr);
                enr.udp6 = Some(socket.port());
            }
        })
    }

    pub fn remove_udp_socket(&mut self, key: &K) -> Result<(), Error> {
        self.apply(key, |enr| {
            enr.ip4 = None;
            enr.udp4 = None;
        })
    }

    pub fn remove_udp6_socket(&mut self, key: &K) -> Result<(), Error> {
        self.apply(key, |enr| {
            enr.ip6 = None;
            enr.udp6 = None;
        })
    }

    // Clone, apply f, re-sign, check size, commit.
    fn apply<F>(&mut self, key: &K, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        let mut new = self.clone();
        f(&mut new);
        new.seq = new.seq.checked_add(1).ok_or(Error::SequenceNumberTooHigh)?;
        new.sign(key)?;
        new.node_id = NodeId::from(key.public());
        if new.size() > MAX_ENR_SIZE {
            return Err(Error::ExceedsMaxSize);
        }
        *self = new;
        Ok(())
    }

    // Encode (seq + k-v pairs) into a flat buffer; signature is prepended only
    // when include_signature is true. Keys emitted in lexicographic sorted order:
    //   attnets < ed25519 < eth2 < id < ip < ip6 < secp256k1 < syncnets < udp <
    // udp6
    fn append_rlp_content(&self, stream: &mut BytesMut, include_signature: bool) {
        if include_signature {
            self.signature.as_ref().encode(stream);
        }
        self.seq.encode(stream);

        let pk_key = self.public_key.enr_key();
        let pk_encoded = self.public_key.encode();

        if let Some(attnets) = self.attnets {
            ATTNETS_ENR_KEY.encode(stream);
            attnets.as_ref().encode(stream);
        }
        if pk_key == b"ed25519" {
            pk_key.encode(stream);
            pk_encoded.as_ref().encode(stream);
        }
        if let Some(eth2) = self.eth2 {
            ETH2_ENR_KEY.encode(stream);
            eth2.as_ref().encode(stream);
        }
        ID_ENR_KEY.encode(stream);
        ENR_VERSION.encode(stream);
        if let Some(ip4) = self.ip4 {
            IP_ENR_KEY.encode(stream);
            ip4.octets().as_ref().encode(stream);
        }
        if let Some(ip6) = self.ip6 {
            IP6_ENR_KEY.encode(stream);
            ip6.octets().as_ref().encode(stream);
        }
        if pk_key == b"secp256k1" {
            pk_key.encode(stream);
            pk_encoded.as_ref().encode(stream);
        }
        if let Some(syncnets) = self.syncnets {
            SYNCNETS_ENR_KEY.encode(stream);
            [syncnets].as_ref().encode(stream);
        }
        if let Some(udp4) = self.udp4 {
            UDP_ENR_KEY.encode(stream);
            udp4.encode(stream);
        }
        if let Some(udp6) = self.udp6 {
            UDP6_ENR_KEY.encode(stream);
            udp6.encode(stream);
        }
    }

    // Returns the RLP list used as the signing payload (no signature prefix).
    fn rlp_content(&self) -> BytesMut {
        let mut stream = BytesMut::with_capacity(MAX_ENR_SIZE);
        self.append_rlp_content(&mut stream, false);
        let header = Header { list: true, payload_length: stream.len() };
        let mut out = BytesMut::new();
        header.encode(&mut out);
        out.extend_from_slice(&stream);
        out
    }

    fn sign(&mut self, key: &K) -> Result<[u8; 64], Error> {
        let sig_bytes = key.sign_v4(&self.rlp_content()).map_err(|_| Error::SigningError)?;
        if sig_bytes.len() != 64 {
            return Err(Error::SigningError);
        }
        let mut new_sig = [0u8; 64];
        new_sig.copy_from_slice(&sig_bytes);
        let old = self.signature;
        self.signature = new_sig;
        Ok(old)
    }
}

impl<K: EnrKey> Clone for Enr<K> {
    fn clone(&self) -> Self {
        Self {
            seq: self.seq,
            node_id: self.node_id,
            ip4: self.ip4,
            ip6: self.ip6,
            udp4: self.udp4,
            udp6: self.udp6,
            eth2: self.eth2,
            attnets: self.attnets,
            syncnets: self.syncnets,
            public_key: self.public_key.clone(),
            signature: self.signature,
        }
    }
}

impl<K: EnrKey> Eq for Enr<K> {}

impl<K: EnrKey> PartialEq for Enr<K> {
    fn eq(&self, other: &Self) -> bool {
        self.seq == other.seq && self.node_id == other.node_id && self.signature == other.signature
    }
}

impl<K: EnrKey> Hash for Enr<K> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.seq.hash(state);
        self.node_id.hash(state);
        self.signature.hash(state);
    }
}

impl<K: EnrKey> std::fmt::Display for Enr<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl<K: EnrKey> std::fmt::Debug for Enr<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Enr")
            .field("seq", &self.seq)
            .field("node_id", &self.node_id())
            .field("ip4", &self.ip4)
            .field("ip6", &self.ip6)
            .field("udp4", &self.udp4)
            .field("udp6", &self.udp6)
            .field("signature", &hex::encode(self.signature))
            .finish_non_exhaustive()
    }
}

impl<K: EnrKey> FromStr for Enr<K> {
    type Err = String;

    fn from_str(base64_string: &str) -> Result<Self, Self::Err> {
        if base64_string.len() < 4 {
            return Err("Invalid ENR string".to_string());
        }
        let decode_string = if base64_string.starts_with("enr:") {
            base64_string.get(4..).ok_or_else(|| "Invalid ENR string".to_string())?
        } else {
            base64_string
        };
        let bytes = URL_SAFE_NO_PAD
            .decode(decode_string)
            .map_err(|e| format!("Invalid base64 encoding: {e:?}"))?;
        Self::decode(&mut bytes.as_ref()).map_err(|e| format!("Invalid ENR: {e:?}"))
    }
}

impl<K: EnrKey> Serialize for Enr<K> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de, K: EnrKey> Deserialize<'de> for Enr<K> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s: String = Deserialize::deserialize(deserializer)?;
        Self::from_str(&s).map_err(D::Error::custom)
    }
}

impl<K: EnrKey> Encodable for Enr<K> {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let mut stream = BytesMut::with_capacity(MAX_ENR_SIZE);
        self.append_rlp_content(&mut stream, true);
        let header = Header { list: true, payload_length: stream.len() };
        header.encode(out);
        out.put_slice(&stream);
    }
}

impl<K: EnrKey> Decodable for Enr<K> {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecoderError> {
        if buf.len() > MAX_ENR_SIZE {
            return Err(DecoderError::Custom("enr exceeds max size"));
        }

        let payload = &mut Header::decode_bytes(buf, true)?;

        if payload.is_empty() {
            return Err(DecoderError::Custom("Payload is empty"));
        }
        let sig_bytes = Header::decode_bytes(payload, false)?;
        if sig_bytes.len() != 64 {
            return Err(DecoderError::Custom("Invalid signature length"));
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(sig_bytes);

        if payload.is_empty() {
            return Err(DecoderError::Custom("Seq is missing"));
        }
        let seq = u64::decode(payload)?;

        // Accumulate all k-v pairs verbatim for signature verification.
        // Unknown fields (tcp, custom) are included here but discarded from the
        // typed struct after the check.
        let mut content_list = BytesMut::with_capacity(MAX_ENR_SIZE);
        seq.encode(&mut content_list);

        let mut ip4: Option<Ipv4Addr> = None;
        let mut ip6: Option<Ipv6Addr> = None;
        let mut udp4: Option<u16> = None;
        let mut udp6: Option<u16> = None;
        let mut eth2: Option<[u8; 16]> = None;
        let mut attnets: Option<[u8; 8]> = None;
        let mut syncnets: Option<u8> = None;
        let mut pubkey_info: Option<(&[u8], &[u8])> = None;

        let mut prev: Option<&[u8]> = None;
        while !payload.is_empty() {
            let key = Header::decode_bytes(payload, false)?;
            if let Some(prev) = prev {
                if prev >= key {
                    return Err(DecoderError::Custom("Unsorted keys"));
                }
            }
            prev = Some(key);
            key.encode(&mut content_list);

            let val_start = *payload;
            match key {
                b"id" => {
                    let id = Header::decode_bytes(payload, false)?;
                    if id != b"v4" {
                        return Err(DecoderError::Custom("Unsupported identity scheme"));
                    }
                }
                UDP_ENR_KEY => {
                    udp4 = Some(u16::decode(payload)?);
                }
                UDP6_ENR_KEY => {
                    udp6 = Some(u16::decode(payload)?);
                }
                IP_ENR_KEY => {
                    ip4 = Some(Ipv4Addr::decode(payload)?);
                }
                IP6_ENR_KEY => {
                    ip6 = Some(Ipv6Addr::decode(payload)?);
                }
                b"secp256k1" | b"ed25519" => {
                    let pk_bytes = Header::decode_bytes(payload, false)?;
                    pubkey_info = Some((key, pk_bytes));
                }
                ETH2_ENR_KEY => {
                    let b = Header::decode_bytes(payload, false)?;
                    if b.len() != 16 {
                        return Err(DecoderError::Custom("invalid eth2 length"));
                    }
                    let mut arr = [0u8; 16];
                    arr.copy_from_slice(b);
                    eth2 = Some(arr);
                }
                ATTNETS_ENR_KEY => {
                    let b = Header::decode_bytes(payload, false)?;
                    if b.len() != 8 {
                        return Err(DecoderError::Custom("invalid attnets length"));
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    attnets = Some(arr);
                }
                SYNCNETS_ENR_KEY => {
                    let b = Header::decode_bytes(payload, false)?;
                    if b.len() != 1 {
                        return Err(DecoderError::Custom("invalid syncnets length"));
                    }
                    syncnets = Some(b[0]);
                }
                _ => {
                    // Skip unknown fields (tcp, custom keys, etc.).
                    // Still include their raw bytes in content_list for signature verification.
                    let h = Header::decode(payload)?;
                    if h.payload_length > payload.len() {
                        return Err(DecoderError::InputTooShort);
                    }
                    payload.advance(h.payload_length);
                }
            }
            // Append exact wire bytes for this value into the content accumulator.
            let raw_val = &val_start[..val_start.len() - payload.len()];
            content_list.extend_from_slice(raw_val);
        }

        let (scheme, pk_bytes) = pubkey_info.ok_or(DecoderError::Custom("Missing public key"))?;
        let public_key = K::enr_to_public(scheme, pk_bytes)?;
        let node_id = NodeId::from(public_key.clone());

        // Verify signature over the full content (including skipped fields).
        let content_rlp = {
            let header = Header { list: true, payload_length: content_list.len() };
            let mut out = BytesMut::with_capacity(header.length() + content_list.len());
            header.encode(&mut out);
            out.extend_from_slice(&content_list);
            out
        };
        if !public_key.verify_v4(&content_rlp, &signature) {
            return Err(DecoderError::Custom("Invalid Signature"));
        }

        Ok(Self {
            seq,
            node_id,
            ip4,
            ip6,
            udp4,
            udp6,
            eth2,
            attnets,
            syncnets,
            public_key,
            signature,
        })
    }
}

pub fn digest(b: &[u8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    output.copy_from_slice(&Keccak256::digest(b));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    type DefaultEnr = Enr<k256::ecdsa::SigningKey>;

    #[test]
    fn test_vector_k256() {
        let valid_record = hex::decode("f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c01826964827634826970847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f").unwrap();
        let signature = hex::decode("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c").unwrap();
        let expected_pubkey =
            hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138")
                .unwrap();

        let mut buf = valid_record.as_slice();
        let enr = DefaultEnr::decode(&mut buf).unwrap();
        assert!(buf.is_empty());

        let pubkey = enr.public_key().encode();

        assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(enr.id(), Some(String::from("v4")));
        assert_eq!(enr.udp4(), Some(30303));
        assert_eq!(enr.signature(), &signature[..]);
        assert_eq!(pubkey.to_vec(), expected_pubkey);
        assert!(enr.verify());
    }

    #[test]
    fn test_vector_2() {
        let text = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
        let signature = hex::decode("7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c").unwrap();
        let expected_pubkey =
            hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138")
                .unwrap();
        let expected_node_id =
            hex::decode("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7")
                .unwrap();

        let enr = text.parse::<DefaultEnr>().unwrap();
        let pubkey = enr.public_key().encode();
        assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(enr.ip6(), None);
        assert_eq!(enr.id(), Some(String::from("v4")));
        assert_eq!(enr.udp4(), Some(30303));
        assert_eq!(enr.udp6(), None);
        assert_eq!(enr.signature(), &signature[..]);
        assert_eq!(pubkey.to_vec(), expected_pubkey);
        assert_eq!(enr.node_id().raw().to_vec(), expected_node_id);
        assert!(enr.verify());
    }

    #[test]
    fn test_vector_2_k256() {
        let text = "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8";
        let expected_node_id =
            hex::decode("a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7")
                .unwrap();

        let enr = text.parse::<Enr<k256::ecdsa::SigningKey>>().unwrap();
        assert_eq!(enr.ip4(), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(enr.id(), Some(String::from("v4")));
        assert_eq!(enr.udp4(), Some(30303));
        assert_eq!(enr.node_id().raw().to_vec(), expected_node_id);
        assert!(enr.verify());
    }

    #[test]
    fn test_read_enr_base64url_decoding_enforce_no_pad_no_extra_trailingbits() {
        let test_data = [
            (
                "padded",
                "Invalid base64 encoding: InvalidPadding",
                "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8=",
            ),
            (
                "extra trailing bits",
                "Invalid base64 encoding: InvalidLastSymbol(178, 57)",
                "enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl9",
            ),
        ];
        for (test_name, err, text) in test_data {
            assert_eq!(text.parse::<DefaultEnr>().unwrap_err(), err, "{test_name}");
        }
    }

    #[test]
    fn test_read_enr_no_prefix() {
        let text = "-Iu4QM-YJF2RRpMcZkFiWzMf2kRd1A5F1GIekPa4Sfi_v0DCLTDBfOMTMMWJhhawr1YLUPb5008CpnBKrgjY3sstjfgCgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQP8u1uyQFyJYuQUTyA1raXKhSw1HhhxNUQ2VE52LNHWMIN0Y3CCIyiDdWRwgiMo";
        text.parse::<DefaultEnr>().unwrap();
    }

    #[test]
    fn test_read_enr_prefix() {
        let text = "enr:-Iu4QM-YJF2RRpMcZkFiWzMf2kRd1A5F1GIekPa4Sfi_v0DCLTDBfOMTMMWJhhawr1YLUPb5008CpnBKrgjY3sstjfgCgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQP8u1uyQFyJYuQUTyA1raXKhSw1HhhxNUQ2VE52LNHWMIN0Y3CCIyiDdWRwgiMo";
        text.parse::<DefaultEnr>().unwrap();
    }

    #[test]
    fn test_read_enr_reject_too_large_record() {
        // 300-byte rlp encoded record, decode should succeed (large custom field is
        // skipped after verification).
        let text = concat!(
            "enr:-QEpuEDaLyrPP4gxBI9YL7QE9U1tZig_Nt8rue8bRIuYv_IMziFc8OEt3LQMwkwt6da-Z0Y8BaqkDalZbBq647UtV2ei",
            "AYJpZIJ2NIJpcIR_AAABiXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTiDdWRwgnZferiieHh4",
            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
            "eHh4eHh4eHh4eHh4eHh4"
        );
        let key_data =
            hex::decode("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
                .unwrap();
        let key = k256::ecdsa::SigningKey::from_slice(&key_data).unwrap();
        let mut record = text.parse::<DefaultEnr>().unwrap();
        assert!(record.set_udp4(record.udp4().unwrap(), &key).is_ok());

        // 301-byte record, creation should fail.
        let text = concat!(
            "enr:-QEquEBxABglcZbIGKJ8RHDCp2Ft59tdf61RhV3XXf2BKTlKE2XwzNfihH-46hKkANsXaGRwH8Dp7a3lTrKiv2FMMaFY",
            "AYJpZIJ2NIJpcIR_AAABiXNlY3AyNTZrMaEDymNMrg1JrLQB2KTGtv6MVbcNEVv0AHacwUAPMljNMTiDdWRwgnZferijeHh4",
            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
            "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4",
            "eHh4eHh4eHh4eHh4eHh4eA"
        );
        assert!(text.parse::<DefaultEnr>().unwrap_err().contains("enr exceeds max size"));
    }

    #[test]
    fn test_rlp_integer_decoding() {
        let text = "enr:-Ia4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5yCAAGCaWSCdjSCaXCEfwAAAYlzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4g3VkcIJ2Xw";
        assert_eq!(text.parse::<DefaultEnr>().unwrap_err(), "Invalid ENR: LeadingZero");
    }

    #[test]
    fn test_encode_decode_k256() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let ip = Ipv4Addr::new(127, 0, 0, 1);
        let udp = 3000u16;

        let enr = Enr::builder().ip4(ip).udp4(udp).build(&key).unwrap();

        let mut encoded_enr = BytesMut::new();
        enr.encode(&mut encoded_enr);

        let decoded_enr =
            Enr::<k256::ecdsa::SigningKey>::decode(&mut encoded_enr.to_vec().as_slice()).unwrap();

        assert_eq!(decoded_enr.id(), Some("v4".into()));
        assert_eq!(decoded_enr.ip4(), Some(ip));
        assert_eq!(decoded_enr.udp4(), Some(udp));
        assert_eq!(decoded_enr.public_key().encode(), key.public().encode());
        decoded_enr.public_key().encode_uncompressed();
        assert!(decoded_enr.verify());
    }

    #[test]
    fn test_set_ip() {
        let mut rng = rand::thread_rng();
        let key = k256::ecdsa::SigningKey::random(&mut rng);
        let udp = 30303u16;
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        let mut enr = Enr::builder().udp4(udp).build(&key).unwrap();

        assert!(enr.set_ip(ip.into(), &key).is_ok());
        assert_eq!(enr.id(), Some("v4".into()));
        assert_eq!(enr.ip4(), Some(ip));
        assert_eq!(enr.udp4(), Some(udp));
        assert!(enr.verify());
        assert_eq!(enr.public_key().encode(), key.public().encode());
    }

    #[test]
    fn ip_mutation_static_node_id() {
        let mut rng = rand::thread_rng();
        let key = k256::ecdsa::SigningKey::random(&mut rng);
        let udp = 30303u16;
        let ip = Ipv4Addr::new(10, 0, 0, 1);

        let mut enr = Enr::builder().ip4(ip).udp4(udp).build(&key).unwrap();
        let node_id = enr.node_id();

        enr.set_udp_socket("192.168.0.1:800".parse::<SocketAddr>().unwrap(), &key).unwrap();
        assert_eq!(node_id, enr.node_id());
        assert_eq!(enr.udp4_socket(), Some("192.168.0.1:800".parse::<SocketAddrV4>().unwrap()));
    }

    #[test]
    fn test_read_enr_rlp_decoding_reject_extra_data() {
        let record_hex = concat!(
            "f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599",
            "ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1",
            "145ccb9c01826964827634826970847f00000189736563703235366b31a103ca",
            "634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd313883",
            "75647082765f"
        );
        let valid_record = hex::decode(record_hex).unwrap();
        let expected_pubkey =
            hex::decode("03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138")
                .unwrap();

        let enr = DefaultEnr::decode(&mut valid_record.as_slice()).unwrap();
        assert_eq!(enr.public_key().encode().to_vec(), expected_pubkey);
        assert!(enr.verify());

        // Truncated payload length
        let invalid_hex = concat!(
            "f883b8407098ad865b00a582051940cb9cf36836572411a47278783077011599",
            "ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1",
            "145ccb9c01826964827634826970847f00000189736563703235366b31a103ca",
            "634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd313883",
            "75647082765f"
        );
        DefaultEnr::decode(&mut hex::decode(invalid_hex).unwrap().as_slice())
            .expect_err("should reject truncated payload");
    }

    #[test]
    fn test_compare_content() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let udp = 30303u16;

        let enr1 = Enr::builder().ip4(ip).udp4(udp).build(&key).unwrap();
        let mut enr2 = enr1.clone();
        enr2.set_seq(1, &key).unwrap();
        let mut enr3 = enr1.clone();
        enr3.set_seq(2, &key).unwrap();

        assert_ne!(enr1.signature(), enr2.signature());
        assert!(enr1.compare_content(&enr2));
        assert_ne!(enr1, enr2);

        assert_ne!(enr1.signature(), enr3.signature());
        assert!(!enr1.compare_content(&enr3));
        assert_ne!(enr1, enr3);
    }

    #[test]
    fn test_set_seq() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let mut enr = Enr::empty(&key).unwrap();
        enr.set_seq(30, &key).unwrap();
        assert_eq!(enr.seq(), 30);
        enr.set_seq(u64::MAX, &key).unwrap();
        assert_eq!(enr.seq(), u64::MAX);
        assert!(enr.verify());
    }

    #[test]
    fn test_eth2_roundtrip() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let mut enr = Enr::builder().ip4(Ipv4Addr::LOCALHOST).udp4(9000u16).build(&key).unwrap();
        let eth2: [u8; 16] = std::array::from_fn(|i| (i + 1) as u8);
        enr.set_eth2(eth2, &key).unwrap();
        assert_eq!(enr.eth2(), Some(eth2));
        assert!(enr.verify());

        let mut encoded = BytesMut::new();
        enr.encode(&mut encoded);
        let decoded = DefaultEnr::decode(&mut encoded.to_vec().as_slice()).unwrap();
        assert_eq!(decoded.eth2(), Some(eth2));
        assert!(decoded.verify());
    }

    #[test]
    fn test_attnets_roundtrip() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let mut enr = Enr::builder().ip4(Ipv4Addr::LOCALHOST).udp4(9000u16).build(&key).unwrap();
        let attnets: [u8; 8] = [0xff, 0x00, 0xab, 0xcd, 0x12, 0x34, 0x56, 0x78];
        enr.set_attnets(attnets, &key).unwrap();
        assert_eq!(enr.attnets(), Some(attnets));
        assert!(enr.verify());

        let mut encoded = BytesMut::new();
        enr.encode(&mut encoded);
        let decoded = DefaultEnr::decode(&mut encoded.to_vec().as_slice()).unwrap();
        assert_eq!(decoded.attnets(), Some(attnets));
        assert!(decoded.verify());
    }

    #[test]
    fn test_syncnets_roundtrip() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let mut enr = Enr::builder().ip4(Ipv4Addr::LOCALHOST).udp4(9000u16).build(&key).unwrap();
        let syncnets: u8 = 0x0f;
        enr.set_syncnets(syncnets, &key).unwrap();
        assert_eq!(enr.syncnets(), Some(syncnets));
        assert!(enr.verify());

        let mut encoded = BytesMut::new();
        enr.encode(&mut encoded);
        let decoded = DefaultEnr::decode(&mut encoded.to_vec().as_slice()).unwrap();
        assert_eq!(decoded.syncnets(), Some(syncnets));
        assert!(decoded.verify());
    }

    #[test]
    fn test_all_cl_fields_roundtrip_with_verify() {
        let key = k256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let mut enr =
            Enr::builder().ip4(Ipv4Addr::new(10, 0, 0, 1)).udp4(30303u16).build(&key).unwrap();

        let eth2: [u8; 16] = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let attnets: [u8; 8] = [0x01; 8];
        let syncnets: u8 = 0x03;

        enr.set_eth2(eth2, &key).unwrap();
        enr.set_attnets(attnets, &key).unwrap();
        enr.set_syncnets(syncnets, &key).unwrap();

        assert_eq!(enr.eth2(), Some(eth2));
        assert_eq!(enr.attnets(), Some(attnets));
        assert_eq!(enr.syncnets(), Some(syncnets));
        assert!(enr.verify());

        let mut encoded = BytesMut::new();
        enr.encode(&mut encoded);
        let decoded = DefaultEnr::decode(&mut encoded.to_vec().as_slice()).unwrap();
        assert_eq!(decoded.eth2(), Some(eth2));
        assert_eq!(decoded.attnets(), Some(attnets));
        assert_eq!(decoded.syncnets(), Some(syncnets));
        assert!(decoded.verify());
    }
}
