use std::fmt;

use secp256k1::{
    SECP256K1, SecretKey,
    hashes::{Hash, sha256},
};

use crate::{Error, util::decode_varint};

/// libp2p peer identity (multihash-encoded).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct PeerId {
    // Maximum id length is theoretically 44 bytes - pad out to 48.
    buffer: [u8; 48],
    length: usize,
}

impl Default for PeerId {
    fn default() -> Self {
        Self { buffer: [0u8; 48], length: 0 }
    }
}

impl PeerId {
    /// Derive from protobuf-encoded libp2p public key.
    /// secp256k1 compressed keys encode to 37 bytes, well under the
    /// 42-byte identity multihash threshold.
    pub fn from_protobuf_encoded(encoded: &[u8]) -> Self {
        debug_assert!(encoded.len() <= 42);
        let mut buffer = [0u8; 48];
        buffer[0] = 0x00; // identity hash function code
        buffer[1] = encoded.len() as u8;
        buffer[2..2 + encoded.len()].copy_from_slice(encoded);
        Self { buffer, length: encoded.len() + 2 }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    /// Returns the secp256k1 pubket embedded in this id.
    pub fn pubkey(&self) -> &[u8] {
        debug_assert!(self.length == 39);
        &self.buffer[6..self.length]
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// secp256k1 keypair for libp2p node identity.
pub struct Keypair {
    signing_key: SecretKey,
    compressed: [u8; 33],
}

impl Keypair {
    /// Create from raw 32-byte secret key.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, Error> {
        let signing_key = SecretKey::from_slice(secret).map_err(|_| Error::BadPrivateKey)?;
        let compressed = signing_key.public_key(SECP256K1).serialize();
        Ok(Self { signing_key, compressed })
    }

    pub fn public_key_compressed(&self) -> &[u8; 33] {
        &self.compressed
    }

    pub fn peer_id(&self) -> PeerId {
        let encoded = encode_secp256k1_protobuf(&self.compressed);
        PeerId::from_protobuf_encoded(&encoded)
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let digest = sha256::Hash::hash(msg);
        let msg = secp256k1::Message::from_digest(digest.to_byte_array());
        let sig = SECP256K1.sign_ecdsa(&msg, &self.signing_key);
        sig.serialize_der().to_vec()
    }
}

/// Encode secp256k1 compressed pubkey as libp2p protobuf PublicKey.
///   message PublicKey { required KeyType Type = 1; required bytes Data = 2; }
pub fn encode_secp256k1_protobuf(compressed: &[u8; 33]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(37);
    buf.push(0x08); // field 1 tag (varint)
    buf.push(0x02); // KeyType::Secp256k1
    buf.push(0x12); // field 2 tag (length-delimited)
    buf.push(33);
    buf.extend_from_slice(compressed);
    buf
}

/// Decode libp2p protobuf PublicKey. Returns (key_type, raw_key_bytes).
pub fn decode_protobuf_pubkey(data: &[u8]) -> Result<(u64, Vec<u8>), Error> {
    let mut pos = 0;
    let mut key_type = None;
    let mut key_data = None;

    while pos < data.len() {
        let tag = data[pos];
        pos += 1;
        let field = tag >> 3;
        let wire = tag & 0x07;

        match (field, wire) {
            // field 1, varint (KeyType)
            (1, 0) => {
                let (v, p) = decode_varint(data, pos)?;
                key_type = Some(v);
                pos = p;
            }
            // field 2, length-delimited (key bytes)
            (2, 2) => {
                let (len, p) = decode_varint(data, pos)?;
                let len = len as usize;
                pos = p;
                if pos + len > data.len() {
                    return Err(Error::BadDer);
                }
                key_data = Some(data[pos..pos + len].to_vec());
                pos += len;
            }
            _ => return Err(Error::BadDer),
        }
    }

    Ok((key_type.ok_or(Error::BadDer)?, key_data.ok_or(Error::BadDer)?))
}
