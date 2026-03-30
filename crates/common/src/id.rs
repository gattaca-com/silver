use std::fmt;

use crate::{Error, util::decode_varint};

/// libp2p peer identity (multihash-encoded).
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct PeerId(Vec<u8>);

impl PeerId {
    /// Derive from protobuf-encoded libp2p public key.
    /// secp256k1 compressed keys encode to 37 bytes, well under the
    /// 42-byte identity multihash threshold.
    pub fn from_protobuf_encoded(encoded: &[u8]) -> Self {
        debug_assert!(encoded.len() <= 42);
        let mut buf = Vec::with_capacity(2 + encoded.len());
        buf.push(0x00); // identity hash function code
        buf.push(encoded.len() as u8);
        buf.extend_from_slice(encoded);
        Self(buf)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// secp256k1 keypair for libp2p node identity.
pub struct Keypair {
    signing_key: k256::ecdsa::SigningKey,
    compressed: [u8; 33],
}

impl Keypair {
    /// Create from raw 32-byte secret key.
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, Error> {
        let signing_key =
            k256::ecdsa::SigningKey::from_bytes(secret.into()).map_err(|_| Error::BadPrivateKey)?;
        let compressed = compress(&signing_key);
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
        use k256::ecdsa::{DerSignature, signature::Signer};
        let sig: DerSignature = self.signing_key.sign(msg);
        sig.as_ref().to_vec()
    }
}

fn compress(key: &k256::ecdsa::SigningKey) -> [u8; 33] {
    let point = key.verifying_key().to_encoded_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(point.as_bytes());
    out
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
