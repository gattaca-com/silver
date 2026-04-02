// secp256k1 ENR identity scheme using libsecp256k1 (C FFI).

use alloy_rlp::Error as DecoderError;
use secp256k1::{PublicKey, SECP256K1, SecretKey, ecdsa::Signature};
use sha3::{Digest, Keccak256};

use super::{EnrKey, EnrKeyUnambiguous, EnrPublicKey, SigningError};

pub const ENR_KEY: &str = "secp256k1";

impl EnrKey for SecretKey {
    type PublicKey = PublicKey;

    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        let hash = Keccak256::digest(msg);
        let msg = secp256k1::Message::from_digest_slice(&hash).map_err(|_| SigningError {})?;
        let sig = SECP256K1.sign_ecdsa(&msg, self);
        Ok(sig.serialize_compact().to_vec())
    }

    fn public(&self) -> Self::PublicKey {
        self.public_key(SECP256K1)
    }

    fn enr_to_public(scheme: &[u8], pubkey_bytes: &[u8]) -> Result<Self::PublicKey, DecoderError> {
        if scheme != ENR_KEY.as_bytes() {
            return Err(DecoderError::Custom("Unknown signature"));
        }
        Self::decode_public(pubkey_bytes)
    }
}

impl EnrKeyUnambiguous for SecretKey {
    fn decode_public(bytes: &[u8]) -> Result<PublicKey, DecoderError> {
        PublicKey::from_slice(bytes).map_err(|_| DecoderError::Custom("Invalid Secp256k1 key"))
    }
}

impl EnrPublicKey for PublicKey {
    type Raw = [u8; 33];
    type RawUncompressed = [u8; 64];

    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(signature) = Signature::from_compact(sig) else { return false };
        let hash = Keccak256::digest(msg);
        let Ok(msg) = secp256k1::Message::from_digest_slice(&hash) else { return false };
        SECP256K1.verify_ecdsa(&msg, &signature, self).is_ok()
    }

    fn encode(&self) -> Self::Raw {
        self.serialize()
    }

    fn encode_uncompressed(&self) -> Self::RawUncompressed {
        let full = self.serialize_uncompressed(); // [u8; 65], 0x04 || x || y
        let mut out = [0u8; 64];
        out.copy_from_slice(&full[1..]);
        out
    }

    fn enr_key(&self) -> &'static [u8] {
        ENR_KEY.as_bytes()
    }
}
