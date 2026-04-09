// secp256k1 ENR key operations.

use std::{
    error::Error,
    fmt::{self, Display},
};

use alloy_rlp::Error as DecoderError;
use secp256k1::{PublicKey, SECP256K1, SecretKey, ecdsa::Signature};
use sha3::{Digest, Keccak256};

pub const ENR_KEY: &[u8] = b"secp256k1";

pub fn sign_v4(key: &SecretKey, msg: &[u8]) -> Result<[u8; 64], SigningError> {
    let hash = Keccak256::digest(msg);
    let msg = secp256k1::Message::from_digest_slice(&hash).map_err(|_| SigningError)?;
    let sig = SECP256K1.sign_ecdsa(&msg, key);
    Ok(sig.serialize_compact())
}

pub fn verify_v4(pubkey: &PublicKey, msg: &[u8], sig: &[u8]) -> bool {
    let Ok(signature) = Signature::from_compact(sig) else { return false };
    let hash = Keccak256::digest(msg);
    let Ok(msg) = secp256k1::Message::from_digest_slice(&hash) else { return false };
    SECP256K1.verify_ecdsa(&msg, &signature, pubkey).is_ok()
}

pub fn decode_public(bytes: &[u8]) -> Result<PublicKey, DecoderError> {
    PublicKey::from_slice(bytes).map_err(|_| DecoderError::Custom("Invalid Secp256k1 key"))
}

pub fn encode_uncompressed(pubkey: &PublicKey) -> [u8; 64] {
    let full = pubkey.serialize_uncompressed();
    let mut out = [0u8; 64];
    out.copy_from_slice(&full[1..]);
    out
}

#[derive(Debug)]
pub struct SigningError;

impl Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signing error")
    }
}

impl Error for SigningError {}
