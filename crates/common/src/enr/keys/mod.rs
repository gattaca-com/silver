// Adapted from https://github.com/sigp/enr (MIT License)

mod k256_key;

use std::{
    error::Error,
    fmt::{self, Debug, Display},
};

use alloy_rlp::Error as DecoderError;

pub trait EnrKey: Send + Sync + Unpin + 'static {
    type PublicKey: EnrPublicKey + Clone;

    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError>;

    fn public(&self) -> Self::PublicKey;

    fn enr_to_public(scheme: &[u8], pubkey_bytes: &[u8]) -> Result<Self::PublicKey, DecoderError>;
}

pub trait EnrKeyUnambiguous: EnrKey {
    fn decode_public(bytes: &[u8]) -> Result<Self::PublicKey, DecoderError>;
}

pub trait EnrPublicKey: Clone + Debug + Send + Sync + Unpin + 'static {
    type Raw: AsRef<[u8]>;
    type RawUncompressed: AsRef<[u8]>;

    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool;

    fn encode(&self) -> Self::Raw;

    fn encode_uncompressed(&self) -> Self::RawUncompressed;

    fn enr_key(&self) -> &'static [u8];
}

#[derive(Debug)]
pub struct SigningError {}

impl Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Signing error")
    }
}

impl Error for SigningError {}
