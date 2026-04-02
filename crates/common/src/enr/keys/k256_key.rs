// Adapted from https://github.com/sigp/enr (MIT License)

use alloy_rlp::Error as DecoderError;
use k256::{
    AffinePoint, CompressedPoint, EncodedPoint,
    ecdsa::{
        Signature, SigningKey, VerifyingKey,
        signature::{DigestVerifier, RandomizedDigestSigner},
    },
    elliptic_curve::{
        point::DecompressPoint,
        sec1::{Coordinates, ToEncodedPoint},
        subtle::Choice,
    },
};
use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};

use super::{EnrKey, EnrKeyUnambiguous, EnrPublicKey, SigningError};

pub const ENR_KEY: &str = "secp256k1";

impl EnrKey for SigningKey {
    type PublicKey = VerifyingKey;

    fn sign_v4(&self, msg: &[u8]) -> Result<Vec<u8>, SigningError> {
        let digest = Keccak256::new().chain_update(msg);
        let signature: Signature =
            self.try_sign_digest_with_rng(&mut OsRng, digest).map_err(|_| SigningError {})?;

        Ok(signature.to_vec())
    }

    fn public(&self) -> Self::PublicKey {
        *self.verifying_key()
    }

    fn enr_to_public(scheme: &[u8], pubkey_bytes: &[u8]) -> Result<Self::PublicKey, DecoderError> {
        if scheme != ENR_KEY.as_bytes() {
            return Err(DecoderError::Custom("Unknown signature"));
        }
        Self::decode_public(pubkey_bytes)
    }
}

impl EnrKeyUnambiguous for SigningKey {
    fn decode_public(bytes: &[u8]) -> Result<Self::PublicKey, DecoderError> {
        VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| DecoderError::Custom("Invalid Secp256k1 Signature"))
    }
}

impl EnrPublicKey for VerifyingKey {
    type Raw = CompressedPoint;
    type RawUncompressed = [u8; 64];

    fn verify_v4(&self, msg: &[u8], sig: &[u8]) -> bool {
        if let Ok(sig) = k256::ecdsa::Signature::try_from(sig) {
            return self.verify_digest(Keccak256::new().chain_update(msg), &sig).is_ok();
        }
        false
    }

    fn encode(&self) -> Self::Raw {
        self.into()
    }

    fn encode_uncompressed(&self) -> Self::RawUncompressed {
        let p = EncodedPoint::from(self);
        let (x, y) = match p.coordinates() {
            Coordinates::Compact { .. } | Coordinates::Identity => unreachable!(),
            Coordinates::Compressed { x, y_is_odd } => (
                x,
                *AffinePoint::decompress(x, Choice::from(u8::from(y_is_odd)))
                    .unwrap()
                    .to_encoded_point(false)
                    .y()
                    .unwrap(),
            ),
            Coordinates::Uncompressed { x, y } => (x, *y),
        };

        let mut coords = [0; 64];
        coords[..32].copy_from_slice(x);
        coords[32..].copy_from_slice(&y);

        coords
    }

    fn enr_key(&self) -> &'static [u8] {
        ENR_KEY.as_bytes()
    }
}
