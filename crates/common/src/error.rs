use std::{fmt, sync::Arc};

use thiserror::Error;

use crate::TCacheError;

#[derive(Debug, Error)]
pub enum Error {
    CertGeneration,
    BadDer,
    BadExtension,
    BadSignature,
    BadPublicKey,
    BadPrivateKey,
    CertExpired,
    MissingExtension,
    UnsupportedCriticalExtension,
    UnsupportedKeyType,
    PeerIdMismatch,
    BufferTooSmall,
    GossipFrameTooLarge,
    GossipPayloadTooLarge,
    ParseTopicError,
    InvalidSnappy,
    IoError(#[from] std::io::Error),
    JsonError(#[from] serde_json::Error),
    TomlError(#[from] toml::de::Error),
    TCacheError(#[from] TCacheError),
    SnappyError(#[from] snap::Error),
    InvalidStreamState,
    IdentifyInvalidProtocol,
    IdentifyMissingAgent,
    IdentifyInvalidObservedAddr,
    IdentifyInvalidMultiAddr,
    IdentifyMissingPubkey,
    EnrError(#[from] crate::enr::Error),
    KeyError(#[from] secp256k1::Error),
    InvalidStreamProtocol,
    ConfigError(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl From<Error> for rustls::Error {
    fn from(e: Error) -> Self {
        use rustls::CertificateError;
        match e {
            Error::BadDer | Error::BadExtension | Error::MissingExtension => {
                rustls::Error::InvalidCertificate(CertificateError::BadEncoding)
            }
            Error::BadSignature => {
                rustls::Error::InvalidCertificate(CertificateError::BadSignature)
            }
            Error::PeerIdMismatch => {
                rustls::Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
            }
            other => rustls::Error::InvalidCertificate(CertificateError::Other(
                rustls::OtherError(Arc::new(other)),
            )),
        }
    }
}
