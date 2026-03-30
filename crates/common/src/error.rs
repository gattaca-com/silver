use std::{fmt, sync::Arc};

#[derive(Debug)]
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
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

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
