/// libp2p TLS 1.3 certificate verifier for rustls.
///
/// Both verify_server_cert/verify_client_cert AND verify_tls13_signature
/// parse the cert ourselves (not webpki) because the libp2p critical
/// extension is unknown to webpki and would be rejected.
use rustls::{
    DigitallySignedStruct, DistinguishedName, SignatureScheme, SupportedCipherSuite,
    SupportedProtocolVersion,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    },
    pki_types::CertificateDer,
    server::danger::{ClientCertVerified, ClientCertVerifier},
};
use silver_common::{Error, PeerId};

use super::certificate;

pub(super) static PROTOCOL_VERSIONS: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];

pub(super) static CIPHERSUITES: &[SupportedCipherSuite] =
    &[TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256];

#[derive(Debug)]
pub(super) struct Libp2pCertificateVerifier {
    remote_peer_id: Option<PeerId>,
}

impl Libp2pCertificateVerifier {
    pub(super) fn new() -> Self {
        Self { remote_peer_id: None }
    }

    pub(super) fn with_remote_peer_id(remote_peer_id: Option<PeerId>) -> Self {
        Self { remote_peer_id }
    }

    fn verification_schemes() -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

/// Verify exactly one self-signed cert with valid libp2p extension.
fn verify_presented_certs(
    end_entity: &CertificateDer,
    intermediates: &[CertificateDer],
) -> Result<PeerId, rustls::Error> {
    if !intermediates.is_empty() {
        return Err(rustls::Error::General("libp2p-tls requires exactly one certificate".into()));
    }
    let cert = certificate::parse(end_entity).map_err(rustls::Error::from)?;
    Ok(cert.peer_id())
}

/// Verify TLS 1.3 CertificateVerify using our own cert parser
/// (webpki rejects the libp2p critical extension).
fn verify_tls13_signature(
    cert: &CertificateDer,
    dss: &DigitallySignedStruct,
    message: &[u8],
) -> Result<HandshakeSignatureValid, rustls::Error> {
    certificate::parse(cert)
        .map_err(rustls::Error::from)?
        .verify_tls_signature(dss.scheme, message, dss.signature())
        .map_err(rustls::Error::from)?;
    Ok(HandshakeSignatureValid::assertion())
}

impl ServerCertVerifier for Libp2pCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let peer_id = verify_presented_certs(end_entity, intermediates)?;
        if let Some(expected) = &self.remote_peer_id {
            if *expected != peer_id {
                return Err(Error::PeerIdMismatch.into());
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unreachable!("TLS 1.3 only")
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(cert, dss, message)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Self::verification_schemes()
    }
}

impl ClientCertVerifier for Libp2pCertificateVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        verify_presented_certs(end_entity, intermediates)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        unreachable!("TLS 1.3 only")
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(cert, dss, message)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Self::verification_schemes()
    }
}
