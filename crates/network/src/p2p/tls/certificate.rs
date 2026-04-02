/// X.509 certificate generation and parsing for libp2p TLS.
use std::sync::Arc;

use silver_common::{Error, Keypair, PeerId, decode_protobuf_pubkey, encode_secp256k1_protobuf};
use x509_parser::prelude::*;

/// OID 1.3.6.1.4.1.53594.1.1 -- IANA-allocated to libp2p.
const P2P_EXT_OID: [u64; 9] = [1, 3, 6, 1, 4, 1, 53594, 1, 1];
const P2P_SIGNING_PREFIX: [u8; 21] = *b"libp2p-tls-handshake:";
static P2P_SIGNATURE_ALGORITHM: &rcgen::SignatureAlgorithm = &rcgen::PKCS_ECDSA_P256_SHA256;

/// Fixed DER prefix for P-256 SubjectPublicKeyInfo.
/// rcgen 0.14 only exposes raw key bytes; we reconstruct the SPKI DER
/// to match what x509-parser returns on the verification side.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, // SEQUENCE (89 bytes)
    0x30, 0x13, // SEQUENCE (19 bytes)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID 1.2.840.10045.3.1.7
    0x03, 0x42, 0x00, // BIT STRING (66 bytes, 0 unused bits)
];

const KEY_TYPE_SECP256K1: u64 = 2;

// ---------------------------------------------------------------------------
// Cert resolver -- always presents our single self-signed cert.
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(super) struct AlwaysResolvesCert(Arc<rustls::sign::CertifiedKey>);

impl AlwaysResolvesCert {
    pub(super) fn new(
        cert: rustls::pki_types::CertificateDer<'static>,
        key: &rustls::pki_types::PrivateKeyDer<'_>,
    ) -> Result<Self, rustls::Error> {
        let ck = rustls::sign::CertifiedKey::new(
            vec![cert],
            rustls::crypto::ring::sign::any_ecdsa_type(key)?,
        );
        Ok(Self(Arc::new(ck)))
    }
}

impl rustls::client::ResolvesClientCert for AlwaysResolvesCert {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

impl rustls::server::ResolvesServerCert for AlwaysResolvesCert {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

// ---------------------------------------------------------------------------
// Certificate generation
// ---------------------------------------------------------------------------

/// Generate self-signed ECDSA P-256 cert with libp2p extension
/// embedding our secp256k1 host identity.
pub(super) fn generate(
    keypair: &Keypair,
) -> Result<
    (rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>),
    Error,
> {
    let cert_kp =
        rcgen::KeyPair::generate_for(P2P_SIGNATURE_ALGORITHM).map_err(|_| Error::CertGeneration)?;
    let privkey = rustls::pki_types::PrivateKeyDer::from(
        rustls::pki_types::PrivatePkcs8KeyDer::from(cert_kp.serialize_der()),
    );

    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.custom_extensions.push(make_libp2p_extension(keypair, &cert_kp)?);
    let cert = params.self_signed(&cert_kp).map_err(|_| Error::CertGeneration)?;

    Ok((cert.into(), privkey))
}

/// Build the libp2p X.509 extension:
///   SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }
/// where signature = host_key.sign("libp2p-tls-handshake:" ||
/// cert_public_key_der).
fn make_libp2p_extension(
    keypair: &Keypair,
    cert_kp: &rcgen::KeyPair,
) -> Result<rcgen::CustomExtension, Error> {
    let raw = cert_kp.public_key_raw();
    let mut msg = Vec::with_capacity(P2P_SIGNING_PREFIX.len() + P256_SPKI_PREFIX.len() + raw.len());
    msg.extend_from_slice(&P2P_SIGNING_PREFIX);
    msg.extend_from_slice(&P256_SPKI_PREFIX);
    msg.extend_from_slice(raw);

    let signature = keypair.sign(&msg);
    let encoded_pubkey = encode_secp256k1_protobuf(keypair.public_key_compressed());
    let ext_content = yasna::encode_der(&(encoded_pubkey, signature));

    let mut ext = rcgen::CustomExtension::from_oid_content(&P2P_EXT_OID, ext_content);
    ext.set_criticality(true);
    Ok(ext)
}

// ---------------------------------------------------------------------------
// Certificate parsing & verification
// ---------------------------------------------------------------------------

pub(super) struct P2pCertificate<'a> {
    certificate: X509Certificate<'a>,
    extension: P2pExtension,
}

struct P2pExtension {
    key_type: u64,
    public_key: Vec<u8>,
    /// Protobuf-encoded public key (used for PeerId derivation).
    encoded_pubkey: Vec<u8>,
    signature: Vec<u8>,
}

/// Parse and verify from raw DER bytes.
pub(super) fn parse_der(der: &[u8]) -> Result<P2pCertificate<'_>, Error> {
    let cert = parse_unverified(der)?;
    cert.verify()?;
    Ok(cert)
}

/// Parse and verify from rustls CertificateDer.
pub(super) fn parse<'a>(
    cert: &'a rustls::pki_types::CertificateDer<'a>,
) -> Result<P2pCertificate<'a>, Error> {
    parse_der(cert.as_ref())
}

fn parse_unverified(der: &[u8]) -> Result<P2pCertificate<'_>, Error> {
    let x509 =
        X509Certificate::from_der(der).map(|(_rest, x509)| x509).map_err(|_| Error::BadDer)?;

    let target_oid = x509_parser::der_parser::oid::Oid::from(&P2P_EXT_OID).expect("valid OID");

    let mut libp2p_ext = None;

    for ext in x509.extensions() {
        if ext.oid == target_oid {
            if libp2p_ext.is_some() {
                return Err(Error::BadDer); // duplicate extension
            }
            let (encoded_pubkey, signature): (Vec<u8>, Vec<u8>) =
                yasna::decode_der(ext.value).map_err(|_| Error::BadExtension)?;
            let (key_type, public_key) = decode_protobuf_pubkey(&encoded_pubkey)?;
            libp2p_ext = Some(P2pExtension { key_type, public_key, encoded_pubkey, signature });
            continue;
        }
        if ext.critical {
            return Err(Error::UnsupportedCriticalExtension);
        }
    }

    Ok(P2pCertificate { certificate: x509, extension: libp2p_ext.ok_or(Error::MissingExtension)? })
}

impl P2pCertificate<'_> {
    pub(super) fn peer_id(&self) -> PeerId {
        PeerId::from_protobuf_encoded(&self.extension.encoded_pubkey)
    }

    /// Verify a TLS handshake signature using the cert's public key.
    pub(super) fn verify_tls_signature(
        &self,
        signature_scheme: rustls::SignatureScheme,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        let expected = self.signature_scheme()?;
        if signature_scheme != expected {
            return Err(Error::BadSignature);
        }

        let alg: &dyn ring::signature::VerificationAlgorithm = match signature_scheme {
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => {
                &ring::signature::ECDSA_P256_SHA256_ASN1
            }
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => {
                &ring::signature::ECDSA_P384_SHA384_ASN1
            }
            rustls::SignatureScheme::ED25519 => &ring::signature::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384 => &ring::signature::RSA_PSS_2048_8192_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512 => &ring::signature::RSA_PSS_2048_8192_SHA512,
            _ => return Err(Error::BadSignature),
        };

        let spki = &self.certificate.tbs_certificate.subject_pki;
        let pk = ring::signature::UnparsedPublicKey::new(alg, spki.subject_public_key.as_ref());
        pk.verify(message, signature).map_err(|_| Error::BadSignature)
    }

    /// Map cert's X.509 algorithm OIDs to a rustls SignatureScheme.
    fn signature_scheme(&self) -> Result<rustls::SignatureScheme, Error> {
        use rustls::SignatureScheme::*;
        use x509_parser::oid_registry::*;

        let sig_alg = &self.certificate.signature_algorithm;
        let pki_alg = &self.certificate.tbs_certificate.subject_pki.algorithm;

        if pki_alg.algorithm == OID_KEY_TYPE_EC_PUBLIC_KEY {
            let param = pki_alg
                .parameters
                .as_ref()
                .ok_or(Error::BadDer)?
                .as_oid()
                .map_err(|_| Error::BadDer)?;
            if param == OID_EC_P256 && sig_alg.algorithm == OID_SIG_ECDSA_WITH_SHA256 {
                return Ok(ECDSA_NISTP256_SHA256);
            }
            if param == OID_NIST_EC_P384 && sig_alg.algorithm == OID_SIG_ECDSA_WITH_SHA384 {
                return Ok(ECDSA_NISTP384_SHA384);
            }
        }

        if sig_alg.algorithm == OID_SIG_ED25519 {
            return Ok(ED25519);
        }

        Err(Error::BadSignature)
    }

    fn verify(&self) -> Result<(), Error> {
        if !self.certificate.validity().is_valid() {
            return Err(Error::CertExpired);
        }

        // X.509 self-signature check (ECDSA P-256).
        self.certificate.verify_signature(None).map_err(|_| Error::BadSignature)?;

        // Verify the libp2p extension: host key signed the cert's SPKI.
        let spki_raw = self.certificate.public_key().raw;
        let mut msg = Vec::with_capacity(P2P_SIGNING_PREFIX.len() + spki_raw.len());
        msg.extend_from_slice(&P2P_SIGNING_PREFIX);
        msg.extend_from_slice(spki_raw);

        verify_host_key_signature(
            self.extension.key_type,
            &self.extension.public_key,
            &msg,
            &self.extension.signature,
        )
    }
}

// ---------------------------------------------------------------------------
// Host key signature verification (libp2p extension)
// ---------------------------------------------------------------------------

fn verify_host_key_signature(
    key_type: u64,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    match key_type {
        KEY_TYPE_SECP256K1 => {
            let pk =
                secp256k1::PublicKey::from_slice(public_key).map_err(|_| Error::BadPublicKey)?;
            let sig = secp256k1::ecdsa::Signature::from_der(signature)
                .map_err(|_| Error::BadSignature)?;
            let msg =
                secp256k1::Message::from_digest_slice(message).map_err(|_| Error::BadSignature)?;
            secp256k1::SECP256K1.verify_ecdsa(&msg, &sig, &pk).map_err(|_| Error::BadSignature)
        }
        _ => Err(Error::UnsupportedKeyType),
    }
}
