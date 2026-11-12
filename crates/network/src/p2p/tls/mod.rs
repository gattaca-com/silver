/// libp2p TLS 1.3 certificate authentication for QUIC transport.
///
/// Vendored from rust-libp2p/libp2p-tls, stripped to secp256k1-only + QUIC.
/// Spec: https://github.com/libp2p/specs/blob/master/tls/tls.md
mod certificate;
mod verifier;

use std::sync::Arc;

use rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768;
use silver_common::{Error, Keypair, PeerId};

pub const P2P_ALPN: [u8; 6] = *b"libp2p";

/// Build rustls client config with libp2p TLS authentication.
pub fn make_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig, Error> {
    let (cert, key) = certificate::generate(keypair)?;

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();
    provider.kx_groups.insert(0, X25519MLKEM768);

    let resolver =
        Arc::new(certificate::AlwaysResolvesCert::new(cert, &key).expect("valid ECDSA P-256 key"));

    let mut cfg = rustls::ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("TLS 1.3 cipher config valid")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            verifier::Libp2pCertificateVerifier::with_remote_peer_id(remote_peer_id),
        ))
        .with_client_cert_resolver(resolver);
    cfg.alpn_protocols = vec![P2P_ALPN.to_vec()];
    Ok(cfg)
}

/// Build rustls server config with libp2p TLS authentication.
pub fn make_server_config(keypair: &Keypair) -> Result<rustls::ServerConfig, Error> {
    let (cert, key) = certificate::generate(keypair)?;

    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = verifier::CIPHERSUITES.to_vec();
    provider.kx_groups.insert(0, X25519MLKEM768);

    let resolver =
        Arc::new(certificate::AlwaysResolvesCert::new(cert, &key).expect("valid ECDSA P-256 key"));

    let mut cfg = rustls::ServerConfig::builder_with_provider(provider.into())
        .with_protocol_versions(verifier::PROTOCOL_VERSIONS)
        .expect("TLS 1.3 cipher config valid")
        .with_client_cert_verifier(Arc::new(verifier::Libp2pCertificateVerifier::new()))
        .with_cert_resolver(resolver);
    cfg.alpn_protocols = vec![P2P_ALPN.to_vec()];
    Ok(cfg)
}

/// Extract PeerId from a DER-encoded peer certificate (post-handshake).
pub fn peer_id_from_certificate(cert_der: &[u8]) -> Result<PeerId, Error> {
    Ok(certificate::parse_der(cert_der)?.peer_id())
}

#[cfg(test)]
mod tests {
    use rustls::{
        NamedGroup,
        quic::{ClientConnection, ServerConnection, Version},
    };

    use super::*;

    #[test]
    fn handshake_negotiates_hybrid_key_exchange() {
        let client = Keypair::from_secret(&[3; 32]).unwrap();
        let server = Keypair::from_secret(&[4; 32]).unwrap();
        let mut client = ClientConnection::new(
            Arc::new(make_client_config(&client, None).unwrap()),
            Version::V1,
            "l".try_into().unwrap(),
            Vec::new(),
        )
        .unwrap();
        let mut server = ServerConnection::new(
            Arc::new(make_server_config(&server).unwrap()),
            Version::V1,
            Vec::new(),
        )
        .unwrap();

        let mut flights = 0;
        while client.is_handshaking() || server.is_handshaking() {
            let mut buf = Vec::new();
            client.write_hs(&mut buf);
            server.read_hs(&buf).unwrap();
            buf.clear();
            server.write_hs(&mut buf);
            client.read_hs(&buf).unwrap();
            flights += 1;
            assert!(flights < 8);
        }

        for group in
            [client.negotiated_key_exchange_group(), server.negotiated_key_exchange_group()]
        {
            assert_eq!(group.unwrap().name(), NamedGroup::X25519MLKEM768);
        }
    }
}
