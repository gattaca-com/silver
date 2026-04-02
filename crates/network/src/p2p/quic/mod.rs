use std::{io::Error, sync::Arc};

use quinn_proto::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use silver_common::{Keypair, PeerId};

use super::tls;

mod peer;

pub(crate) use peer::Peer;

/// Create an endpoint that uses a self-signed server certificate.
pub fn create_endpoint(server_config: Option<Arc<ServerConfig>>) -> Result<Endpoint, Error> {
    let endpoint_config = Arc::new(EndpointConfig::default());
    let endpoint = Endpoint::new(endpoint_config, server_config, false, None);
    Ok(endpoint)
}

/// QUIC client config with libp2p TLS authentication.
pub fn create_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<ClientConfig, Error> {
    let rustls_cfg = tls::make_client_config(keypair, remote_peer_id).map_err(Error::other)?;
    Ok(ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_cfg).map_err(Error::other)?)))
}

/// QUIC server config with libp2p TLS authentication.
pub fn create_server_config(keypair: &Keypair) -> Result<ServerConfig, Error> {
    let rustls_cfg = tls::make_server_config(keypair).map_err(Error::other)?;
    Ok(ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rustls_cfg).map_err(Error::other)?,
    )))
}
