use std::{io::Error, sync::Arc};

use quinn_proto::{
    ClientConfig, Endpoint, EndpointConfig, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use silver_common::{Keypair, PeerId};

use super::tls;

mod leased;
mod peer;
mod stream;

pub(crate) use leased::Leased;
#[cfg(test)]
pub(crate) use leased::OutboundLeaseWheel;
pub(crate) use peer::Peer;
pub(crate) use stream::StreamWriter;

/// Create an endpoint that uses a self-signed server certificate.
pub fn create_endpoint(server_config: Option<Arc<ServerConfig>>) -> Result<Endpoint, Error> {
    let endpoint_config = Arc::new(EndpointConfig::default());
    let endpoint = Endpoint::new(endpoint_config, server_config, false, None);
    Ok(endpoint)
}

/// Quinn defaults are 10s idle with keep-alive off: quieter than 10s —
/// e.g. a connection holding no mesh slots — died `TimedOut`, since both
/// our 17s app ping and libp2p's typical 15s keep-alive are slower.
/// 30s idle matches the libp2p ecosystem; the transport-level keep-alive
/// makes quiet connections self-sustaining.
fn transport_config() -> Arc<quinn_proto::TransportConfig> {
    let mut tc = quinn_proto::TransportConfig::default();
    tc.max_idle_timeout(Some(quinn_proto::IdleTimeout::try_from(IDLE_TIMEOUT).unwrap()));
    tc.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    Arc::new(tc)
}

const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// QUIC client config with libp2p TLS authentication.
pub fn create_client_config(
    keypair: &Keypair,
    remote_peer_id: Option<PeerId>,
) -> Result<ClientConfig, Error> {
    let rustls_cfg = tls::make_client_config(keypair, remote_peer_id).map_err(Error::other)?;
    let mut config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_cfg).map_err(Error::other)?));
    config.transport_config(transport_config());
    Ok(config)
}

/// QUIC server config with libp2p TLS authentication.
pub fn create_server_config(keypair: &Keypair) -> Result<ServerConfig, Error> {
    let rustls_cfg = tls::make_server_config(keypair).map_err(Error::other)?;
    let mut config = ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(rustls_cfg).map_err(Error::other)?,
    ));
    config.transport_config(transport_config());
    Ok(config)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendResult {
    Ok,
    StreamCreationError,
    /// RPC response targeted a stream no longer in the map (closed/reset
    /// before the response was enqueued).
    StreamGone,
    MessageDropped,
    UnknownPeer,
    /// Connection is closing/draining: nothing sent on it can be delivered,
    /// and opening a stream would misreport as credit exhaustion.
    ConnectionClosing,
}
