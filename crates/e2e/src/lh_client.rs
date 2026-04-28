//! rust-libp2p test peer for end-to-end wire-format checks against silver.
//!
//! Bring-up only: builds a Swarm with the libp2p QUIC transport (libp2p TLS,
//! same as silver) and a no-op `dummy::Behaviour`. Verifies the QUIC + libp2p
//! TLS handshake. RPC / gossip protocols are layered on once silver responds.
//!
//! All swarm work runs on a dedicated current-thread tokio runtime owned by
//! the harness, so callers stay synchronous: `tick(timeout)` block_ons one
//! event with a deadline.

use std::{net::SocketAddr, time::Duration};

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm,
    identity::Keypair,
    swarm::{SwarmEvent, dummy},
};
use tokio::runtime::Runtime;

pub struct LhClient {
    runtime: Runtime,
    swarm: Swarm<dummy::Behaviour>,
    /// `Some(peer)` once a `ConnectionEstablished` event has fired.
    connected: Option<PeerId>,
}

impl LhClient {
    /// Build a libp2p Swarm with libp2p-quic + a no-op behaviour. Generates
    /// a fresh secp256k1 keypair (peer ids are not deterministic across
    /// runs — silver's listen socket validates the cert against the dialed
    /// peer id, not the other way around). Also binds an ephemeral UDP
    /// socket so the QUIC transport has a source address to dial from.
    pub fn new() -> Self {
        let keypair = Keypair::generate_secp256k1();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let mut swarm = runtime.block_on(async {
            libp2p::SwarmBuilder::with_existing_identity(keypair)
                .with_tokio()
                .with_quic()
                .with_behaviour(|_| dummy::Behaviour)
                .expect("dummy behaviour")
                .build()
        });

        // libp2p-quic needs an explicit listener to bind its UDP socket;
        // without this `dial` panics inside quinn for lack of source addr.
        runtime.block_on(async {
            swarm
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().expect("multiaddr"))
                .expect("listen_on");
        });

        Self { runtime, swarm, connected: None }
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Dial silver at `addr`. Multistream-select / TLS happen on the way to
    /// `ConnectionEstablished`. Returns the dial result; subsequent state
    /// changes are observed via `tick`.
    pub fn dial(&mut self, addr: SocketAddr) -> Result<(), libp2p::swarm::DialError> {
        let multiaddr: Multiaddr = format!("/ip4/{}/udp/{}/quic-v1", addr.ip(), addr.port())
            .parse()
            .expect("valid multiaddr");
        let swarm = &mut self.swarm;
        // Quinn's tokio runtime adapter panics if reached outside a reactor.
        self.runtime.block_on(async move { swarm.dial(multiaddr) })
    }

    /// Drive the swarm for at most `timeout`. Processes a single event if one
    /// is available; otherwise returns when the deadline expires.
    pub fn tick(&mut self, timeout: Duration) {
        let connected = &mut self.connected;
        let swarm = &mut self.swarm;
        self.runtime.block_on(async {
            if let Ok(SwarmEvent::ConnectionEstablished { peer_id, .. }) =
                tokio::time::timeout(timeout, swarm.select_next_some()).await
            {
                *connected = Some(peer_id);
            }
        });
    }

    pub fn connected_peer(&self) -> Option<PeerId> {
        self.connected
    }
}

impl Default for LhClient {
    fn default() -> Self {
        Self::new()
    }
}
