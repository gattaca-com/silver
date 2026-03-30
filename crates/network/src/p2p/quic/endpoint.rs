use std::{io::Error, net::SocketAddr, sync::Arc};

use mio::net::UdpSocket;
use quinn_proto::ServerConfig;

use crate::p2p::quic::create_endpoint;

pub struct Endpoint {
    socket: UdpSocket,
    endpoint: quinn_proto::Endpoint,
}

impl Endpoint {
    pub fn new(addr: SocketAddr, server_config: Option<Arc<ServerConfig>>) -> Result<Self, Error> {
        let socket = UdpSocket::bind(addr)?;
        let mut endpoint = create_endpoint(server_config)?;
        Ok(Self { socket, endpoint })
    }

    pub fn socket(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    pub fn endpoint(&mut self) -> &mut quinn_proto::Endpoint {
        &mut self.endpoint
    }
}
