use std::time::Duration;

use flux::{tile::Tile, tracing};
use mio::{net::UdpSocket, Events, Poll};
use silver_common::SilverSpine;
use slab::Slab;

pub struct NetworkTile {
    connections: Slab<UdpSocket>,
    poll: Poll,
    events: Events,
}

impl Tile<SilverSpine> for NetworkTile {
    fn loop_body(&mut self, _adapter: &mut flux::spine::SpineAdapter<SilverSpine>) {
        if let Err(e) = self.poll.poll(&mut self.events, Some(Duration::ZERO)) {
            tracing::error!(error=?e, "error on poll"); // TODO
            return;
        }

        for evt in self.events.iter() {
            match self.connections.get_mut(evt.token().0) {
                Some(_socket) => {
                    // TODO
                }
                None => {
                    tracing::warn!(token=evt.token().0, "No socket found for event"); // TODO
                }
            }
        }
    }
}