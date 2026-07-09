mod control;
mod dedup;
#[path = "generated/protobuf.gossipsub.rs"]
#[allow(dead_code)]
#[rustfmt::skip]
#[allow(clippy::all)]
mod generated;
mod handler;
mod mcache;
mod message;

pub use control::{
    copy_grafts_to_protobuf_output, copy_prunes_to_protobuf_output,
    copy_subscribes_to_protobuf_output, copy_unsubscribes_to_protobuf_output,
};
pub use handler::GossipHandler;
use silver_common::{GossipMsgOut, NewGossipMsg, PeerEvent};

/// Events emitted by the GossipHandler.
#[allow(clippy::large_enum_variant)]
pub enum GossipHandlerEvent {
    PeerEvent(PeerEvent),
    NewGossip(NewGossipMsg),
    SendGossip(GossipMsgOut),
}
