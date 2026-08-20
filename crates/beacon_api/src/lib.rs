mod blocks;
mod config;
mod identity;
mod ids;
mod json;
mod node_status;
mod response;
mod router;
mod routes;
mod server;
mod statics;
mod validators;

pub use node_status::{NodeStatus, PeerCounts, SlotStatus};
pub use server::BeaconApi;
