mod config;
mod identity;
mod json;
mod node_status;
mod response;
mod router;
mod routes;
mod server;
mod statics;

pub use node_status::{NodeStatus, SlotStatus};
pub use server::BeaconApi;
