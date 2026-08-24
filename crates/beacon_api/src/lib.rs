mod config;
mod identity;
mod ids;
mod json;
mod node_status;
mod receipts;
mod response;
mod router;
mod routes;
mod server;
mod statics;

pub use node_status::{NodeStatus, SlotStatus};
pub use server::BeaconApi;
