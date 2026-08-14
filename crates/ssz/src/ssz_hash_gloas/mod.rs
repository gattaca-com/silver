//! Gloas EIP-7688 progressive hashers over raw SSZ bytes. Layouts are unchanged
//! from fulu ([`crate::ssz_hash`]); only the trees differ — progressive, no
//! limits. One file per container: each type owns its `hash_tree_root` next to
//! its [`ProgressiveContainer`](crate::progressive::ProgressiveContainer)
//! `ACTIVE_FIELDS`. Today every field is active, so the masks are
//! `packed_active_fields(N)`.

mod attestation;
mod block_body;
mod execution_payload;
mod execution_payload_bid;
mod execution_requests;
mod payload_attestation;

pub use execution_requests::{EMPTY_EXECUTION_REQUESTS_ROOT, ExecutionRequestsView};
