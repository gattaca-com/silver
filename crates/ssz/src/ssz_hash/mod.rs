//! Eth2-shape (fulu) hash-tree-root hashers over raw SSZ bytes. One file per
//! area: block body, execution payload, execution requests, attestations,
//! block operations (slashings / deposits / exits / bls-changes), and the
//! signing-root helpers. Built on the Merkleization core in [`crate::merkle`].
//! Gloas overrides live in [`crate::ssz_hash_gloas`].

mod attestation;
mod block_body;
mod execution_payload;
mod execution_requests;
mod operations;
mod signing;

pub use attestation::{
    hash_attestation, hash_attestation_data, hash_attester_slashing, hash_indexed_attestation,
    hash_tree_root_aggregate_and_proof,
};
pub use block_body::{
    hash_eth1_data_bytes, hash_sync_aggregate, hash_tree_root_body, hash_tree_root_body_fulu,
    kzg_commitments_inclusion_proof,
};
pub use execution_payload::{
    hash_execution_payload, hash_transactions, hash_transactions_from_payload, hash_withdrawals,
    hash_withdrawals_from_payload,
};
pub use execution_requests::hash_execution_requests_fulu;
pub use operations::{
    hash_beacon_block_header_bytes, hash_signed_beacon_block_header, hash_tree_root_deposit_data,
};
pub use signing::{
    hash_tree_root_bls_change, hash_tree_root_fork_data, hash_tree_root_voluntary_exit,
};
