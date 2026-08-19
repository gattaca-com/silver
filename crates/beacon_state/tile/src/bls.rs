pub(crate) use blst::min_pk::{PublicKey, Signature};
use blst::{BLST_ERROR, min_pk::AggregatePublicKey};
use flux_profiler::timed;
use silver_beacon_state_data::{B256, BLSPubkey, BeaconBlockHeader, SYNC_COMMITTEE_SIZE};
use silver_common::ssz_view::{
    SIGNED_BEACON_BLOCK_MIN, SINGLE_ATT_SIZE, SignedBeaconBlockView, SingleAttestationView,
};

use crate::{
    merkle,
    ssz_hash::{self, hash_tree_root_block_header},
};

mod aggregator;
mod sig_batch;

pub(crate) use aggregator::PubkeyAggregator;
pub use sig_batch::SigBatch;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// G2 point at infinity (compressed). Spec: a sync_aggregate over an empty
/// participant set verifies iff the signature is this value.
pub(crate) const G2_POINT_AT_INFINITY: [u8; 96] = {
    let mut s = [0u8; 96];
    s[0] = 0xc0;
    s
};

pub const DOMAIN_BEACON_PROPOSER: u32 = 0x0000_0000;
pub const DOMAIN_BEACON_ATTESTER: u32 = 0x0000_0001;
pub const DOMAIN_RANDAO: u32 = 0x0000_0002;
pub const DOMAIN_DEPOSIT: u32 = 0x0000_0003;
pub const DOMAIN_VOLUNTARY_EXIT: u32 = 0x0000_0004;
pub const DOMAIN_SELECTION_PROOF: u32 = 0x0000_0005;
pub const DOMAIN_AGGREGATE_AND_PROOF: u32 = 0x0000_0006;
pub const DOMAIN_SYNC_COMMITTEE: u32 = 0x0000_0007;
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: u32 = 0x0000_000a;
// Gloas
pub const DOMAIN_BEACON_BUILDER: u32 = 0x0000_000b;
pub const DOMAIN_PTC_ATTESTER: u32 = 0x0000_000c;
pub const DOMAIN_BUILDER_DEPOSIT: u32 = 0x0000_000e;

#[timed]
pub fn compute_domain(
    domain_type: u32,
    fork_version: [u8; 4],
    genesis_validators_root: &B256,
) -> B256 {
    let fork_data_root = ssz_hash::hash_tree_root_fork_data(fork_version, genesis_validators_root);
    domain_from_fork_data(domain_type, &fork_data_root)
}

pub fn domain_from_fork_data(domain_type: u32, fork_data_root: &B256) -> B256 {
    let mut domain = [0u8; 32];
    domain[0..4].copy_from_slice(&domain_type.to_le_bytes());
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

pub fn compute_signing_root(object_root: &B256, domain: &B256) -> B256 {
    merkle::hash_concat(object_root, domain)
}

#[inline]
pub fn fork_version_at_epoch(
    fork_epoch: u64,
    previous_version: [u8; 4],
    current_version: [u8; 4],
    epoch: u64,
) -> [u8; 4] {
    if epoch < fork_epoch { previous_version } else { current_version }
}

/// Single-key BLS verify over an arbitrary 32-byte message. Caller passes
/// a decompressed pubkey (from `vid.val_pubkey_decompressed`) — pubkeys are
/// admission-validated, so we skip `pk_validate` and only group-check the
/// signature. For one-shot paths where only the compressed bytes are
/// available (e.g. `verify_deposit_signature`), use `verify_one_compressed`.
pub(crate) fn verify_one(pk: &PublicKey, sig: &[u8; 96], message: &B256) -> bool {
    let Ok(sig) = Signature::from_bytes(sig) else { return false };
    verify_one_parsed(pk, &sig, message)
}

#[timed]
pub(crate) fn verify_one_parsed(pk: &PublicKey, sig: &Signature, message: &B256) -> bool {
    sig.verify(true, message, DST, &[], pk, false) == BLST_ERROR::BLST_SUCCESS
}

/// Same as `verify_one` but decompresses the pubkey inline. Used at
/// admission time (deposit pop) before the cache exists.
pub(crate) fn verify_one_compressed(pubkey: &BLSPubkey, sig: &[u8; 96], message: &B256) -> bool {
    let Ok(pk) = PublicKey::key_validate(pubkey) else { return false };
    verify_one(&pk, sig, message)
}

pub fn aggregate_pubkeys(pubkeys: &[BLSPubkey; SYNC_COMMITTEE_SIZE]) -> BLSPubkey {
    let mut iter = pubkeys.iter();
    let Some(first_bytes) = iter.next() else { return [0u8; 48] };
    let Ok(first_pk) = PublicKey::from_bytes(first_bytes) else { return [0u8; 48] };
    let mut agg = AggregatePublicKey::from_public_key(&first_pk);
    for pk_bytes in iter {
        let Ok(pk) = PublicKey::from_bytes(pk_bytes) else { return [0u8; 48] };
        if agg.add_public_key(&pk, true).is_err() {
            return [0u8; 48];
        }
    }
    agg.to_public_key().to_bytes()
}

pub fn verify_block_signature(
    block_ssz: &[u8],
    proposer_pubkey: &PublicKey,
    body_root: &B256,
    domain: &B256,
) -> bool {
    if block_ssz.len() < SIGNED_BEACON_BLOCK_MIN {
        return false;
    }

    let sig = SignedBeaconBlockView::signature(block_ssz);
    let header = BeaconBlockHeader {
        slot: SignedBeaconBlockView::slot(block_ssz),
        proposer_index: SignedBeaconBlockView::proposer_index(block_ssz),
        parent_root: *SignedBeaconBlockView::parent_root(block_ssz),
        state_root: *SignedBeaconBlockView::state_root(block_ssz),
        body_root: *body_root,
    };
    let object_root = hash_tree_root_block_header(&header);
    let signing_root = compute_signing_root(&object_root, domain);

    verify_one(proposer_pubkey, sig, &signing_root)
}

/// Verify a deposit proof-of-possession. Pubkey comes from the deposit
/// data (not yet a registered validator) so we decompress inline.
pub fn verify_deposit_signature(pubkey: &BLSPubkey, sig: &[u8; 96], signing_root: &B256) -> bool {
    verify_one_compressed(pubkey, sig, signing_root)
}

/// Signature is subgroup-checked by the verify, so downstream aggregation
/// may add it without a second group check.
pub struct VerifiedSingleAttestation {
    pub data_root: B256,
    pub signature: Signature,
}

/// Verify a single-attester `SingleAttestation` (gossip subnet form) against
/// caller-derived roots (they repeat across a slot's attestations, so the
/// caller memoizes them). The body-included aggregate path goes through
/// `stf::validate_attestations` + `SigBatch`.
#[timed]
pub fn verify_single_attestation(
    att: &[u8; SINGLE_ATT_SIZE],
    attester_pubkey: &PublicKey,
    data_root: B256,
    signing_root: &B256,
) -> Option<VerifiedSingleAttestation> {
    let signature = Signature::from_bytes(SingleAttestationView::signature(att)).ok()?;

    verify_one_parsed(attester_pubkey, &signature, signing_root)
        .then_some(VerifiedSingleAttestation { data_root, signature })
}
