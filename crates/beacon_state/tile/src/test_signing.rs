//! Test-only BLS signing kit emitting signed SSZ buffers for the gossip
//! handlers.

#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

use blst::min_pk::{PublicKey, SecretKey};
use silver_beacon_state_data::{
    B256, BLSPubkey, BeaconBlockHeader, Fork, Immutable, SLOTS_PER_EPOCH,
};
use silver_common::ssz_view::{
    ATTESTATION_FIXED, AttestationView, IndexedAttestationView, PAYLOAD_ATTESTATION_MESSAGE_SIZE,
    PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_AGG_PROOF_MIN, SIGNED_BLS_CHANGE_SIZE,
    SIGNED_VOLUNTARY_EXIT_SIZE, SINGLE_ATT_SIZE, SignedAggregateAndProofView,
    SignedBlsToExecutionChangeView, SignedVoluntaryExitView, SingleAttestationView,
};

use crate::{
    bls, merkle,
    ssz_hash::{self, hash_tree_root_block_header},
};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Spec test private keys (consensus-specs/tests/core/.../bls/constants.py).
pub const PRIVKEY_HEX: [&str; 3] = [
    "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
    "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
];

pub fn privkey(idx: usize) -> SecretKey {
    let bytes = hex_to_bytes(PRIVKEY_HEX[idx]);
    SecretKey::from_bytes(&bytes).unwrap()
}

pub fn pubkey_pk(idx: usize) -> PublicKey {
    privkey(idx).sk_to_pk()
}

pub fn pubkey_bytes(idx: usize) -> BLSPubkey {
    pubkey_pk(idx).to_bytes()
}

pub fn sign(sk_idx: usize, message: &[u8]) -> [u8; 96] {
    privkey(sk_idx).sign(message, DST, &[]).to_bytes()
}

fn test_fork_version(target_epoch: u64) -> [u8; 4] {
    let f = Fork::default();
    bls::fork_version_at_epoch(f.epoch, f.previous_version, f.current_version, target_epoch)
}

pub fn hex_to_bytes(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).unwrap();
        out[i] = u8::from_str_radix(s, 16).unwrap();
    }
    out
}

/// Build a `SignedVoluntaryExit` signed by `sk_idx`.
pub fn sign_voluntary_exit(
    sk_idx: usize,
    exit_epoch: u64,
    vi: u64,
    imm: &Immutable,
) -> [u8; SIGNED_VOLUNTARY_EXIT_SIZE] {
    let mut buf = [0u8; SIGNED_VOLUNTARY_EXIT_SIZE];
    buf[0..8].copy_from_slice(&exit_epoch.to_le_bytes());
    buf[8..16].copy_from_slice(&vi.to_le_bytes());

    let object_root = ssz_hash::hash_tree_root_voluntary_exit(exit_epoch, vi);
    let domain = bls::compute_domain(
        bls::DOMAIN_VOLUNTARY_EXIT,
        imm.capella_fork_version,
        &imm.genesis_validators_root,
    );
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    let sig = sign(sk_idx, &signing_root);
    buf[16..112].copy_from_slice(&sig);
    debug_assert_eq!(SignedVoluntaryExitView::signature(&buf), &sig);
    buf
}

/// Build a `ProposerSlashing` with two distinct-`body_root` headers, both
/// signed by `sk_idx`. Same slot, same proposer.
pub fn sign_proposer_slashing(
    sk_idx: usize,
    vi: u64,
    slot: u64,
    imm: &Immutable,
) -> [u8; PROPOSER_SLASHING_SIZE] {
    let mk_header = |body_root: B256| BeaconBlockHeader {
        slot,
        proposer_index: vi,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body_root,
    };
    let h1 = mk_header([0xAA; 32]);
    let h2 = mk_header([0xBB; 32]);

    let fv = test_fork_version(slot / SLOTS_PER_EPOCH);
    let domain = bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fv, &imm.genesis_validators_root);
    let sr1 = bls::compute_signing_root(&hash_tree_root_block_header(&h1), &domain);
    let sr2 = bls::compute_signing_root(&hash_tree_root_block_header(&h2), &domain);
    let sig1 = sign(sk_idx, &sr1);
    let sig2 = sign(sk_idx, &sr2);

    let mut buf = [0u8; PROPOSER_SLASHING_SIZE];
    write_header(&mut buf[0..112], &h1);
    buf[112..208].copy_from_slice(&sig1);
    write_header(&mut buf[208..320], &h2);
    buf[320..416].copy_from_slice(&sig2);
    debug_assert_eq!(ProposerSlashingView::h1_signature(&buf), &sig1);
    debug_assert_eq!(ProposerSlashingView::h2_signature(&buf), &sig2);
    buf
}

fn write_header(out: &mut [u8], h: &BeaconBlockHeader) {
    out[0..8].copy_from_slice(&h.slot.to_le_bytes());
    out[8..16].copy_from_slice(&h.proposer_index.to_le_bytes());
    out[16..48].copy_from_slice(&h.parent_root);
    out[48..80].copy_from_slice(&h.state_root);
    out[80..112].copy_from_slice(&h.body_root);
}

/// Build a `SignedBLSToExecutionChange` signed by `sk_idx`. Caller must
/// ensure the validator at `vi` has BLS-prefix withdrawal credentials whose
/// `[1..]` bytes equal `sha256(pubkey_bytes(sk_idx))[1..]`.
pub fn sign_bls_to_execution_change(
    sk_idx: usize,
    vi: u64,
    to_address: &[u8; 20],
    imm: &Immutable,
) -> [u8; SIGNED_BLS_CHANGE_SIZE] {
    let from_pubkey = pubkey_bytes(sk_idx);
    let object_root = ssz_hash::hash_tree_root_bls_change(vi, &from_pubkey, to_address);
    let domain = bls::compute_domain(
        bls::DOMAIN_BLS_TO_EXECUTION_CHANGE,
        imm.genesis_fork_version,
        &imm.genesis_validators_root,
    );
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    let sig = sign(sk_idx, &signing_root);

    let mut buf = [0u8; SIGNED_BLS_CHANGE_SIZE];
    buf[0..8].copy_from_slice(&vi.to_le_bytes());
    buf[8..56].copy_from_slice(&from_pubkey);
    buf[56..76].copy_from_slice(to_address);
    buf[76..172].copy_from_slice(&sig);
    debug_assert_eq!(SignedBlsToExecutionChangeView::signature(&buf), &sig);
    buf
}

/// Build a single-signer `IndexedAttestation` for use inside an
/// `AttesterSlashing`. `target_epoch` and the optional `source_epoch_override`
/// drive double-vote vs surround-vote semantics.
pub fn build_indexed_attestation(
    sk_idx: usize,
    vi: u64,
    slot: u64,
    target_epoch: u64,
    source_epoch: u64,
    beacon_block_root_marker: u8,
    imm: &Immutable,
) -> Vec<u8> {
    // IndexedAttestation: { offset(4) to attesting_indices(var),
    //   data(128), sig(96), attesting_indices(var) }
    // Fixed part = 228B. attesting_indices = 1 × u64 = 8B.
    let mut buf = vec![0u8; 228 + 8];
    let indices_off: u32 = 228;
    buf[0..4].copy_from_slice(&indices_off.to_le_bytes());

    // AttestationData: slot(8), index(8), beacon_block_root(32),
    //   source(epoch+root, 40), target(epoch+root, 40) = 128B
    buf[4..12].copy_from_slice(&slot.to_le_bytes());
    // index = 0 (Fulu single-committee invariant)
    buf[20] = beacon_block_root_marker;
    buf[52..60].copy_from_slice(&source_epoch.to_le_bytes());
    buf[92..100].copy_from_slice(&target_epoch.to_le_bytes());

    // Sign the AttestationData under DOMAIN_BEACON_ATTESTER for target_epoch.
    let fv = test_fork_version(target_epoch);
    let data: &[u8; 128] = buf[4..132].try_into().unwrap();
    let object_root = ssz_hash::hash_attestation_data(data);
    let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    let sig = sign(sk_idx, &signing_root);
    buf[132..228].copy_from_slice(&sig);

    // attesting_indices = [vi]
    buf[228..236].copy_from_slice(&vi.to_le_bytes());

    debug_assert_eq!(IndexedAttestationView::target_epoch(&buf), target_epoch);
    debug_assert_eq!(IndexedAttestationView::signature(&buf), &sig);
    buf
}

/// Build an `AttesterSlashing` (single-validator double-vote, both attestations
/// signed by `sk_idx` over `vi`). Same target_epoch, different
/// beacon_block_root → double-vote per spec.
pub fn sign_attester_slashing_double_vote(
    sk_idx: usize,
    vi: u64,
    slot: u64,
    target_epoch: u64,
    imm: &Immutable,
) -> Vec<u8> {
    let ia1 = build_indexed_attestation(sk_idx, vi, slot, target_epoch, 0, 0xAA, imm);
    let ia2 = build_indexed_attestation(sk_idx, vi, slot, target_epoch, 0, 0xBB, imm);

    // AttesterSlashing: { offset(4) to att_1, offset(4) to att_2,
    //   att_1(var), att_2(var) }
    let mut buf = Vec::with_capacity(8 + ia1.len() + ia2.len());
    let off1: u32 = 8;
    let off2: u32 = off1 + ia1.len() as u32;
    buf.extend_from_slice(&off1.to_le_bytes());
    buf.extend_from_slice(&off2.to_le_bytes());
    buf.extend_from_slice(&ia1);
    buf.extend_from_slice(&ia2);
    buf
}

/// Build a `SingleAttestation` (gossip subnet form) signed by `sk_idx`.
/// Caller resolves `(slot, committee_index)` so `attester_index` is in the
/// resolved committee.
#[allow(clippy::too_many_arguments)]
pub fn sign_single_attestation(
    sk_idx: usize,
    attester_index: u64,
    committee_index: u64,
    slot: u64,
    beacon_block_root: B256,
    target_epoch: u64,
    target_root: B256,
    imm: &Immutable,
) -> [u8; SINGLE_ATT_SIZE] {
    let mut buf = [0u8; SINGLE_ATT_SIZE];
    buf[0..8].copy_from_slice(&committee_index.to_le_bytes());
    buf[8..16].copy_from_slice(&attester_index.to_le_bytes());
    // AttestationData @ buf[16..144]: slot, index=0 (Fulu), beacon_block_root,
    // source (zero), target — written at the view's spec offsets.
    buf[16..24].copy_from_slice(&slot.to_le_bytes());
    buf[32..64].copy_from_slice(&beacon_block_root);
    buf[104..112].copy_from_slice(&target_epoch.to_le_bytes());
    buf[112..144].copy_from_slice(&target_root);

    resign_single_attestation(sk_idx, &mut buf, imm);
    buf
}

/// Recompute the signature over the buffer's current `AttestationData`, for
/// tests that mutate data fields after `sign_single_attestation`.
pub fn resign_single_attestation(sk_idx: usize, buf: &mut [u8; SINGLE_ATT_SIZE], imm: &Immutable) {
    let data: [u8; 128] = buf[16..144].try_into().unwrap();
    let fv = test_fork_version(SingleAttestationView::target_epoch(buf));
    let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &imm.genesis_validators_root);
    let signing_root = bls::compute_signing_root(&ssz_hash::hash_attestation_data(&data), &domain);
    let sig = sign(sk_idx, &signing_root);
    buf[144..240].copy_from_slice(&sig);
    debug_assert_eq!(SingleAttestationView::signature(buf), &sig);
}

pub fn sign_sync_committee_message(
    sk_idx: usize,
    vi: u64,
    slot: u64,
    beacon_block_root: B256,
    imm: &Immutable,
) -> [u8; 144] {
    let mut buf = [0u8; 144];
    buf[0..8].copy_from_slice(&slot.to_le_bytes());
    buf[8..40].copy_from_slice(&beacon_block_root);
    buf[40..48].copy_from_slice(&vi.to_le_bytes());

    let fv = test_fork_version(slot / SLOTS_PER_EPOCH);
    let domain = bls::compute_domain(bls::DOMAIN_SYNC_COMMITTEE, fv, &imm.genesis_validators_root);
    let sig = sign(sk_idx, &bls::compute_signing_root(&beacon_block_root, &domain));
    buf[48..144].copy_from_slice(&sig);
    buf
}

pub fn sign_payload_attestation_message(
    sk_idx: usize,
    validator_index: u64,
    slot: u64,
    beacon_block_root: B256,
    payload_present: u8,
    blob_data_available: u8,
    imm: &Immutable,
) -> [u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE] {
    let mut buf = [0u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE];
    buf[0..8].copy_from_slice(&validator_index.to_le_bytes());
    buf[8..40].copy_from_slice(&beacon_block_root);
    buf[40..48].copy_from_slice(&slot.to_le_bytes());
    buf[48] = payload_present;
    buf[49] = blob_data_available;

    let data: &[u8; 42] = (&buf[8..50]).try_into().unwrap();
    let fv = test_fork_version(slot / SLOTS_PER_EPOCH);
    let domain = bls::compute_domain(bls::DOMAIN_PTC_ATTESTER, fv, &imm.genesis_validators_root);
    let signing_root =
        bls::compute_signing_root(&crate::stf::hash_payload_attestation_data(data), &domain);
    let signature = sign(sk_idx, &signing_root);
    buf[50..146].copy_from_slice(&signature);
    buf
}

pub fn sync_selection_proof(
    sk_idx: usize,
    slot: u64,
    subcommittee: u64,
    imm: &Immutable,
) -> [u8; 96] {
    let fv = test_fork_version(slot / SLOTS_PER_EPOCH);
    let domain = bls::compute_domain(
        bls::DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
        fv,
        &imm.genesis_validators_root,
    );
    let root = ssz_hash::hash_tree_root_sync_selection_data(slot, subcommittee);
    sign(sk_idx, &bls::compute_signing_root(&root, &domain))
}

pub fn sign_contribution_and_proof(
    sk_agg: usize,
    aggregator_index: u64,
    slot: u64,
    subcommittee: u64,
    participant_pos: usize,
    sk_part: usize,
    beacon_block_root: B256,
    imm: &Immutable,
) -> [u8; 360] {
    let fv = test_fork_version(slot / SLOTS_PER_EPOCH);
    let domain = |ty| bls::compute_domain(ty, fv, &imm.genesis_validators_root);

    let mut bits = [0u8; 16];
    bits[participant_pos / 8] |= 1 << (participant_pos % 8);
    let contrib_sig = sign(
        sk_part,
        &bls::compute_signing_root(&beacon_block_root, &domain(bls::DOMAIN_SYNC_COMMITTEE)),
    );
    let selection_proof = sync_selection_proof(sk_agg, slot, subcommittee, imm);

    let contribution_root = ssz_hash::hash_tree_root_sync_contribution(
        slot,
        &beacon_block_root,
        subcommittee,
        &bits,
        &contrib_sig,
    );
    let cap_root = ssz_hash::hash_tree_root_contribution_and_proof(
        aggregator_index,
        &contribution_root,
        &selection_proof,
    );
    let outer = sign(
        sk_agg,
        &bls::compute_signing_root(&cap_root, &domain(bls::DOMAIN_CONTRIBUTION_AND_PROOF)),
    );

    let mut buf = [0u8; 360];
    buf[0..8].copy_from_slice(&aggregator_index.to_le_bytes());
    buf[8..16].copy_from_slice(&slot.to_le_bytes());
    buf[16..48].copy_from_slice(&beacon_block_root);
    buf[48..56].copy_from_slice(&subcommittee.to_le_bytes());
    buf[56..72].copy_from_slice(&bits);
    buf[72..168].copy_from_slice(&contrib_sig);
    buf[168..264].copy_from_slice(&selection_proof);
    buf[264..360].copy_from_slice(&outer);
    buf
}

/// Build a single-signer `Attestation`: `committee_index` is the (single)
/// bit in `committee_bits`; the bit at `participant_pos` is the only set bit
/// in `aggregation_bits` — that participant signs the aggregate.
pub fn build_attestation(
    sk_idx: usize,
    slot: u64,
    target_epoch: u64,
    beacon_block_root: B256,
    target_root: B256,
    committee_index: usize,
    participant_pos: usize,
    committee_size: usize,
    imm: &Immutable,
) -> Vec<u8> {
    // Trailing Bitlist[committee_size] with terminator bit at position
    // `committee_size` → length = ceil((committee_size+1)/8).
    let bl_len = (committee_size + 1).div_ceil(8);
    let mut buf = vec![0u8; ATTESTATION_FIXED + bl_len];

    buf[0..4].copy_from_slice(&(ATTESTATION_FIXED as u32).to_le_bytes());

    // AttestationData[4..132]: slot, index(=0), beacon_block_root, source,
    // target.
    buf[4..12].copy_from_slice(&slot.to_le_bytes());
    buf[20..52].copy_from_slice(&beacon_block_root);
    buf[92..100].copy_from_slice(&target_epoch.to_le_bytes());
    buf[100..132].copy_from_slice(&target_root);

    // committee_bits[228..236]: single bit at `committee_index`.
    buf[228 + committee_index / 8] |= 1 << (committee_index % 8);

    // aggregation_bits: participant bit, then terminator.
    buf[ATTESTATION_FIXED + participant_pos / 8] |= 1 << (participant_pos % 8);
    buf[ATTESTATION_FIXED + committee_size / 8] |= 1 << (committee_size % 8);

    let fv = test_fork_version(target_epoch);
    let data: &[u8; 128] = buf[4..132].try_into().unwrap();
    let data_root = ssz_hash::hash_attestation_data(data);
    let domain_att =
        bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &imm.genesis_validators_root);
    let sig = sign(sk_idx, &bls::compute_signing_root(&data_root, &domain_att));
    buf[132..228].copy_from_slice(&sig);

    debug_assert_eq!(AttestationView::signature(&buf), &sig);
    debug_assert_eq!(AttestationView::data(&buf).target_epoch(), target_epoch);
    buf
}

/// Wrap an existing inner `Attestation` SSZ buffer in a fully signed
/// `SignedAggregateAndProof`: `sk_idx` (the aggregator's key) signs the
/// selection proof over the attestation's slot and the outer signature;
/// the inner aggregate keeps whatever signature it carries.
pub fn wrap_aggregate_and_proof(
    sk_idx: usize,
    aggregator_index: u64,
    attestation: &[u8],
    imm: &Immutable,
) -> Vec<u8> {
    const PREFIX: usize = SIGNED_AGG_PROOF_MIN - ATTESTATION_FIXED;

    // Outer fixed: offset to message(4) = 100, signature(96) = [4..100).
    // AggregateAndProof: aggregator_index(8) at 100, offset to aggregate(4)
    // = 108 (relative-to-message = 108), selection_proof(96) at 112.
    let mut buf = vec![0u8; PREFIX + attestation.len()];
    buf[0..4].copy_from_slice(&100u32.to_le_bytes());
    buf[100..108].copy_from_slice(&aggregator_index.to_le_bytes());
    buf[108..112].copy_from_slice(&108u32.to_le_bytes());
    buf[PREFIX..].copy_from_slice(attestation);

    let data = AttestationView::data(attestation);
    let fv = test_fork_version(data.target_epoch());

    // Selection proof: signer = aggregator, msg = htr(uint64(slot)).
    let slot_root = merkle::uint64_chunk(data.slot());
    let domain_sp =
        bls::compute_domain(bls::DOMAIN_SELECTION_PROOF, fv, &imm.genesis_validators_root);
    let selection_proof = sign(sk_idx, &bls::compute_signing_root(&slot_root, &domain_sp));
    buf[112..208].copy_from_slice(&selection_proof);

    let agg_proof_root = ssz_hash::hash_tree_root_aggregate_and_proof(
        aggregator_index,
        &buf[PREFIX..],
        ssz_hash::hash_attestation_data(data.as_bytes()),
        &selection_proof,
        fv == imm.gloas_fork_version,
    );
    let domain_aap =
        bls::compute_domain(bls::DOMAIN_AGGREGATE_AND_PROOF, fv, &imm.genesis_validators_root);
    let outer_sig = sign(sk_idx, &bls::compute_signing_root(&agg_proof_root, &domain_aap));
    buf[4..100].copy_from_slice(&outer_sig);

    debug_assert_eq!(SignedAggregateAndProofView::signature(&buf), &outer_sig);
    buf
}

/// Build a fully signed `SignedAggregateAndProof` from a single-signer
/// committee — the participant at `aggregator_pos_in_committee` signs the
/// inner aggregate, and the same validator is the aggregator.
#[allow(clippy::too_many_arguments)]
pub fn sign_aggregate_and_proof(
    sk_idx: usize,
    aggregator_index: u64,
    slot: u64,
    target_epoch: u64,
    beacon_block_root: B256,
    target_root: B256,
    committee_index: usize,
    aggregator_pos_in_committee: usize,
    committee_size: usize,
    imm: &Immutable,
) -> Vec<u8> {
    let att = build_attestation(
        sk_idx,
        slot,
        target_epoch,
        beacon_block_root,
        target_root,
        committee_index,
        aggregator_pos_in_committee,
        committee_size,
        imm,
    );
    wrap_aggregate_and_proof(sk_idx, aggregator_index, &att, imm)
}
