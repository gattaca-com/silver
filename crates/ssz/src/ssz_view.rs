// Zero-copy SSZ field extraction for Fulu p2p wire types.

pub enum SszView {
    SingleAttestation(SingleAttestationView),
    ProposerSlashing(ProposerSlashingView),
    SignedVoluntaryExit(SignedVoluntaryExitView),
    SyncCommittee(SyncCommitteeView),
    SignedContributionAndProof(SignedContributionAndProofView),
    SignedBlsToExecutionChange(SignedBlsToExecutionChangeView),
    SignedBeaconBlock(SignedBeaconBlockView),
    SignedAggregateAndProof(SignedAggregateAndProofView),
    AttesterSlashing(AttesterSlashingView),
    DataColumnSidecar(DataColumnSidecarFuluView),
    LightClientHeader(LightClientHeaderView),
    LightClientFinalityUpdate(LightClientFinalityUpdateView),
    LightClientOptimisticUpdate(LightClientOptimisticUpdateView),
    Status(StatusView),
    Metadata(MetadataView),
    BeaconBlocksByRangeRequest(BeaconBlocksByRangeRequestView),
    Ping(PingView),
    Goodbye(GoodbyeView),
    BeaconBlocksByRootRequest(BeaconBlocksByRootRequestView),
    DataColumnSidecarsByRangeRequest(DataColumnSidecarsByRangeRequestView),
    DataColumnsByRootIdentifier(DataColumnsByRootIdentifierView),

    // [New in Gloas]
    SignedExecutionPayloadBid(SignedExecutionPayloadBidView),
    SignedExecutionPayloadEnvelope(SignedExecutionPayloadEnvelopeView),
    PayloadAttestationMessage(PayloadAttestationMessageView),
    SignedProposerPreferences(SignedProposerPreferencesView),
    DataColumnSidecarGloas(DataColumnSidecarGloasView),
    ExecutionPayloadEnvelopesByRangeRequest(ExecutionPayloadEnvelopesByRangeRequestView),
    ExecutionPayloadEnvelopesByRootRequest(ExecutionPayloadEnvelopesByRootRequestView),
    None,
}

#[inline(always)]
fn u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

#[inline(always)]
fn u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

#[inline(always)]
fn fixed<const N: usize>(buf: &[u8], off: usize) -> &[u8; N] {
    buf[off..off + N].try_into().unwrap()
}

// -- Spec size bounds (Fulu) ------------------------------------------
//
// Global cap on any uncompressed gossip/RPC payload. Per-type SSZ bounds
// below are the tighter, type-specific caps derived from list limits;
// the enforced cap is `min(MAX_PAYLOAD_SIZE, <type_max>)`.

pub const MAX_PAYLOAD_SIZE: usize = 10 * 1024 * 1024;

// List/bit-length limits referenced by the views below.
pub const MAX_VALIDATORS_PER_COMMITTEE: usize = 2048;
pub const MAX_COMMITTEES_PER_SLOT: usize = 64;
pub const MAX_ATTESTING_INDICES: usize = MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT;
pub const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
pub const NUMBER_OF_COLUMNS: usize = 128;
pub const MAX_REQUEST_BLOCKS_DENEB: usize = 128;
pub const MAX_REQUEST_PAYLOADS: usize = 128;

// Element sizes used in list-length bounds.
pub const BYTES_PER_CELL: usize = 2048; // 64 field elems * 32B
pub const BYTES_PER_KZG_COMMITMENT: usize = 48;
pub const BYTES_PER_KZG_PROOF: usize = 48;

// Block-body list limits (beacon-chain.md).
pub const MAX_PROPOSER_SLASHINGS: usize = 16;
pub const MAX_ATTESTER_SLASHINGS_ELECTRA: usize = 1;
pub const MAX_ATTESTATIONS_ELECTRA: usize = 8;
pub const MAX_DEPOSITS: usize = 16;
pub const MAX_VOLUNTARY_EXITS: usize = 16;
pub const MAX_BLS_TO_EXECUTION_CHANGES: usize = 16;
pub const MAX_PAYLOAD_ATTESTATIONS: usize = 4;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 16;
pub const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1 << 20;
pub const MAX_BYTES_PER_TRANSACTION: usize = 1 << 30;
pub const MAX_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 8192;
pub const MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD: usize = 16;
pub const MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD: usize = 2;
pub const MAX_BUILDER_DEPOSIT_REQUESTS_PER_PAYLOAD: usize = 256;
pub const MAX_BUILDER_EXIT_REQUESTS_PER_PAYLOAD: usize = 16;
pub const DEPOSIT_CONTRACT_TREE_DEPTH: usize = 32;
pub const SYNC_COMMITTEE_SIZE: usize = 512;

// -- SingleAttestation (beacon_attestation_{subnet_id}) ---------------
//
// All fixed, exactly 240B.
//   [0..8)     committee_index
//   [8..16)    attester_index
//   [16..144)  AttestationData (128B)
//     [16..24)   slot
//     [24..32)   index (always 0 post-Electra)
//     [32..64)   beacon_block_root
//     [64..72)   source.epoch
//     [72..104)  source.root
//     [104..112) target.epoch
//     [112..144) target.root
//   [144..240) signature

pub const SINGLE_ATT_SIZE: usize = 240;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SingleAttestationView;

impl SingleAttestationView {
    #[inline]
    pub fn committee_index(buf: &[u8; SINGLE_ATT_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn attester_index(buf: &[u8; SINGLE_ATT_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn slot(buf: &[u8; SINGLE_ATT_SIZE]) -> u64 {
        u64_le(buf, 16)
    }
    #[inline]
    pub fn data_index(buf: &[u8; SINGLE_ATT_SIZE]) -> u64 {
        u64_le(buf, 24)
    }
    #[inline]
    pub fn beacon_block_root(buf: &[u8; SINGLE_ATT_SIZE]) -> &[u8; 32] {
        fixed(buf, 32)
    }
    #[inline]
    pub fn source_epoch(buf: &[u8; SINGLE_ATT_SIZE]) -> u64 {
        u64_le(buf, 64)
    }
    #[inline]
    pub fn source_root(buf: &[u8; SINGLE_ATT_SIZE]) -> &[u8; 32] {
        fixed(buf, 72)
    }
    #[inline]
    pub fn target_epoch(buf: &[u8; SINGLE_ATT_SIZE]) -> u64 {
        u64_le(buf, 104)
    }
    #[inline]
    pub fn target_root(buf: &[u8; SINGLE_ATT_SIZE]) -> &[u8; 32] {
        fixed(buf, 112)
    }
    #[inline]
    pub fn signature(buf: &[u8; SINGLE_ATT_SIZE]) -> &[u8; 96] {
        fixed(buf, 144)
    }
    #[inline]
    pub fn data(buf: &[u8; SINGLE_ATT_SIZE]) -> &[u8; 128] {
        fixed(buf, 16)
    }
}

// -- IndexedAttestation (inside AttesterSlashing) ---------------------
//
// Variable (trailing `attesting_indices`). Fixed prefix 228B.
//
// IndexedAttestation: { attesting_indices: List[u64, MAX_ATTESTING_INDICES],
//                       data: AttestationData(128), signature(96) }
//
//   [0..4)     offset to attesting_indices (== 228)
//   [4..132)   data (AttestationData 128B)
//     [4..12)    slot
//     [12..20)   index
//     [20..52)   beacon_block_root
//     [52..60)   source.epoch
//     [60..92)   source.root
//     [92..100)  target.epoch
//     [100..132) target.root
//   [132..228) signature
//   [228..)    attesting_indices (8 * n)

pub const INDEXED_ATTESTATION_FIXED: usize = 228;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct IndexedAttestationView;

impl IndexedAttestationView {
    #[inline]
    pub fn data(buf: &[u8]) -> &[u8; 128] {
        fixed(buf, 4)
    }
    #[inline]
    pub fn signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 132)
    }
    #[inline]
    pub fn target_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, 92)
    }
    /// Raw attesting_indices bytes (length-prefix already consumed by the
    /// container offset; trailing slice is `n * u64`).
    #[inline]
    pub fn attesting_indices(buf: &[u8]) -> &[u8] {
        &buf[INDEXED_ATTESTATION_FIXED..]
    }
}

// -- Attestation (block-body attestations list element, Fulu) -----
//
// Variable (trailing `aggregation_bits` Bitlist). Fixed prefix 236B.
//
// Attestation: { aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE *
//                  MAX_COMMITTEES_PER_SLOT],
//                data: AttestationData(128), signature(96),
//                committee_bits: Bitvector[MAX_COMMITTEES_PER_SLOT] (8B) }
//
//   [0..4)     offset to aggregation_bits (== 236)
//   [4..132)   data (AttestationData 128B)
//   [132..228) signature
//   [228..236) committee_bits (8B)
//   [236..)    aggregation_bits (Bitlist)

pub const ATTESTATION_FIXED: usize = 236;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct AttestationView;

impl AttestationView {
    #[inline]
    pub fn data(buf: &[u8]) -> &[u8; 128] {
        fixed(buf, 4)
    }
    #[inline]
    pub fn signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 132)
    }
    #[inline]
    pub fn committee_bits(buf: &[u8]) -> &[u8; 8] {
        fixed(buf, 228)
    }
    #[inline]
    pub fn aggregation_bits(buf: &[u8]) -> &[u8] {
        &buf[ATTESTATION_FIXED..]
    }
}

// -- ProposerSlashing (proposer_slashing) ----------------------------
//
// All fixed, exactly 416B. Two SignedBeaconBlockHeaders (208B each).
// BeaconBlockHeader = slot(8) + proposer_index(8) + parent_root(32)
//                   + state_root(32) + body_root(32) = 112B
// SignedBeaconBlockHeader = header(112) + signature(96) = 208B
//
//   [0..112)   h1 header
//   [112..208) h1 signature
//   [208..320) h2 header
//   [320..416) h2 signature

pub const PROPOSER_SLASHING_SIZE: usize = 416;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ProposerSlashingView;

impl ProposerSlashingView {
    #[inline]
    pub fn h1_slot(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn h1_proposer_index(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn h1_parent_root(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 32] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn h1_state_root(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 32] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn h1_body_root(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 32] {
        fixed(buf, 80)
    }
    #[inline]
    pub fn h1_signature(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 96] {
        fixed(buf, 112)
    }
    #[inline]
    pub fn h2_slot(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> u64 {
        u64_le(buf, 208)
    }
    #[inline]
    pub fn h2_proposer_index(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> u64 {
        u64_le(buf, 216)
    }
    #[inline]
    pub fn h2_parent_root(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 32] {
        fixed(buf, 224)
    }
    #[inline]
    pub fn h2_state_root(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 32] {
        fixed(buf, 256)
    }
    #[inline]
    pub fn h2_body_root(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 32] {
        fixed(buf, 288)
    }
    #[inline]
    pub fn h2_signature(buf: &[u8; PROPOSER_SLASHING_SIZE]) -> &[u8; 96] {
        fixed(buf, 320)
    }
}

// -- SignedVoluntaryExit (voluntary_exit) ----------------------------
//
// All fixed, exactly 112B.
//   [0..8)    epoch
//   [8..16)   validator_index
//   [16..112) signature

pub const SIGNED_VOLUNTARY_EXIT_SIZE: usize = 112;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedVoluntaryExitView;

impl SignedVoluntaryExitView {
    #[inline]
    pub fn epoch(buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn validator_index(buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn signature(buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE]) -> &[u8; 96] {
        fixed(buf, 16)
    }
}

// -- SyncCommitteeMessage (sync_committee_{subnet_id}) ---------------
//
// All fixed, exactly 144B.
//   [0..8)    slot
//   [8..40)   beacon_block_root
//   [40..48)  validator_index
//   [48..144) signature

pub const SYNC_COMMITTEE_MSG_SIZE: usize = 144;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SyncCommitteeView;

impl SyncCommitteeView {
    #[inline]
    pub fn slot(buf: &[u8; SYNC_COMMITTEE_MSG_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn beacon_block_root(buf: &[u8; SYNC_COMMITTEE_MSG_SIZE]) -> &[u8; 32] {
        fixed(buf, 8)
    }
    #[inline]
    pub fn validator_index(buf: &[u8; SYNC_COMMITTEE_MSG_SIZE]) -> u64 {
        u64_le(buf, 40)
    }
    #[inline]
    pub fn signature(buf: &[u8; SYNC_COMMITTEE_MSG_SIZE]) -> &[u8; 96] {
        fixed(buf, 48)
    }
}

// -- SignedContributionAndProof (sync_committee_contribution_and_proof)
//
// All fixed, exactly 360B.
// Outer: { message: ContributionAndProof(264B), signature(96B) }
// ContributionAndProof: { aggregator_index(8), contribution(160B),
// selection_proof(96) } SyncCommitteeContribution: { slot(8),
// beacon_block_root(32), subcommittee_index(8),
//   aggregation_bits(Bitvector[128]=16B), signature(96) } = 160B
//
//   [0..8)     aggregator_index
//   [8..16)    contribution.slot
//   [16..48)   contribution.beacon_block_root
//   [48..56)   contribution.subcommittee_index
//   [56..72)   contribution.aggregation_bits (16B)
//   [72..168)  contribution.signature
//   [168..264) selection_proof
//   [264..360) signature (outer)

pub const SIGNED_CONTRIBUTION_AND_PROOF_SIZE: usize = 360;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedContributionAndProofView;

impl SignedContributionAndProofView {
    #[inline]
    pub fn aggregator_index(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn slot(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn beacon_block_root(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> &[u8; 32] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn subcommittee_index(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> u64 {
        u64_le(buf, 48)
    }
    #[inline]
    pub fn aggregation_bits(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> &[u8; 16] {
        fixed(buf, 56)
    }
    #[inline]
    pub fn contribution_signature(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> &[u8; 96] {
        fixed(buf, 72)
    }
    #[inline]
    pub fn selection_proof(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> &[u8; 96] {
        fixed(buf, 168)
    }
    #[inline]
    pub fn signature(buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE]) -> &[u8; 96] {
        fixed(buf, 264)
    }
}

// -- SignedBLSToExecutionChange (bls_to_execution_change) ------------
//
// All fixed, exactly 172B.
//   [0..8)    validator_index
//   [8..56)   from_bls_pubkey (48B)
//   [56..76)  to_execution_address (20B)
//   [76..172) signature

pub const SIGNED_BLS_CHANGE_SIZE: usize = 172;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedBlsToExecutionChangeView;

impl SignedBlsToExecutionChangeView {
    #[inline]
    pub fn validator_index(buf: &[u8; SIGNED_BLS_CHANGE_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn from_bls_pubkey(buf: &[u8; SIGNED_BLS_CHANGE_SIZE]) -> &[u8; 48] {
        fixed(buf, 8)
    }
    #[inline]
    pub fn to_execution_address(buf: &[u8; SIGNED_BLS_CHANGE_SIZE]) -> &[u8; 20] {
        fixed(buf, 56)
    }
    #[inline]
    pub fn signature(buf: &[u8; SIGNED_BLS_CHANGE_SIZE]) -> &[u8; 96] {
        fixed(buf, 76)
    }
}

// -- SignedBeaconBlock (beacon_block) ---------------------------------
//
// Variable (body is deeply nested). Header fields at compile-time offsets.
//
// SignedBeaconBlock: { message: BeaconBlock(var), signature(96) }
//   Fixed part: offset(4) + sig(96) = 100B
// BeaconBlock: { slot(8), proposer_index(8), parent_root(32), state_root(32),
// body(var) }   Fixed part: 8+8+32+32+offset(4) = 84B
//
//   [0..4)     offset to message (== 100)
//   [4..100)   signature
//   [100..108) slot
//   [108..116) proposer_index
//   [116..148) parent_root
//   [148..180) state_root
//   [180..184) offset to body (relative to 100)
//   [184..)    body data

pub const SIGNED_BEACON_BLOCK_MIN: usize = 184;

// Raw SSZ type bound. Dominated by transactions list
// (MAX_TRANSACTIONS_PER_PAYLOAD * MAX_BYTES_PER_TRANSACTION ≈ 2^50 B), so
// vastly exceeds MAX_PAYLOAD_SIZE — the global cap is the practical limit
// (p2p-interface.md §"Why is there a limit on message sizes at all?").
//
// Body breakdown:
//   fixed part:    randao_reveal(96) + eth1_data(72) + graffiti(32)
//                  + sync_aggregate(160) + 9*offset(4) = 396
//   proposer_slashings:       16 * 416
//   attester_slashings:       4 + ATTESTER_SLASHING_MAX
//   attestations:             8*4 + 8 * (236 + Bitlist[MAX_ATTESTING_INDICES])
//   deposits:                 16 * 1240          (proof 1056 + DepositData 184)
//   voluntary_exits:          16 * 112
//   execution_payload:        528 + 32 + (4 + MAX_BYTES_PER_TRANSACTION)
//                             * MAX_TRANSACTIONS_PER_PAYLOAD + 16 * 44
//   bls_to_execution_changes: 16 * 172
//   blob_kzg_commitments:     4096 * 48
//   execution_requests:       12 + 8192*192 + 16*76 + 2*116
pub const SIGNED_BEACON_BLOCK_MAX: usize = SIGNED_BEACON_BLOCK_MIN +
    396 +
    MAX_PROPOSER_SLASHINGS * PROPOSER_SLASHING_SIZE +
    4 +
    ATTESTER_SLASHING_MAX +
    MAX_ATTESTATIONS_ELECTRA * 4 +
    MAX_ATTESTATIONS_ELECTRA * (236 + MAX_ATTESTING_INDICES / 8 + 1) +
    MAX_DEPOSITS * 1240 +
    MAX_VOLUNTARY_EXITS * SIGNED_VOLUNTARY_EXIT_SIZE +
    528 +
    MAX_EXTRA_DATA_BYTES +
    (4 + MAX_BYTES_PER_TRANSACTION) * MAX_TRANSACTIONS_PER_PAYLOAD +
    MAX_WITHDRAWALS_PER_PAYLOAD * 44 +
    MAX_BLS_TO_EXECUTION_CHANGES * SIGNED_BLS_CHANGE_SIZE +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT +
    12 +
    MAX_DEPOSIT_REQUESTS_PER_PAYLOAD * 192 +
    MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD * 76 +
    MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD * 116;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedBeaconBlockView;

impl SignedBeaconBlockView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 4)
    }
    #[inline]
    pub fn slot(buf: &[u8]) -> u64 {
        u64_le(buf, 100)
    }
    #[inline]
    pub fn proposer_index(buf: &[u8]) -> u64 {
        u64_le(buf, 108)
    }
    #[inline]
    pub fn parent_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 116)
    }
    #[inline]
    pub fn state_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 148)
    }
    /// Raw serialized BeaconBlockBody bytes.
    #[inline]
    pub fn body(buf: &[u8]) -> &[u8] {
        &buf[184..]
    }
    /// Validates `buf` is large enough for every accessor above to read
    /// without panicking. Accessors only read compile-time fixed offsets
    /// plus `&buf[184..]`, so a bare length bound suffices.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_BEACON_BLOCK_MIN && buf.len() <= SIGNED_BEACON_BLOCK_MAX
    }

    #[inline]
    pub fn has_data_columns(buf: &[u8]) -> bool {
        let beacon_block_body = Self::body(buf);
        if beacon_block_body.len() < BEACON_BLOCK_BODY_FIXED {
            return false;
        }
        let kzg_commitments_offset =
            BeaconBlockBodyFuluView::blob_kzg_commitments_offset(beacon_block_body);
        let execution_requests_offset =
            BeaconBlockBodyFuluView::execution_requests_offset(beacon_block_body);

        (kzg_commitments_offset as usize) < beacon_block_body.len() &&
            kzg_commitments_offset < execution_requests_offset
    }
}

// -- BeaconBlockBody --------------------------------------------------
//
// Variable. 13 fields, fixed part 396B; trailing variable region holds the
// 9 offset-pointed lists / containers.
//
//   [0..96)    randao_reveal
//   [96..168)  eth1_data (72B)
//   [168..200) graffiti (32B)
//   [200..204) offset: proposer_slashings
//   [204..208) offset: attester_slashings
//   [208..212) offset: attestations
//   [212..216) offset: deposits
//   [216..220) offset: voluntary_exits
//   [220..380) sync_aggregate (160B)
//   [380..384) offset: execution_payload
//   [384..388) offset: bls_to_execution_changes
//   [388..392) offset: blob_kzg_commitments
//   [392..396) offset: execution_requests
//   [396..)    variable region

pub const BEACON_BLOCK_BODY_FIXED: usize = 396;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct BeaconBlockBodyFuluView;

impl BeaconBlockBodyFuluView {
    #[inline]
    pub fn randao_reveal(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn eth1_data(buf: &[u8]) -> &[u8; 72] {
        fixed(buf, 96)
    }
    #[inline]
    pub fn graffiti(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 168)
    }
    #[inline]
    pub fn proposer_slashings_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 200)
    }
    #[inline]
    pub fn attester_slashings_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 204)
    }
    #[inline]
    pub fn attestations_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 208)
    }
    #[inline]
    pub fn deposits_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 212)
    }
    #[inline]
    pub fn voluntary_exits_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 216)
    }
    #[inline]
    pub fn sync_aggregate(buf: &[u8]) -> &[u8; BLOCK_SYNC_AGGREGATE_SIZE] {
        fixed(buf, 220)
    }
    #[inline]
    pub fn execution_payload_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 380)
    }
    #[inline]
    pub fn bls_to_execution_changes_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 384)
    }
    #[inline]
    pub fn blob_kzg_commitments_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 388)
    }
    #[inline]
    pub fn execution_requests_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 392)
    }
}

// -- SignedAggregateAndProof (beacon_aggregate_and_proof) -------------
//
// Variable (inner Attestation has Bitlist aggregation_bits).
// Each nesting level has exactly one variable field appended at the end,
// so all fixed fields are at compile-time offsets.
//
// SignedAggregateAndProof: { message: AggregateAndProof(var), signature(96) }
//   Fixed part: offset(4) + sig(96) = 100B
// AggregateAndProof: { aggregator_index(8), aggregate: Attestation(var),
// selection_proof(96) }   Fixed part: 8 + offset(4) + 96 = 108B
// Attestation: { aggregation_bits(var), data(128), signature(96),
// committee_bits(8) }   Fixed part: offset(4) + 128 + 96 + 8 = 236B
//
//   [0..4)     offset to message (== 100)
//   [4..100)   signature (outer)
//   [100..108) aggregator_index
//   [108..112) offset to aggregate (rel. to 100, == 108)
//   [112..208) selection_proof
//   [208..212) offset to aggregation_bits (rel. to 208, == 236)
//   [212..340) aggregate.data (AttestationData 128B)
//     [212..220) slot
//     [220..228) index (always 0 post-Electra)
//     [228..260) beacon_block_root
//     [260..268) source.epoch
//     [268..300) source.root
//     [300..308) target.epoch
//     [308..340) target.root
//   [340..436) aggregate.signature
//   [436..444) committee_bits
//   [444..)    aggregation_bits (variable)

pub const SIGNED_AGG_PROOF_MIN: usize = 444;

// aggregation_bits: Bitlist[MAX_ATTESTING_INDICES], ceil((N+1)/8) bytes.
pub const SIGNED_AGG_PROOF_MAX: usize = SIGNED_AGG_PROOF_MIN + MAX_ATTESTING_INDICES / 8 + 1;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedAggregateAndProofView;

impl SignedAggregateAndProofView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 4)
    }
    #[inline]
    pub fn aggregator_index(buf: &[u8]) -> u64 {
        u64_le(buf, 100)
    }
    #[inline]
    pub fn selection_proof(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 112)
    }
    #[inline]
    pub fn agg_slot(buf: &[u8]) -> u64 {
        u64_le(buf, 212)
    }
    #[inline]
    pub fn agg_data_index(buf: &[u8]) -> u64 {
        u64_le(buf, 220)
    }
    #[inline]
    pub fn agg_beacon_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 228)
    }
    #[inline]
    pub fn agg_source_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, 260)
    }
    #[inline]
    pub fn agg_source_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 268)
    }
    #[inline]
    pub fn agg_target_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, 300)
    }
    #[inline]
    pub fn agg_target_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 308)
    }
    #[inline]
    pub fn agg_signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 340)
    }
    #[inline]
    pub fn agg_committee_bits(buf: &[u8]) -> &[u8; 8] {
        fixed(buf, 436)
    }
    #[inline]
    pub fn agg_data(buf: &[u8]) -> &[u8; 128] {
        fixed(buf, 212)
    }
    #[inline]
    pub fn agg_aggregation_bits(buf: &[u8]) -> &[u8] {
        &buf[444..]
    }
    /// Inner Attestation SSZ slice (variable, runs to end-of-buf). Used as
    /// input to the AggregateAndProof container hash tree root.
    #[inline]
    pub fn aggregate(buf: &[u8]) -> &[u8] {
        &buf[208..]
    }
    /// All accessors read compile-time fixed offsets plus `&buf[444..]`;
    /// a length bound suffices.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_AGG_PROOF_MIN && buf.len() <= SIGNED_AGG_PROOF_MAX
    }
}

// -- AttesterSlashing (attester_slashing) -----------------------------
//
// Variable. Two Fulu IndexedAttestations, each variable.
// IndexedAttestation: { attesting_indices: List[ValidatorIndex](var),
// data(128), sig(96) }   Fixed part: offset(4) + 128 + 96 = 228B
//
// AttesterSlashing fixed part: offset_1(4) + offset_2(4) = 8B
//   [0..4)  offset to att_1 (== 8)
//   [4..8)  offset to att_2
//
// att_1 at byte 8 (compile-time):
//   +0..4    offset to attesting_indices (== 228)
//   +4..132  data (128B): slot, index, beacon_block_root, source, target
//   +132..228 signature
//   +228..    attesting_indices data
//
// att_2 at att2_off (one hop via [4..8)): same relative layout.

pub const ATTESTER_SLASHING_MIN: usize = 8 + 228 + 228; // 464

// Two IndexedAttestations; each: 228B fixed + MAX_ATTESTING_INDICES * 8B.
pub const ATTESTER_SLASHING_MAX: usize = 8 + 2 * (228 + MAX_ATTESTING_INDICES * 8);

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct AttesterSlashingView;

impl AttesterSlashingView {
    // -- attestation_1 (compile-time offsets, starts at byte 8) --

    #[inline]
    pub fn att1_slot(buf: &[u8]) -> u64 {
        u64_le(buf, 12)
    }
    #[inline]
    pub fn att1_data_index(buf: &[u8]) -> u64 {
        u64_le(buf, 20)
    }
    #[inline]
    pub fn att1_beacon_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 28)
    }
    #[inline]
    pub fn att1_source_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, 60)
    }
    #[inline]
    pub fn att1_source_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 68)
    }
    #[inline]
    pub fn att1_target_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, 100)
    }
    #[inline]
    pub fn att1_target_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 108)
    }
    #[inline]
    pub fn att1_signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 140)
    }
    #[inline]
    pub fn att1_data(buf: &[u8]) -> &[u8; 128] {
        fixed(buf, 12)
    }
    #[inline]
    pub fn att1_attesting_indices(buf: &[u8]) -> &[u8] {
        let att2 = u32_le(buf, 4) as usize;
        &buf[236..att2]
    }

    // -- attestation_2 (one hop via offset at [4..8)) --

    #[inline]
    fn att2_off(buf: &[u8]) -> usize {
        u32_le(buf, 4) as usize
    }

    #[inline]
    pub fn att2_slot(buf: &[u8]) -> u64 {
        u64_le(buf, Self::att2_off(buf) + 4)
    }
    #[inline]
    pub fn att2_data_index(buf: &[u8]) -> u64 {
        u64_le(buf, Self::att2_off(buf) + 12)
    }
    #[inline]
    pub fn att2_beacon_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, Self::att2_off(buf) + 20)
    }
    #[inline]
    pub fn att2_source_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, Self::att2_off(buf) + 52)
    }
    #[inline]
    pub fn att2_source_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, Self::att2_off(buf) + 60)
    }
    #[inline]
    pub fn att2_target_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, Self::att2_off(buf) + 92)
    }
    #[inline]
    pub fn att2_target_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, Self::att2_off(buf) + 100)
    }
    #[inline]
    pub fn att2_signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, Self::att2_off(buf) + 132)
    }
    #[inline]
    pub fn att2_data(buf: &[u8]) -> &[u8; 128] {
        fixed(buf, Self::att2_off(buf) + 4)
    }
    #[inline]
    pub fn att2_attesting_indices(buf: &[u8]) -> &[u8] {
        let off = Self::att2_off(buf);
        &buf[off + 228..]
    }
    /// Validates:
    ///   - `buf.len()` within [MIN, MAX];
    ///   - `att2_off` at least 236 (att_1 fixed ends there) so
    ///     `&buf[236..att2_off]` is a valid slice;
    ///   - `att2_off + 228 <= buf.len()` so att_2's fixed reads and the
    ///     `&buf[att2_off+228..]` tail are in-bounds.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < ATTESTER_SLASHING_MIN || buf.len() > ATTESTER_SLASHING_MAX {
            return false;
        }
        let off2 = u32_le(buf, 4) as usize;
        off2 >= 236 && off2.saturating_add(228) <= buf.len()
    }
}

// -- DataColumnSidecar (data_column_sidecar_{subnet_id}) -------------
//
// Variable. Three Lists in the middle, fixed fields on both sides.
//
// DataColumnSidecar: {
//   index(8), column: List[Cell](var), kzg_commitments:
// List[KZGCommitment](var),   kzg_proofs: List[KZGProof](var),
// signed_block_header(208), inclusion_proof(128) }
//
// Fixed part: 8 + 4 + 4 + 4 + 208 + 128 = 356B
//   [0..8)     index (ColumnIndex)
//   [8..12)    offset to column
//   [12..16)   offset to kzg_commitments
//   [16..20)   offset to kzg_proofs
//   [20..228)  signed_block_header (208B)
//     [20..28)   slot
//     [28..36)   proposer_index
//     [36..68)   parent_root
//     [68..100)  state_root
//     [100..132) body_root
//     [132..228) block_signature
//   [228..356) kzg_commitments_inclusion_proof (Vector[Bytes32, 4] = 128B)
//   [356..)    variable data: column | kzg_commitments | kzg_proofs

pub const DATA_COLUMN_SIDECAR_MIN: usize = 356;

// column + kzg_commitments + kzg_proofs, each List[_,
// MAX_BLOB_COMMITMENTS_PER_BLOCK].
pub const DATA_COLUMN_SIDECAR_MAX: usize = DATA_COLUMN_SIDECAR_MIN +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_CELL +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_KZG_PROOF;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct DataColumnSidecarFuluView;

impl DataColumnSidecarFuluView {
    // -- fixed fields (compile-time offsets) --

    #[inline]
    pub fn index(buf: &[u8]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn slot(buf: &[u8]) -> u64 {
        u64_le(buf, 20)
    }
    #[inline]
    pub fn proposer_index(buf: &[u8]) -> u64 {
        u64_le(buf, 28)
    }
    #[inline]
    pub fn parent_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 36)
    }
    #[inline]
    pub fn state_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 68)
    }
    #[inline]
    pub fn body_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 100)
    }
    #[inline]
    pub fn block_signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 132)
    }
    #[inline]
    pub fn inclusion_proof(buf: &[u8]) -> &[u8; 128] {
        fixed(buf, 228)
    }

    // -- variable fields (hop via offset pointers at [8..20)) --

    #[inline]
    pub fn column(buf: &[u8]) -> &[u8] {
        let start = u32_le(buf, 8) as usize;
        let end = u32_le(buf, 12) as usize;
        &buf[start..end]
    }
    #[inline]
    pub fn kzg_commitments(buf: &[u8]) -> &[u8] {
        let start = u32_le(buf, 12) as usize;
        let end = u32_le(buf, 16) as usize;
        &buf[start..end]
    }
    #[inline]
    pub fn kzg_proofs(buf: &[u8]) -> &[u8] {
        let start = u32_le(buf, 16) as usize;
        &buf[start..]
    }
    /// Validates fixed part fits, then hops through the three offset
    /// fields at [8..20) and checks the classic SSZ offset invariants:
    /// first >= fixed-part size, monotonically non-decreasing, last
    /// <= buf.len(). That makes every variable-field slice in-bounds.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < DATA_COLUMN_SIDECAR_MIN || buf.len() > DATA_COLUMN_SIDECAR_MAX {
            return false;
        }
        let col_off = u32_le(buf, 8) as usize;
        let com_off = u32_le(buf, 12) as usize;
        let proof_off = u32_le(buf, 16) as usize;
        col_off >= DATA_COLUMN_SIDECAR_MIN &&
            col_off <= com_off &&
            com_off <= proof_off &&
            proof_off <= buf.len()
    }
}

// -- LightClientHeader (inner container for LC updates) --------------
//
// Variable (inner ExecutionPayloadHeader has variable extra_data).
//
// Fixed part: beacon(112) + offset(4) + execution_branch(128) = 244B
//   [0..112)   beacon (BeaconBlockHeader)
//     [0..8)     slot
//     [8..16)    proposer_index
//     [16..48)   parent_root
//     [48..80)   state_root
//     [80..112)  body_root
//   [112..116) offset to execution (== 244)
//   [116..244) execution_branch
//                (Vector[Bytes32, EXECUTION_BRANCH_DEPTH=4] = 128B)
//   [244..)    execution (ExecutionPayloadHeader, variable)

pub const EXECUTION_BRANCH_DEPTH: usize = 4;
pub const EXECUTION_BRANCH_SIZE: usize = EXECUTION_BRANCH_DEPTH * 32;
// ExecutionPayloadHeader fixed part: parent_hash(32) + fee_recipient(20)
// + state_root(32) + receipts_root(32) + logs_bloom(256) + prev_randao(32)
// + block_number(8) + gas_limit(8) + gas_used(8) + timestamp(8)
// + extra_data_offset(4) + base_fee_per_gas(32) + block_hash(32)
// + transactions_root(32) + withdrawals_root(32) + blob_gas_used(8)
// + excess_blob_gas(8) = 584B.
pub const EXECUTION_PAYLOAD_HEADER_FIXED: usize = 584;
pub const LC_HEADER_FIXED: usize = 112 + 4 + EXECUTION_BRANCH_SIZE;
pub const LIGHT_CLIENT_HEADER_MIN: usize = LC_HEADER_FIXED + EXECUTION_PAYLOAD_HEADER_FIXED;
pub const LIGHT_CLIENT_HEADER_MAX: usize = LIGHT_CLIENT_HEADER_MIN + MAX_EXTRA_DATA_BYTES;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct LightClientHeaderView;

impl LightClientHeaderView {
    #[inline]
    pub fn slot(buf: &[u8]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn proposer_index(buf: &[u8]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn parent_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn state_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn body_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 80)
    }
    #[inline]
    pub fn execution_branch(buf: &[u8]) -> &[u8; EXECUTION_BRANCH_SIZE] {
        fixed(buf, 116)
    }
    /// Raw ExecutionPayloadHeader bytes.
    #[inline]
    pub fn execution(buf: &[u8]) -> &[u8] {
        &buf[LC_HEADER_FIXED..]
    }
    /// Accessors read compile-time fixed offsets plus `&buf[244..]`;
    /// a length bound suffices.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= LIGHT_CLIENT_HEADER_MIN && buf.len() <= LIGHT_CLIENT_HEADER_MAX
    }
}

// -- LightClientFinalityUpdate (light_client_finality_update) --------
//
// Variable. Two nested LightClientHeaders, each variable.
//
// Fixed part: offset(4) + offset(4) + finality_branch(224)
//             + sync_aggregate(160) + signature_slot(8) = 400B
//   [0..4)     offset to attested_header (== 400)
//   [4..8)     offset to finalized_header (>= 400 + LCH_MIN)
//   [8..232)   finality_branch
//                (Vector[Bytes32, FINALITY_BRANCH_DEPTH=7] = 224B)
//   [232..392) sync_aggregate (160B)
//     [232..296) sync_committee_bits (Bitvector[512] = 64B)
//     [296..392) sync_committee_signature (96B)
//   [392..400) signature_slot
//   [400..fin_off)  attested_header
//   [fin_off..)     finalized_header

pub const FINALITY_BRANCH_DEPTH: usize = 7;
pub const FINALITY_BRANCH_SIZE: usize = FINALITY_BRANCH_DEPTH * 32;
pub const SYNC_AGGREGATE_SIZE: usize = SYNC_COMMITTEE_SIZE / 8 + 96; // 160
pub const LC_FINALITY_UPDATE_FIXED: usize = 4 + 4 + FINALITY_BRANCH_SIZE + SYNC_AGGREGATE_SIZE + 8;
pub const LIGHT_CLIENT_FINALITY_UPDATE_MIN: usize =
    LC_FINALITY_UPDATE_FIXED + 2 * LIGHT_CLIENT_HEADER_MIN;
pub const LIGHT_CLIENT_FINALITY_UPDATE_MAX: usize =
    LC_FINALITY_UPDATE_FIXED + 2 * LIGHT_CLIENT_HEADER_MAX;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct LightClientFinalityUpdateView;

impl LightClientFinalityUpdateView {
    #[inline]
    pub fn finality_branch(buf: &[u8]) -> &[u8; FINALITY_BRANCH_SIZE] {
        fixed(buf, 8)
    }
    #[inline]
    pub fn sync_committee_bits(buf: &[u8]) -> &[u8; SYNC_COMMITTEE_SIZE / 8] {
        fixed(buf, 232)
    }
    #[inline]
    pub fn sync_committee_signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 296)
    }
    #[inline]
    pub fn signature_slot(buf: &[u8]) -> u64 {
        u64_le(buf, 392)
    }
    #[inline]
    fn finalized_off(buf: &[u8]) -> usize {
        u32_le(buf, 4) as usize
    }
    /// Raw LightClientHeader bytes for `attested_header` — feed to
    /// `LightClientHeaderView`.
    #[inline]
    pub fn attested_header(buf: &[u8]) -> &[u8] {
        &buf[LC_FINALITY_UPDATE_FIXED..Self::finalized_off(buf)]
    }
    /// Raw LightClientHeader bytes for `finalized_header`.
    #[inline]
    pub fn finalized_header(buf: &[u8]) -> &[u8] {
        &buf[Self::finalized_off(buf)..]
    }
    /// Validates:
    ///   - `buf.len()` within [MIN, MAX];
    ///   - `finalized_off` leaves attested_header with an LCH-valid length
    ///     (i.e. `LC_FINALITY_UPDATE_FIXED + LCH_MIN <= fin_off <=
    ///     LC_FINALITY_UPDATE_FIXED + LCH_MAX`);
    ///   - `finalized_header` slice (`buf[fin_off..]`) has an LCH-valid length.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < LIGHT_CLIENT_FINALITY_UPDATE_MIN ||
            buf.len() > LIGHT_CLIENT_FINALITY_UPDATE_MAX
        {
            return false;
        }
        let fin_off = Self::finalized_off(buf);
        let att_range = LC_FINALITY_UPDATE_FIXED + LIGHT_CLIENT_HEADER_MIN..=
            LC_FINALITY_UPDATE_FIXED + LIGHT_CLIENT_HEADER_MAX;
        if !att_range.contains(&fin_off) {
            return false;
        }
        let rem = buf.len() - fin_off;
        (LIGHT_CLIENT_HEADER_MIN..=LIGHT_CLIENT_HEADER_MAX).contains(&rem)
    }
}

// -- LightClientOptimisticUpdate (light_client_optimistic_update) ----
//
// Variable. One nested LightClientHeader.
//
// Fixed part: offset(4) + sync_aggregate(160) + signature_slot(8) = 172B
//   [0..4)    offset to attested_header (== 172)
//   [4..164)  sync_aggregate
//     [4..68)   sync_committee_bits
//     [68..164) sync_committee_signature
//   [164..172) signature_slot
//   [172..)   attested_header

pub const LC_OPTIMISTIC_UPDATE_FIXED: usize = 4 + SYNC_AGGREGATE_SIZE + 8;
pub const LIGHT_CLIENT_OPTIMISTIC_UPDATE_MIN: usize =
    LC_OPTIMISTIC_UPDATE_FIXED + LIGHT_CLIENT_HEADER_MIN;
pub const LIGHT_CLIENT_OPTIMISTIC_UPDATE_MAX: usize =
    LC_OPTIMISTIC_UPDATE_FIXED + LIGHT_CLIENT_HEADER_MAX;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct LightClientOptimisticUpdateView;

impl LightClientOptimisticUpdateView {
    #[inline]
    pub fn sync_committee_bits(buf: &[u8]) -> &[u8; SYNC_COMMITTEE_SIZE / 8] {
        fixed(buf, 4)
    }
    #[inline]
    pub fn sync_committee_signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 68)
    }
    #[inline]
    pub fn signature_slot(buf: &[u8]) -> u64 {
        u64_le(buf, 164)
    }
    /// Raw LightClientHeader bytes for `attested_header` — feed to
    /// `LightClientHeaderView`.
    #[inline]
    pub fn attested_header(buf: &[u8]) -> &[u8] {
        &buf[LC_OPTIMISTIC_UPDATE_FIXED..]
    }
    /// Accessors read compile-time fixed offsets plus `&buf[172..]`;
    /// a length bound suffices.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= LIGHT_CLIENT_OPTIMISTIC_UPDATE_MIN &&
            buf.len() <= LIGHT_CLIENT_OPTIMISTIC_UPDATE_MAX
    }
}

// -- Status (req/status/{1,2}, req & resp) ----------------------------
//
// All fixed. v1 is 84B; v2 (new in Fulu) appends `earliest_available_slot`
// for 92B total. ForkDigest = [u8; 4], Root = [u8; 32], Epoch/Slot = u64.
//   [0..4)    fork_digest
//   [4..36)   finalized_root
//   [36..44)  finalized_epoch
//   [44..76)  head_root
//   [76..84)  head_slot
//   [84..92)  earliest_available_slot (v2 only)

pub const STATUS_V1_SIZE: usize = 84;
pub const STATUS_V2_SIZE: usize = 92;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct StatusView;

impl StatusView {
    #[inline]
    pub fn fork_digest(buf: &[u8]) -> &[u8; 4] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn finalized_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 4)
    }
    #[inline]
    pub fn finalized_epoch(buf: &[u8]) -> u64 {
        u64_le(buf, 36)
    }
    #[inline]
    pub fn head_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 44)
    }
    #[inline]
    pub fn head_slot(buf: &[u8]) -> u64 {
        u64_le(buf, 76)
    }
    /// v2-only; `None` for v1 buffers.
    #[inline]
    pub fn earliest_available_slot(buf: &[u8]) -> Option<u64> {
        (buf.len() >= STATUS_V2_SIZE).then(|| u64_le(buf, 84))
    }
    /// A Status buffer is valid at exactly v1 or v2 size.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() == STATUS_V1_SIZE || buf.len() == STATUS_V2_SIZE
    }

    #[inline]
    pub fn as_v1(buf: &[u8]) -> &[u8] {
        &buf[..STATUS_V1_SIZE]
    }
}

// -- MetaData (req/metadata/3, resp only) -----------------------------
//
// All fixed, exactly 25B.
//   [0..8)    seq_number
//   [8..16)   attnets (Bitvector[64] = 8B)
//   [16..17)  syncnets (Bitvector[4] = 1B)
//   [17..25)  custody_group_count (new in Fulu)

pub const METADATA_SIZE: usize = 25;

#[derive(Clone, Copy, Debug)]
pub struct MetadataView;

impl MetadataView {
    #[inline]
    pub fn seq_number(buf: &[u8; METADATA_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn attnets(buf: &[u8; METADATA_SIZE]) -> &[u8; 8] {
        fixed(buf, 8)
    }
    #[inline]
    pub fn syncnets(buf: &[u8; METADATA_SIZE]) -> u8 {
        buf[16]
    }
    #[inline]
    pub fn custody_group_count(buf: &[u8; METADATA_SIZE]) -> u64 {
        u64_le(buf, 17)
    }
}

// -- BeaconBlocksByRangeRequest (req/beacon_blocks_by_range/2, req) ---
//
// All fixed, exactly 24B.
//   [0..8)   start_slot
//   [8..16)  count
//   [16..24) step (deprecated, must be 1)

pub const BLOCKS_BY_RANGE_REQ_SIZE: usize = 24;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BeaconBlocksByRangeRequestView;

impl BeaconBlocksByRangeRequestView {
    #[inline]
    pub fn start_slot(buf: &[u8; BLOCKS_BY_RANGE_REQ_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn count(buf: &[u8; BLOCKS_BY_RANGE_REQ_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn step(buf: &[u8; BLOCKS_BY_RANGE_REQ_SIZE]) -> u64 {
        u64_le(buf, 16)
    }
}

// -- Ping (req/ping/1, req & resp) -----------------------------------

pub const PING_SIZE: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct PingView;

impl PingView {
    #[inline]
    pub fn seq_number(buf: &[u8; PING_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
}

// -- Goodbye (req/goodbye/1, req & resp) -----------------------------

pub const GOODBYE_SIZE: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct GoodbyeView;

impl GoodbyeView {
    #[inline]
    pub fn reason(buf: &[u8; GOODBYE_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
}

// -- BeaconBlocksByRootRequest (req/beacon_blocks_by_root/2, req) ----
//
// Variable. SSZ List[Root, MAX_REQUEST_BLOCKS] with fixed-size elements
// is encoded as the concatenation of 32B roots (no offsets).
//   [i*32..(i+1)*32)  root_i

// Deneb+ caps at MAX_REQUEST_BLOCKS_DENEB.
pub const BLOCKS_BY_ROOT_REQ_MAX: usize = 32 * MAX_REQUEST_BLOCKS_DENEB;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct BeaconBlocksByRootRequestView;

impl BeaconBlocksByRootRequestView {
    #[inline]
    pub fn count(buf: &[u8]) -> usize {
        buf.len() / 32
    }
    #[inline]
    pub fn root(buf: &[u8], i: usize) -> &[u8; 32] {
        fixed(buf, i * 32)
    }
    /// List of fixed-size (32B) roots: length must be a multiple of 32
    /// and bounded by the Deneb+ request cap. `root(buf, i)` is then safe
    /// for all `i < count(buf)`.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() <= BLOCKS_BY_ROOT_REQ_MAX && buf.len().is_multiple_of(32)
    }
}

// -- DataColumnSidecarsByRangeRequest (req/data_column_sidecars_by_range/1)
//
// Variable (columns is a List[ColumnIndex, NUMBER_OF_COLUMNS]).
// Fixed part: start_slot(8) + count(8) + offset(4) = 20B
//   [0..8)   start_slot
//   [8..16)  count
//   [16..20) offset to columns (== 20)
//   [20..)   columns data (each ColumnIndex = u64, 8B)

pub const DC_BY_RANGE_REQ_MIN: usize = 20;

// Data columns by root, requesting a single column.
pub const DC_BY_ROOT_SINGLE_SIZE: usize = 48;

// columns: List[ColumnIndex, NUMBER_OF_COLUMNS], ColumnIndex = u64.
pub const DC_BY_RANGE_REQ_MAX: usize = DC_BY_RANGE_REQ_MIN + NUMBER_OF_COLUMNS * 8;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DataColumnSidecarsByRangeRequestView;

impl DataColumnSidecarsByRangeRequestView {
    #[inline]
    pub fn start_slot(buf: &[u8]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn count(buf: &[u8]) -> u64 {
        u64_le(buf, 8)
    }
    /// Raw bytes of the columns list. Each element is a u64 LE ColumnIndex
    /// (8B).
    #[inline]
    pub fn columns(buf: &[u8]) -> &[u8] {
        &buf[20..]
    }
    /// Fixed part must fit and the columns list tail must be a whole
    /// number of 8B ColumnIndex elements.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < DC_BY_RANGE_REQ_MIN || buf.len() > DC_BY_RANGE_REQ_MAX {
            return false;
        }
        (buf.len() - DC_BY_RANGE_REQ_MIN).is_multiple_of(8)
    }
}

// -- DataColumnsByRootIdentifier (used in req/data_column_sidecars_by_root/1)
//
// Variable (columns is a List[ColumnIndex, NUMBER_OF_COLUMNS]).
// Fixed part: block_root(32) + offset(4) = 36B
//   [0..32)  block_root
//   [32..36) offset to columns (== 36)
//   [36..)   columns data (each ColumnIndex = u64, 8B)

pub const DC_BY_ROOT_ID_MIN: usize = 36;

// columns: List[ColumnIndex, NUMBER_OF_COLUMNS], ColumnIndex = u64.
pub const DC_BY_ROOT_ID_MAX: usize = DC_BY_ROOT_ID_MIN + NUMBER_OF_COLUMNS * 8;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct DataColumnsByRootIdentifierView;

impl DataColumnsByRootIdentifierView {
    #[inline]
    pub fn block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 0)
    }
    /// Raw bytes of the columns list. Each element is a u64 LE ColumnIndex
    /// (8B).
    #[inline]
    pub fn columns(buf: &[u8]) -> &[u8] {
        &buf[36..]
    }
    /// Fixed part must fit and the columns list tail must be a whole
    /// number of 8B ColumnIndex elements.
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < DC_BY_ROOT_ID_MIN || buf.len() > DC_BY_ROOT_ID_MAX {
            return false;
        }
        (buf.len() - DC_BY_ROOT_ID_MIN).is_multiple_of(8)
    }
}

// -- PayloadAttestationData -------------------------------------------
//
// All fixed, 42B.
//   [0..32)  beacon_block_root
//   [32..40) slot
//   [40]     payload_present (bool)
//   [41]     blob_data_available (bool)

pub const PAYLOAD_ATTESTATION_DATA_SIZE: usize = 42;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct PayloadAttestationDataView;

impl PayloadAttestationDataView {
    #[inline]
    pub fn beacon_block_root(buf: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn slot(buf: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) -> u64 {
        u64_le(buf, 32)
    }
    #[inline]
    pub fn payload_present(buf: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) -> bool {
        buf[40] != 0
    }
    #[inline]
    pub fn blob_data_available(buf: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) -> bool {
        buf[41] != 0
    }
}

// -- PayloadAttestation (beacon block body payload_attestations element) --
//
// All fixed, 202B.
//   [0..64)    aggregation_bits (Bitvector[PTC_SIZE=512])
//   [64..106)  data (PayloadAttestationData 42B)
//   [106..202) signature

// aggregation_bits: Bitvector[PTC_SIZE] where PTC_SIZE = 512.
pub const PTC_AGGREGATION_BITS_SIZE: usize = 512 / 8;
pub const PAYLOAD_ATTESTATION_SIZE: usize =
    PTC_AGGREGATION_BITS_SIZE + PAYLOAD_ATTESTATION_DATA_SIZE + 96;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct PayloadAttestationView;

impl PayloadAttestationView {
    #[inline]
    pub fn aggregation_bits(
        buf: &[u8; PAYLOAD_ATTESTATION_SIZE],
    ) -> &[u8; PTC_AGGREGATION_BITS_SIZE] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn data(buf: &[u8; PAYLOAD_ATTESTATION_SIZE]) -> &[u8; PAYLOAD_ATTESTATION_DATA_SIZE] {
        fixed(buf, PTC_AGGREGATION_BITS_SIZE)
    }
    #[inline]
    pub fn signature(buf: &[u8; PAYLOAD_ATTESTATION_SIZE]) -> &[u8; 96] {
        fixed(buf, PTC_AGGREGATION_BITS_SIZE + PAYLOAD_ATTESTATION_DATA_SIZE)
    }
}

// -- PayloadAttestationMessage (payload_attestation_message) ----------
//
// All fixed, 146B.
//   [0..8)    validator_index
//   [8..50)   data (PayloadAttestationData 42B)
//   [50..146) signature

pub const PAYLOAD_ATTESTATION_MESSAGE_SIZE: usize = 146;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct PayloadAttestationMessageView;

impl PayloadAttestationMessageView {
    #[inline]
    pub fn validator_index(buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn data(
        buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE],
    ) -> &[u8; PAYLOAD_ATTESTATION_DATA_SIZE] {
        fixed(buf, 8)
    }
    #[inline]
    pub fn signature(buf: &[u8; PAYLOAD_ATTESTATION_MESSAGE_SIZE]) -> &[u8; 96] {
        fixed(buf, 50)
    }
}

// -- ExecutionPayloadBid ----------------------------------------------
//
// Variable (blob_kzg_commitments: List[KZGCommitment,
// MAX_BLOB_COMMITMENTS_PER_BLOCK]). Fixed part 224B.
//   [0..32)    parent_block_hash
//   [32..64)   parent_block_root
//   [64..96)   block_hash
//   [96..128)  prev_randao
//   [128..148) fee_recipient (20)
//   [148..156) gas_limit
//   [156..164) builder_index
//   [164..172) slot
//   [172..180) value
//   [180..188) execution_payment
//   [188..192) offset: blob_kzg_commitments (== 224)
//   [192..224) execution_requests_root
//   [224..)    blob_kzg_commitments (48B each)

pub const EXECUTION_PAYLOAD_BID_MIN: usize = 224;
pub const EXECUTION_PAYLOAD_BID_MAX: usize =
    EXECUTION_PAYLOAD_BID_MIN + MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ExecutionPayloadBidView;

impl ExecutionPayloadBidView {
    #[inline]
    pub fn parent_block_hash(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn parent_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 32)
    }
    #[inline]
    pub fn block_hash(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 64)
    }
    #[inline]
    pub fn prev_randao(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 96)
    }
    #[inline]
    pub fn fee_recipient(buf: &[u8]) -> &[u8; 20] {
        fixed(buf, 128)
    }
    #[inline]
    pub fn gas_limit(buf: &[u8]) -> u64 {
        u64_le(buf, 148)
    }
    #[inline]
    pub fn builder_index(buf: &[u8]) -> u64 {
        u64_le(buf, 156)
    }
    #[inline]
    pub fn slot(buf: &[u8]) -> u64 {
        u64_le(buf, 164)
    }
    #[inline]
    pub fn value(buf: &[u8]) -> u64 {
        u64_le(buf, 172)
    }
    #[inline]
    pub fn execution_payment(buf: &[u8]) -> u64 {
        u64_le(buf, 180)
    }
    #[inline]
    pub fn execution_requests_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 192)
    }
    #[inline]
    pub fn blob_kzg_commitments(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 188) as usize..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < EXECUTION_PAYLOAD_BID_MIN || buf.len() > EXECUTION_PAYLOAD_BID_MAX {
            return false;
        }
        let off = u32_le(buf, 188) as usize;
        off == EXECUTION_PAYLOAD_BID_MIN && off <= buf.len()
    }
}

// -- SignedExecutionPayloadBid (execution_payload_bid) ----------------
//
// Variable. { message: ExecutionPayloadBid(var), signature(96) }.
// Fixed part 100B: offset(4) + signature(96); message body at [100..).

pub const SIGNED_EXECUTION_PAYLOAD_BID_MIN: usize = 100 + EXECUTION_PAYLOAD_BID_MIN;
pub const SIGNED_EXECUTION_PAYLOAD_BID_MAX: usize = 100 + EXECUTION_PAYLOAD_BID_MAX;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedExecutionPayloadBidView;

impl SignedExecutionPayloadBidView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 4)
    }
    /// Raw serialized `ExecutionPayloadBid` bytes.
    #[inline]
    pub fn message(buf: &[u8]) -> &[u8] {
        &buf[100..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_EXECUTION_PAYLOAD_BID_MIN &&
            buf.len() <= SIGNED_EXECUTION_PAYLOAD_BID_MAX &&
            u32_le(buf, 0) as usize == 100
    }
}

// -- ExecutionPayloadEnvelope -----------------------------------------
//
// Variable. { payload: ExecutionPayload(var), execution_requests:
// ExecutionRequests(var), builder_index(8), beacon_block_root(32),
// parent_beacon_block_root(32) }. Fixed part 80B.
//   [0..4)   offset: payload (== 80)
//   [4..8)   offset: execution_requests
//   [8..16)  builder_index
//   [16..48) beacon_block_root
//   [48..80) parent_beacon_block_root

pub const EXECUTION_PAYLOAD_ENVELOPE_MIN: usize = 80;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ExecutionPayloadEnvelopeView;

impl ExecutionPayloadEnvelopeView {
    #[inline]
    pub fn builder_index(buf: &[u8]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn beacon_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn parent_beacon_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn payload(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 0) as usize..u32_le(buf, 4) as usize]
    }
    #[inline]
    pub fn execution_requests(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 4) as usize..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < EXECUTION_PAYLOAD_ENVELOPE_MIN || buf.len() > MAX_PAYLOAD_SIZE {
            return false;
        }
        let payload_off = u32_le(buf, 0) as usize;
        let requests_off = u32_le(buf, 4) as usize;
        payload_off == EXECUTION_PAYLOAD_ENVELOPE_MIN &&
            payload_off <= requests_off &&
            requests_off <= buf.len()
    }
}

// -- SignedExecutionPayloadEnvelope (execution_payload) ---------------
//
// Variable. { message: ExecutionPayloadEnvelope(var), signature(96) }.
// Fixed part 100B: offset(4) + signature(96); message body at [100..).

pub const SIGNED_EXECUTION_PAYLOAD_ENVELOPE_MIN: usize = 100 + EXECUTION_PAYLOAD_ENVELOPE_MIN;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedExecutionPayloadEnvelopeView;

impl SignedExecutionPayloadEnvelopeView {
    #[inline]
    pub fn signature(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 4)
    }
    /// Raw serialized `ExecutionPayloadEnvelope` bytes.
    #[inline]
    pub fn message(buf: &[u8]) -> &[u8] {
        &buf[100..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() >= SIGNED_EXECUTION_PAYLOAD_ENVELOPE_MIN &&
            buf.len() <= MAX_PAYLOAD_SIZE &&
            u32_le(buf, 0) as usize == 100
    }
}

// -- ProposerPreferences ----------------------------------------------
//
// All fixed, 76B.
//   [0..32)  dependent_root
//   [32..40) proposal_slot
//   [40..48) validator_index
//   [48..68) fee_recipient (20)
//   [68..76) target_gas_limit

pub const PROPOSER_PREFERENCES_SIZE: usize = 76;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ProposerPreferencesView;

impl ProposerPreferencesView {
    #[inline]
    pub fn dependent_root(buf: &[u8; PROPOSER_PREFERENCES_SIZE]) -> &[u8; 32] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn proposal_slot(buf: &[u8; PROPOSER_PREFERENCES_SIZE]) -> u64 {
        u64_le(buf, 32)
    }
    #[inline]
    pub fn validator_index(buf: &[u8; PROPOSER_PREFERENCES_SIZE]) -> u64 {
        u64_le(buf, 40)
    }
    #[inline]
    pub fn fee_recipient(buf: &[u8; PROPOSER_PREFERENCES_SIZE]) -> &[u8; 20] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn target_gas_limit(buf: &[u8; PROPOSER_PREFERENCES_SIZE]) -> u64 {
        u64_le(buf, 68)
    }
}

// -- SignedProposerPreferences (proposer_preferences) -----------------
//
// All fixed, 172B: message(76) + signature(96).

pub const SIGNED_PROPOSER_PREFERENCES_SIZE: usize = 172;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SignedProposerPreferencesView;

impl SignedProposerPreferencesView {
    #[inline]
    pub fn message(
        buf: &[u8; SIGNED_PROPOSER_PREFERENCES_SIZE],
    ) -> &[u8; PROPOSER_PREFERENCES_SIZE] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn signature(buf: &[u8; SIGNED_PROPOSER_PREFERENCES_SIZE]) -> &[u8; 96] {
        fixed(buf, 76)
    }
}

// -- ExecutionPayloadEnvelopesByRange v1 request ----------------------
//
// All fixed, 16B: start_slot(8) + count(8).

pub const EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE: usize = 16;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ExecutionPayloadEnvelopesByRangeRequestView;

impl ExecutionPayloadEnvelopesByRangeRequestView {
    #[inline]
    pub fn start_slot(buf: &[u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn count(buf: &[u8; EXECUTION_PAYLOAD_ENVELOPES_BY_RANGE_REQ_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
}

// -- ExecutionPayloadEnvelopesByRoot v1 request -----------------------
//
// List[Root, MAX_REQUEST_PAYLOADS] — contiguous 32B roots.

pub const EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_REQ_MAX: usize = 32 * MAX_REQUEST_PAYLOADS;

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct ExecutionPayloadEnvelopesByRootRequestView;

impl ExecutionPayloadEnvelopesByRootRequestView {
    #[inline]
    pub fn count(buf: &[u8]) -> usize {
        buf.len() / 32
    }
    #[inline]
    pub fn root(buf: &[u8], i: usize) -> &[u8; 32] {
        fixed(buf, i * 32)
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        buf.len() <= EXECUTION_PAYLOAD_ENVELOPES_BY_ROOT_REQ_MAX && buf.len().is_multiple_of(32)
    }
}

// -- DataColumnSidecar (Gloas) ----------------------------------------
//
// [Modified in Gloas] `signed_block_header`, `kzg_commitments`, and
// `kzg_commitments_inclusion_proof` removed; `slot` + `beacon_block_root`
// added. Variable, fixed part 56B.
//   [0..8)    index (ColumnIndex)
//   [8..12)   offset: column
//   [12..16)  offset: kzg_proofs
//   [16..24)  slot
//   [24..56)  beacon_block_root
//   [56..)    column | kzg_proofs

pub const DATA_COLUMN_SIDECAR_GLOAS_MIN: usize = 56;
pub const DATA_COLUMN_SIDECAR_GLOAS_MAX: usize = DATA_COLUMN_SIDECAR_GLOAS_MIN +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_CELL +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_KZG_PROOF;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct DataColumnSidecarGloasView;

impl DataColumnSidecarGloasView {
    #[inline]
    pub fn index(buf: &[u8]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn slot(buf: &[u8]) -> u64 {
        u64_le(buf, 16)
    }
    #[inline]
    pub fn beacon_block_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 24)
    }
    #[inline]
    pub fn column(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 8) as usize..u32_le(buf, 12) as usize]
    }
    #[inline]
    pub fn kzg_proofs(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 12) as usize..]
    }
    #[inline]
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < DATA_COLUMN_SIDECAR_GLOAS_MIN || buf.len() > DATA_COLUMN_SIDECAR_GLOAS_MAX {
            return false;
        }
        let col_off = u32_le(buf, 8) as usize;
        let proof_off = u32_le(buf, 12) as usize;
        col_off >= DATA_COLUMN_SIDECAR_GLOAS_MIN && col_off <= proof_off && proof_off <= buf.len()
    }
}

// -- BeaconBlockBody (Gloas) ------------------------------------------
//
// [Modified in Gloas] `execution_payload`, `blob_kzg_commitments`, and
// `execution_requests` removed; `signed_execution_payload_bid`,
// `payload_attestations`, and `parent_execution_requests` added. Fixed part
// 396B (the four post-`sync_aggregate` offset slots are unchanged in position).
//   [0..96)    randao_reveal
//   [96..168)  eth1_data (72B)
//   [168..200) graffiti
//   [200..204) offset: proposer_slashings
//   [204..208) offset: attester_slashings
//   [208..212) offset: attestations
//   [212..216) offset: deposits
//   [216..220) offset: voluntary_exits
//   [220..380) sync_aggregate (160B)
//   [380..384) offset: bls_to_execution_changes
//   [384..388) offset: signed_execution_payload_bid
//   [388..392) offset: payload_attestations
//   [392..396) offset: parent_execution_requests

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct BeaconBlockBodyGloasView;

impl BeaconBlockBodyGloasView {
    #[inline]
    pub fn randao_reveal(buf: &[u8]) -> &[u8; 96] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn eth1_data(buf: &[u8]) -> &[u8; 72] {
        fixed(buf, 96)
    }
    #[inline]
    pub fn graffiti(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 168)
    }
    #[inline]
    pub fn proposer_slashings_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 200)
    }
    #[inline]
    pub fn attester_slashings_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 204)
    }
    #[inline]
    pub fn attestations_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 208)
    }
    #[inline]
    pub fn deposits_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 212)
    }
    #[inline]
    pub fn voluntary_exits_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 216)
    }
    #[inline]
    pub fn sync_aggregate(buf: &[u8]) -> &[u8; BLOCK_SYNC_AGGREGATE_SIZE] {
        fixed(buf, 220)
    }
    #[inline]
    pub fn bls_to_execution_changes_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 380)
    }
    #[inline]
    pub fn signed_execution_payload_bid_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 384)
    }
    #[inline]
    pub fn payload_attestations_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 388)
    }
    #[inline]
    pub fn parent_execution_requests_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 392)
    }
}

// -- AttestationData (inner 128B; reused inside Attestation,
// IndexedAttestation, SingleAttestation, AggregateAndProof)
// -------------------------------
//
//   [0..8)    slot
//   [8..16)   index (always 0 post-Electra)
//   [16..48)  beacon_block_root
//   [48..56)  source.epoch
//   [56..88)  source.root
//   [88..96)  target.epoch
//   [96..128) target.root

pub const ATTESTATION_DATA_SIZE: usize = 128;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct AttestationDataView;

impl AttestationDataView {
    #[inline]
    pub fn slot(buf: &[u8; ATTESTATION_DATA_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn index(buf: &[u8; ATTESTATION_DATA_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn beacon_block_root(buf: &[u8; ATTESTATION_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn source_epoch(buf: &[u8; ATTESTATION_DATA_SIZE]) -> u64 {
        u64_le(buf, 48)
    }
    #[inline]
    pub fn source_root(buf: &[u8; ATTESTATION_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 56)
    }
    #[inline]
    pub fn target_epoch(buf: &[u8; ATTESTATION_DATA_SIZE]) -> u64 {
        u64_le(buf, 88)
    }
    #[inline]
    pub fn target_root(buf: &[u8; ATTESTATION_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 96)
    }
}

// -- BeaconBlockHeader (112B; nested inside SignedBeaconBlockHeader,
// ProposerSlashing, LightClientHeader, DataColumnSidecar) -

pub const BEACON_BLOCK_HEADER_SIZE: usize = 112;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct BeaconBlockHeaderView;

impl BeaconBlockHeaderView {
    #[inline]
    pub fn slot(buf: &[u8; BEACON_BLOCK_HEADER_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn proposer_index(buf: &[u8; BEACON_BLOCK_HEADER_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn parent_root(buf: &[u8; BEACON_BLOCK_HEADER_SIZE]) -> &[u8; 32] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn state_root(buf: &[u8; BEACON_BLOCK_HEADER_SIZE]) -> &[u8; 32] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn body_root(buf: &[u8; BEACON_BLOCK_HEADER_SIZE]) -> &[u8; 32] {
        fixed(buf, 80)
    }
}

// -- Eth1Data (72B; in BeaconBlockBody and BeaconState) ---------------
//   [0..32)   deposit_root
//   [32..40)  deposit_count
//   [40..72)  block_hash

pub const ETH1_DATA_SIZE: usize = 72;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct Eth1DataView;

impl Eth1DataView {
    #[inline]
    pub fn deposit_root(buf: &[u8; ETH1_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn deposit_count(buf: &[u8; ETH1_DATA_SIZE]) -> u64 {
        u64_le(buf, 32)
    }
    #[inline]
    pub fn block_hash(buf: &[u8; ETH1_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 40)
    }
}

// -- Withdrawal (44B; ExecutionPayload.withdrawals element) -----------
//   [0..8)    index
//   [8..16)   validator_index
//   [16..36)  address
//   [36..44)  amount

pub const WITHDRAWAL_SIZE: usize = 44;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct WithdrawalView;

impl WithdrawalView {
    #[inline]
    pub fn index(buf: &[u8; WITHDRAWAL_SIZE]) -> u64 {
        u64_le(buf, 0)
    }
    #[inline]
    pub fn validator_index(buf: &[u8; WITHDRAWAL_SIZE]) -> u64 {
        u64_le(buf, 8)
    }
    #[inline]
    pub fn address(buf: &[u8; WITHDRAWAL_SIZE]) -> &[u8; 20] {
        fixed(buf, 16)
    }
    #[inline]
    pub fn amount(buf: &[u8; WITHDRAWAL_SIZE]) -> u64 {
        u64_le(buf, 36)
    }
}

// -- SyncAggregate (160B; in BeaconBlockBody) -------------------------
//   [0..64)   sync_committee_bits (Bitvector[512] = 64B)
//   [64..160) sync_committee_signature

pub const BLOCK_SYNC_AGGREGATE_SIZE: usize = 160;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct SyncAggregateView;

impl SyncAggregateView {
    #[inline]
    pub fn sync_committee_bits(buf: &[u8; BLOCK_SYNC_AGGREGATE_SIZE]) -> &[u8; 64] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn sync_committee_signature(buf: &[u8; BLOCK_SYNC_AGGREGATE_SIZE]) -> &[u8; 96] {
        fixed(buf, 64)
    }
}

// -- DepositData (184B; signed by depositor, hashed for deposit root) -
//   [0..48)    pubkey
//   [48..80)   withdrawal_credentials
//   [80..88)   amount
//   [88..184)  signature

pub const DEPOSIT_DATA_SIZE: usize = 184;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct DepositDataView;

impl DepositDataView {
    #[inline]
    pub fn pubkey(buf: &[u8; DEPOSIT_DATA_SIZE]) -> &[u8; 48] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn withdrawal_credentials(buf: &[u8; DEPOSIT_DATA_SIZE]) -> &[u8; 32] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn amount(buf: &[u8; DEPOSIT_DATA_SIZE]) -> u64 {
        u64_le(buf, 80)
    }
    #[inline]
    pub fn signature(buf: &[u8; DEPOSIT_DATA_SIZE]) -> &[u8; 96] {
        fixed(buf, 88)
    }
}

// -- Deposit (1240B; BeaconBlockBody.deposits element) ----------------
// proof: Vector[Bytes32, DEPOSIT_CONTRACT_TREE_DEPTH+1] = 33 * 32 = 1056B
// data : DepositData (184B)
//   [0..1056)    proof
//   [1056..1240) data

pub const DEPOSIT_SIZE: usize = 1240;
pub const DEPOSIT_PROOF_SIZE: usize = 1056;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct DepositView;

impl DepositView {
    #[inline]
    pub fn proof(buf: &[u8; DEPOSIT_SIZE]) -> &[u8; DEPOSIT_PROOF_SIZE] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn data(buf: &[u8; DEPOSIT_SIZE]) -> &[u8; DEPOSIT_DATA_SIZE] {
        fixed(buf, DEPOSIT_PROOF_SIZE)
    }
}

// -- DepositRequest (192B; ExecutionRequests.deposits element) --------
//   [0..48)    pubkey
//   [48..80)   withdrawal_credentials
//   [80..88)   amount
//   [88..184)  signature
//   [184..192) index

pub const DEPOSIT_REQUEST_SIZE: usize = 192;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct DepositRequestView;

impl DepositRequestView {
    #[inline]
    pub fn pubkey(buf: &[u8; DEPOSIT_REQUEST_SIZE]) -> &[u8; 48] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn withdrawal_credentials(buf: &[u8; DEPOSIT_REQUEST_SIZE]) -> &[u8; 32] {
        fixed(buf, 48)
    }
    #[inline]
    pub fn amount(buf: &[u8; DEPOSIT_REQUEST_SIZE]) -> u64 {
        u64_le(buf, 80)
    }
    #[inline]
    pub fn signature(buf: &[u8; DEPOSIT_REQUEST_SIZE]) -> &[u8; 96] {
        fixed(buf, 88)
    }
    #[inline]
    pub fn index(buf: &[u8; DEPOSIT_REQUEST_SIZE]) -> u64 {
        u64_le(buf, 184)
    }
}

// -- WithdrawalRequest (76B; ExecutionRequests.withdrawals element) ---
//   [0..20)    source_address
//   [20..68)   validator_pubkey
//   [68..76)   amount

pub const WITHDRAWAL_REQUEST_SIZE: usize = 76;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct WithdrawalRequestView;

impl WithdrawalRequestView {
    #[inline]
    pub fn source_address(buf: &[u8; WITHDRAWAL_REQUEST_SIZE]) -> &[u8; 20] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn validator_pubkey(buf: &[u8; WITHDRAWAL_REQUEST_SIZE]) -> &[u8; 48] {
        fixed(buf, 20)
    }
    #[inline]
    pub fn amount(buf: &[u8; WITHDRAWAL_REQUEST_SIZE]) -> u64 {
        u64_le(buf, 68)
    }
}

// -- ConsolidationRequest (116B; ExecutionRequests.consolidations element)
//   [0..20)    source_address
//   [20..68)   source_pubkey
//   [68..116)  target_pubkey

pub const CONSOLIDATION_REQUEST_SIZE: usize = 116;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ConsolidationRequestView;

impl ConsolidationRequestView {
    #[inline]
    pub fn source_address(buf: &[u8; CONSOLIDATION_REQUEST_SIZE]) -> &[u8; 20] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn source_pubkey(buf: &[u8; CONSOLIDATION_REQUEST_SIZE]) -> &[u8; 48] {
        fixed(buf, 20)
    }
    #[inline]
    pub fn target_pubkey(buf: &[u8; CONSOLIDATION_REQUEST_SIZE]) -> &[u8; 48] {
        fixed(buf, 68)
    }
}

// -- ExecutionPayload (variable; in BeaconBlockBody.execution_payload) -
//
// Fixed part 528B; trailing variable region holds extra_data, transactions,
// withdrawals (each pointed to by a u32 offset in the fixed part).
//   [0..32)    parent_hash
//   [32..52)   fee_recipient
//   [52..84)   state_root
//   [84..116)  receipts_root
//   [116..372) logs_bloom (256B)
//   [372..404) prev_randao
//   [404..412) block_number
//   [412..420) gas_limit
//   [420..428) gas_used
//   [428..436) timestamp
//   [436..440) offset to extra_data
//   [440..472) base_fee_per_gas (Bytes32 LE)
//   [472..504) block_hash
//   [504..508) offset to transactions
//   [508..512) offset to withdrawals
//   [512..520) blob_gas_used
//   [520..528) excess_blob_gas
//   [528..)    extra_data | transactions | withdrawals

pub const EXECUTION_PAYLOAD_FIXED: usize = 528;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
#[repr(C)]
pub struct ExecutionPayloadView;

impl ExecutionPayloadView {
    #[inline]
    pub fn parent_hash(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 0)
    }
    #[inline]
    pub fn fee_recipient(buf: &[u8]) -> &[u8; 20] {
        fixed(buf, 32)
    }
    #[inline]
    pub fn state_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 52)
    }
    #[inline]
    pub fn receipts_root(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 84)
    }
    #[inline]
    pub fn logs_bloom(buf: &[u8]) -> &[u8; 256] {
        fixed(buf, 116)
    }
    #[inline]
    pub fn prev_randao(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 372)
    }
    #[inline]
    pub fn block_number(buf: &[u8]) -> u64 {
        u64_le(buf, 404)
    }
    #[inline]
    pub fn gas_limit(buf: &[u8]) -> u64 {
        u64_le(buf, 412)
    }
    #[inline]
    pub fn gas_used(buf: &[u8]) -> u64 {
        u64_le(buf, 420)
    }
    #[inline]
    pub fn timestamp(buf: &[u8]) -> u64 {
        u64_le(buf, 428)
    }
    #[inline]
    pub fn extra_data_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 436)
    }
    #[inline]
    pub fn base_fee_per_gas(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 440)
    }
    #[inline]
    pub fn block_hash(buf: &[u8]) -> &[u8; 32] {
        fixed(buf, 472)
    }
    #[inline]
    pub fn transactions_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 504)
    }
    #[inline]
    pub fn withdrawals_offset(buf: &[u8]) -> u32 {
        u32_le(buf, 508)
    }
    #[inline]
    pub fn blob_gas_used(buf: &[u8]) -> u64 {
        u64_le(buf, 512)
    }
    #[inline]
    pub fn excess_blob_gas(buf: &[u8]) -> u64 {
        u64_le(buf, 520)
    }
}
