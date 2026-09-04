use silver_beacon_state_data::{B256, BLSPubkey, BlockBodyError, Epoch, Slot};
use thiserror::Error;

use crate::tile::Feedback;

#[derive(Clone, Copy, Debug, Error)]
pub enum PrecheckError {
    #[error("block size precheck failed: expected {expected_min}..={expected_max} got {got}")]
    SizeMismatch { expected_min: usize, expected_max: usize, got: usize },
    #[error(
        "block parent precheck failed: parent_root=0x{} last_applied_slot={last_applied_slot} \
         block_slot={block_slot}",
        b256_hex(parent_root)
    )]
    ParentMissing { parent_root: B256, block_root: B256, last_applied_slot: Slot, block_slot: Slot },
    #[error(
        "block parent invalid: parent_root=0x{} block_root=0x{}",
        b256_hex(parent_root),
        b256_hex(block_root)
    )]
    ParentInvalid { parent_root: B256, block_root: B256 },
    #[error("past block: block_epoch={block_epoch} finalized_epoch={finalized_epoch}")]
    PreFinalized { block_epoch: Epoch, finalized_epoch: Epoch },
    #[error("block past-slot precheck failed: block_slot={block_slot} parent_slot={parent_slot}")]
    PastSlot { block_slot: Slot, parent_slot: Slot },
    #[error("block already imported: block_root=0x{}", b256_hex(block_root))]
    AlreadyKnown { block_root: B256 },
    #[error("block ticker slot precheck failed: block_slot={block_slot} wall_slot={wall_slot}")]
    FutureSlot { block_slot: Slot, wall_slot: Slot },
    #[error(
        "block proposer lookahead precheck failed: expected={expected} got={got} \
         block_root=0x{}",
        b256_hex(block_root)
    )]
    ProposerLookaheadMismatch { expected: u64, got: u64, block_root: B256 },
    #[error(
        "block proposer index precheck failed: got={got} validator_count={validator_count} \
         block_root=0x{}",
        b256_hex(block_root)
    )]
    ProposerIndexTooBig { got: u64, validator_count: usize, block_root: B256 },
    #[error(
        "block extends parent's unverified FULL payload: parent_root=0x{} block_root=0x{}",
        b256_hex(parent_root),
        b256_hex(block_root)
    )]
    UnverifiedParentPayload { parent_root: B256, block_root: B256 },
    #[error(
        "block execution payload timestamp precheck failed: expected={expected} got={got} \
         block_root=0x{}",
        b256_hex(block_root)
    )]
    PayloadTimestamp { expected: u64, got: u64, block_root: B256 },
    #[error(
        "block execution payload too short for its fork: len={len} min={min} \
         block_root=0x{}",
        b256_hex(block_root)
    )]
    PayloadTooShort { len: usize, min: usize, block_root: B256 },
    #[error(
        "block blob commitment count precheck failed: got={got} max={max} \
         block_root=0x{}",
        b256_hex(block_root)
    )]
    TooManyCommitments { got: usize, max: usize, block_root: B256 },
    #[error("invalid block signature: block_root=0x{}", b256_hex(block_root))]
    InvalidSignature { block_root: B256 },
}

impl PrecheckError {
    pub fn feedback(self) -> Feedback {
        match self {
            Self::SizeMismatch { .. } => Feedback::Reject(None),
            Self::ParentMissing { parent_root, block_root, .. } => {
                Feedback::RequestParent { parent_root, block_root }
            }
            Self::PreFinalized { .. } | Self::PastSlot { .. } | Self::FutureSlot { .. } => {
                Feedback::Ignore
            }
            Self::AlreadyKnown { block_root } => Feedback::AlreadyKnown(block_root),
            Self::UnverifiedParentPayload { parent_root, block_root } => {
                Feedback::AwaitParentPayload { parent_root, block_root }
            }
            Self::ParentInvalid { block_root, .. } |
            Self::ProposerLookaheadMismatch { block_root, .. } |
            Self::ProposerIndexTooBig { block_root, .. } |
            Self::PayloadTimestamp { block_root, .. } |
            Self::PayloadTooShort { block_root, .. } |
            Self::TooManyCommitments { block_root, .. } => Feedback::Reject(Some(block_root)),
            Self::InvalidSignature { block_root } => Feedback::Reject(Some(block_root)),
        }
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid block (block_state_root=0x{}): {kind}", b256_hex(state_root))]
    InvalidBlock { state_root: B256, kind: BlockError },

    #[error("block BLS signature invalid")]
    InvalidBlockSig,
    #[error("BLS sig batch verification failed")]
    SigBatchFailed,

    #[error("invalid attestation: {0}")]
    InvalidAttestation(#[from] AttestationError),
    #[error("invalid attester slashing: {0}")]
    InvalidAttesterSlashing(#[from] AttesterSlashingError),
    #[error("invalid proposer slashing: {0}")]
    InvalidProposerSlashing(#[from] ProposerSlashingError),
    #[error("invalid voluntary exit: {0}")]
    InvalidVoluntaryExit(#[from] VoluntaryExitError),
    #[error("invalid bls_to_execution_change: {0}")]
    InvalidBlsToExecutionChange(#[from] BlsToExecutionChangeError),
    #[error("invalid sync aggregate: {0}")]
    InvalidSyncAggregate(#[from] SyncAggregateError),
    #[error("invalid withdrawals: {0}")]
    InvalidWithdrawals(#[from] WithdrawalsError),
    #[error("invalid execution payload: {0}")]
    InvalidExecutionPayload(#[from] ExecutionPayloadError),
    #[error("invalid execution payload bid: {0}")]
    InvalidExecutionPayloadBid(#[from] ExecutionPayloadBidError),
    #[error("invalid parent execution payload: {0}")]
    InvalidParentExecutionPayload(#[from] ParentExecutionPayloadError),
    #[error("invalid payload attestation: {0}")]
    InvalidPayloadAttestation(#[from] PayloadAttestationError),
    #[error("invalid deposit Merkle branch at leaf index {index}")]
    InvalidDepositProof { index: u64 },

    #[error("deposit signature invalid (skipped, leaf index {index})")]
    SkipDepositBadSig { index: u64 },
    #[error("execution request skipped: {reason}")]
    SkipExecutionRequest { reason: &'static str },
}

impl Error {
    #[inline]
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::SkipDepositBadSig { .. } | Self::SkipExecutionRequest { .. })
    }

    /// state_root is the block's claimed post-state_root — unique per block,
    /// already in hand from the caller, no merkleize required.
    #[inline]
    pub fn invalid_block(state_root: B256, kind: BlockError) -> Self {
        Self::InvalidBlock { state_root, kind }
    }
}

#[derive(Debug, Error)]
pub enum ExecutionPayloadBidError {
    #[error("malformed SignedExecutionPayloadBid SSZ (len {len})")]
    Malformed { len: usize },
    #[error("self-build bid value must be zero, got {value}")]
    SelfBuildNonZeroValue { value: u64 },
    #[error("self-build bid signature must be the infinity point")]
    SelfBuildSignature,
    #[error("builder index {index} out of range (count {count})")]
    BuilderOutOfRange { index: u64, count: usize },
    #[error("builder {index} pubkey is not a valid BLS point")]
    BadBuilderPubkey { index: u64 },
    #[error("builder {index} is not active")]
    BuilderInactive { index: u64 },
    #[error("builder {index} version {version} != PAYLOAD_BUILDER_VERSION")]
    BuilderVersion { index: u64, version: u8 },
    #[error("builder {index} cannot cover bid value {value}")]
    InsufficientBalance { index: u64, value: u64 },
    #[error("{got} blob commitments exceeds max {max}")]
    TooManyBlobCommitments { got: usize, max: usize },
    #[error("bid slot {bid} != state slot {state}")]
    SlotMismatch { bid: u64, state: u64 },
    #[error("bid at genesis slot")]
    GenesisSlot,
    #[error("bid parent_block_hash does not match latest_block_hash")]
    ParentBlockHashMismatch,
    #[error("bid parent_block_root does not match block root at slot-1")]
    ParentBlockRootMismatch,
    #[error("bid prev_randao does not match the current randao mix")]
    PrevRandaoMismatch,
}

#[derive(Debug, Error)]
pub enum PayloadAttestationError {
    #[error("malformed PayloadAttestation SSZ (len {len})")]
    Malformed { len: usize },
    #[error("payload attestation beacon_block_root != parent block root")]
    BadBeaconBlockRoot,
    #[error("payload attestation slot {slot} is not state slot {state} - 1")]
    BadSlot { slot: u64, state: u64 },
    #[error("payload attestation has no attesting indices")]
    NoAttestingIndices,
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("malformed envelope payload")]
    Malformed,
    #[error("envelope disagrees with the committed bid: {field}")]
    BidMismatch { field: &'static str },
    #[error("envelope payload {field} disagrees with the state")]
    PayloadMismatch { field: &'static str },
    #[error("builder index {index} out of range")]
    BuilderOutOfRange { index: u64 },
    #[error("invalid builder signature")]
    BadSignature,
}

#[derive(Debug, Error)]
pub enum ParentExecutionPayloadError {
    #[error("malformed parent_execution_requests / block body offsets")]
    Malformed,
    #[error("parent declared EMPTY but carries non-empty execution requests")]
    EmptyParentHasRequests,
    #[error(
        "parent_execution_requests root mismatch: expected=0x{} got=0x{}",
        b256_hex(expected),
        b256_hex(got)
    )]
    RequestsRootMismatch { expected: B256, got: B256 },
    #[error("{kind} request count {count} over the per-payload limit {max}")]
    TooManyRequests { kind: &'static str, count: usize, max: usize },
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum BlockError {
    #[error("block too short: len={len} min={min}")]
    TooShort { len: usize, min: usize },
    #[error("block slot {slot} not after latest header slot {latest}")]
    SlotNotAfterHeader { slot: u64, latest: u64 },
    #[error("block slot != state slot: block={block} state={state}")]
    SlotStateMismatch { block: u64, state: u64 },
    #[error("proposer lookahead mismatch: got={got} expected={expected}")]
    ProposerLookaheadMismatch { got: u64, expected: u64 },
    #[error("proposer_index {idx} >= validator_count {count}")]
    ProposerOutOfRange { idx: u64, count: usize },
    #[error("proposer slashed: index={idx} pubkey=0x{}", pubkey_hex(pubkey))]
    ProposerSlashed { idx: u64, pubkey: BLSPubkey },
    #[error("parent root mismatch: expected=0x{} got=0x{}", b256_hex(expected), b256_hex(got))]
    ParentRootMismatch { expected: B256, got: B256 },
    #[error("post-state root mismatch: expected=0x{} got=0x{}", b256_hex(expected), b256_hex(got))]
    PostStateRootMismatch { expected: B256, got: B256 },
    #[error(transparent)]
    Body(#[from] BlockBodyError),
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation too short: len={len} min={min}")]
    TooShort { len: usize, min: usize },
    #[error("Gloas attestation payload-vote index invalid: {index}")]
    InvalidPayloadIndex { index: u64 },
    #[error("att_slot {att_slot} not before state slot {state_slot}")]
    SlotNotPast { att_slot: u64, state_slot: u64 },
    #[error("target_epoch mismatch: expected={att} got={target}")]
    TargetEpochMismatch { target: u64, att: u64 },
    #[error("target_epoch {target} not in [prev={prev}, curr={curr}]")]
    TargetEpochOutOfWindow { target: u64, prev: u64, curr: u64 },
    #[error("attestation index {idx} != 0")]
    IndexNonZero { idx: u64 },
    #[error("attestations list bad offsets: start={start} end={end} parent_len={parent_len}")]
    BadOffsets { start: usize, end: usize, parent_len: usize },
    #[error("no shuffling supplied")]
    MissingShuffling,
    #[error("empty shuffling or zero committees_per_slot")]
    EmptyShuffling,
    #[error("committee_bits == 0")]
    EmptyCommitteeBits,
    #[error("committee_bits {bits:#x} overflow committees_per_slot {committees_per_slot}")]
    CommitteeBitsOverflow { committees_per_slot: usize, bits: u64 },
    #[error("validator index {vi} >= validator_count {count}")]
    ValidatorOutOfRange { vi: usize, count: usize },
    #[error(
        "source mismatch: expected (epoch={expected_epoch}, root=0x{}) got (epoch={got_epoch}, root=0x{})",
        b256_hex(expected_root),
        b256_hex(got_root)
    )]
    SourceMismatch { expected_epoch: u64, expected_root: B256, got_epoch: u64, got_root: B256 },
    #[error("committee with no participating bits")]
    EmptyCommittee,
    #[error("bitlist length mismatch: expected={expected} got={got}")]
    BitlistLenMismatch { expected: usize, got: usize },
}

#[derive(Debug, Error)]
pub enum ProposerSlashingError {
    #[error("proposer slashing too short: len={len} min={min}")]
    TooShort { len: usize, min: usize },
    #[error("h1 proposer_index {h1} != h2 proposer_index {h2}")]
    ProposerIndexMismatch { h1: u64, h2: u64 },
    #[error("h1 slot {h1} != h2 slot {h2}")]
    SlotMismatch { h1: u64, h2: u64 },
    #[error("h1 and h2 are the same signed header (not slashable)")]
    SameHeader,
    #[error("validator index {vi} >= validator_count {count}")]
    ValidatorOutOfRange { vi: usize, count: usize },
    #[error("validator {vi} (pubkey=0x{}) not slashable in epoch {epoch}", pubkey_hex(pubkey))]
    NotSlashable { vi: usize, pubkey: BLSPubkey, epoch: u64 },
}

#[derive(Debug, Error)]
pub enum AttesterSlashingError {
    #[error("attester slashing list bad offsets: start={start} end={end} parent_len={parent_len}")]
    BadOffsets { start: usize, end: usize, parent_len: usize },
    #[error("attester slashing entry too short: len={len} min={min}")]
    TooShort { len: usize, min: usize },
    #[error(
        "bad inner IndexedAttestation offsets: off1={off1} off2={off2} slashing_len={slashing_len}"
    )]
    BadInnerOffsets { off1: usize, off2: usize, slashing_len: usize },
    #[error("validator index {vi} >= validator_count {count}")]
    ValidatorOutOfRange { vi: usize, count: usize },
    #[error("attestation data pair is not slashable")]
    NotSlashableData,
    #[error("attesting_indices not strictly ascending")]
    IndicesNotSorted,
    #[error("no slashable validator in attesting-indices intersection")]
    NoSlashedIntersection,
}

#[derive(Debug, Error)]
pub enum VoluntaryExitError {
    #[error("validator index {vi} >= validator_count {count}")]
    ValidatorOutOfRange { vi: usize, count: usize },
    #[error("validator {vi} (pubkey=0x{}) not active in epoch {epoch}", pubkey_hex(pubkey))]
    NotActive { vi: usize, pubkey: BLSPubkey, epoch: u64 },
    #[error("validator {vi} (pubkey=0x{}) already exiting", pubkey_hex(pubkey))]
    AlreadyExiting { vi: usize, pubkey: BLSPubkey },
    #[error("exit_epoch {exit} > current_epoch {current}")]
    ExitEpochInFuture { current: u64, exit: u64 },
    #[error(
        "shard committee period not elapsed for validator {vi} (pubkey=0x{})",
        pubkey_hex(pubkey)
    )]
    TooEarly { vi: usize, pubkey: BLSPubkey },
    #[error("validator {vi} (pubkey=0x{}) has pending balance to withdraw", pubkey_hex(pubkey))]
    HasPendingBalance { vi: usize, pubkey: BLSPubkey },
}

#[derive(Debug, Error)]
pub enum BlsToExecutionChangeError {
    #[error("validator index {vi} >= validator_count {count}")]
    ValidatorOutOfRange { vi: usize, count: usize },
    #[error(
        "validator {vi} (pubkey=0x{}) credentials prefix is not BLS_WITHDRAWAL (got {prefix:#x})",
        pubkey_hex(pubkey)
    )]
    BadCredentialPrefix { vi: usize, pubkey: BLSPubkey, prefix: u8 },
    #[error(
        "from_pubkey hash mismatch: from_pubkey=0x{} expected=0x{} got=0x{}",
        pubkey_hex(from_pubkey),
        b256_hex(expected),
        b256_hex(got)
    )]
    PubkeyHashMismatch { from_pubkey: BLSPubkey, expected: B256, got: B256 },
    #[error("from_pubkey failed to decompress: 0x{}", pubkey_hex(from_pubkey))]
    BadPubkey { from_pubkey: BLSPubkey },
}

#[derive(Debug, Error)]
pub enum SyncAggregateError {
    #[error("proposer index {idx} >= validator_count {count}")]
    ProposerOutOfRange { idx: u64, count: usize },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WithdrawalRecord {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8; 20],
    pub amount: u64,
}

impl core::fmt::Display for WithdrawalRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "idx={} vi={} addr=0x{} amount={}",
            self.index,
            self.validator_index,
            bytes_hex(&self.address),
            self.amount,
        )
    }
}

#[derive(Debug, Error)]
pub enum WithdrawalsError {
    #[error("execution payload too short for withdrawals: len={len} min={min}")]
    PayloadTooShort { len: usize, min: usize },
    #[error("withdrawals_offset {withdrawals_off} > payload_len {payload_len}")]
    BadOffsets { withdrawals_off: usize, payload_len: usize },
    #[error("withdrawals payload count {count} > max {max}")]
    TooMany { count: usize, max: usize },
    #[error(
        "withdrawal mismatch at payload index {payload_index}: expected ({expected}) got ({got})"
    )]
    Mismatch { payload_index: usize, expected: WithdrawalRecord, got: WithdrawalRecord },
    #[error("withdrawal count mismatch: expected={expected} got={actual}")]
    CountMismatch { expected: usize, actual: usize },
}

#[derive(Debug, Error)]
pub enum ExecutionPayloadError {
    #[error("execution payload too short: len={len} min={min}")]
    TooShort { len: usize, min: usize },
    #[error("parent_hash mismatch: expected=0x{} got=0x{}", b256_hex(expected), b256_hex(got))]
    ParentHashMismatch { expected: B256, got: B256 },
    #[error("timestamp mismatch: expected={expected} got={got}")]
    TimestampMismatch { expected: u64, got: u64 },
    #[error("prev_randao mismatch: expected=0x{} got=0x{}", b256_hex(expected), b256_hex(got))]
    RandaoMismatch { expected: B256, got: B256 },
}

fn b256_hex(b: &B256) -> String {
    bytes_hex(b)
}

fn pubkey_hex(p: &BLSPubkey) -> String {
    bytes_hex(p)
}

fn bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}
