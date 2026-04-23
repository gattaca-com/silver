use std::alloc::{Layout, alloc_zeroed};

use flux::utils::ArrayVec;

pub fn box_zeroed<T>() -> Box<T> {
    let layout = Layout::new::<T>();
    unsafe {
        let ptr = alloc_zeroed(layout);
        assert!(!ptr.is_null(), "allocation failed");
        Box::from_raw(ptr.cast::<T>())
    }
}

pub type B256 = [u8; 32];
pub type BLSPubkey = [u8; 48];
pub type BLSSignature = [u8; 96];
pub type Slot = u64;
pub type Epoch = u64;

pub const MAX_VALIDATORS: usize = 2 * 1024 * 1024;
pub const VALIDATOR_REGISTRY_LIMIT: usize = 1 << 40;
pub const SLOTS_PER_HISTORICAL_ROOT: usize = 8192;
pub const SLOTS_PER_EPOCH: u64 = 32;
pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 65536;
pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 8192;
pub const SYNC_COMMITTEE_SIZE: usize = 512;
pub const MAX_ETH1_VOTES: usize = 2048;
/// In-memory cap for the `historical_summaries` list. Mainnet grows by 1 entry
/// per 256 epochs (~27h); 8192 covers ~25 years.
pub const HISTORICAL_SUMMARIES_CAP: usize = 8192;
pub const HISTORICAL_ROOTS_LIMIT: usize = 1 << 24;
pub const MIN_SEED_LOOKAHEAD: u64 = 1;
pub const PROPOSER_LOOKAHEAD_SIZE: usize =
    (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize; // 64
pub const BYTES_PER_LOGS_BLOOM: usize = 256;
pub const MAX_EXTRA_DATA_BYTES: usize = 32;

// These are the pending queue high-water marks observed on mainnet.
pub const PENDING_DEPOSITS_CAP: usize = 8192;
pub const PENDING_PARTIAL_WITHDRAWALS_CAP: usize = 8192;
pub const PENDING_CONSOLIDATIONS_CAP: usize = 4096;

// Spec limits
pub const PENDING_DEPOSITS_LIMIT: usize = 1 << 27;
pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 1 << 27;
pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 1 << 18;

pub const PENDING_POOL_CAP: usize = 32;

// Tier pool capacities.
/// `Immutable` mutates only across hard forks; one slot suffices until
/// fork-transition lands.
pub const IMM_POOL_CAP: usize = 1;
pub const VID_POOL_CAP: usize = 4;
pub const LONGTAIL_POOL_CAP: usize = 2;
pub const EPOCH_POOL_CAP: usize = 8;
pub const ROOTS_POOL_CAP: usize = 32;
pub const SLOT_POOL_CAP: usize = 32;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub epoch: Epoch,
    pub root: B256,
}

/// Tier 0: never-mutated-on-hot-path scalars.
/// Mutated only at hard forks. 88 B.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Immutable {
    pub genesis_time: u64,
    pub genesis_validators_root: B256,
    /// Precomputed SSZ tree hash root of the frozen historical_roots list.
    pub historical_roots_hash: B256,
    pub fork: Fork,
}

/// Mutated rarely — new deposits, BLS-to-exec changes, compounding switch.
/// ~160 MB at 2M validators.
#[repr(C)]
pub struct ValidatorIdentity {
    pub validator_cnt: usize,
    pub val_pubkey: [BLSPubkey; MAX_VALIDATORS],
    pub val_withdrawal_credentials: [B256; MAX_VALIDATORS],
}

/// Mutated every 256 epochs (~27h) on sync committee rotation and every
/// 256 epochs on historical summary push.
#[repr(C)]
pub struct HistoricalLongtail {
    pub historical_summaries: ArrayVec<HistoricalSummary, HISTORICAL_SUMMARIES_CAP>,
    pub current_sync_committee: SyncCommittee,
    pub next_sync_committee: SyncCommittee,
    pub sync_committee_indices: [u32; SYNC_COMMITTEE_SIZE],
}

/// Size of the `val_slashed` bitset in bytes (1 bit per validator).
pub const VAL_SLASHED_BYTES: usize = MAX_VALIDATORS / 8;

/// Mutated every epoch boundary.
/// ~100 MB at 2M validators.
#[repr(C)]
pub struct EpochData {
    // hot — scanned by fork choice weight + committee shuffling
    pub val_effective_balance: [u64; MAX_VALIDATORS],
    pub val_activation_epoch: [u64; MAX_VALIDATORS],
    pub val_exit_epoch: [u64; MAX_VALIDATORS],

    // warm — epoch boundary only
    pub val_activation_eligibility_epoch: [u64; MAX_VALIDATORS],
    pub val_slashed: [u8; VAL_SLASHED_BYTES],
    pub val_withdrawable_epoch: [u64; MAX_VALIDATORS],

    pub inactivity_scores: [u64; MAX_VALIDATORS],

    pub randao_mixes: [B256; EPOCHS_PER_HISTORICAL_VECTOR],
    pub slashings: [u64; EPOCHS_PER_SLASHINGS_VECTOR],
}

impl EpochData {
    #[inline]
    pub fn val_slashed(&self, i: usize) -> bool {
        self.val_slashed[i / 8] & (1u8 << (i % 8)) != 0
    }

    #[inline]
    pub fn set_val_slashed(&mut self, i: usize, v: bool) {
        let mask = 1u8 << (i % 8);
        if v {
            self.val_slashed[i / 8] |= mask;
        } else {
            self.val_slashed[i / 8] &= !mask;
        }
    }
}

/// Circular buffers: block_roots and state_roots. ~512 KB.
#[repr(C)]
pub struct SlotRoots {
    pub block_roots: [B256; SLOTS_PER_HISTORICAL_ROOT],
    pub state_roots: [B256; SLOTS_PER_HISTORICAL_ROOT],
}

/// Per-slot mutable state. Owned per-fork, mutated in place.
/// ~20 MB at 2M validators (balances 16MB + participation 4MB + scalars).
/// Pending queues live in a separate PendingQueues tier.
#[repr(C)]
pub struct SlotData {
    pub balances: [u64; MAX_VALIDATORS],
    pub current_epoch_participation: [u8; MAX_VALIDATORS],
    pub previous_epoch_participation: [u8; MAX_VALIDATORS],

    pub randao_mix_current: B256,

    pub eth1_data: Eth1Data,
    pub eth1_votes: ArrayVec<Eth1Data, MAX_ETH1_VOTES>,
    pub eth1_deposit_index: u64,

    pub slot: Slot,
    pub latest_block_header: BeaconBlockHeader,
    pub justification_bits: u8,
    pub previous_justified_checkpoint: Checkpoint,
    pub current_justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,

    pub latest_execution_payload_header: ExecutionPayloadHeader, // ~600B
    pub next_withdrawal_index: u64,
    pub next_withdrawal_validator_index: u64,

    pub deposit_requests_start_index: u64,
    pub deposit_balance_to_consume: u64,
    pub exit_balance_to_consume: u64,
    pub earliest_exit_epoch: Epoch,
    pub consolidation_balance_to_consume: u64,
    pub earliest_consolidation_epoch: Epoch,
    pub proposer_lookahead: [u64; PROPOSER_LOOKAHEAD_SIZE],
}

/// Vec-backed: spec limits (2^27) are infeasible to preallocate.
#[derive(Clone, Default)]
pub struct PendingQueues {
    pub pending_deposits: Vec<PendingDeposit>,
    pub pending_partial_withdrawals: Vec<PendingPartialWithdrawal>,
    pub pending_consolidations: Vec<PendingConsolidation>,
}

impl PendingQueues {
    pub fn new() -> Self {
        Self {
            pending_deposits: Vec::with_capacity(PENDING_DEPOSITS_CAP),
            pending_partial_withdrawals: Vec::with_capacity(PENDING_PARTIAL_WITHDRAWALS_CAP),
            pending_consolidations: Vec::with_capacity(PENDING_CONSOLIDATIONS_CAP),
        }
    }
}

/// Indices into each tier's pool. Every tier is arena-resident except
/// `pending_idx` (heap Vec — see `PendingQueues`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BeaconStateRef {
    pub imm_idx: usize,
    pub vid_idx: usize,
    pub longtail_idx: usize,
    pub epoch_idx: usize,
    pub roots_idx: usize,
    pub slot_idx: usize,
    pub pending_idx: usize,
}

pub type Version = [u8; 4];
pub type ExecutionAddress = [u8; 20];

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Fork {
    pub previous_version: Version,
    pub current_version: Version,
    pub epoch: Epoch,
}

/// Execution layer payload header (Deneb/Electra).
/// 17 fields. extra_data is variable but bounded to 32 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecutionPayloadHeader {
    pub parent_hash: B256,
    pub fee_recipient: ExecutionAddress,
    pub state_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: [u8; BYTES_PER_LOGS_BLOOM],
    pub prev_randao: B256,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data_len: u8, // length of extra_data (max 32)
    pub extra_data: [u8; MAX_EXTRA_DATA_BYTES],
    pub base_fee_per_gas: [u8; 32], // uint256 LE
    pub block_hash: B256,
    pub transactions_root: B256,
    pub withdrawals_root: B256,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingDeposit {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: B256,
    pub amount: u64,
    pub signature: BLSSignature,
    pub slot: Slot,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PendingPartialWithdrawal {
    pub index: u64,
    pub amount: u64,
    pub withdrawable_epoch: Epoch,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PendingConsolidation {
    pub source_index: u64,
    pub target_index: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HistoricalSummary {
    pub block_summary_root: B256,
    pub state_summary_root: B256,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SyncCommittee {
    pub pubkeys: [BLSPubkey; SYNC_COMMITTEE_SIZE],
    pub aggregate_pubkey: BLSPubkey,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Eth1Data {
    pub deposit_root: B256,
    pub deposit_count: u64,
    pub block_hash: B256,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BeaconBlockHeader {
    pub slot: Slot,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

const _: () = {
    use core::mem::{align_of, size_of};

    assert!(size_of::<Fork>() == 4 + 4 + 8);
    assert!(size_of::<Checkpoint>() == 8 + 32);

    assert!(size_of::<Immutable>() == 8 + 32 + 32 + size_of::<Fork>());

    assert!(
        size_of::<ValidatorIdentity>() ==
            size_of::<usize>() +
                size_of::<BLSPubkey>() * MAX_VALIDATORS +
                size_of::<B256>() * MAX_VALIDATORS
    );

    assert!(
        size_of::<EpochData>() ==
            6 * size_of::<[u64; MAX_VALIDATORS]>()     // eff_bal, activation, exit, eligibility, withdrawable, inactivity
                + size_of::<[u8; VAL_SLASHED_BYTES]>()    // slashed (bitset)
                + size_of::<[B256; EPOCHS_PER_HISTORICAL_VECTOR]>()
                + size_of::<[u64; EPOCHS_PER_SLASHINGS_VECTOR]>()
    );

    assert!(size_of::<SlotRoots>() == 2 * size_of::<[B256; SLOTS_PER_HISTORICAL_ROOT]>());

    // Wire-mirror fixed-size containers: struct layout exactly equals the
    // SSZ serialized size (no compiler padding). decompose.rs's *_SSZ_SIZE
    // constants depend on these values matching the spec.
    assert!(size_of::<Eth1Data>() == 72);
    assert!(size_of::<BeaconBlockHeader>() == 112);
    assert!(size_of::<SyncCommittee>() == SYNC_COMMITTEE_SIZE * 48 + 48); // 24624
    assert!(size_of::<HistoricalSummary>() == 64);
    assert!(size_of::<PendingDeposit>() == 192);
    assert!(size_of::<PendingPartialWithdrawal>() == 24);
    assert!(size_of::<PendingConsolidation>() == 16);

    // ExecutionPayloadHeader: 584 B of field data + 4 B align pad before
    // `block_number` + 7 B align pad before `blob_gas_used` = 624 B total.
    assert!(size_of::<ExecutionPayloadHeader>() == 624);

    // SlotData layout: the only non-trivial padding is 7 B between
    // `justification_bits` (u8) and `previous_justified_checkpoint`
    // (align 8). All other transitions are already 8-aligned.
    assert!(
        size_of::<SlotData>() ==
            size_of::<[u64; MAX_VALIDATORS]>()
                + 2 * size_of::<[u8; MAX_VALIDATORS]>()
                + size_of::<B256>()
                + size_of::<Eth1Data>()
                + size_of::<ArrayVec<Eth1Data, MAX_ETH1_VOTES>>()
                + size_of::<[u64; 2]>()                // eth1_deposit_index, slot
                + size_of::<BeaconBlockHeader>()
                + 8                                    // justification_bits (u8) + 7 align pad
                + 3 * size_of::<Checkpoint>()
                + size_of::<ExecutionPayloadHeader>()
                + size_of::<[u64; 8]>()                // 8 trailing scalars
                + size_of::<[u64; PROPOSER_LOOKAHEAD_SIZE]>()
    );

    // `decompose.rs` casts &[u8] to &[B256] via from_raw_parts; that's
    // only sound while B256 has byte alignment.
    assert!(align_of::<B256>() == 1);
};
