pub const PRESET_BASE: &str = "minimal";

// phase0
pub const MAX_COMMITTEES_PER_SLOT: usize = 4;
pub const TARGET_COMMITTEE_SIZE: usize = 4;
pub const SHUFFLE_ROUND_COUNT: u8 = 10;
pub const SLOTS_PER_EPOCH: u64 = 8;
pub const EPOCHS_PER_ETH1_VOTING_PERIOD: u64 = 4;
pub const SLOTS_PER_HISTORICAL_ROOT: usize = 64;
pub const EPOCHS_PER_HISTORICAL_VECTOR: usize = 64;
pub const EPOCHS_PER_SLASHINGS_VECTOR: usize = 64;
pub const INACTIVITY_PENALTY_QUOTIENT: u64 = 1 << 25;
pub const MIN_SLASHING_PENALTY_QUOTIENT: u64 = 64;
pub const PROPORTIONAL_SLASHING_MULTIPLIER: u64 = 2;

// altair
pub const SYNC_COMMITTEE_SIZE: usize = 32;
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 8;
pub const UPDATE_TIMEOUT: u64 = 64;

// capella
pub const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 4;
pub const MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP: u64 = 16;

// electra
pub const PENDING_PARTIAL_WITHDRAWALS_LIMIT: usize = 64;
pub const PENDING_CONSOLIDATIONS_LIMIT: usize = 64;
pub const MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP: usize = 2;

// gloas
pub const MAX_SIGNED_AGGREGATE_AND_PROOF_SIZE: usize = 1_462;
pub const MAX_ATTESTER_SLASHING_SIZE: usize = 131_536;
pub const PTC_SIZE: usize = 16;
pub const MAX_BUILDERS_PER_WITHDRAWALS_SWEEP: u64 = 16;
