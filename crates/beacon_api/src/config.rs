//! Every value the spec calls a preset is a constant here, because silver
//! runs the mainnet preset only; every config-file key a network can vary
//! comes from [`SpecConfig`] — including the genesis, merge and eth1
//! parameters silver itself never reads. What is left are the fork-choice and
//! networking parameters silver fixes in its own tiles.

use silver_beacon_state_data::{
    BYTES_PER_LOGS_BLOOM, EFFECTIVE_BALANCE_INCREMENT, EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR, EPOCHS_PER_SYNC_COMMITTEE_PERIOD, FAR_FUTURE_EPOCH, Fork,
    ForkName, HISTORICAL_ROOTS_LIMIT, MAX_EXTRA_DATA_BYTES, MIN_SEED_LOOKAHEAD,
    PENDING_CONSOLIDATIONS_LIMIT, PENDING_DEPOSITS_LIMIT, PENDING_PARTIAL_WITHDRAWALS_LIMIT,
    SLOTS_PER_EPOCH, SLOTS_PER_HISTORICAL_ROOT, SYNC_COMMITTEE_SIZE, SpecConfig,
    VALIDATOR_REGISTRY_LIMIT,
};
use silver_common::{
    EPOCHS_PER_SUBNET_SUBSCRIPTION, NUMBER_OF_CUSTODY_GROUPS, SAMPLES_PER_SLOT, SUBNETS_PER_NODE,
    ssz_view::{
        MAX_BLOB_COMMITMENTS_PER_BLOCK, MAX_COMMITTEES_PER_SLOT, MAX_PAYLOAD_SIZE,
        MAX_REQUEST_BLOCKS_DENEB, MAX_VALIDATORS_PER_COMMITTEE, NUMBER_OF_COLUMNS,
    },
    ticker::MAXIMUM_GOSSIP_CLOCK_DISPARITY,
};

use crate::json::Json;

const PRESET_BASE: &str = "mainnet";

/// `presets/mainnet/*.yaml` (consensus-specs v1.6.0), in fork order. Values
/// silver itself computes with are imported rather than respelled.
const PRESET: &[(&str, u64)] = &[
    // phase0.yaml
    ("MAX_COMMITTEES_PER_SLOT", MAX_COMMITTEES_PER_SLOT as u64),
    ("TARGET_COMMITTEE_SIZE", 128),
    ("MAX_VALIDATORS_PER_COMMITTEE", MAX_VALIDATORS_PER_COMMITTEE as u64),
    ("SHUFFLE_ROUND_COUNT", 90),
    ("HYSTERESIS_QUOTIENT", 4),
    ("HYSTERESIS_DOWNWARD_MULTIPLIER", 1),
    ("HYSTERESIS_UPWARD_MULTIPLIER", 5),
    ("MIN_DEPOSIT_AMOUNT", 1_000_000_000),
    ("MAX_EFFECTIVE_BALANCE", 32_000_000_000),
    ("EFFECTIVE_BALANCE_INCREMENT", EFFECTIVE_BALANCE_INCREMENT),
    ("MIN_ATTESTATION_INCLUSION_DELAY", 1),
    ("SLOTS_PER_EPOCH", SLOTS_PER_EPOCH),
    ("MIN_SEED_LOOKAHEAD", MIN_SEED_LOOKAHEAD),
    ("EPOCHS_PER_ETH1_VOTING_PERIOD", 64),
    ("SLOTS_PER_HISTORICAL_ROOT", SLOTS_PER_HISTORICAL_ROOT as u64),
    ("EPOCHS_PER_HISTORICAL_VECTOR", EPOCHS_PER_HISTORICAL_VECTOR as u64),
    ("EPOCHS_PER_SLASHINGS_VECTOR", EPOCHS_PER_SLASHINGS_VECTOR as u64),
    ("HISTORICAL_ROOTS_LIMIT", HISTORICAL_ROOTS_LIMIT as u64),
    ("VALIDATOR_REGISTRY_LIMIT", VALIDATOR_REGISTRY_LIMIT as u64),
    ("BASE_REWARD_FACTOR", 64),
    ("WHISTLEBLOWER_REWARD_QUOTIENT", 512),
    ("PROPOSER_REWARD_QUOTIENT", 8),
    ("INACTIVITY_PENALTY_QUOTIENT", 67_108_864),
    ("MIN_SLASHING_PENALTY_QUOTIENT", 128),
    ("PROPORTIONAL_SLASHING_MULTIPLIER", 1),
    ("MAX_PROPOSER_SLASHINGS", 16),
    ("MAX_ATTESTER_SLASHINGS", 2),
    ("MAX_ATTESTATIONS", 128),
    ("MAX_DEPOSITS", 16),
    ("MAX_VOLUNTARY_EXITS", 16),
    // altair.yaml
    ("INACTIVITY_PENALTY_QUOTIENT_ALTAIR", 50_331_648),
    ("MIN_SLASHING_PENALTY_QUOTIENT_ALTAIR", 64),
    ("PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR", 2),
    ("SYNC_COMMITTEE_SIZE", SYNC_COMMITTEE_SIZE as u64),
    ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", EPOCHS_PER_SYNC_COMMITTEE_PERIOD),
    ("MIN_SYNC_COMMITTEE_PARTICIPANTS", 1),
    ("UPDATE_TIMEOUT", 8192),
    // bellatrix.yaml
    ("MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX", 32),
    ("MAX_BYTES_PER_TRANSACTION", 1_073_741_824),
    ("MAX_TRANSACTIONS_PER_PAYLOAD", 1_048_576),
    ("BYTES_PER_LOGS_BLOOM", BYTES_PER_LOGS_BLOOM as u64),
    ("MAX_EXTRA_DATA_BYTES", MAX_EXTRA_DATA_BYTES as u64),
    // capella.yaml
    ("MAX_BLS_TO_EXECUTION_CHANGES", 16),
    ("MAX_WITHDRAWALS_PER_PAYLOAD", 16),
    ("MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP", 16_384),
    // deneb.yaml
    ("FIELD_ELEMENTS_PER_BLOB", 4096),
    ("MAX_BLOB_COMMITMENTS_PER_BLOCK", MAX_BLOB_COMMITMENTS_PER_BLOCK as u64),
    ("KZG_COMMITMENT_INCLUSION_PROOF_DEPTH", 17),
    // electra.yaml
    ("MIN_ACTIVATION_BALANCE", 32_000_000_000),
    ("MAX_EFFECTIVE_BALANCE_ELECTRA", 2_048_000_000_000),
    ("WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA", 4096),
    ("PENDING_DEPOSITS_LIMIT", PENDING_DEPOSITS_LIMIT as u64),
    ("PENDING_PARTIAL_WITHDRAWALS_LIMIT", PENDING_PARTIAL_WITHDRAWALS_LIMIT as u64),
    ("PENDING_CONSOLIDATIONS_LIMIT", PENDING_CONSOLIDATIONS_LIMIT as u64),
    ("MAX_ATTESTER_SLASHINGS_ELECTRA", 1),
    ("MAX_ATTESTATIONS_ELECTRA", 8),
    ("MAX_DEPOSIT_REQUESTS_PER_PAYLOAD", 8192),
    ("MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD", 16),
    ("MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD", 2),
    ("MAX_PENDING_PARTIALS_PER_WITHDRAWALS_SWEEP", 8),
    ("MAX_PENDING_DEPOSITS_PER_EPOCH", 16),
    // fulu.yaml
    ("FIELD_ELEMENTS_PER_CELL", 64),
    ("FIELD_ELEMENTS_PER_EXT_BLOB", 8192),
    ("KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH", 4),
    ("CELLS_PER_EXT_BLOB", 128),
    ("NUMBER_OF_COLUMNS", NUMBER_OF_COLUMNS as u64),
];

/// Spec constants — the values no config file carries because no network may
/// change them. A validator client reads its aggregator thresholds and
/// subnet counts from here.
const CONSTANTS: &[(&str, u64)] = &[
    ("GENESIS_SLOT", 0),
    ("FAR_FUTURE_EPOCH", FAR_FUTURE_EPOCH),
    ("BASE_REWARDS_PER_EPOCH", 4),
    ("DEPOSIT_CONTRACT_TREE_DEPTH", 32),
    ("JUSTIFICATION_BITS_LENGTH", 4),
    ("TARGET_AGGREGATORS_PER_COMMITTEE", 16),
    ("TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE", 16),
    ("SYNC_COMMITTEE_SUBNET_COUNT", 4),
    ("TIMELY_SOURCE_FLAG_INDEX", 0),
    ("TIMELY_TARGET_FLAG_INDEX", 1),
    ("TIMELY_HEAD_FLAG_INDEX", 2),
    ("TIMELY_SOURCE_WEIGHT", 14),
    ("TIMELY_TARGET_WEIGHT", 26),
    ("TIMELY_HEAD_WEIGHT", 14),
    ("SYNC_REWARD_WEIGHT", 2),
    ("PROPOSER_WEIGHT", 8),
    ("WEIGHT_DENOMINATOR", 64),
    ("UNSET_DEPOSIT_REQUESTS_START_INDEX", FAR_FUTURE_EPOCH),
    ("FULL_EXIT_REQUEST_AMOUNT", 0),
];

/// Four-byte constants: the signing-domain types a validator client mixes
/// into its own domains, and the two gossip message-id domains.
const BYTES4_CONSTANTS: &[(&str, [u8; 4])] = &[
    ("DOMAIN_BEACON_PROPOSER", [0x00, 0x00, 0x00, 0x00]),
    ("DOMAIN_BEACON_ATTESTER", [0x01, 0x00, 0x00, 0x00]),
    ("DOMAIN_RANDAO", [0x02, 0x00, 0x00, 0x00]),
    ("DOMAIN_DEPOSIT", [0x03, 0x00, 0x00, 0x00]),
    ("DOMAIN_VOLUNTARY_EXIT", [0x04, 0x00, 0x00, 0x00]),
    ("DOMAIN_SELECTION_PROOF", [0x05, 0x00, 0x00, 0x00]),
    ("DOMAIN_AGGREGATE_AND_PROOF", [0x06, 0x00, 0x00, 0x00]),
    ("DOMAIN_SYNC_COMMITTEE", [0x07, 0x00, 0x00, 0x00]),
    ("DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF", [0x08, 0x00, 0x00, 0x00]),
    ("DOMAIN_CONTRIBUTION_AND_PROOF", [0x09, 0x00, 0x00, 0x00]),
    ("DOMAIN_BLS_TO_EXECUTION_CHANGE", [0x0a, 0x00, 0x00, 0x00]),
    ("DOMAIN_APPLICATION_BUILDER", [0x00, 0x00, 0x00, 0x01]),
    ("DOMAIN_PTC_ATTESTER", [0x0c, 0x00, 0x00, 0x00]),
    ("MESSAGE_DOMAIN_INVALID_SNAPPY", [0x00, 0x00, 0x00, 0x00]),
    ("MESSAGE_DOMAIN_VALID_SNAPPY", [0x01, 0x00, 0x00, 0x00]),
];

/// One-byte withdrawal-credential prefixes.
const BYTE_CONSTANTS: &[(&str, [u8; 1])] = &[
    ("BLS_WITHDRAWAL_PREFIX", [0x00]),
    ("ETH1_ADDRESS_WITHDRAWAL_PREFIX", [0x01]),
    ("COMPOUNDING_WITHDRAWAL_PREFIX", [0x02]),
];

/// Config keys a fork retired. Silver keeps one scalar per quantity and
/// serves it under the successor's name from [`configured`]; the retired
/// spelling is frozen at the value it had, since no network silver can join
/// is on the wrong side of the fork that replaced it.
const SUPERSEDED_CONFIG: &[(&str, u64)] = &[
    ("MIN_PER_EPOCH_CHURN_LIMIT", 4),
    ("MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT", 8),
    ("MAX_BLOBS_PER_BLOCK", 6),
];

/// Fork-choice, slot-timing and networking parameters. No config file silver
/// has seen varies them, so the ones silver acts on live as constants of the
/// tile that acts on them (`SlotTicker`'s attesting-interval divisors are the
/// `*_DUE_BPS` deadlines) and the rest are published for clients only.
const NETWORK_CONFIG: &[(&str, u64)] = &[
    ("PROPOSER_SCORE_BOOST", 40),
    ("REORG_HEAD_WEIGHT_THRESHOLD", 20),
    ("REORG_PARENT_WEIGHT_THRESHOLD", 160),
    ("REORG_MAX_EPOCHS_SINCE_FINALIZATION", 2),
    ("PROPOSER_REORG_CUTOFF_BPS", 1667),
    ("ATTESTATION_DUE_BPS", 3333),
    ("AGGREGATE_DUE_BPS", 6667),
    ("SYNC_MESSAGE_DUE_BPS", 3333),
    ("CONTRIBUTION_DUE_BPS", 6667),
    ("ATTESTATION_DUE_BPS_GLOAS", 2500),
    ("AGGREGATE_DUE_BPS_GLOAS", 5000),
    ("SYNC_MESSAGE_DUE_BPS_GLOAS", 2500),
    ("CONTRIBUTION_DUE_BPS_GLOAS", 5000),
    ("PAYLOAD_ATTESTATION_DUE_BPS", 7500),
    ("VIEW_FREEZE_CUTOFF_BPS", 7500),
    ("INCLUSION_LIST_SUBMISSION_DUE_BPS", 6667),
    ("PROPOSER_INCLUSION_LIST_CUTOFF_BPS", 9167),
    ("MAX_PAYLOAD_SIZE", MAX_PAYLOAD_SIZE as u64),
    ("MAX_REQUEST_BLOCKS", 1024),
    ("MAX_REQUEST_BLOCKS_DENEB", MAX_REQUEST_BLOCKS_DENEB as u64),
    ("EPOCHS_PER_SUBNET_SUBSCRIPTION", EPOCHS_PER_SUBNET_SUBSCRIPTION),
    ("MIN_EPOCHS_FOR_BLOCK_REQUESTS", 33_024),
    ("ATTESTATION_PROPAGATION_SLOT_RANGE", 32),
    ("MAXIMUM_GOSSIP_CLOCK_DISPARITY", MAXIMUM_GOSSIP_CLOCK_DISPARITY.as_millis() as u64),
    ("SUBNETS_PER_NODE", SUBNETS_PER_NODE as u64),
    ("ATTESTATION_SUBNET_COUNT", 64),
    ("ATTESTATION_SUBNET_EXTRA_BITS", 0),
    ("ATTESTATION_SUBNET_PREFIX_BITS", 6),
    ("NUMBER_OF_CUSTODY_GROUPS", NUMBER_OF_CUSTODY_GROUPS as u64),
    ("DATA_COLUMN_SIDECAR_SUBNET_COUNT", 128),
    ("MAX_REQUEST_DATA_COLUMN_SIDECARS", 16_384),
    ("SAMPLES_PER_SLOT", SAMPLES_PER_SLOT as u64),
    ("CUSTODY_REQUIREMENT", 4),
    ("VALIDATOR_CUSTODY_REQUIREMENT", 8),
    ("BALANCE_PER_ADDITIONAL_CUSTODY_GROUP", 32_000_000_000),
    ("MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS", 4096),
    // gloas.yaml
    ("MAX_REQUEST_PAYLOADS", 128),
    // EIP7441
    ("EPOCHS_PER_SHUFFLING_PHASE", 256),
    ("PROPOSER_SELECTION_GAP", 2),
    // EIP7805
    ("MAX_REQUEST_INCLUSION_LIST", 16),
    ("MAX_BYTES_PER_INCLUSION_LIST", 8192),
];

/// `*_FORK_VERSION` stubs the spec mints for EIPs no fork has scheduled.
/// Literals rather than [`SpecConfig`] fields: a network cannot schedule a
/// fork that does not exist, so every config file carries the same stub
/// version and a `FAR_FUTURE_EPOCH` activation.
const EIP_FORK_STUB_VERSIONS: &[(&str, [u8; 4])] = &[
    ("EIP7441_FORK_VERSION", [0x08, 0x00, 0x00, 0x00]),
    ("EIP7805_FORK_VERSION", [0x0a, 0x00, 0x00, 0x00]),
    ("EIP7928_FORK_VERSION", [0x0b, 0x00, 0x00, 0x00]),
];

const EIP_FORK_STUB_EPOCHS: &[(&str, u64)] = &[
    ("EIP7441_FORK_EPOCH", FAR_FUTURE_EPOCH),
    ("EIP7805_FORK_EPOCH", FAR_FUTURE_EPOCH),
    ("EIP7928_FORK_EPOCH", FAR_FUTURE_EPOCH),
];

/// `GET /eth/v1/config/spec`.
pub(crate) fn spec_body(spec: &SpecConfig) -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_object();

    json.key("PRESET_BASE");
    json.string(PRESET_BASE);
    json.key("CONFIG_NAME");
    json.string(&spec.network_name());

    for fork in ForkName::ALL {
        json.key(fork_version_key(fork));
        json.hex(&spec.fork_version(fork));
        json.key(fork_epoch_key(fork));
        json.quoted_u64(spec.fork_epoch(fork));
    }

    for (name, value) in configured(spec) {
        json.key(name);
        json.quoted_u64(value);
    }
    json.key("DEPOSIT_CONTRACT_ADDRESS");
    json.hex(&spec.deposit_contract_address);
    json.key("TERMINAL_TOTAL_DIFFICULTY");
    json.string(&spec.terminal_total_difficulty.to_string());
    json.key("TERMINAL_BLOCK_HASH");
    json.hex(&spec.terminal_block_hash);

    for (name, value) in SUPERSEDED_CONFIG
        .iter()
        .chain(EIP_FORK_STUB_EPOCHS)
        .chain(NETWORK_CONFIG)
        .chain(PRESET)
        .chain(CONSTANTS)
    {
        json.key(name);
        json.quoted_u64(*value);
    }
    for (name, bytes) in BYTES4_CONSTANTS.iter().chain(EIP_FORK_STUB_VERSIONS) {
        json.key(name);
        json.hex(bytes);
    }
    for (name, bytes) in BYTE_CONSTANTS {
        json.key(name);
        json.hex(bytes);
    }

    json.key("BLOB_SCHEDULE");
    json.begin_array();
    for entry in &spec.blob_schedule {
        json.begin_object();
        json.key("EPOCH");
        json.quoted_u64(entry.epoch);
        json.key("MAX_BLOBS_PER_BLOCK");
        json.quoted_u64(entry.max_blobs_per_block);
        json.end_object();
    }
    json.end_array();

    json.end_object();
    json.end_object();
    out
}

/// `GET /eth/v1/config/fork_schedule`. Unscheduled forks are omitted: the
/// list is what this node is aware of *scheduling*, and a client that
/// derives a signing domain from the last entry must not land on a fork
/// that will never activate.
pub(crate) fn fork_schedule_body(spec: &SpecConfig) -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_array();
    let mut previous_version = spec.fork_version(ForkName::Phase0);
    for fork in ForkName::ALL {
        let epoch = spec.fork_epoch(fork);
        if epoch == FAR_FUTURE_EPOCH {
            continue;
        }
        let current_version = spec.fork_version(fork);
        json.fork(&Fork { previous_version, current_version, epoch });
        previous_version = current_version;
    }
    json.end_array();
    json.end_object();
    out
}

/// `GET /eth/v1/config/deposit_contract`.
pub(crate) fn deposit_contract_body(spec: &SpecConfig) -> Vec<u8> {
    let mut out = Vec::new();
    let mut json = Json::new(&mut out);
    json.begin_object();
    json.key("data");
    json.begin_object();
    json.key("chain_id");
    json.quoted_u64(spec.deposit_chain_id);
    json.key("address");
    json.hex(&spec.deposit_contract_address);
    json.end_object();
    json.end_object();
    out
}

/// The `SpecConfig` fields under their spec names. Several carry a fork suffix
/// silver's own scalar does not, because it runs only the latest fork's
/// variant of that quantity; the retired spellings are in
/// [`SUPERSEDED_CONFIG`] and [`PRESET`].
fn configured(spec: &SpecConfig) -> impl IntoIterator<Item = (&'static str, u64)> {
    [
        ("MIN_GENESIS_ACTIVE_VALIDATOR_COUNT", spec.min_genesis_active_validator_count),
        ("MIN_GENESIS_TIME", spec.min_genesis_time),
        ("GENESIS_DELAY", spec.genesis_delay),
        ("TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH", spec.terminal_block_hash_activation_epoch),
        ("SECONDS_PER_SLOT", spec.seconds_per_slot()),
        // Teku and Nimbus reject a body whose two spellings of the slot length
        // disagree, so this is derived rather than a mainnet literal.
        ("SLOT_DURATION_MS", spec.slot_duration_ms()),
        ("SECONDS_PER_ETH1_BLOCK", spec.seconds_per_eth1_block),
        ("ETH1_FOLLOW_DISTANCE", spec.eth1_follow_distance),
        ("SHARD_COMMITTEE_PERIOD", spec.shard_committee_period),
        ("MIN_VALIDATOR_WITHDRAWABILITY_DELAY", spec.min_validator_withdrawability_delay),
        ("MAX_SEED_LOOKAHEAD", spec.max_seed_lookahead),
        ("MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA", spec.min_per_epoch_churn_limit),
        (
            "MAX_PER_EPOCH_ACTIVATION_EXIT_CHURN_LIMIT",
            spec.max_per_epoch_activation_exit_churn_limit,
        ),
        ("CHURN_LIMIT_QUOTIENT", spec.churn_limit_quotient),
        ("CHURN_LIMIT_QUOTIENT_GLOAS", spec.churn_limit_quotient_gloas),
        ("CONSOLIDATION_CHURN_LIMIT_QUOTIENT", spec.consolidation_churn_limit_quotient),
        (
            "MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT_GLOAS",
            spec.max_per_epoch_activation_churn_limit_gloas,
        ),
        ("INACTIVITY_SCORE_BIAS", spec.inactivity_score_bias),
        ("INACTIVITY_SCORE_RECOVERY_RATE", spec.inactivity_score_recovery_rate),
        ("INACTIVITY_PENALTY_QUOTIENT_BELLATRIX", spec.inactivity_penalty_quotient),
        ("MIN_EPOCHS_TO_INACTIVITY_PENALTY", spec.min_epochs_to_inactivity_penalty),
        ("PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX", spec.proportional_slashing_multiplier),
        ("MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA", spec.min_slashing_penalty_quotient),
        ("EJECTION_BALANCE", spec.ejection_balance),
        ("MAX_BLOBS_PER_BLOCK_ELECTRA", spec.max_blobs_per_block_electra),
        ("BLOB_SIDECAR_SUBNET_COUNT", spec.blob_sidecar_subnet_count),
        ("BLOB_SIDECAR_SUBNET_COUNT_ELECTRA", spec.blob_sidecar_subnet_count_electra),
        ("MAX_REQUEST_BLOB_SIDECARS", spec.max_request_blob_sidecars),
        ("MAX_REQUEST_BLOB_SIDECARS_ELECTRA", spec.max_request_blob_sidecars_electra),
        ("MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS", spec.min_epochs_for_blob_sidecars_requests),
        ("DEPOSIT_CHAIN_ID", spec.deposit_chain_id),
        ("DEPOSIT_NETWORK_ID", spec.deposit_network_id),
    ]
}

fn fork_version_key(fork: ForkName) -> &'static str {
    match fork {
        ForkName::Phase0 => "GENESIS_FORK_VERSION",
        ForkName::Altair => "ALTAIR_FORK_VERSION",
        ForkName::Bellatrix => "BELLATRIX_FORK_VERSION",
        ForkName::Capella => "CAPELLA_FORK_VERSION",
        ForkName::Deneb => "DENEB_FORK_VERSION",
        ForkName::Electra => "ELECTRA_FORK_VERSION",
        ForkName::Fulu => "FULU_FORK_VERSION",
        ForkName::Gloas => "GLOAS_FORK_VERSION",
    }
}

fn fork_epoch_key(fork: ForkName) -> &'static str {
    match fork {
        ForkName::Phase0 => "GENESIS_EPOCH",
        ForkName::Altair => "ALTAIR_FORK_EPOCH",
        ForkName::Bellatrix => "BELLATRIX_FORK_EPOCH",
        ForkName::Capella => "CAPELLA_FORK_EPOCH",
        ForkName::Deneb => "DENEB_FORK_EPOCH",
        ForkName::Electra => "ELECTRA_FORK_EPOCH",
        ForkName::Fulu => "FULU_FORK_EPOCH",
        ForkName::Gloas => "GLOAS_FORK_EPOCH",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value};

    use super::*;

    fn data(body: &[u8]) -> Value {
        serde_json::from_slice::<Value>(body).expect("valid JSON")["data"].clone()
    }

    fn spec_map(spec: &SpecConfig) -> Map<String, Value> {
        data(&spec_body(spec)).as_object().unwrap().clone()
    }

    /// The two rules the endpoint's description states: every numeric value
    /// is a quoted decimal, every `0x` value a hex string. Hex is lowercase
    /// because a client comparing an address against its own config compares
    /// strings.
    #[test]
    fn every_spec_value_is_a_quoted_decimal_or_lowercase_hex_string() {
        for (name, value) in spec_map(&SpecConfig::mainnet()) {
            if name == "BLOB_SCHEDULE" {
                continue;
            }
            let text = value.as_str().unwrap_or_else(|| panic!("{name} is not a string"));
            match text.strip_prefix("0x") {
                Some(digits) => {
                    assert!(!digits.is_empty(), "{name}");
                    assert!(
                        digits.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                        "{name} = {text}"
                    );
                    assert!(digits.len().is_multiple_of(2), "{name} = {text}");
                }
                None if name == "PRESET_BASE" || name == "CONFIG_NAME" => {
                    assert_eq!(text, "mainnet")
                }
                None => assert!(text.bytes().all(|b| b.is_ascii_digit()), "{name} = {text}"),
            }
        }
    }

    /// A repeated key is well-formed JSON that silently drops one of the two
    /// values, so a parsed body cannot catch it — count the raw text. Only
    /// the flat part is searched: `BLOB_SCHEDULE`, written last, repeats
    /// `MAX_BLOBS_PER_BLOCK` inside every entry.
    #[test]
    fn no_key_is_written_twice() {
        let body = String::from_utf8(spec_body(&SpecConfig::mainnet())).unwrap();
        let flat = &body[..body.find("\"BLOB_SCHEDULE\":").unwrap()];
        for name in spec_map(&SpecConfig::mainnet()).keys() {
            if name == "BLOB_SCHEDULE" {
                continue;
            }
            assert_eq!(flat.matches(&format!("\"{name}\":")).count(), 1, "{name}");
        }
    }

    /// Vouch derives signing domains, aggregator thresholds and the sync
    /// committee period from this body; Teku and Lighthouse compare the fork
    /// versions and deposit contract against their own config.
    #[test]
    fn the_keys_validator_clients_read_are_all_present() {
        let spec = spec_map(&SpecConfig::mainnet());
        for name in [
            "PRESET_BASE",
            "SECONDS_PER_SLOT",
            "SLOTS_PER_EPOCH",
            "SYNC_COMMITTEE_SIZE",
            "EPOCHS_PER_SYNC_COMMITTEE_PERIOD",
            "SYNC_COMMITTEE_SUBNET_COUNT",
            "TARGET_AGGREGATORS_PER_COMMITTEE",
            "TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE",
            "TARGET_COMMITTEE_SIZE",
            "MAX_COMMITTEES_PER_SLOT",
            "MAX_VALIDATORS_PER_COMMITTEE",
            "MIN_ATTESTATION_INCLUSION_DELAY",
            "MAX_EFFECTIVE_BALANCE",
            "MIN_ACTIVATION_BALANCE",
            "GENESIS_FORK_VERSION",
            "ALTAIR_FORK_VERSION",
            "FULU_FORK_EPOCH",
            "GLOAS_FORK_EPOCH",
            "DEPOSIT_CHAIN_ID",
            "DEPOSIT_NETWORK_ID",
            "DEPOSIT_CONTRACT_ADDRESS",
            "DOMAIN_BEACON_PROPOSER",
            "DOMAIN_BEACON_ATTESTER",
            "DOMAIN_RANDAO",
            "DOMAIN_SELECTION_PROOF",
            "DOMAIN_AGGREGATE_AND_PROOF",
            "DOMAIN_SYNC_COMMITTEE",
            "DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF",
            "DOMAIN_CONTRIBUTION_AND_PROOF",
            "DOMAIN_APPLICATION_BUILDER",
            "BLS_WITHDRAWAL_PREFIX",
            "FAR_FUTURE_EPOCH",
            "BLOB_SCHEDULE",
        ] {
            assert!(spec.contains_key(name), "missing {name}");
        }
    }

    /// Values transcribed from `consensus-specs` v1.6.0
    /// `configs/mainnet.yaml`. Hoodi carries no key of its own for any of
    /// them, so they are network-invariant literals — except
    /// `SLOT_DURATION_MS`, which is derived, because a client that also reads
    /// `SECONDS_PER_SLOT` rejects a body where the two disagree.
    #[test]
    fn the_config_file_keys_silver_serves_as_literals_match_v1_6_0_mainnet() {
        let spec = spec_map(&SpecConfig::mainnet());
        for (name, value) in [
            ("SLOT_DURATION_MS", "12000"),
            ("PROPOSER_REORG_CUTOFF_BPS", "1667"),
            ("ATTESTATION_DUE_BPS", "3333"),
            ("AGGREGATE_DUE_BPS", "6667"),
            ("SYNC_MESSAGE_DUE_BPS", "3333"),
            ("CONTRIBUTION_DUE_BPS", "6667"),
            ("ATTESTATION_DUE_BPS_GLOAS", "2500"),
            ("AGGREGATE_DUE_BPS_GLOAS", "5000"),
            ("SYNC_MESSAGE_DUE_BPS_GLOAS", "2500"),
            ("CONTRIBUTION_DUE_BPS_GLOAS", "5000"),
            ("PAYLOAD_ATTESTATION_DUE_BPS", "7500"),
            ("VIEW_FREEZE_CUTOFF_BPS", "7500"),
            ("INCLUSION_LIST_SUBMISSION_DUE_BPS", "6667"),
            ("PROPOSER_INCLUSION_LIST_CUTOFF_BPS", "9167"),
            ("MAX_REQUEST_PAYLOADS", "128"),
            ("EPOCHS_PER_SHUFFLING_PHASE", "256"),
            ("PROPOSER_SELECTION_GAP", "2"),
            ("MAX_REQUEST_INCLUSION_LIST", "16"),
            ("MAX_BYTES_PER_INCLUSION_LIST", "8192"),
            ("EIP7441_FORK_VERSION", "0x08000000"),
            ("EIP7441_FORK_EPOCH", "18446744073709551615"),
            ("EIP7805_FORK_VERSION", "0x0a000000"),
            ("EIP7805_FORK_EPOCH", "18446744073709551615"),
            ("EIP7928_FORK_VERSION", "0x0b000000"),
            ("EIP7928_FORK_EPOCH", "18446744073709551615"),
            ("MIN_PER_EPOCH_CHURN_LIMIT", "4"),
            ("MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT", "8"),
            ("MAX_BLOBS_PER_BLOCK", "6"),
        ] {
            assert_eq!(spec.get(name).map(Value::as_str), Some(Some(value)), "{name}");
        }
    }

    /// `SlotTicker` splits the slot at 1/3 pre-Gloas and 1/4 from Gloas, which
    /// is what `ATTESTATION_DUE_BPS` and its Gloas variant name; a client that
    /// times its attestations off the served body must not disagree with the
    /// node it is attesting through.
    #[test]
    fn the_attestation_deadlines_served_match_the_ones_silver_ticks_on() {
        let spec = spec_map(&SpecConfig::mainnet());
        assert_eq!(spec["ATTESTATION_DUE_BPS"], (10_000 / 3).to_string());
        assert_eq!(spec["ATTESTATION_DUE_BPS_GLOAS"], (10_000 / 4).to_string());
    }

    /// Two spellings of the slot length in one body: a client that reads both
    /// aborts unless they agree, and `SECONDS_PER_SLOT` is overridable.
    #[test]
    fn slot_duration_ms_follows_an_overridden_seconds_per_slot() {
        let spec = spec_map(&SpecConfig { seconds_per_slot: Some(4), ..SpecConfig::mainnet() });
        assert_eq!(spec["SECONDS_PER_SLOT"], "4");
        assert_eq!(spec["SLOT_DURATION_MS"], "4000");
    }

    /// Teku's `--network auto` preloads a builtin base config by
    /// `CONFIG_NAME` while signing domains come from the fork versions, so a
    /// body contradicting itself hands the client two different networks.
    #[test]
    fn config_name_is_the_network_the_fork_version_names() {
        let sepolia =
            SpecConfig { genesis_fork_version: [0x90, 0x00, 0x00, 0x69], ..SpecConfig::mainnet() };
        assert_eq!(spec_map(&sepolia)["CONFIG_NAME"], "sepolia");

        let devnet =
            SpecConfig { genesis_fork_version: [0x10, 0x00, 0x00, 0x38], ..SpecConfig::mainnet() };
        assert_eq!(spec_map(&devnet)["CONFIG_NAME"], devnet.network_name());
        assert_eq!(spec_map(&devnet)["CONFIG_NAME"], "devnet-10000038");

        let named = SpecConfig { config_name: Some("my-devnet".to_owned()), ..devnet };
        assert_eq!(spec_map(&named)["CONFIG_NAME"], "my-devnet");
    }

    #[test]
    fn spec_values_track_the_config_this_node_runs() {
        let hoodi = spec_map(&SpecConfig::hoodi());
        assert_eq!(hoodi["CONFIG_NAME"], "hoodi");
        assert_eq!(hoodi["GENESIS_FORK_VERSION"], "0x10000910");
        assert_eq!(hoodi["FULU_FORK_VERSION"], "0x70000910");
        assert_eq!(hoodi["FULU_FORK_EPOCH"], "50688");
        assert_eq!(hoodi["ELECTRA_FORK_EPOCH"], "2048");
        assert_eq!(hoodi["DEPOSIT_CHAIN_ID"], "560048");
        assert_eq!(hoodi["DEPOSIT_NETWORK_ID"], "560048");
        assert_eq!(hoodi["MIN_GENESIS_TIME"], "1742212800");
        assert_eq!(hoodi["GENESIS_DELAY"], "600");
        assert_eq!(hoodi["SECONDS_PER_ETH1_BLOCK"], "12");
        assert_eq!(hoodi["TERMINAL_TOTAL_DIFFICULTY"], "0", "Hoodi merged at genesis");
        assert_eq!(hoodi["BLOB_SCHEDULE"].as_array().unwrap().len(), 2);
        assert_eq!(hoodi["BLOB_SCHEDULE"][0]["EPOCH"], "52480");
        assert_eq!(hoodi["BLOB_SCHEDULE"][0]["MAX_BLOBS_PER_BLOCK"], "15");
        assert_eq!(hoodi["BLOB_SCHEDULE"][1]["EPOCH"], "54016");
        assert_eq!(hoodi["BLOB_SCHEDULE"][1]["MAX_BLOBS_PER_BLOCK"], "21");

        let mainnet = spec_map(&SpecConfig::mainnet());
        assert_eq!(mainnet["CONFIG_NAME"], "mainnet");
        assert_eq!(
            mainnet["DEPOSIT_CONTRACT_ADDRESS"],
            "0x00000000219ab540356cbb839cbe05303d7705fa"
        );
        assert_eq!(mainnet["GLOAS_FORK_EPOCH"], "18446744073709551615", "unscheduled");
        assert_eq!(mainnet["MAX_BLOBS_PER_BLOCK_ELECTRA"], "9");
        assert_eq!(mainnet["MIN_GENESIS_TIME"], "1606824000");
        assert_eq!(mainnet["GENESIS_DELAY"], "604800");
        assert_eq!(mainnet["SECONDS_PER_ETH1_BLOCK"], "14");
        assert_eq!(mainnet["TERMINAL_TOTAL_DIFFICULTY"], "58750000000000000000000");
        assert_eq!(mainnet["TERMINAL_BLOCK_HASH"], format!("0x{}", "00".repeat(32)));
        assert_eq!(mainnet["BLOB_SCHEDULE"][0]["EPOCH"], "412672");
        assert_eq!(mainnet["BLOB_SCHEDULE"][0]["MAX_BLOBS_PER_BLOCK"], "15");
        assert_eq!(mainnet["BLOB_SCHEDULE"][1]["EPOCH"], "419072");
    }

    /// The fork-suffixed keys carry the scalars silver runs on, so a config
    /// file that overrides one has to move the served value with it. Their
    /// pre-fork spellings are frozen historical values and must not follow.
    #[test]
    fn churn_and_penalty_scalars_are_served_under_their_fork_suffixed_names() {
        let spec: SpecConfig = toml::from_str(
            r#"
            MIN_PER_EPOCH_CHURN_LIMIT = 7
            MIN_SLASHING_PENALTY_QUOTIENT = 64
            INACTIVITY_PENALTY_QUOTIENT = 128
            PROPORTIONAL_SLASHING_MULTIPLIER = 5
            "#,
        )
        .unwrap();
        let served = spec_map(&spec);
        assert_eq!(served["MIN_PER_EPOCH_CHURN_LIMIT_ELECTRA"], "7");
        assert_eq!(served["MIN_SLASHING_PENALTY_QUOTIENT_ELECTRA"], "64");
        assert_eq!(served["INACTIVITY_PENALTY_QUOTIENT_BELLATRIX"], "128");
        assert_eq!(served["PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX"], "5");

        assert_eq!(served["MIN_PER_EPOCH_CHURN_LIMIT"], "4");
        assert_eq!(served["MIN_SLASHING_PENALTY_QUOTIENT"], "128");
        assert_eq!(served["MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX"], "32");
        assert_eq!(served["INACTIVITY_PENALTY_QUOTIENT"], "67108864");
        assert_eq!(served["INACTIVITY_PENALTY_QUOTIENT_ALTAIR"], "50331648");
        assert_eq!(served["PROPORTIONAL_SLASHING_MULTIPLIER"], "1");
        assert_eq!(served["PROPORTIONAL_SLASHING_MULTIPLIER_ALTAIR"], "2");
    }

    #[test]
    fn fork_schedule_starts_at_phase0_and_chains_versions() {
        let spec = SpecConfig::mainnet();
        let forks = data(&fork_schedule_body(&spec));
        let forks = forks.as_array().unwrap();

        assert_eq!(
            forks[0],
            serde_json::json!({
                "previous_version": "0x00000000",
                "current_version": "0x00000000",
                "epoch": "0",
            })
        );
        for pair in forks.windows(2) {
            assert_eq!(pair[1]["previous_version"], pair[0]["current_version"]);
        }
        assert_eq!(forks.last().unwrap()["current_version"], "0x06000000", "fulu is last");
        assert_eq!(forks.last().unwrap()["epoch"], "411392");
    }

    /// Unscheduled forks are omitted: Nimbus polls this list every epoch and
    /// Vouch derives signing domains from it, and an entry at
    /// `FAR_FUTURE_EPOCH` describes a fork that may never happen.
    #[test]
    fn fork_schedule_omits_unscheduled_forks_and_lists_scheduled_ones() {
        let mainnet = data(&fork_schedule_body(&SpecConfig::mainnet()));
        assert_eq!(mainnet.as_array().unwrap().len(), 7, "phase0 through fulu, no gloas");
        assert!(
            !mainnet.as_array().unwrap().iter().any(|f| f["epoch"] == "18446744073709551615"),
            "no FAR_FUTURE_EPOCH entry"
        );

        let scheduled = SpecConfig { gloas_fork_epoch: 500_000, ..SpecConfig::mainnet() };
        let with_gloas = data(&fork_schedule_body(&scheduled));
        let with_gloas = with_gloas.as_array().unwrap();
        assert_eq!(with_gloas.len(), 8);
        assert_eq!(
            with_gloas[7],
            serde_json::json!({
                "previous_version": "0x06000000",
                "current_version": "0x07000000",
                "epoch": "500000",
            })
        );
    }

    /// Hoodi activates altair through deneb at epoch 0, so five entries
    /// share an epoch — the list is by fork, not by epoch.
    #[test]
    fn fork_schedule_keeps_one_entry_per_fork_when_several_share_an_epoch() {
        let forks = data(&fork_schedule_body(&SpecConfig::hoodi()));
        let forks = forks.as_array().unwrap();
        assert_eq!(forks.len(), 7);
        assert_eq!(forks.iter().filter(|f| f["epoch"] == "0").count(), 5);
        assert_eq!(forks[5]["epoch"], "2048");
        assert_eq!(forks[6]["current_version"], "0x70000910");
    }

    #[test]
    fn deposit_contract_body_golden() {
        assert_eq!(
            String::from_utf8(deposit_contract_body(&SpecConfig::mainnet())).unwrap(),
            "{\"data\":{\"chain_id\":\"1\",\"address\":\"0x00000000219ab540356cbb839cbe05303d7705fa\"}}"
        );
        assert_eq!(data(&deposit_contract_body(&SpecConfig::hoodi()))["chain_id"], "560048");
    }
}
