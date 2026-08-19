use serde::{Deserialize, Serialize};

const fn default_u64<const V: u64>() -> u64 {
    V
}

/// Mainnet preset; every network we support uses it.
const SLOTS_PER_EPOCH: u64 = 32;

/// Fulu `BLOB_SCHEDULE` entry (EIP-7892). Per-epoch override on
/// `max_blobs_per_block`. Network-specific.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct BlobParameters {
    pub epoch: u64,
    pub max_blobs_per_block: u64,
}

/// Per-network spec parameters that vary across mainnet / testnets / devnets.
///
/// Compile-time array dimensions (`SLOTS_PER_EPOCH`,
/// `SYNC_COMMITTEE_SIZE`, etc.) stay hardcoded — every real testnet uses
/// the mainnet preset; only the spec "minimal" preset differs and we don't
/// support running it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct SpecConfig {
    /// Genesis (phase-0) fork version. Used as the `current_version` in the
    /// genesis fork-data root, which is the domain mixed into deposit
    /// signatures (`DOMAIN_DEPOSIT`). 0x00000000 mainnet, 0x10000910 Hoodi.
    #[serde(default = "default_genesis_fork_version", with = "hex_0x")]
    pub genesis_fork_version: [u8; 4],
    /// Capella fork version. Withdrawal-credential domain on Capella+.
    /// 0x03000000 mainnet, 0x40000910 Hoodi.
    #[serde(default = "default_capella_fork_version", with = "hex_0x")]
    pub capella_fork_version: [u8; 4],
    /// Fulu fork version. Mixed into every Fulu
    /// fork digest.
    #[serde(default = "default_fulu_fork_version", with = "hex_0x")]
    pub fulu_fork_version: [u8; 4],
    /// Gloas (EIP-7732) fork version, compared against
    /// `state.fork.current_version` to gate Gloas state logic.
    #[serde(default = "default_gloas_fork_version", with = "hex_0x")]
    pub gloas_fork_version: [u8; 4],
    /// Gloas activation epoch.
    #[serde(default = "default_gloas_fork_epoch")]
    pub gloas_fork_epoch: u64,
    /// Per-epoch override on `max_blobs_per_block` (EIP-7892). Sorted by
    /// `epoch`; the active entry is the highest-epoch entry whose epoch
    /// <= the queried epoch. Empty ⇒ always fall back to the Electra
    /// defaults (`electra_fork_epoch`, `max_blobs_per_block_electra`).
    #[serde(default = "default_blob_schedule")]
    pub blob_schedule: Vec<BlobParameters>,
    /// Activation epoch of the Electra fork — used
    /// as the epoch field of the active blob params when no `blob_schedule`
    /// entry applies.
    #[serde(default = "default_u64::<364032>")]
    pub electra_fork_epoch: u64,
    /// Blob count active between Electra
    /// activation and the first BPO upgrade. 9 mainnet.
    #[serde(default = "default_u64::<9>")]
    pub max_blobs_per_block_electra: u64,
    /// Seconds per beacon chain slot. 12 mainnet; testnets may use shorter.
    #[serde(default = "default_u64::<12>")]
    pub seconds_per_slot: u64,
    /// Minimum activation period before a validator may voluntarily exit.
    #[serde(default = "default_u64::<256>")]
    pub shard_committee_period: u64,
    /// Delay between exit_epoch and withdrawability.
    #[serde(default = "default_u64::<256>")]
    pub min_validator_withdrawability_delay: u64,
    /// Seed lookahead for shuffling / activation delay.
    #[serde(default = "default_u64::<4>")]
    pub max_seed_lookahead: u64,
    /// Floor on per-epoch consensus stake churn, in Gwei.
    #[serde(default = "default_u64::<128_000_000_000>")]
    pub min_per_epoch_churn_limit: u64,
    /// Ceiling on per-epoch activation/exit churn, in Gwei.
    #[serde(default = "default_u64::<256_000_000_000>")]
    pub max_per_epoch_activation_exit_churn_limit: u64,
    /// Divisor: `churn = max(min_per_epoch_churn_limit, total_stake /
    /// churn_limit_quotient)`. `1<<16` mainnet.
    #[serde(default = "default_u64::<65536>")]
    pub churn_limit_quotient: u64,
    /// EIP-8061: Gloas replaces `churn_limit_quotient` for the base churn
    /// (`1<<15`, double the Electra rate). Deposit/exit churn split off it.
    #[serde(default = "default_u64::<32768>")]
    pub churn_limit_quotient_gloas: u64,
    /// EIP-8061: Gloas consolidation churn is independently derived as
    /// `total_stake / this`, rounded. `1<<16` mainnet.
    #[serde(default = "default_u64::<65536>")]
    pub consolidation_churn_limit_quotient: u64,
    /// EIP-8061: Gloas cap on per-epoch *activation* (deposit) churn, in Gwei.
    /// Exit churn is uncapped in Gloas.
    #[serde(default = "default_u64::<256_000_000_000>")]
    pub max_per_epoch_activation_churn_limit_gloas: u64,
    /// Per-validator inactivity score increment for missed-target epochs.
    #[serde(default = "default_u64::<4>")]
    pub inactivity_score_bias: u64,
    /// Score recovery per epoch when participating.
    #[serde(default = "default_u64::<16>")]
    pub inactivity_score_recovery_rate: u64,
    /// Inactivity-leak penalty divisor (Bellatrix-onward, `1<<24` mainnet).
    /// Per-fork in spec; we only support Fulu so one scalar.
    #[serde(default = "default_u64::<16777216>")]
    pub inactivity_penalty_quotient: u64,
    /// Inactivity leak triggers after `previous_epoch - finalized_epoch >`
    /// this many epochs.
    #[serde(default = "default_u64::<4>")]
    pub min_epochs_to_inactivity_penalty: u64,
    /// Multiplier for slashed-validator penalty as a fraction of total
    /// slashed stake.
    #[serde(default = "default_u64::<3>")]
    pub proportional_slashing_multiplier: u64,
    /// Per-validator slashing penalty divisor.
    #[serde(default = "default_u64::<4096>")]
    pub min_slashing_penalty_quotient: u64,
    /// Effective-balance threshold at or below which an active validator is
    /// auto-ejected at the epoch boundary (`process_registry_updates`).
    /// 16 ETH = 16e9 Gwei on mainnet/Hoodi.
    #[serde(default = "default_u64::<16_000_000_000>")]
    pub ejection_balance: u64,
}

fn default_genesis_fork_version() -> [u8; 4] {
    [0x00, 0x00, 0x00, 0x00]
}

fn default_capella_fork_version() -> [u8; 4] {
    [0x03, 0x00, 0x00, 0x00]
}

fn default_fulu_fork_version() -> [u8; 4] {
    [0x06, 0x00, 0x00, 0x00]
}

fn default_gloas_fork_version() -> [u8; 4] {
    [0x07, 0x00, 0x00, 0x00]
}

fn default_gloas_fork_epoch() -> u64 {
    u64::MAX
}

fn default_blob_schedule() -> Vec<BlobParameters> {
    vec![BlobParameters { epoch: 412672, max_blobs_per_block: 15 }, BlobParameters {
        epoch: 419072,
        max_blobs_per_block: 21,
    }]
}

/// Serde adapter for `0x`-prefixed lowercase hex (`0x06000000`), which is
/// the format used by upstream `consensus-specs/configs/*.yaml` for all
/// fork-version fields. The bare `hex::serde` adapter rejects the prefix.
mod hex_0x {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(bytes: &[u8; 4], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 4], D::Error> {
        let s: String = Deserialize::deserialize(d)?;
        let body = s.strip_prefix("0x").unwrap_or(&s);
        let v = hex::decode(body).map_err(D::Error::custom)?;
        v.try_into().map_err(|_: Vec<u8>| D::Error::custom("expected 4-byte hex"))
    }
}

impl SpecConfig {
    /// Active blob params when no `blob_schedule` entry covers `epoch`.
    /// Built from the Electra activation epoch + Electra-era blob count
    /// rather than carried as a standalone field, because upstream YAMLs
    /// only express these two scalars.
    pub fn default_blob_params(&self) -> BlobParameters {
        BlobParameters {
            epoch: self.electra_fork_epoch,
            max_blobs_per_block: self.max_blobs_per_block_electra,
        }
    }

    /// Whether `epoch` is at or past the Gloas activation.
    #[inline]
    pub fn is_gloas_at(&self, epoch: u64) -> bool {
        epoch >= self.gloas_fork_epoch
    }

    #[inline]
    pub fn is_gloas_at_slot(&self, slot: u64) -> bool {
        self.is_gloas_at(slot / SLOTS_PER_EPOCH)
    }

    #[inline]
    pub fn is_gloas_activation_epoch(&self, epoch: u64) -> bool {
        epoch == self.gloas_fork_epoch
    }

    /// First Gloas slot, or `u64::MAX` if Gloas isn't scheduled.
    #[inline]
    pub fn gloas_fork_slot(&self) -> u64 {
        self.gloas_fork_epoch.saturating_mul(SLOTS_PER_EPOCH)
    }

    #[inline]
    pub fn fork_version_at(&self, epoch: u64) -> [u8; 4] {
        if self.is_gloas_at(epoch) { self.gloas_fork_version } else { self.fulu_fork_version }
    }

    /// `(next_fork_version, next_fork_epoch)` for the ENR `eth2` field at
    /// `epoch`: the scheduled Gloas activation until it passes, then
    /// FAR_FUTURE.
    pub fn next_fork(&self, epoch: u64) -> ([u8; 4], u64) {
        if self.gloas_fork_epoch != u64::MAX && epoch < self.gloas_fork_epoch {
            (self.gloas_fork_version, self.gloas_fork_epoch)
        } else {
            (self.fork_version_at(epoch), u64::MAX)
        }
    }

    pub fn network_name(&self) -> String {
        match self.genesis_fork_version {
            [0x00, 0x00, 0x00, 0x00] => "mainnet".to_owned(),
            [0x90, 0x00, 0x00, 0x69] => "sepolia".to_owned(),
            [0x10, 0x00, 0x09, 0x10] => "hoodi".to_owned(),
            version => format!("0x{}", hex::encode(version)),
        }
    }

    /// Hoodi testnet (launched 2025-03-17). Differs from mainnet in fork
    /// versions and a few fork epochs only — preset dimensions, validator
    /// lifecycle, inactivity, slashing, and churn scalars are all identical
    /// to mainnet (see `eth-clients/hoodi/metadata/config.yaml`).
    ///
    /// Diffs from mainnet:
    ///   - All pre-Fulu forks (Altair → Electra) activated at epoch 0 except
    ///     Electra, which activated at epoch 2048.
    ///   - `*_FORK_VERSION` pattern is `0xN0000910` (N = fork ordinal) instead
    ///     of mainnet's `0x0N000000`.
    ///   - Hoodi-specific `BLOB_SCHEDULE` entries should be cross-checked
    ///     against the upstream config file before long-running use.
    pub fn hoodi() -> Self {
        Self {
            // Hoodi fork-version pattern is `0xN0000910`.
            genesis_fork_version: [0x10, 0x00, 0x09, 0x10],
            capella_fork_version: [0x40, 0x00, 0x09, 0x10],
            fulu_fork_version: [0x70, 0x00, 0x09, 0x10],
            gloas_fork_version: [0x80, 0x00, 0x09, 0x10],
            gloas_fork_epoch: u64::MAX,
            // No BPO entries spec'd on Hoodi at time of writing. Empty ⇒
            // always fall back to (`electra_fork_epoch`,
            // `max_blobs_per_block_electra`).
            blob_schedule: vec![],
            electra_fork_epoch: 2048,
            max_blobs_per_block_electra: 9,
            // Identical to mainnet preset / config below this line.
            seconds_per_slot: 12,
            shard_committee_period: 256,
            min_validator_withdrawability_delay: 256,
            max_seed_lookahead: 4,
            min_per_epoch_churn_limit: 128_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 256_000_000_000,
            churn_limit_quotient: 1 << 16,
            churn_limit_quotient_gloas: 1 << 15,
            consolidation_churn_limit_quotient: 1 << 16,
            max_per_epoch_activation_churn_limit_gloas: 256_000_000_000,
            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            inactivity_penalty_quotient: 1 << 24,
            min_epochs_to_inactivity_penalty: 4,
            proportional_slashing_multiplier: 3,
            min_slashing_penalty_quotient: 4096,
            ejection_balance: 16_000_000_000,
        }
    }

    pub fn mainnet() -> Self {
        Self {
            genesis_fork_version: default_genesis_fork_version(),
            capella_fork_version: default_capella_fork_version(),
            fulu_fork_version: default_fulu_fork_version(),
            gloas_fork_version: default_gloas_fork_version(),
            gloas_fork_epoch: default_gloas_fork_epoch(),
            blob_schedule: default_blob_schedule(),
            electra_fork_epoch: 364032,
            max_blobs_per_block_electra: 9,
            seconds_per_slot: 12,
            shard_committee_period: 256,
            min_validator_withdrawability_delay: 256,
            max_seed_lookahead: 4,
            min_per_epoch_churn_limit: 128_000_000_000,
            max_per_epoch_activation_exit_churn_limit: 256_000_000_000,
            churn_limit_quotient: 1 << 16,
            churn_limit_quotient_gloas: 1 << 15,
            consolidation_churn_limit_quotient: 1 << 16,
            max_per_epoch_activation_churn_limit_gloas: 256_000_000_000,
            inactivity_score_bias: 4,
            inactivity_score_recovery_rate: 16,
            inactivity_penalty_quotient: 1 << 24,
            min_epochs_to_inactivity_penalty: 4,
            proportional_slashing_multiplier: 3,
            min_slashing_penalty_quotient: 4096,
            ejection_balance: 16_000_000_000,
        }
    }
}

impl Default for SpecConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constructors and the lookup read `genesis_fork_version` from
    /// opposite ends; a typo in either shows up here.
    #[test]
    fn known_networks_are_named() {
        assert_eq!(SpecConfig::mainnet().network_name(), "mainnet");
        assert_eq!(SpecConfig::hoodi().network_name(), "hoodi");
    }

    #[test]
    fn a_devnet_is_named_by_its_fork_version() {
        let devnet =
            SpecConfig { genesis_fork_version: [0x10, 0x00, 0x00, 0x38], ..SpecConfig::mainnet() };
        assert_eq!(devnet.network_name(), "0x10000038");
    }
}
