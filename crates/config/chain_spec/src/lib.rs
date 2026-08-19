use serde::{Deserialize, Serialize};

const fn default_u64<const V: u64>() -> u64 {
    V
}

/// Fork versions are written big-endian in every upstream config
/// (`0x06000000`), so the literal in a `#[serde(default)]` reads as the
/// config file does.
const fn default_fork_version<const V: u32>() -> [u8; 4] {
    V.to_be_bytes()
}

/// `FAR_FUTURE_EPOCH`: a fork with no scheduled activation.
const fn unscheduled() -> u64 {
    u64::MAX
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

/// Every fork silver's config can name, in activation order. The set is
/// closed and minted upstream, so it is an enum rather than a table
/// (ADR-0003); forks past Gloas are added here as the spec schedules them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
}

impl ForkName {
    /// Activation order: every cascade over the fork table walks it from the
    /// end, and the beacon-API fork schedule is served in this order.
    pub const ALL: [Self; 8] = [
        Self::Phase0,
        Self::Altair,
        Self::Bellatrix,
        Self::Capella,
        Self::Deneb,
        Self::Electra,
        Self::Fulu,
        Self::Gloas,
    ];

    /// Lowercase spec spelling, as the wire wants it in
    /// `Eth-Consensus-Version` and in the `version` field of a beacon-API
    /// body.
    pub fn name(self) -> &'static str {
        match self {
            Self::Phase0 => "phase0",
            Self::Altair => "altair",
            Self::Bellatrix => "bellatrix",
            Self::Capella => "capella",
            Self::Deneb => "deneb",
            Self::Electra => "electra",
            Self::Fulu => "fulu",
            Self::Gloas => "gloas",
        }
    }
}

/// Per-network spec parameters that vary across mainnet / testnets / devnets.
///
/// Compile-time array dimensions (`SLOTS_PER_EPOCH`,
/// `SYNC_COMMITTEE_SIZE`, etc.) stay hardcoded — every real testnet uses
/// the mainnet preset; only the spec "minimal" preset differs and we don't
/// support running it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub struct SpecConfig {
    /// The network's own name for itself. Silver derives nothing from it; it
    /// is carried because a validator client builds its runtime config from
    /// the spec this node serves and labels its logs with this string.
    #[serde(default = "default_config_name")]
    pub config_name: String,
    /// Genesis (phase-0) fork version. Used as the `current_version` in the
    /// genesis fork-data root, which is the domain mixed into deposit
    /// signatures (`DOMAIN_DEPOSIT`). 0x00000000 mainnet, 0x10000910 Hoodi.
    #[serde(default = "default_fork_version::<0x00000000>", with = "hex_0x")]
    pub genesis_fork_version: [u8; 4],
    /// Genesis generation parameters. Silver starts from a checkpoint and
    /// never derives a genesis state, so it reads none of these; they are
    /// carried so the config it serves describes the network a client joined.
    #[serde(default = "default_u64::<16_384>")]
    pub min_genesis_active_validator_count: u64,
    #[serde(default = "default_u64::<1_606_824_000>")]
    pub min_genesis_time: u64,
    #[serde(default = "default_u64::<604_800>")]
    pub genesis_delay: u64,
    /// Altair through Electra gate none of silver's own consensus — it runs
    /// Fulu and Gloas only. They are carried because a validator client
    /// derives signing domains for historical epochs from the fork schedule
    /// this node publishes.
    #[serde(default = "default_fork_version::<0x01000000>", with = "hex_0x")]
    pub altair_fork_version: [u8; 4],
    #[serde(default = "default_u64::<74240>")]
    pub altair_fork_epoch: u64,
    #[serde(default = "default_fork_version::<0x02000000>", with = "hex_0x")]
    pub bellatrix_fork_version: [u8; 4],
    #[serde(default = "default_u64::<144896>")]
    pub bellatrix_fork_epoch: u64,
    /// Merge transition parameters. Every network silver can join is already
    /// past its merge, so these gate nothing here; they are carried because a
    /// client that builds its whole runtime spec from the served config aborts
    /// on a missing key.
    #[serde(default = "default_terminal_total_difficulty", with = "quoted_u128")]
    pub terminal_total_difficulty: u128,
    #[serde(default, with = "hex_0x")]
    pub terminal_block_hash: [u8; 32],
    #[serde(default = "unscheduled")]
    pub terminal_block_hash_activation_epoch: u64,
    /// Capella fork version. Withdrawal-credential domain on Capella+.
    /// 0x03000000 mainnet, 0x40000910 Hoodi.
    #[serde(default = "default_fork_version::<0x03000000>", with = "hex_0x")]
    pub capella_fork_version: [u8; 4],
    #[serde(default = "default_u64::<194048>")]
    pub capella_fork_epoch: u64,
    #[serde(default = "default_fork_version::<0x04000000>", with = "hex_0x")]
    pub deneb_fork_version: [u8; 4],
    #[serde(default = "default_u64::<269568>")]
    pub deneb_fork_epoch: u64,
    #[serde(default = "default_fork_version::<0x05000000>", with = "hex_0x")]
    pub electra_fork_version: [u8; 4],
    /// Doubles as the epoch of the active blob params when no
    /// `blob_schedule` entry applies.
    #[serde(default = "default_u64::<364032>")]
    pub electra_fork_epoch: u64,
    /// Fulu fork version. Mixed into every Fulu
    /// fork digest.
    #[serde(default = "default_fork_version::<0x06000000>", with = "hex_0x")]
    pub fulu_fork_version: [u8; 4],
    #[serde(default = "default_u64::<411392>")]
    pub fulu_fork_epoch: u64,
    /// Gloas (EIP-7732) fork version, compared against
    /// `state.fork.current_version` to gate Gloas state logic.
    #[serde(default = "default_fork_version::<0x07000000>", with = "hex_0x")]
    pub gloas_fork_version: [u8; 4],
    /// Gloas activation epoch.
    #[serde(default = "unscheduled")]
    pub gloas_fork_epoch: u64,
    /// Per-epoch override on `max_blobs_per_block` (EIP-7892). Sorted by
    /// `epoch`; the active entry is the highest-epoch entry whose epoch
    /// <= the queried epoch. Empty ⇒ always fall back to the Electra
    /// defaults (`electra_fork_epoch`, `max_blobs_per_block_electra`).
    #[serde(default = "default_blob_schedule")]
    pub blob_schedule: Vec<BlobParameters>,
    /// Blob count active between Electra
    /// activation and the first BPO upgrade. 9 mainnet.
    #[serde(default = "default_u64::<9>")]
    pub max_blobs_per_block_electra: u64,
    /// Blob-sidecar gossip and req/resp limits. Fulu replaced sidecars with
    /// data columns, so silver's own networking uses the column parameters
    /// instead; these describe the pre-Fulu topics a client may still ask
    /// about.
    #[serde(default = "default_u64::<6>")]
    pub blob_sidecar_subnet_count: u64,
    #[serde(default = "default_u64::<9>")]
    pub blob_sidecar_subnet_count_electra: u64,
    #[serde(default = "default_u64::<768>")]
    pub max_request_blob_sidecars: u64,
    #[serde(default = "default_u64::<1152>")]
    pub max_request_blob_sidecars_electra: u64,
    #[serde(default = "default_u64::<4096>")]
    pub min_epochs_for_blob_sidecars_requests: u64,
    /// Deposit contract identity. Silver follows no eth1 deposit stream, so
    /// nothing here is verified against; it is carried so the node can tell a
    /// validator client which contract the network it joined deposits to.
    #[serde(default = "default_u64::<1>")]
    pub deposit_chain_id: u64,
    #[serde(default = "default_u64::<1>")]
    pub deposit_network_id: u64,
    #[serde(default = "default_deposit_contract_address", with = "hex_0x")]
    pub deposit_contract_address: [u8; 20],
    /// Seconds per beacon chain slot. 12 mainnet; testnets may use shorter.
    #[serde(default = "default_u64::<12>")]
    pub seconds_per_slot: u64,
    /// Eth1 following parameters. Silver follows no eth1 deposit stream, so
    /// nothing here is used; they are carried so a client can tell which eth1
    /// chain the network it joined votes on.
    #[serde(default = "default_u64::<14>")]
    pub seconds_per_eth1_block: u64,
    #[serde(default = "default_u64::<2048>")]
    pub eth1_follow_distance: u64,
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

fn default_config_name() -> String {
    "mainnet".to_owned()
}

/// Mainnet's merge threshold, crossed 2022-09-15.
const fn default_terminal_total_difficulty() -> u128 {
    58_750_000_000_000_000_000_000
}

/// Mainnet deposit contract, live since 2020-11-04. Hoodi reuses the very
/// same address.
fn default_deposit_contract_address() -> [u8; 20] {
    [
        0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe, 0x05,
        0x30, 0x3d, 0x77, 0x05, 0xfa,
    ]
}

fn default_blob_schedule() -> Vec<BlobParameters> {
    vec![BlobParameters { epoch: 412672, max_blobs_per_block: 15 }, BlobParameters {
        epoch: 419072,
        max_blobs_per_block: 21,
    }]
}

/// Serde adapter for `0x`-prefixed hex (`0x06000000`), which is the format
/// used by upstream `consensus-specs/configs/*.yaml` for fork versions and
/// the deposit contract address. The bare `hex::serde` adapter rejects the
/// prefix.
mod hex_0x {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<const N: usize, S: Serializer>(
        bytes: &[u8; N],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, const N: usize, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; N], D::Error> {
        let s: String = Deserialize::deserialize(d)?;
        let body = s.strip_prefix("0x").unwrap_or(&s);
        let v = hex::decode(body).map_err(D::Error::custom)?;
        v.try_into().map_err(|_: Vec<u8>| D::Error::custom(format!("expected {N}-byte hex")))
    }
}

/// Serde adapter for a decimal too wide for the `i64` a TOML integer holds
/// (mainnet's `TERMINAL_TOTAL_DIFFICULTY` needs 76 bits), so it is written
/// quoted — as the beacon-API also serves it. A testnet's small value is
/// accepted either quoted or bare.
mod quoted_u128 {
    use serde::{Deserialize, Deserializer, Serializer, de::Error};

    pub fn serialize<S: Serializer>(value: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Written {
            Quoted(String),
            Bare(u64),
        }
        match Written::deserialize(d)? {
            Written::Quoted(text) => text.parse().map_err(D::Error::custom),
            Written::Bare(value) => Ok(value.into()),
        }
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

    pub fn fork_at(&self, epoch: u64) -> ForkName {
        if epoch >= self.gloas_fork_epoch {
            ForkName::Gloas
        } else if epoch >= self.fulu_fork_epoch {
            ForkName::Fulu
        } else if epoch >= self.electra_fork_epoch {
            ForkName::Electra
        } else if epoch >= self.deneb_fork_epoch {
            ForkName::Deneb
        } else if epoch >= self.capella_fork_epoch {
            ForkName::Capella
        } else if epoch >= self.bellatrix_fork_epoch {
            ForkName::Bellatrix
        } else if epoch >= self.altair_fork_epoch {
            ForkName::Altair
        } else {
            ForkName::Phase0
        }
    }

    #[inline]
    pub fn fork_at_slot(&self, slot: u64) -> ForkName {
        self.fork_at(slot / SLOTS_PER_EPOCH)
    }

    pub fn fork_version(&self, fork: ForkName) -> [u8; 4] {
        match fork {
            ForkName::Phase0 => self.genesis_fork_version,
            ForkName::Altair => self.altair_fork_version,
            ForkName::Bellatrix => self.bellatrix_fork_version,
            ForkName::Capella => self.capella_fork_version,
            ForkName::Deneb => self.deneb_fork_version,
            ForkName::Electra => self.electra_fork_version,
            ForkName::Fulu => self.fulu_fork_version,
            ForkName::Gloas => self.gloas_fork_version,
        }
    }

    /// `u64::MAX` for a fork this network has not scheduled.
    pub fn fork_epoch(&self, fork: ForkName) -> u64 {
        match fork {
            ForkName::Phase0 => 0,
            ForkName::Altair => self.altair_fork_epoch,
            ForkName::Bellatrix => self.bellatrix_fork_epoch,
            ForkName::Capella => self.capella_fork_epoch,
            ForkName::Deneb => self.deneb_fork_epoch,
            ForkName::Electra => self.electra_fork_epoch,
            ForkName::Fulu => self.fulu_fork_epoch,
            ForkName::Gloas => self.gloas_fork_epoch,
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
        self.fork_version(self.fork_at(epoch))
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

    /// Hoodi testnet (launched 2025-03-17), transcribed from
    /// `eth-clients/hoodi/metadata/config.yaml` as of 2026-08-19. Preset
    /// dimensions, validator lifecycle, inactivity, slashing and churn
    /// scalars are all mainnet's; what differs is the `0xN0000910`
    /// fork-version pattern (N = fork ordinal), the fork epochs, genesis time
    /// and delay, `SECONDS_PER_ETH1_BLOCK`, a `TERMINAL_TOTAL_DIFFICULTY` of
    /// 0 (Hoodi merged at genesis), the deposit chain/network ids, and its own
    /// `BLOB_SCHEDULE`.
    pub fn hoodi() -> Self {
        Self {
            config_name: "hoodi".to_owned(),
            // Hoodi fork-version pattern is `0xN0000910`.
            genesis_fork_version: default_fork_version::<0x10000910>(),
            min_genesis_active_validator_count: 16_384,
            min_genesis_time: 1_742_212_800,
            genesis_delay: 600,
            altair_fork_version: default_fork_version::<0x20000910>(),
            altair_fork_epoch: 0,
            bellatrix_fork_version: default_fork_version::<0x30000910>(),
            bellatrix_fork_epoch: 0,
            terminal_total_difficulty: 0,
            terminal_block_hash: [0; 32],
            terminal_block_hash_activation_epoch: unscheduled(),
            capella_fork_version: default_fork_version::<0x40000910>(),
            capella_fork_epoch: 0,
            deneb_fork_version: default_fork_version::<0x50000910>(),
            deneb_fork_epoch: 0,
            electra_fork_version: default_fork_version::<0x60000910>(),
            electra_fork_epoch: 2048,
            fulu_fork_version: default_fork_version::<0x70000910>(),
            fulu_fork_epoch: 50688,
            gloas_fork_version: default_fork_version::<0x80000910>(),
            gloas_fork_epoch: unscheduled(),
            blob_schedule: vec![
                BlobParameters { epoch: 52480, max_blobs_per_block: 15 },
                BlobParameters { epoch: 54016, max_blobs_per_block: 21 },
            ],
            max_blobs_per_block_electra: 9,
            blob_sidecar_subnet_count: 6,
            blob_sidecar_subnet_count_electra: 9,
            max_request_blob_sidecars: 768,
            max_request_blob_sidecars_electra: 1152,
            min_epochs_for_blob_sidecars_requests: 4096,
            deposit_chain_id: 560048,
            deposit_network_id: 560048,
            deposit_contract_address: default_deposit_contract_address(),
            seconds_per_slot: 12,
            seconds_per_eth1_block: 12,
            eth1_follow_distance: 2048,
            // Identical to mainnet preset / config below this line.
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
            config_name: default_config_name(),
            genesis_fork_version: default_fork_version::<0x00000000>(),
            min_genesis_active_validator_count: 16_384,
            min_genesis_time: 1_606_824_000,
            genesis_delay: 604_800,
            altair_fork_version: default_fork_version::<0x01000000>(),
            altair_fork_epoch: 74240,
            bellatrix_fork_version: default_fork_version::<0x02000000>(),
            bellatrix_fork_epoch: 144896,
            terminal_total_difficulty: default_terminal_total_difficulty(),
            terminal_block_hash: [0; 32],
            terminal_block_hash_activation_epoch: unscheduled(),
            capella_fork_version: default_fork_version::<0x03000000>(),
            capella_fork_epoch: 194048,
            deneb_fork_version: default_fork_version::<0x04000000>(),
            deneb_fork_epoch: 269568,
            electra_fork_version: default_fork_version::<0x05000000>(),
            electra_fork_epoch: 364032,
            fulu_fork_version: default_fork_version::<0x06000000>(),
            fulu_fork_epoch: 411392,
            gloas_fork_version: default_fork_version::<0x07000000>(),
            gloas_fork_epoch: unscheduled(),
            blob_schedule: default_blob_schedule(),
            max_blobs_per_block_electra: 9,
            blob_sidecar_subnet_count: 6,
            blob_sidecar_subnet_count_electra: 9,
            max_request_blob_sidecars: 768,
            max_request_blob_sidecars_electra: 1152,
            min_epochs_for_blob_sidecars_requests: 4096,
            deposit_chain_id: 1,
            deposit_network_id: 1,
            deposit_contract_address: default_deposit_contract_address(),
            seconds_per_slot: 12,
            seconds_per_eth1_block: 14,
            eth1_follow_distance: 2048,
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

    /// Every default is the mainnet value from
    /// `ethereum/consensus-specs` `configs/mainnet.yaml` (fork versions and
    /// epochs, `BLOB_SCHEDULE`, `DEPOSIT_CHAIN_ID` / `DEPOSIT_NETWORK_ID` /
    /// `DEPOSIT_CONTRACT_ADDRESS`), so a config file naming only its
    /// network's diffs still describes mainnet everywhere else.
    #[test]
    fn toml_defaults_are_mainnet() {
        let spec: SpecConfig = toml::from_str("").unwrap();
        assert_eq!(spec, SpecConfig::mainnet());

        assert_eq!(spec.altair_fork_epoch, 74240);
        assert_eq!(spec.bellatrix_fork_epoch, 144896);
        assert_eq!(spec.capella_fork_epoch, 194048);
        assert_eq!(spec.deneb_fork_epoch, 269568);
        assert_eq!(spec.electra_fork_epoch, 364032);
        assert_eq!(spec.fulu_fork_epoch, 411392);
        assert_eq!(spec.gloas_fork_epoch, u64::MAX);
        assert_eq!(spec.deposit_chain_id, 1);
        assert_eq!(spec.deposit_network_id, 1);
        assert_eq!(spec.config_name, "mainnet");
        assert_eq!(spec.min_genesis_time, 1_606_824_000);
        assert_eq!(spec.genesis_delay, 604_800);
        assert_eq!(spec.seconds_per_eth1_block, 14);
        assert_eq!(spec.terminal_total_difficulty, 58_750_000_000_000_000_000_000);
        assert_eq!(spec.terminal_block_hash, [0; 32]);
        assert_eq!(spec.terminal_block_hash_activation_epoch, u64::MAX);
    }

    /// `TERMINAL_TOTAL_DIFFICULTY` outgrows the `i64` a TOML integer holds, so
    /// the wide value has to survive being written as a string.
    #[test]
    fn terminal_total_difficulty_parses_quoted_or_bare() {
        let quoted: SpecConfig =
            toml::from_str(r#"TERMINAL_TOTAL_DIFFICULTY = "58750000000000000000000""#).unwrap();
        assert_eq!(quoted.terminal_total_difficulty, 58_750_000_000_000_000_000_000);

        let bare: SpecConfig = toml::from_str("TERMINAL_TOTAL_DIFFICULTY = 0").unwrap();
        assert_eq!(bare.terminal_total_difficulty, 0);
    }

    #[test]
    fn hoodi_matches_its_upstream_config_file() {
        let spec = SpecConfig::hoodi();
        assert_eq!(spec.config_name, "hoodi");
        assert_eq!(spec.min_genesis_time, 1_742_212_800);
        assert_eq!(spec.genesis_delay, 600);
        assert_eq!(spec.seconds_per_eth1_block, 12);
        assert_eq!(spec.terminal_total_difficulty, 0);
        assert_eq!(spec.blob_schedule, [
            BlobParameters { epoch: 52480, max_blobs_per_block: 15 },
            BlobParameters { epoch: 54016, max_blobs_per_block: 21 },
        ]);
        assert_eq!(spec.min_genesis_active_validator_count, 16_384, "mainnet's value");
        assert_eq!(spec.eth1_follow_distance, 2048, "mainnet's value");
    }

    #[test]
    fn every_fork_field_is_overridable() {
        let spec: SpecConfig = toml::from_str(
            r#"
            ALTAIR_FORK_VERSION = "0x20000910"
            ALTAIR_FORK_EPOCH = 0
            FULU_FORK_EPOCH = 50688
            DEPOSIT_CHAIN_ID = 560048
            "#,
        )
        .unwrap();
        assert_eq!(spec.altair_fork_version, [0x20, 0x00, 0x09, 0x10]);
        assert_eq!(spec.altair_fork_epoch, 0);
        assert_eq!(spec.fulu_fork_epoch, 50688);
        assert_eq!(spec.deposit_chain_id, 560048);
        assert_eq!(spec.bellatrix_fork_epoch, 144896, "untouched fields keep the mainnet default");
    }

    /// Upstream writes the address checksummed (mixed case); `hex::decode`
    /// must not be handed it case-sensitively.
    #[test]
    fn deposit_contract_address_parses_checksummed_hex() {
        let spec: SpecConfig = toml::from_str(
            r#"DEPOSIT_CONTRACT_ADDRESS = "0x00000000219ab540356cBB839Cbe05303d7705Fa""#,
        )
        .unwrap();
        assert_eq!(spec.deposit_contract_address, SpecConfig::mainnet().deposit_contract_address);
        assert_eq!(spec.deposit_contract_address[4], 0x21);
    }

    #[test]
    fn fork_at_switches_on_each_activation_epoch() {
        let spec = SpecConfig::mainnet();
        assert_eq!(spec.fork_at(0), ForkName::Phase0);

        for (epoch, before, after) in [
            (spec.altair_fork_epoch, ForkName::Phase0, ForkName::Altair),
            (spec.bellatrix_fork_epoch, ForkName::Altair, ForkName::Bellatrix),
            (spec.capella_fork_epoch, ForkName::Bellatrix, ForkName::Capella),
            (spec.deneb_fork_epoch, ForkName::Capella, ForkName::Deneb),
            (spec.electra_fork_epoch, ForkName::Deneb, ForkName::Electra),
            (spec.fulu_fork_epoch, ForkName::Electra, ForkName::Fulu),
        ] {
            assert_eq!(spec.fork_at(epoch - 1), before, "epoch {epoch} - 1");
            assert_eq!(spec.fork_at(epoch), after, "epoch {epoch}");
            assert_eq!(spec.fork_at(epoch + 1), after, "epoch {epoch} + 1");
        }

        assert_eq!(spec.fork_at(u64::MAX - 1), ForkName::Fulu, "Gloas is unscheduled on mainnet");
    }

    /// A validator client derives signing domains for historical epochs from
    /// the versions this node reports, so every fork in the table — not just
    /// the two silver's own consensus runs — must map to its own version.
    #[test]
    fn fork_version_at_returns_the_version_of_the_fork_active_then() {
        let spec = SpecConfig::mainnet();
        for (epoch, version) in [
            (0, spec.genesis_fork_version),
            (spec.altair_fork_epoch, spec.altair_fork_version),
            (spec.bellatrix_fork_epoch, spec.bellatrix_fork_version),
            (spec.capella_fork_epoch, spec.capella_fork_version),
            (spec.deneb_fork_epoch, spec.deneb_fork_version),
            (spec.deneb_fork_epoch + 1, spec.deneb_fork_version),
            (spec.electra_fork_epoch - 1, spec.deneb_fork_version),
            (spec.electra_fork_epoch, spec.electra_fork_version),
            (spec.fulu_fork_epoch, spec.fulu_fork_version),
            (u64::MAX - 1, spec.fulu_fork_version),
        ] {
            assert_eq!(spec.fork_version_at(epoch), version, "epoch {epoch}");
        }
    }

    /// Hoodi activates altair through deneb all at epoch 0, so the genesis
    /// version is never the active one and the cascade must report the
    /// highest fork sharing that epoch.
    #[test]
    fn fork_version_at_on_hoodi_reports_the_highest_fork_sharing_an_epoch() {
        let spec = SpecConfig::hoodi();
        for (epoch, version) in [
            (0, spec.deneb_fork_version),
            (spec.electra_fork_epoch - 1, spec.deneb_fork_version),
            (spec.electra_fork_epoch, spec.electra_fork_version),
            (spec.fulu_fork_epoch - 1, spec.electra_fork_version),
            (spec.fulu_fork_epoch, spec.fulu_fork_version),
        ] {
            assert_eq!(spec.fork_version_at(epoch), version, "epoch {epoch}");
        }
    }

    #[test]
    fn every_fork_maps_to_its_own_version_and_epoch() {
        let spec = SpecConfig::mainnet();
        assert_eq!(ForkName::ALL.map(|fork| spec.fork_version(fork)), [
            spec.genesis_fork_version,
            spec.altair_fork_version,
            spec.bellatrix_fork_version,
            spec.capella_fork_version,
            spec.deneb_fork_version,
            spec.electra_fork_version,
            spec.fulu_fork_version,
            spec.gloas_fork_version,
        ]);
        assert_eq!(ForkName::ALL.map(|fork| spec.fork_epoch(fork)), [
            0,
            spec.altair_fork_epoch,
            spec.bellatrix_fork_epoch,
            spec.capella_fork_epoch,
            spec.deneb_fork_epoch,
            spec.electra_fork_epoch,
            spec.fulu_fork_epoch,
            u64::MAX,
        ]);
        assert!(ForkName::ALL.is_sorted(), "ALL is in activation order");
    }

    #[test]
    fn next_fork_still_announces_the_scheduled_gloas_activation() {
        let scheduled = SpecConfig { gloas_fork_epoch: 500_000, ..SpecConfig::mainnet() };
        assert_eq!(scheduled.next_fork(499_999), (scheduled.gloas_fork_version, 500_000));
        assert_eq!(scheduled.next_fork(500_000), (scheduled.gloas_fork_version, u64::MAX));

        let mainnet = SpecConfig::mainnet();
        assert_eq!(
            mainnet.next_fork(mainnet.fulu_fork_epoch),
            (mainnet.fulu_fork_version, u64::MAX)
        );
    }

    #[test]
    fn fork_at_slot_switches_on_the_activation_epoch_boundary() {
        let spec = SpecConfig { gloas_fork_epoch: 500_000, ..SpecConfig::mainnet() };
        let first_gloas_slot = 500_000 * SLOTS_PER_EPOCH;
        assert_eq!(spec.fork_at_slot(first_gloas_slot - 1), ForkName::Fulu);
        assert_eq!(spec.fork_at_slot(first_gloas_slot), ForkName::Gloas);
    }

    /// These strings go on the wire in `Eth-Consensus-Version` and in the
    /// `version` field of every versioned beacon-API body.
    #[test]
    fn fork_names_match_the_wire_spelling() {
        assert_eq!(
            [
                ForkName::Phase0,
                ForkName::Altair,
                ForkName::Bellatrix,
                ForkName::Capella,
                ForkName::Deneb,
                ForkName::Electra,
                ForkName::Fulu,
                ForkName::Gloas,
            ]
            .map(ForkName::name),
            ["phase0", "altair", "bellatrix", "capella", "deneb", "electra", "fulu", "gloas"]
        );
    }
}
