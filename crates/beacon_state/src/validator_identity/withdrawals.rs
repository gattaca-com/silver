use crate::types::B256;

const COMPOUNDING_WITHDRAWAL_PREFIX: u8 = 0x02;
const ETH1_ADDRESS_WITHDRAWAL_PREFIX: u8 = 0x01;
const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;
const MAX_EFFECTIVE_BALANCE: u64 = 2048 * 1_000_000_000;

/// 32-byte validator withdrawal credentials. `#[repr(transparent)]` over
/// `B256` so `[WithdrawalCredentials; N]` has the same layout as
/// `[B256; N]` — necessary because `ValidatorsData` is a fixed-layout
/// boxed arena and the field used to be `[B256; MAX_VALIDATORS]`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Withdrawals(pub B256);

impl Withdrawals {
    pub const ZERO: Self = Self([0u8; 32]);

    /// Build eth1-prefixed credentials (`0x01 || 11 zero bytes || addr`).
    #[inline]
    pub fn eth1(execution_address: &[u8; 20]) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
        bytes[12..32].copy_from_slice(execution_address);
        Self(bytes)
    }

    #[inline]
    pub fn prefix(&self) -> u8 {
        self.0[0]
    }

    #[inline]
    pub fn has_execution_credential(&self) -> bool {
        self.has_eth1_credential() || self.has_compounding_credential()
    }

    #[inline]
    pub fn has_eth1_credential(&self) -> bool {
        self.prefix() == ETH1_ADDRESS_WITHDRAWAL_PREFIX
    }

    #[inline]
    pub fn has_compounding_credential(&self) -> bool {
        self.prefix() == COMPOUNDING_WITHDRAWAL_PREFIX
    }

    #[inline]
    pub fn set_compounding_prefix(&mut self) {
        self.0[0] = COMPOUNDING_WITHDRAWAL_PREFIX;
    }

    #[inline]
    pub fn max_effective_balance(&self) -> u64 {
        if self.has_compounding_credential() {
            MAX_EFFECTIVE_BALANCE
        } else {
            MIN_ACTIVATION_BALANCE
        }
    }

    /// Bytes [12..32] — the 20-byte execution address for `0x01` / `0x02`
    /// prefixed credentials.
    #[inline]
    pub fn execution_address(&self) -> &[u8; 20] {
        (&self.0[12..32]).try_into().unwrap()
    }
}

impl std::fmt::Debug for Withdrawals {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Withdrawals(0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}
