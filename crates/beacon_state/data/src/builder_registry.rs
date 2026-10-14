use silver_ssz::ssz_hash::{compute_domain, compute_signing_root};
use thiserror::Error;

use crate::{
    Builder, BuildersView, EpochView, PendingView, SlotState, StateReadView, StateWriterView,
    types::{B256, Epoch, Immutable},
};

/// `UINT64_MAX` — the proposer self-built the payload (no builder, no payment).
pub const BUILDER_INDEX_SELF_BUILD: u64 = u64::MAX;
/// `uint8(0)` — the only builder version permitted to submit bids.
pub const PAYLOAD_BUILDER_VERSION: u8 = 0;
pub const DOMAIN_BEACON_BUILDER: u32 = 0x0000_000b;
/// 1 ETH — collateral floor a builder must keep above its pending obligations.
const MIN_DEPOSIT_AMOUNT: u64 = 1_000_000_000;

#[derive(Debug, Error)]
pub enum BidBuilderError {
    #[error("builder index {index} out of range (count {count})")]
    OutOfRange { index: u64, count: usize },
    #[error("builder {index} is not active")]
    Inactive { index: u64 },
    #[error("builder {index} version {version} != PAYLOAD_BUILDER_VERSION")]
    Version { index: u64, version: u8 },
    #[error("builder {index} cannot cover bid value {value}")]
    InsufficientBalance { index: u64, value: u64 },
}

/// The state a builder's obligations are read from; block import projects it
/// from its writer, gossip from the parent post-state.
#[derive(Clone, Copy)]
pub struct BuilderRegistry<'a> {
    builders: BuildersView<'a>,
    pending: PendingView<'a>,
    slot: &'a SlotState,
}

impl<'a> BuilderRegistry<'a> {
    pub fn of_writer(view: &'a StateWriterView) -> Self {
        Self {
            builders: view.builders.reader(),
            pending: view.pending.reader(),
            slot: view.slot.state(),
        }
    }

    pub fn of_reader(view: &StateReadView<'a>) -> Self {
        Self { builders: view.builders, pending: view.pending, slot: view.slot.state() }
    }

    pub fn builders(&self) -> &BuildersView<'a> {
        &self.builders
    }

    /// Index, version, activity and collateral of an external builder's bid.
    pub fn check_bid(
        &self,
        finalized_epoch: Epoch,
        builder_index: u64,
        value: u64,
    ) -> Result<&'a Builder, BidBuilderError> {
        let builder =
            self.builders.get(builder_index as usize).ok_or(BidBuilderError::OutOfRange {
                index: builder_index,
                count: self.builders.len(),
            })?;
        if !builder.is_active(finalized_epoch) {
            return Err(BidBuilderError::Inactive { index: builder_index });
        }
        if builder.version != PAYLOAD_BUILDER_VERSION {
            return Err(BidBuilderError::Version { index: builder_index, version: builder.version });
        }
        if !self.can_cover_bid(builder_index, value) {
            return Err(BidBuilderError::InsufficientBalance { index: builder_index, value });
        }
        Ok(builder)
    }

    pub fn pending_balance_to_withdraw(&self, builder_index: u64) -> u64 {
        let mut total = 0u64;
        let withdrawals = self.pending.builder_withdrawals;
        for i in 0..withdrawals.len() {
            let w = withdrawals.get(i);
            if w.builder_index == builder_index {
                total += w.amount;
            }
        }
        for payment in self.slot.builder_pending_payments.iter() {
            if payment.withdrawal.builder_index == builder_index {
                total += payment.withdrawal.amount;
            }
        }
        total
    }

    fn can_cover_bid(&self, builder_index: u64, bid_amount: u64) -> bool {
        let balance = self.builders.get(builder_index as usize).map_or(0, |b| b.balance);
        let min_balance = MIN_DEPOSIT_AMOUNT + self.pending_balance_to_withdraw(builder_index);
        balance >= min_balance && balance - min_balance >= bid_amount
    }
}

/// Signing root of a bid whose hash tree root is `bid_root`, under
/// `DOMAIN_BEACON_BUILDER` at the fork of `fork_epoch`.
pub fn bid_signing_root(
    imm: &Immutable,
    epoch: &EpochView,
    bid_root: &B256,
    fork_epoch: Epoch,
) -> B256 {
    let fork_version = epoch.fork_version_at(fork_epoch);
    let domain = compute_domain(DOMAIN_BEACON_BUILDER, fork_version, &imm.genesis_validators_root);
    compute_signing_root(bid_root, &domain)
}
