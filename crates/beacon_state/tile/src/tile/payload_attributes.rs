use flux::spine::SpineProducers;
use silver_beacon_state_data::{
    B256, ExecutionAddress, ForkWriter, PayloadWithdrawals, SLOTS_PER_EPOCH, Slot, SpecConfig,
    Withdrawal,
};
use silver_common::{
    BeaconStateEvent, PreparedPayloadAttributes, ProduceBlockFailure, TCacheProducer, TCacheRead,
    ssz_hash_gloas::ExecutionRequestsView, ssz_view::WITHDRAWAL_SIZE,
};

use super::{BeaconStateTile, Producers};
use crate::stf::{self, get_expected_withdrawals};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PayloadContext {
    pub(super) head_block_hash: B256,
    pub(super) fee_recipient: ExecutionAddress,
    pub(super) target_gas_limit: u64,
    pub(super) is_gloas: bool,
    pub(super) full_parent: bool,
}

/// What resolves without touching state, so a repeat is caught before the
/// withdrawal sweep.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct PayloadBasis {
    pub(super) slot: Slot,
    pub(super) proposer: u64,
    pub(super) local_proposer: bool,
    pub(super) head_root: B256,
    pub(super) safe_block_hash: B256,
    pub(super) finalized_block_hash: B256,
    pub(super) parent_block_number: Option<u64>,
    pub(super) timestamp: u64,
    pub(super) context: PayloadContext,
}

#[derive(Clone, Copy)]
pub(super) struct PayloadInputs {
    pub(super) prev_randao: B256,
    pub(super) withdrawals: PayloadWithdrawals,
}

/// Attributes published for slots no local validator proposes, while the API
/// has `payload_attributes` subscribers.
#[derive(Default)]
pub(super) struct PayloadAttributesFeed {
    wanted: bool,
    announced: Option<(PayloadBasis, PayloadInputs)>,
}

impl PayloadBasis {
    /// RANDAO and withdrawals do not depend on who is paid.
    fn shares_inputs_with(&self, other: &PayloadBasis) -> bool {
        self.slot == other.slot &&
            self.head_root == other.head_root &&
            self.context.is_gloas == other.context.is_gloas &&
            self.context.full_parent == other.context.full_parent
    }
}

impl BeaconStateTile {
    /// `fallback_fee_recipient` pays when the proposer named none.
    pub(super) fn payload_basis(
        &self,
        slot: Slot,
        fallback_fee_recipient: ExecutionAddress,
    ) -> Result<PayloadBasis, ProduceBlockFailure> {
        if slot <= self.last_applied_block_slot() {
            return Err(ProduceBlockFailure::SlotNotProposable);
        }
        let (head_root, head_block_hash, safe_block_hash, finalized_block_hash) =
            self.fork_choice.fcu_execution_hashes();
        if head_root != self.head_block_root() {
            silver_log::warn!(slot, "head state does not follow fork choice; payload not prepared");
            return Err(ProduceBlockFailure::Internal);
        }
        let proposer = self.proposer_on_head(slot).ok_or(ProduceBlockFailure::Internal)?;

        let is_gloas = self.spec.is_gloas_at_slot(slot);
        let (head_block_hash, full_parent) = if is_gloas {
            self.execution_parent(slot, head_root)?
        } else {
            (head_block_hash, true)
        };

        let dependent_root = self.preferences_dependent_root(slot, head_root);
        let preferences =
            dependent_root.and_then(|root| self.seen_proposer_preferences.get(slot, &root));
        let local_preferences =
            dependent_root.is_some_and(|root| self.seen_proposer_preferences.is_local(slot, &root));
        let registered = self.proposer_preparations.fee_recipient(proposer);
        let fee_recipient = preferences
            .map(|prefs| prefs.fee_recipient)
            .or(registered)
            .unwrap_or(fallback_fee_recipient);
        let target_gas_limit = match preferences {
            _ if !is_gloas => 0,
            Some(prefs) => prefs.target_gas_limit,
            None => self.head_gas_limit(),
        };

        let head = self.state.read_view(self.last_applied);
        let parent_block_number =
            (!is_gloas).then(|| head.slot.state().latest_execution_payload_header.block_number);
        Ok(PayloadBasis {
            slot,
            proposer,
            local_proposer: local_preferences || registered.is_some(),
            head_root,
            safe_block_hash,
            finalized_block_hash,
            parent_block_number,
            timestamp: head.imm.genesis_time + slot * self.spec.seconds_per_slot(),
            context: PayloadContext {
                head_block_hash,
                fee_recipient,
                target_gas_limit,
                is_gloas,
                full_parent,
            },
        })
    }

    /// `None` before Gloas, which has no proposer preferences.
    fn preferences_dependent_root(&self, slot: Slot, head_root: B256) -> Option<B256> {
        if !self.spec.is_gloas_at_slot(slot) {
            return None;
        }
        self.fork_choice.shuffling_dependent_root(&head_root, slot / SLOTS_PER_EPOCH)
    }

    fn head_gas_limit(&self) -> u64 {
        let head = self.state.read_view(self.last_applied);
        if head.is_gloas() {
            head.slot.state().latest_execution_payload_bid.gas_limit
        } else {
            head.slot.state().latest_execution_payload_header.gas_limit
        }
    }

    pub(super) fn payload_inputs(
        &mut self,
        basis: &PayloadBasis,
    ) -> Result<PayloadInputs, ProduceBlockFailure> {
        if let Some((announced, inputs)) = &self.payload_attributes_feed.announced &&
            announced.shares_inputs_with(basis)
        {
            return Ok(*inputs);
        }
        let PayloadBasis { slot, head_root, context, .. } = *basis;
        let state_id = self.epoch_start_state(self.last_applied, slot);
        // Never committed: the ring slots it rolls are freed with the tail.
        let mut fork = self.state.apply_block_view(state_id);
        if context.is_gloas {
            stf::process_slots(&self.spec, &mut fork, slot, &mut self.stf_scratch);
        }
        let prev_randao = fork.view.randao_mixes.at_epoch(slot / SLOTS_PER_EPOCH);
        let withdrawals = match (context.is_gloas, context.full_parent) {
            (false, _) => get_expected_withdrawals(&fork.view).withdrawals,
            (true, true) => {
                let requests = self.payload_execution_requests.get(&head_root);
                withdrawals_after_parent_payload(&mut fork, &self.spec, requests, slot)?
            }
            (true, false) => withdrawals_owed_by_empty_parent(&fork),
        };
        Ok(PayloadInputs { prev_randao, withdrawals })
    }

    pub(super) fn publish_payload_attributes(
        &mut self,
        basis: &PayloadBasis,
        inputs: &PayloadInputs,
        producers: &mut Producers,
    ) {
        let mut withdrawals = None;
        if !inputs.withdrawals.is_empty() {
            withdrawals = self.post_withdrawals(basis.slot, &inputs.withdrawals);
            if withdrawals.is_none() {
                return;
            }
        }
        producers.produce(BeaconStateEvent::PayloadAttributes(PreparedPayloadAttributes {
            proposal_slot: basis.slot,
            proposer_index: basis.proposer,
            parent_block_root: basis.head_root,
            parent_block_hash: basis.context.head_block_hash,
            parent_block_number: basis.parent_block_number,
            safe_block_hash: basis.safe_block_hash,
            finalized_block_hash: basis.finalized_block_hash,
            timestamp: basis.timestamp,
            prev_randao: inputs.prev_randao,
            fee_recipient: basis.context.fee_recipient,
            target_gas_limit: basis.context.target_gas_limit,
            withdrawals,
        }));
    }

    fn post_withdrawals(&mut self, slot: Slot, withdrawals: &[Withdrawal]) -> Option<TCacheRead> {
        let len = withdrawals.len() * WITHDRAWAL_SIZE;
        let posted = self.events_producer.write_with(len, |mut out| {
            for withdrawal in withdrawals {
                withdrawal.write_ssz(&mut out).expect("reserved to size");
            }
        });
        if posted.is_none() {
            silver_log::warn!(slot, "beacon_state tcache full; payload attributes not posted");
        }
        posted
    }

    /// The EL builds only for a local proposer; any other slot's attributes
    /// are computed only for subscribers.
    pub(super) fn prepare_or_announce_payload(&mut self, slot: Slot, producers: &mut Producers) {
        let Some(basis) = self.feed_basis(slot) else { return };
        if basis.local_proposer {
            let _ = self.prepare_payload_on(basis, producers);
        } else if self.payload_attributes_feed.wanted {
            self.announce_payload_attributes(basis, producers);
        }
    }

    pub(super) fn set_payload_attributes_wanted(
        &mut self,
        wanted: bool,
        producers: &mut Producers,
    ) {
        self.payload_attributes_feed = PayloadAttributesFeed { wanted, announced: None };
        if wanted && let Some(basis) = self.feed_basis(self.ticker.current_slot() + 1) {
            self.announce_payload_attributes(basis, producers);
        }
    }

    /// A slot the EL is building for is refreshed with its preparation.
    pub(super) fn refresh_payload_attributes(&mut self, producers: &mut Producers) {
        let Some((announced, _)) = self.payload_attributes_feed.announced else { return };
        let slot = announced.slot;
        let current = slot >= self.ticker.current_slot();
        if current &&
            self.block_production.prepared_slot() != Some(slot) &&
            let Some(basis) = self.feed_basis(slot)
        {
            self.announce_payload_attributes(basis, producers);
        }
    }

    /// The fee recipient falls back to the default, then to zero: consumers
    /// are told to ignore it.
    fn feed_basis(&self, slot: Slot) -> Option<PayloadBasis> {
        self.payload_basis(slot, self.default_fee_recipient.unwrap_or_default()).ok()
    }

    fn announce_payload_attributes(&mut self, basis: PayloadBasis, producers: &mut Producers) {
        if self.payload_attributes_feed.announced.is_some_and(|(announced, _)| announced == basis) {
            return;
        }
        let Ok(inputs) = self.payload_inputs(&basis) else { return };
        self.payload_attributes_feed.announced = Some((basis, inputs));
        self.publish_payload_attributes(&basis, &inputs, producers);
    }
}

fn withdrawals_after_parent_payload(
    fork: &mut ForkWriter<'_>,
    spec: &SpecConfig,
    requests: &[u8],
    slot: Slot,
) -> Result<PayloadWithdrawals, ProduceBlockFailure> {
    let parent = fork.view.slot.state();
    if ExecutionRequestsView::hash_tree_root(requests) !=
        parent.latest_execution_payload_bid.execution_requests_root
    {
        silver_log::warn!(slot, "parent execution requests unavailable for payload preparation");
        return Err(ProduceBlockFailure::PayloadUnavailable);
    }
    let parent_slot = parent.latest_block_header.slot;
    let epoch = fork.epoch.view_opt(fork.epoch_idx);
    stf::apply_parent_execution_payload(&mut fork.view, &epoch, spec, requests, parent_slot);
    Ok(stf::get_expected_withdrawals_gloas(&fork.view).withdrawals)
}

fn withdrawals_owed_by_empty_parent(fork: &ForkWriter<'_>) -> PayloadWithdrawals {
    let mut withdrawals = PayloadWithdrawals::new();
    for withdrawal in &fork.view.slot.state().payload_expected_withdrawals {
        withdrawals.push(*withdrawal);
    }
    withdrawals
}
