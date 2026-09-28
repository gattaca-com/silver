use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::{
    EnginePreparePayloadReq, EnginePreparePayloadResp, EngineReq, ProduceBlockFailure,
    WithdrawalInline,
};

use super::{BeaconStateTile, Producers};
use crate::stf::{ExpectedWithdrawals, get_expected_withdrawals};

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct PayloadKey {
    slot: Slot,
    parent_root: B256,
}

#[derive(Default)]
pub(super) struct PayloadPreparations {
    next_id: u64,
    prepared_slot: Slot,
    requested: FxHashMap<u64, PayloadKey>,
    payload_ids: FxHashMap<PayloadKey, [u8; 8]>,
}

impl PayloadPreparations {
    fn request(&mut self, slot: Slot, parent_root: B256) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.prepared_slot = slot;
        self.requested.insert(id, PayloadKey { slot, parent_root });
        id
    }

    fn covers(&self, slot: Slot, parent_root: B256) -> bool {
        let key = PayloadKey { slot, parent_root };
        self.payload_ids.contains_key(&key) || self.requested.values().any(|k| *k == key)
    }

    pub(super) fn on_response(&mut self, response: EnginePreparePayloadResp) {
        let Some(key) = self.requested.remove(&response.id) else {
            return;
        };
        if let Some(payload_id) = response.payload_id {
            self.payload_ids.insert(key, payload_id);
        }
    }

    pub(super) fn payload_id(&self, slot: Slot, parent_root: B256) -> Option<[u8; 8]> {
        self.payload_ids.get(&PayloadKey { slot, parent_root }).copied()
    }

    pub(super) fn prune_before(&mut self, slot: Slot) {
        self.requested.retain(|_, key| key.slot >= slot);
        self.payload_ids.retain(|key, _| key.slot >= slot);
    }
}

impl BeaconStateTile {
    /// The head state's lookahead entry for `slot`.
    pub(super) fn proposer_on_head(&self, slot: Slot) -> Option<u64> {
        let head = self.state.read_view(self.last_applied);
        let head_epoch_start = head.slot.state().slot / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;
        let proposer = head.epoch.proposer_at(slot.checked_sub(head_epoch_start)? as usize);
        if proposer.is_none() {
            silver_log::error!(slot, "proposer lookahead does not reach the slot");
        }
        proposer
    }

    /// Starts the EL building a payload for `slot` on the head, when a
    /// registered validator proposes it. Returns the preparation's request id.
    pub(super) fn prepare_payload(
        &mut self,
        slot: Slot,
        producers: &mut Producers,
    ) -> Result<u64, ProduceBlockFailure> {
        if self.spec.is_gloas_at_slot(slot) {
            return Err(ProduceBlockFailure::SlotNotProposable);
        }
        let (head_root, head_block_hash, safe_block_hash, finalized_block_hash) =
            self.fork_choice.fcu_execution_hashes();
        if head_root != self.head_block_root() {
            silver_log::warn!(slot, "head state does not follow fork choice; payload not prepared");
            return Err(ProduceBlockFailure::Internal);
        }
        if self.payload_preparations.covers(slot, head_root) {
            return;
        }

        let proposer = self.proposer_on_head(slot).ok_or(ProduceBlockFailure::Internal)?;
        let fee_recipient = self
            .proposer_preparations
            .fee_recipient(proposer)
            .ok_or(ProduceBlockFailure::NoFeeRecipient)?;
        let genesis_time = self.state.read_view(self.last_applied).imm.genesis_time;

        let state_id = self.epoch_start_state(self.last_applied, slot);
        // Never committed: the ring slots it rolls are freed with the tail.
        let fork = self.state.apply_block_view(state_id);
        let prev_randao = fork.view.randao_mixes.at_epoch(slot / SLOTS_PER_EPOCH);
        let ExpectedWithdrawals { withdrawals, .. } = get_expected_withdrawals(&fork.view);

        let mut attrs_withdrawals = [WithdrawalInline::default(); 16];
        for (inline, withdrawal) in attrs_withdrawals.iter_mut().zip(withdrawals.iter()) {
            *inline = WithdrawalInline {
                index: withdrawal.index,
                validator_index: withdrawal.validator_index,
                amount: withdrawal.amount,
                address: withdrawal.address,
            };
        }

        let id = self.payload_preparations.request(slot, head_root);
        producers.produce(EngineReq::PreparePayload(EnginePreparePayloadReq {
            id,
            head_block_hash,
            safe_block_hash,
            finalized_block_hash,
            attrs_timestamp: genesis_time + slot * self.spec.seconds_per_slot(),
            attrs_prev_randao: prev_randao,
            attrs_fee_recipient: fee_recipient,
            attrs_parent_beacon_block_root: head_root,
            attrs_withdrawal_count: withdrawals.len() as u8,
            attrs_withdrawals,
        }));

        silver_log::info!(slot, proposer, "payload preparation requested");
        Ok(id)
    }

    pub(super) fn prepare_payload_on_new_head(&mut self, producers: &mut Producers) {
        let slot = self.payload_preparations.prepared_slot;
        if slot > self.ticker.current_slot() {
            self.prepare_payload(slot, producers);
        }
    }
}
