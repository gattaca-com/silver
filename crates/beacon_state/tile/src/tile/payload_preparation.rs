use flux::spine::SpineProducers;
use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, Slot};
use silver_common::{
    EnginePreparePayloadReq, EnginePreparePayloadResp, EngineReq, WithdrawalInline,
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
    requested: FxHashMap<u64, PayloadKey>,
    payload_ids: FxHashMap<PayloadKey, [u8; 8]>,
}

impl PayloadPreparations {
    fn request(&mut self, slot: Slot, parent_root: B256) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.requested.insert(id, PayloadKey { slot, parent_root });
        id
    }

    pub(super) fn on_response(&mut self, response: EnginePreparePayloadResp) {
        let Some(key) = self.requested.remove(&response.id) else {
            return;
        };
        if let Some(payload_id) = response.payload_id {
            self.payload_ids.insert(key, payload_id);
        }
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "block production reads it next"))]
    pub(super) fn payload_id(&self, slot: Slot, parent_root: B256) -> Option<[u8; 8]> {
        self.payload_ids.get(&PayloadKey { slot, parent_root }).copied()
    }

    pub(super) fn prune_before(&mut self, slot: Slot) {
        self.requested.retain(|_, key| key.slot >= slot);
        self.payload_ids.retain(|key, _| key.slot >= slot);
    }
}

impl BeaconStateTile {
    /// Starts the EL building a payload for `slot` on the head, when a
    /// registered validator proposes it.
    pub(super) fn prepare_payload(&mut self, slot: Slot, producers: &mut Producers) {
        if self.spec.is_gloas_at_slot(slot) {
            return;
        }
        let (head_root, head_block_hash, safe_block_hash, finalized_block_hash) =
            self.fork_choice.fcu_execution_hashes();
        if head_root != self.head_block_root() {
            tracing::warn!(slot, "head state does not follow fork choice; payload not prepared");
            return;
        }

        let head = self.state.read_view(self.last_applied);
        let head_epoch_start = head.slot.state().slot / SLOTS_PER_EPOCH * SLOTS_PER_EPOCH;
        let Some(proposer) = head.epoch.proposer_at((slot - head_epoch_start) as usize) else {
            tracing::error!(slot, "proposer lookahead does not reach the next slot");
            return;
        };
        let Some(fee_recipient) = self.proposer_preparations.fee_recipient(proposer) else {
            return;
        };
        let genesis_time = head.imm.genesis_time;

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
            attrs_timestamp: genesis_time + slot * self.spec.slot_duration_ms() / 1000,
            attrs_prev_randao: prev_randao,
            attrs_fee_recipient: fee_recipient,
            attrs_parent_beacon_block_root: head_root,
            attrs_withdrawal_count: withdrawals.len() as u8,
            attrs_withdrawals,
        }));
        tracing::info!(slot, proposer, "payload preparation requested");
    }
}
