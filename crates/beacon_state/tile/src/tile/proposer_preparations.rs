use rustc_hash::FxHashMap;
use silver_beacon_state_data::{Epoch, ExecutionAddress};
use silver_common::{ProposerPreparation, hex32};

const RETAINED_EPOCHS: Epoch = 2;

struct Preparation {
    fee_recipient: ExecutionAddress,
    received_epoch: Epoch,
}

#[derive(Default)]
pub(super) struct ProposerPreparations {
    by_index: FxHashMap<u64, Preparation>,
}

impl ProposerPreparations {
    pub(super) fn record(&mut self, encoded: &[u8], epoch: Epoch) {
        for ProposerPreparation { validator_index, fee_recipient } in
            ProposerPreparation::decode_all(encoded)
        {
            let preparation = Preparation { fee_recipient, received_epoch: epoch };
            if let Some(replaced) = self.by_index.insert(validator_index, preparation) &&
                replaced.fee_recipient != fee_recipient
            {
                silver_log::warn!(
                    validator_index,
                    from = hex32(&replaced.fee_recipient),
                    to = hex32(&fee_recipient),
                    "proposer fee recipient changed"
                );
            }
        }
    }

    pub(super) fn fee_recipient(&self, validator_index: u64) -> Option<ExecutionAddress> {
        self.by_index.get(&validator_index).map(|preparation| preparation.fee_recipient)
    }

    pub(super) fn prune(&mut self, epoch: Epoch) {
        let floor = epoch.saturating_sub(RETAINED_EPOCHS);
        self.by_index.retain(|_, preparation| preparation.received_epoch >= floor);
    }
}
