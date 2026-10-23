use silver_beacon_state_data::{B256, Slot};
use silver_common::{ProducedEnvelope, TRead, ssz_view::EXECUTION_PAYLOAD_ENVELOPE_MIN};

use super::super::bid_pool::BidBranch;

const MAX_CACHED_ENVELOPES: usize = 64;

#[derive(Default)]
pub(super) struct LocalPayloads(Vec<CachedPayload>);

struct CachedPayload {
    branch: BidBranch,
    block_root: B256,
    header: [u8; EXECUTION_PAYLOAD_ENVELOPE_MIN],
    payload: TRead,
}

impl LocalPayloads {
    pub(super) fn insert(
        &mut self,
        branch: BidBranch,
        block_root: B256,
        header: [u8; EXECUTION_PAYLOAD_ENVELOPE_MIN],
        payload: TRead,
    ) {
        if self.0.iter().any(|entry| entry.block_root == block_root) {
            return;
        }
        if self.0.len() == MAX_CACHED_ENVELOPES {
            self.0.remove(0);
        }
        self.0.push(CachedPayload { branch, block_root, header, payload });
    }

    pub(super) fn get(&self, slot: Slot, block_root: &B256) -> Option<ProducedEnvelope> {
        let entry = self
            .0
            .iter()
            .find(|entry| entry.branch.slot == slot && entry.block_root == *block_root)?;
        entry.payload.buffer().ok()?;
        Some(ProducedEnvelope { header: entry.header, payload: entry.payload.to_read() })
    }

    pub(super) fn retain_branch(&mut self, slot: Slot, parent_root: B256, parent_hash: B256) {
        self.0.retain(|entry| {
            entry.branch.slot != slot ||
                (entry.branch.parent_root == parent_root &&
                    entry.branch.parent_hash == parent_hash)
        });
    }

    pub(super) fn prune_before(&mut self, slot: Slot) {
        self.0.retain(|entry| entry.branch.slot >= slot);
    }
}
