use serde::Deserialize;
use silver_common::{GossipTopic, LocalGossipFailure, TCacheRead, ssz_view::ATTESTATION_DATA_SIZE};

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{Hex, Uint64, each_body_entry},
        response::Response,
        router::Request,
    },
};

pub(crate) fn post_submission<'a, T: Deserialize<'a> + SubmittedEntry>(
    req: &Request<'a>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if !req.body_is_json() {
        resp.error(415, "only application/json bodies are read");
        return;
    }
    if !ctx.follows_chain(resp) {
        return;
    }

    let parsed = each_body_entry(req.body, |body_index, entry: T| match entry.accept(ctx) {
        Ok(topic) => {
            resp.await_verdict(body_index, topic, entry.ssz_len(), |out| entry.encode(out))
        }
        Err(message) => resp.fail_entry(body_index, message),
    });
    match parsed {
        Err(message) => resp.error(400, message),
        Ok(0) => resp.error(400, "the body must name at least one entry"),
        Ok(_) => {}
    }
}

/// A body entry this node can publish.
pub(crate) trait SubmittedEntry {
    /// The topic the entry is published on, or why it is not.
    fn accept(&self, ctx: &ApiCtx) -> Result<GossipTopic, &'static str>;

    fn ssz_len(&self) -> usize;

    /// `out` is [`SubmittedEntry::ssz_len`] bytes holding whatever the tcache
    /// last carried there.
    fn encode(&self, out: &mut [u8]);
}

/// An entry encoded into the submissions tcache, awaiting its verdict.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AcceptedEntry {
    pub(crate) body_index: usize,
    pub(crate) topic: GossipTopic,
    pub(crate) ssz: TCacheRead,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SubmissionFailure {
    pub(crate) body_index: usize,
    pub(crate) message: &'static str,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Submission {
    pub(crate) accepted: Vec<AcceptedEntry>,
    pub(crate) failures: Vec<SubmissionFailure>,
}

#[derive(Deserialize)]
pub(crate) struct SubmittedData {
    pub(crate) slot: Uint64,
    index: Uint64,
    beacon_block_root: Hex<32>,
    source: SubmittedCheckpoint,
    target: SubmittedCheckpoint,
}

#[derive(Deserialize)]
struct SubmittedCheckpoint {
    epoch: Uint64,
    root: Hex<32>,
}

impl SubmittedData {
    pub(crate) fn encode(&self, out: &mut [u8; ATTESTATION_DATA_SIZE]) {
        out[0..8].copy_from_slice(&self.slot.0.to_le_bytes());
        out[8..16].copy_from_slice(&self.index.0.to_le_bytes());
        out[16..48].copy_from_slice(&self.beacon_block_root.0);
        out[48..56].copy_from_slice(&self.source.epoch.0.to_le_bytes());
        out[56..88].copy_from_slice(&self.source.root.0);
        out[88..96].copy_from_slice(&self.target.epoch.0.to_le_bytes());
        out[96..128].copy_from_slice(&self.target.root.0);
    }
}

pub(crate) fn failure_message(failure: LocalGossipFailure) -> &'static str {
    match failure {
        LocalGossipFailure::NotSynced => "the node is not synced",
        LocalGossipFailure::BeforeStartupFloor => "older than the node's startup floor",
        LocalGossipFailure::TooOld => "too old to publish",
        LocalGossipFailure::Future => "too far in the future to publish",
        LocalGossipFailure::ConflictingAttestation => {
            "this validator already attested to another block for the slot"
        }
        LocalGossipFailure::TimedOut => "validation did not complete in time",
        LocalGossipFailure::Invalid => "rejected as invalid",
        LocalGossipFailure::Unverifiable => {
            "the node does not know the attested block, its target or the committee"
        }
        LocalGossipFailure::Internal => "the node could not publish it",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use silver_beacon_state_data::{BeaconStateOwner, SLOTS_PER_EPOCH, SpecConfig};
    use silver_common::SyncUpdate;

    use crate::ctx::{ApiCtx, test_ctx};

    const ACTIVE: usize = 4;
    pub(crate) const SLOT: u64 = 300 * SLOTS_PER_EPOCH + 5;

    /// A following node with the submitted slot's shuffling posted.
    pub(crate) fn ctx() -> ApiCtx {
        let owner = BeaconStateOwner::published_empty_test(SLOT);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx.shufflings.record(SLOT / SLOTS_PER_EPOCH, &[0u8; ACTIVE * size_of::<u32>()]);
        ctx
    }

    /// How many committees the posted active set shuffles into, which bounds
    /// the committee index a submission may name.
    pub(crate) fn posted_committees(ctx: &ApiCtx) -> u64 {
        ctx.shufflings
            .committees_per_slot(SLOT / SLOTS_PER_EPOCH)
            .expect("the fixture posts a shuffling")
    }
}
