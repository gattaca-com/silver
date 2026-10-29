use std::time::Instant;

use serde::Deserialize;
use silver_beacon_state_data::B256;
use silver_common::{
    BroadcastValidation, GossipTopic, LocalGossipFailure, PayloadValidationStatus, TCacheRead,
};

use crate::{
    ctx::ApiCtx,
    http::{ids::each_body_entry, response::Response, router::Request},
};

pub(crate) fn post_submission<'a, T: Deserialize<'a> + SubmittedEntry>(
    req: &Request<'a>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if !reads_submission(req, ctx, resp) {
        return;
    }
    let parsed =
        each_body_entry(req.body, |body_index, entry: T| submit(ctx, resp, body_index, entry));
    match parsed {
        Err(message) => resp.error(400, message),
        Ok(0) => resp.error(400, "the body must name at least one entry"),
        Ok(_) => {}
    }
}

/// For endpoints whose body is one entry, not an array. It answers as entry 0
/// of an array would; the indexed 400 still carries `ErrorMessage`'s fields.
pub(crate) fn post_single_submission<'a, T: Deserialize<'a> + SubmittedEntry>(
    req: &Request<'a>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    if !reads_submission(req, ctx, resp) {
        return;
    }
    match serde_json::from_slice::<T>(req.body) {
        Ok(entry) => submit(ctx, resp, 0, entry),
        Err(_) => resp.error(400, "invalid request body"),
    }
}

fn reads_submission(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) -> bool {
    if !ctx.follows_chain(resp) {
        return false;
    }
    if !req.body_is_json() {
        resp.error(415, "only application/json bodies are read");
        return false;
    }
    true
}

fn submit(ctx: &ApiCtx, resp: &mut Response<'_>, body_index: usize, entry: impl SubmittedEntry) {
    match entry.accept(ctx) {
        Ok(topics) => {
            resp.await_verdicts(body_index, topics, entry.ssz_len(), |out| entry.encode(out))
        }
        Err(message) => resp.fail_entry(body_index, message),
    }
}

/// A body entry this node can publish.
pub(crate) trait SubmittedEntry {
    /// The topics the entry is published on, or why it is not.
    fn accept(&self, ctx: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str>;

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
    pub(crate) forward: Option<BuilderForward>,
    pub(crate) validation: BroadcastValidation,
    pub(crate) envelope: Option<EnvelopePublication>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EnvelopePublication {
    pub(crate) blob_data_included: bool,
}

/// `None` for a level the schema does not define.
pub(crate) fn requested_validation(req: &Request<'_>) -> Option<BroadcastValidation> {
    match req.query_value("broadcast_validation").as_deref() {
        None | Some("gossip") => Some(BroadcastValidation::Gossip),
        Some("consensus") => Some(BroadcastValidation::Consensus),
        Some("consensus_and_equivocation") => Some(BroadcastValidation::ConsensusAndEquivocation),
        _ => None,
    }
}

/// A published block's import, which its 200 waits on: a block broadcast but
/// not integrated is answered 202.
#[derive(Debug)]
pub(crate) struct AwaitedImport {
    block_root: B256,
    imported: bool,
    /// `None` until the EL answers; a Gloas block carries no payload.
    execution: Option<PayloadValidationStatus>,
    rejected: bool,
    deadline: Instant,
}

impl AwaitedImport {
    pub(crate) fn new(block_root: B256, awaits_execution: bool, deadline: Instant) -> Self {
        let execution = (!awaits_execution).then_some(PayloadValidationStatus::Valid);
        Self { block_root, imported: false, execution, rejected: false, deadline }
    }

    pub(crate) fn names(&self, block_root: &B256) -> bool {
        self.block_root == *block_root
    }

    pub(crate) fn on_imported(&mut self) {
        self.imported = true;
    }

    /// Imported before it was published, so its execution was settled then.
    pub(crate) fn on_already_known(&mut self) {
        self.imported = true;
        self.execution.get_or_insert(PayloadValidationStatus::Valid);
    }

    pub(crate) fn on_rejected(&mut self) {
        self.rejected = true;
    }

    pub(crate) fn on_execution(&mut self, status: PayloadValidationStatus) {
        self.execution = Some(status);
    }

    /// `Some(true)` once integrated, `Some(false)` once it cannot be in time.
    /// An EL still syncing leaves the block optimistically imported.
    pub(crate) fn integrated(&self, now: Instant) -> Option<bool> {
        if self.rejected || self.execution == Some(PayloadValidationStatus::Invalid) {
            return Some(false);
        }
        if self.imported && self.execution.is_some() {
            return Some(true);
        }
        (now >= self.deadline).then_some(false)
    }
}

/// A block for the builder whose bid it commits to, sent once every verdict
/// accepts it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuilderForward {
    pub(crate) url: Box<str>,
    pub(crate) ssz: TCacheRead,
}

impl Submission {
    pub(crate) fn body_len(&self) -> usize {
        let accepted = self.accepted.iter().map(|entry| entry.body_index);
        let failed = self.failures.iter().map(|failure| failure.body_index);
        accepted.chain(failed).max().map_or(0, |last| last + 1)
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
        LocalGossipFailure::ConflictingProposal => {
            "this validator already proposed a block for the slot"
        }
        LocalGossipFailure::TimedOut => "validation did not complete in time",
        LocalGossipFailure::Invalid => "rejected as invalid",
        LocalGossipFailure::Unverifiable => {
            "the node cannot verify it against its view of the chain"
        }
        LocalGossipFailure::Internal => "the node could not publish it",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use silver_beacon_state_data::{BeaconStateOwner, SLOTS_PER_EPOCH, ShufflingId, SpecConfig};
    use silver_common::SyncUpdate;

    use super::*;
    use crate::ctx::{ApiCtx, test_ctx};

    const ACTIVE: usize = 4;
    pub(crate) const SLOT: u64 = 300 * SLOTS_PER_EPOCH + 5;

    /// A following node with the submitted slot's shuffling posted.
    pub(crate) fn ctx() -> ApiCtx {
        let owner = BeaconStateOwner::published_empty_test(SLOT);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        let id =
            ctx.read_state(|view| ShufflingId::from_state(&view, SLOT / SLOTS_PER_EPOCH).unwrap());
        ctx.shufflings.record(id, &[0u8; ACTIVE * size_of::<u32>()]);
        ctx
    }

    /// How many committees the posted active set shuffles into, which bounds
    /// the committee index a submission may name.
    pub(crate) fn posted_committees(ctx: &ApiCtx) -> u64 {
        ctx.read_state(|view| ctx.shufflings.committees_per_slot(&view, SLOT / SLOTS_PER_EPOCH))
            .expect("the fixture posts a shuffling")
    }

    #[test]
    fn block_is_integrated_once_imported_and_executed_in_either_order() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut import = AwaitedImport::new([1; 32], true, later);
        import.on_imported();
        assert_eq!(import.integrated(now), None, "the EL has not answered");
        import.on_execution(PayloadValidationStatus::Syncing);
        assert_eq!(import.integrated(now), Some(true), "optimistic import counts");

        let mut import = AwaitedImport::new([1; 32], true, later);
        import.on_execution(PayloadValidationStatus::Valid);
        assert_eq!(import.integrated(now), None, "not yet imported");
        import.on_imported();
        assert_eq!(import.integrated(now), Some(true));

        let mut gloas = AwaitedImport::new([1; 32], false, later);
        gloas.on_imported();
        assert_eq!(gloas.integrated(now), Some(true), "Gloas waits on no EL");

        let mut known = AwaitedImport::new([1; 32], true, later);
        known.on_already_known();
        assert_eq!(known.integrated(now), Some(true));
    }

    #[test]
    fn refused_or_late_import_is_not_integrated() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let mut rejected = AwaitedImport::new([1; 32], true, later);
        rejected.on_rejected();
        assert_eq!(rejected.integrated(now), Some(false));

        let mut refused = AwaitedImport::new([1; 32], true, later);
        refused.on_imported();
        refused.on_execution(PayloadValidationStatus::Invalid);
        assert_eq!(refused.integrated(now), Some(false));

        let waiting = AwaitedImport::new([1; 32], true, later);
        assert_eq!(waiting.integrated(now), None);
        assert_eq!(waiting.integrated(later), Some(false), "out of time");
    }
}
