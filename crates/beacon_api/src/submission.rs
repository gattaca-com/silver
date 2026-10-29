use std::time::{Duration, Instant};

use serde::Deserialize;
use silver_beacon_state_data::{B256, Slot, SpecConfig};
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
    if !reads_submission(req, resp) {
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
    if !reads_submission(req, resp) {
        return;
    }
    match serde_json::from_slice::<T>(req.body) {
        Ok(entry) => submit(ctx, resp, 0, entry),
        Err(_) => resp.error(400, "invalid request body"),
    }
}

fn reads_submission(req: &Request<'_>, resp: &mut Response<'_>) -> bool {
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
    pub(crate) integration: Integration,
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

/// What a broadcast submission's answer waits on: 200 once integrated, 202
/// once broadcast but not integrated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Integration {
    #[default]
    Integrated,
    BroadcastOnly,
    AwaitingEnvelopeCheck,
    AwaitingImport(AwaitedImport),
}

impl Integration {
    pub(crate) fn of(integrated: bool) -> Self {
        if integrated { Self::Integrated } else { Self::BroadcastOnly }
    }

    pub(crate) fn is_settled(&self) -> bool {
        matches!(self, Self::Integrated | Self::BroadcastOnly)
    }

    pub(crate) fn awaits_import(&self) -> bool {
        matches!(self, Self::AwaitingImport(_))
    }

    /// An import is settled by what `imports` holds for its block, or by
    /// its deadline.
    pub(crate) fn update(&mut self, imports: &RecentImports, now: Instant) {
        if let Self::AwaitingImport(import) = self &&
            let Some(integrated) = import.integrated(imports, now)
        {
            *self = Self::of(integrated);
        }
    }

    /// A published block's verdict names it; one that names none cannot be
    /// followed, so it is known only to be broadcast.
    pub(crate) fn on_published(&mut self, block_root: Option<B256>) {
        if let Self::AwaitingImport(import) = self {
            match block_root {
                Some(block_root) => import.block_root = Some(block_root),
                None => *self = Self::BroadcastOnly,
            }
        }
    }
}

/// Its root comes with the block's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AwaitedImport {
    block_root: Option<B256>,
    awaits_execution: bool,
    deadline: Instant,
}

impl AwaitedImport {
    /// A quarter slot answers within helix's 4 s publish timeout and
    /// Lighthouse's half slot, so a late import reaches them as a 202. A Gloas
    /// block carries no payload.
    pub(crate) fn of_block(slot: Slot, spec: &SpecConfig, now: Instant) -> Self {
        Self {
            block_root: None,
            awaits_execution: !spec.is_gloas_at_slot(slot),
            deadline: now + Duration::from_millis(spec.seconds_per_slot() * 1000 / 4),
        }
    }

    /// `Some(true)` once integrated, `Some(false)` once it cannot be in time.
    /// An EL still syncing leaves the block optimistically imported.
    fn integrated(&self, imports: &RecentImports, now: Instant) -> Option<bool> {
        if let Some(progress) = self.block_root.and_then(|root| imports.get(&root)) {
            if progress.rejected || progress.execution == Some(PayloadValidationStatus::Invalid) {
                return Some(false);
            }
            if progress.imported && (progress.execution.is_some() || !self.awaits_execution) {
                return Some(true);
            }
        }
        (now >= self.deadline).then_some(false)
    }
}

const RECENT_IMPORTS: usize = 32;

/// What happened to the last blocks seen while a publication awaits its
/// import. Its verdict, which names the block, can trail these events.
#[derive(Default)]
pub(crate) struct RecentImports {
    blocks: [ImportProgress; RECENT_IMPORTS],
    next: usize,
}

#[derive(Clone, Copy, Default)]
struct ImportProgress {
    block_root: B256,
    imported: bool,
    execution: Option<PayloadValidationStatus>,
    rejected: bool,
}

impl RecentImports {
    pub(crate) fn on_imported(&mut self, block_root: &B256) {
        self.entry(block_root).imported = true;
    }

    /// Imported before it was published, so its execution was settled then.
    pub(crate) fn on_already_known(&mut self, block_root: &B256) {
        let progress = self.entry(block_root);
        progress.imported = true;
        progress.execution.get_or_insert(PayloadValidationStatus::Valid);
    }

    pub(crate) fn on_rejected(&mut self, block_root: &B256) {
        self.entry(block_root).rejected = true;
    }

    pub(crate) fn on_execution(&mut self, block_root: &B256, status: PayloadValidationStatus) {
        self.entry(block_root).execution = Some(status);
    }

    fn get(&self, block_root: &B256) -> Option<&ImportProgress> {
        self.blocks.iter().find(|progress| progress.block_root == *block_root)
    }

    /// The oldest entry gives way to a block not yet seen.
    fn entry(&mut self, block_root: &B256) -> &mut ImportProgress {
        let at = match self.blocks.iter().position(|progress| progress.block_root == *block_root) {
            Some(at) => at,
            None => {
                let at = self.next;
                self.next = (at + 1) % RECENT_IMPORTS;
                self.blocks[at] = ImportProgress { block_root: *block_root, ..Default::default() };
                at
            }
        };
        &mut self.blocks[at]
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

    fn awaited(awaits_execution: bool, deadline: Instant) -> AwaitedImport {
        AwaitedImport { block_root: Some([1; 32]), awaits_execution, deadline }
    }

    #[test]
    fn block_is_integrated_once_imported_and_executed_in_either_order() {
        let now = Instant::now();
        let import = awaited(true, now + Duration::from_secs(1));

        let mut imports = RecentImports::default();
        imports.on_imported(&[1; 32]);
        assert_eq!(import.integrated(&imports, now), None, "the EL has not answered");
        imports.on_execution(&[1; 32], PayloadValidationStatus::Syncing);
        assert_eq!(import.integrated(&imports, now), Some(true), "optimistic import counts");

        let mut imports = RecentImports::default();
        imports.on_execution(&[1; 32], PayloadValidationStatus::Valid);
        assert_eq!(import.integrated(&imports, now), None, "not yet imported");
        imports.on_imported(&[1; 32]);
        assert_eq!(import.integrated(&imports, now), Some(true));

        let mut imports = RecentImports::default();
        imports.on_imported(&[1; 32]);
        let gloas = awaited(false, now + Duration::from_secs(1));
        assert_eq!(gloas.integrated(&imports, now), Some(true), "Gloas waits on no EL");

        let mut imports = RecentImports::default();
        imports.on_already_known(&[1; 32]);
        assert_eq!(import.integrated(&imports, now), Some(true));
    }

    #[test]
    fn refused_or_late_import_is_not_integrated() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let import = awaited(true, later);

        let mut imports = RecentImports::default();
        imports.on_rejected(&[1; 32]);
        assert_eq!(import.integrated(&imports, now), Some(false));

        let mut imports = RecentImports::default();
        imports.on_imported(&[1; 32]);
        imports.on_execution(&[1; 32], PayloadValidationStatus::Invalid);
        assert_eq!(import.integrated(&imports, now), Some(false));

        let imports = RecentImports::default();
        assert_eq!(import.integrated(&imports, now), None);
        assert_eq!(import.integrated(&imports, later), Some(false), "out of time");
        let unnamed = AwaitedImport { block_root: None, ..import };
        assert_eq!(unnamed.integrated(&imports, now), None, "its verdict has not come");
    }

    #[test]
    fn oldest_import_gives_way_to_a_new_block() {
        let mut imports = RecentImports::default();
        for fill in 0..=RECENT_IMPORTS as u8 {
            imports.on_imported(&[fill; 32]);
        }
        assert!(imports.get(&[0; 32]).is_none());
        assert!(imports.get(&[1; 32]).is_some_and(|progress| progress.imported));
        assert!(imports.get(&[RECENT_IMPORTS as u8; 32]).is_some());
    }
}
