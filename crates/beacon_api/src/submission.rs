use std::time::{Duration, Instant};

use serde::Deserialize;
use silver_beacon_state_data::{B256, Slot, SpecConfig};
use silver_common::{
    BroadcastValidation, GossipTopic, LocalGossipFailure, PayloadValidationStatus, TCacheRead,
    ssz_hash::HashedBody,
};

use crate::{
    ctx::ApiCtx,
    entry_signatures::SignatureCheck,
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
        Err(message) => return resp.error(400, message),
        Ok(0) => return resp.error(400, "the body must name at least one entry"),
        Ok(_) => {}
    }
    resp.fail_forged();
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
    let Ok(entry) = serde_json::from_slice::<T>(req.body) else {
        return resp.error(400, "invalid request body");
    };
    submit(ctx, resp, 0, entry);
    resp.fail_forged();
}

fn reads_submission(req: &Request<'_>, resp: &mut Response<'_>) -> bool {
    if !req.body_is_json() {
        resp.error(415, "only application/json bodies are read");
        return false;
    }
    true
}

fn submit(ctx: &ApiCtx, resp: &mut Response<'_>, body_index: usize, entry: impl SubmittedEntry) {
    let topics = match entry.accept(ctx) {
        Ok(topics) => topics,
        Err(message) => return resp.fail_entry(body_index, message),
    };
    let check = match entry.signature_check(ctx) {
        Ok(check) => check,
        Err(message) => return resp.fail_entry(body_index, message),
    };
    let signature_verified = check.is_some();
    let encode = |out: &mut [u8]| entry.encode(out);
    if resp.await_verdicts(body_index, topics, signature_verified, entry.ssz_len(), encode) &&
        let Some(check) = check
    {
        resp.await_signature(body_index, check);
    }
}

pub(crate) trait SubmittedEntry {
    /// The topics the entry is published on, or why it is not.
    fn accept(&self, ctx: &ApiCtx) -> Result<impl IntoIterator<Item = GossipTopic>, &'static str>;

    /// The signature to verify before the entry reaches a slashing-protection
    /// lock.
    fn signature_check(&self, _ctx: &ApiCtx) -> Result<Option<SignatureCheck>, &'static str> {
        Ok(None)
    }

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
    pub(crate) signature_verified: bool,
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
    pub(crate) hashed_body: Option<HashedBody>,
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
    /// A published block, whose root comes with its verdict.
    AwaitingImport {
        block_root: Option<B256>,
        awaits_execution: bool,
        deadline: Instant,
    },
}

impl Integration {
    /// A quarter slot answers within helix's 4 s publish timeout and
    /// Lighthouse's half slot, so a late import reaches them as a 202. A Gloas
    /// block carries no payload.
    pub(crate) fn import_of_block(slot: Slot, spec: &SpecConfig, now: Instant) -> Self {
        Self::AwaitingImport {
            block_root: None,
            awaits_execution: !spec.is_gloas_at_slot(slot),
            deadline: now + Duration::from_millis(spec.seconds_per_slot() * 1000 / 4),
        }
    }

    pub(crate) fn awaits_import(&self) -> bool {
        matches!(self, Self::AwaitingImport { .. })
    }

    /// An import is integrated once imported and, before Gloas, executed;
    /// an EL still syncing leaves it optimistically imported. It is only
    /// broadcast once rejected, or once its deadline passes.
    pub(crate) fn update(&mut self, imports: &RecentImports, now: Instant) {
        let Self::AwaitingImport { block_root, awaits_execution, deadline } = *self else {
            return;
        };
        if let Some(progress) = block_root.and_then(|root| imports.get(&root)) {
            if progress.rejected || progress.execution == Some(PayloadValidationStatus::Invalid) {
                *self = Self::BroadcastOnly;
                return;
            }
            if progress.imported && (progress.execution.is_some() || !awaits_execution) {
                *self = Self::Integrated;
                return;
            }
        }
        if now >= deadline {
            *self = Self::BroadcastOnly;
        }
    }

    /// A published block's verdict names it; one that names none cannot be
    /// followed, so it is known only to be broadcast.
    pub(crate) fn on_published(&mut self, published_root: Option<B256>) {
        if let Self::AwaitingImport { block_root, .. } = self {
            match published_root {
                Some(root) => *block_root = Some(root),
                None => *self = Self::BroadcastOnly,
            }
        }
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
    /// `body_indices` ascend, as entries are accepted in body order.
    pub(crate) fn fail_accepted(&mut self, body_indices: &[usize], message: &'static str) {
        debug_assert!(body_indices.is_sorted());
        if body_indices.is_empty() {
            return;
        }
        self.accepted.retain(|entry| body_indices.binary_search(&entry.body_index).is_err());
        let failures =
            body_indices.iter().map(|&body_index| SubmissionFailure { body_index, message });
        self.failures.extend(failures);
    }

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

    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, Immutable, SLOTS_PER_EPOCH,
        ShufflingId, SpecConfig, ValSeed,
        bls::{
            self,
            test_keys::{privkey, sign},
        },
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::ctx::{ApiCtx, test_ctx};

    const ACTIVE: usize = 4;
    pub(crate) const SLOT: u64 = 300 * SLOTS_PER_EPOCH + 5;

    /// `ACTIVE` validators that sign with [`validator_signature`].
    pub(crate) fn signing_state(slot: u64) -> BeaconStateOwner {
        let seeds: Vec<_> = (0..ACTIVE)
            .map(|index| ValSeed {
                pubkey: privkey(index).sk_to_pk().to_bytes(),
                activation_epoch: 0,
                ..ValSeed::default()
            })
            .collect();
        let mut owner = BeaconStateOwner::new(BeaconState::for_test(
            EpochStateFinalized::default(),
            &seeds,
            slot,
        ));
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        owner
    }

    pub(crate) fn validator_signature(
        spec: &SpecConfig,
        index: u64,
        domain_type: u32,
        epoch: u64,
        object_root: &B256,
    ) -> [u8; 96] {
        let genesis_validators_root = Immutable::default().genesis_validators_root;
        let domain =
            bls::compute_domain(domain_type, spec.fork_version_at(epoch), &genesis_validators_root);
        let signing_root = bls::compute_signing_root(object_root, &domain);
        sign(index as usize, &signing_root)
    }

    /// A following node with the submitted slot's shuffling posted.
    pub(crate) fn ctx() -> ApiCtx {
        let owner = signing_state(SLOT);
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

    fn awaited(awaits_execution: bool, deadline: Instant) -> Integration {
        Integration::AwaitingImport { block_root: Some([1; 32]), awaits_execution, deadline }
    }

    fn updated(mut import: Integration, imports: &RecentImports, now: Instant) -> Integration {
        import.update(imports, now);
        import
    }

    #[test]
    fn block_is_integrated_once_imported_and_executed_in_either_order() {
        let now = Instant::now();
        let import = awaited(true, now + Duration::from_secs(1));

        let mut imports = RecentImports::default();
        imports.on_imported(&[1; 32]);
        assert_eq!(updated(import, &imports, now), import, "the EL has not answered");
        imports.on_execution(&[1; 32], PayloadValidationStatus::Syncing);
        let integrated = updated(import, &imports, now);
        assert_eq!(integrated, Integration::Integrated, "optimistic import counts");

        let mut imports = RecentImports::default();
        imports.on_execution(&[1; 32], PayloadValidationStatus::Valid);
        assert_eq!(updated(import, &imports, now), import, "not yet imported");
        imports.on_imported(&[1; 32]);
        assert_eq!(updated(import, &imports, now), Integration::Integrated);

        let mut imports = RecentImports::default();
        imports.on_imported(&[1; 32]);
        let gloas = awaited(false, now + Duration::from_secs(1));
        assert_eq!(updated(gloas, &imports, now), Integration::Integrated, "Gloas waits on no EL");

        let mut imports = RecentImports::default();
        imports.on_already_known(&[1; 32]);
        assert_eq!(updated(import, &imports, now), Integration::Integrated);
    }

    #[test]
    fn refused_or_late_import_is_not_integrated() {
        let now = Instant::now();
        let later = now + Duration::from_secs(1);
        let import = awaited(true, later);

        let mut imports = RecentImports::default();
        imports.on_rejected(&[1; 32]);
        assert_eq!(updated(import, &imports, now), Integration::BroadcastOnly);

        let mut imports = RecentImports::default();
        imports.on_imported(&[1; 32]);
        imports.on_execution(&[1; 32], PayloadValidationStatus::Invalid);
        assert_eq!(updated(import, &imports, now), Integration::BroadcastOnly);

        let imports = RecentImports::default();
        assert_eq!(updated(import, &imports, now), import);
        assert_eq!(updated(import, &imports, later), Integration::BroadcastOnly, "out of time");
        let unnamed = Integration::AwaitingImport {
            block_root: None,
            awaits_execution: true,
            deadline: later,
        };
        assert_eq!(updated(unnamed, &imports, now), unnamed, "its verdict has not come");
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
