use silver_beacon_state_data::{B256, BLSPubkey, Epoch, SLOTS_PER_EPOCH, Slot, StateReadView};

use crate::{
    duties::{CURRENTLY_SYNCING, DutyWindow, OutOfWindow, RequestedEpoch},
    response::Response,
    router::Request,
    routes::ApiCtx,
};

/// One entry of `GetProposerDutiesResponse.data` (`ProposerDuty` in
/// `types/duty.yaml`), which v1 and v2 share.
pub(crate) struct ProposerDuty {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) validator_index: u64,
    pub(crate) slot: Slot,
}

pub(crate) fn get_proposer_duties(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    respond_with_proposers(req, ctx, resp, DependentEpoch::Requested);
}

pub(crate) fn get_proposer_duties_v2(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    respond_with_proposers(req, ctx, resp, DependentEpoch::Preceding);
}

fn respond_with_proposers(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
    dependent: DependentEpoch,
) {
    let Some(requested) = RequestedEpoch::parse(req, ctx, resp) else {
        return;
    };
    let read = |view: StateReadView<'_>, head_root| {
        EpochProposers::read(&view, head_root, requested, dependent)
    };
    let Some(answer) = ctx.read_state_or(resp, 503, CURRENTLY_SYNCING, read) else {
        return;
    };
    match answer {
        Ok(proposers) => {
            let execution_optimistic = ctx.node_status.execution_optimistic();
            resp.json_body(|json| {
                json.dependent_envelope(&proposers.dependent_root, execution_optimistic, |json| {
                    json.proposer_duties(&proposers.duties)
                })
            });
        }
        Err(error) => error.respond(resp),
    }
}

/// Every slot of one epoch and who proposes it, with the root the answer
/// depends on.
struct EpochProposers {
    dependent_root: B256,
    duties: Vec<ProposerDuty>,
}

impl EpochProposers {
    fn read(
        view: &StateReadView<'_>,
        head_root: B256,
        requested: RequestedEpoch,
        dependent: DependentEpoch,
    ) -> Result<Self, ProposerError> {
        let epochs_ahead =
            DutyWindow::ProposerLookahead.units_ahead(requested, view.slot.current_epoch())?;
        let dependent_root = dependent
            .root(view, head_root, requested.epoch)
            .ok_or(ProposerError::NoDependentRoot)?;

        let first_slot = requested.epoch * SLOTS_PER_EPOCH;
        let first_entry = epochs_ahead * SLOTS_PER_EPOCH;
        let duties = (0..SLOTS_PER_EPOCH)
            .map(|offset| {
                let validator_index = view
                    .epoch
                    .proposer_at((first_entry + offset) as usize)
                    .expect("the window bounds the lookahead index");
                let ix = usize::try_from(validator_index)
                    .ok()
                    .filter(|&ix| ix < view.validators.count())
                    .ok_or(ProposerError::UnknownProposer)?;
                Ok(ProposerDuty {
                    pubkey: *view.validators.pubkey(ix),
                    validator_index,
                    slot: first_slot + offset,
                })
            })
            .collect::<Result<_, ProposerError>>()?;
        Ok(Self { dependent_root, duties })
    }
}

/// Whose first slot the answer's `dependent_root` is the entry before.
#[derive(Clone, Copy)]
enum DependentEpoch {
    /// The epoch asked about (`apis/validator/duties/proposer.yaml`).
    Requested,
    /// The epoch before it (`proposer.v2.yaml`), which is where EIP-7917's
    /// deterministic lookahead seeded that epoch's proposers — and the reason
    /// a v2 exists at all. Silver holds Fulu states and later ones only, so no
    /// epoch it answers for had its proposers seeded at a different boundary.
    Preceding,
}

impl DependentEpoch {
    /// `get_block_root_at_slot(state, compute_start_slot_at_epoch(epoch) - 1)`,
    /// or the genesis block root on underflow — the entry slot zero records.
    /// A [`Self::Requested`] epoch above the head state's own names a slot
    /// that has not happened, and the endpoint's head-event rule applies
    /// instead: a client matches the answer against `event.block` unless the
    /// head is in the epoch it asked for, so the answer is the head block's
    /// root.
    fn root(self, view: &StateReadView<'_>, head_root: B256, epoch: Epoch) -> Option<B256> {
        let dependent = match self {
            Self::Requested => epoch,
            Self::Preceding => epoch.saturating_sub(1),
        };
        if dependent > view.slot.current_epoch() {
            return Some(head_root);
        }
        view.block_roots
            .recorded_at((dependent * SLOTS_PER_EPOCH).saturating_sub(1), view.slot.slot_number())
    }
}

enum ProposerError {
    OutOfWindow(OutOfWindow),
    /// `block_roots` holds no entry for the slot the dependent root names,
    /// which past genesis it always does — only a state still on slot zero
    /// depends on a block root the state itself does not carry.
    NoDependentRoot,
    /// The lookahead names a validator this state's own registry does not
    /// hold. Nothing a request can send causes it, and leaving the slot out of
    /// the answer would hide a proposal duty.
    UnknownProposer,
}

impl From<OutOfWindow> for ProposerError {
    fn from(out: OutOfWindow) -> Self {
        Self::OutOfWindow(out)
    }
}

impl ProposerError {
    fn respond(self, resp: &mut Response<'_>) {
        match self {
            Self::OutOfWindow(out) => DutyWindow::ProposerLookahead.respond(out, resp),
            Self::NoDependentRoot => resp.error(503, CURRENTLY_SYNCING),
            Self::UnknownProposer => {
                resp.error(500, "proposer lookahead names a validator this state does not hold")
            }
        }
    }
}
