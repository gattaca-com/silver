use silver_beacon_state_data::{
    BLSPubkey, SYNC_COMMITTEE_SIZE, StateReadView, SyncCommittee, ValidatorsView,
};

use crate::{
    duties::{CURRENTLY_SYNCING, DutyWindow, OutOfWindow, RequestedEpoch},
    ids::{MAX_BODY_IDS, parse_uint64},
    response::Response,
    router::Request,
    routes::ApiCtx,
};

/// One entry of `GetSyncCommitteeDutiesResponse.data` (`Altair.SyncDuty`);
/// `committee_positions` is its `validator_sync_committee_indices`, and is
/// never empty — see [`CommitteeSeats::duty_of`].
pub(crate) struct SyncDuty {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) validator_index: u64,
    pub(crate) committee_positions: Vec<u64>,
}

pub(crate) fn post_sync_duties(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(requested) = RequestedEpoch::parse(req, ctx, resp) else {
        return;
    };
    let indices = match requested_indices(req.body) {
        Ok(indices) => indices,
        Err(message) => {
            resp.error(400, message);
            return;
        }
    };
    let read = |view: StateReadView<'_>, _| {
        CommitteeSeats::serving(&view, requested)
            .map(|seats| seats.duties(&view.validators, &indices))
    };
    let Some(answer) = ctx.read_state_or(resp, 503, CURRENTLY_SYNCING, read) else {
        return;
    };
    match answer {
        Ok(duties) => {
            let execution_optimistic = ctx.node_status.execution_optimistic();
            resp.json_body(|json| {
                json.optimistic_envelope(execution_optimistic, |json| json.sync_duties(&duties))
            });
        }
        Err(out) => DutyWindow::SeatedSyncCommittees.respond(out, resp),
    }
}

/// A sync committee read the direction a duty request needs it: the state
/// holds a position's pubkey, a request names an index, and the registry
/// answers what pubkey that index carries — so `by_pubkey` orders the
/// positions by the pubkey seated there and one validator's seats are a
/// contiguous run of it. Resolving the request's own index rather than the
/// committee's 512 pubkeys also makes the `(validator_index, pubkey)` pair
/// each duty carries agree by construction.
struct CommitteeSeats<'a> {
    committee: &'a SyncCommittee,
    by_pubkey: Vec<u32>,
}

impl<'a> CommitteeSeats<'a> {
    fn serving(view: &StateReadView<'a>, requested: RequestedEpoch) -> Result<Self, OutOfWindow> {
        let periods_ahead =
            DutyWindow::SeatedSyncCommittees.units_ahead(requested, view.slot.current_epoch())?;
        let longtail = view.longtail.state();
        let committee = if periods_ahead == 0 {
            &longtail.current_sync_committee
        } else {
            &longtail.next_sync_committee
        };

        let pubkeys = &committee.pubkeys;
        let mut by_pubkey: Vec<u32> = (0..SYNC_COMMITTEE_SIZE as u32).collect();
        by_pubkey.sort_unstable_by_key(|&position| (&pubkeys[position as usize], position));
        Ok(Self { committee, by_pubkey })
    }

    fn duties(&self, validators: &ValidatorsView<'_>, requested: &[u64]) -> Vec<SyncDuty> {
        requested.iter().filter_map(|&index| self.duty_of(validators, index)).collect()
    }

    /// `None` for an index the registry does not hold and for a validator this
    /// committee does not seat: the schema puts `minItems: 1` on
    /// `validator_sync_committee_indices`, so a non-member is left out of the
    /// response rather than carried with an empty list.
    fn duty_of(&self, validators: &ValidatorsView<'_>, validator_index: u64) -> Option<SyncDuty> {
        let ix = usize::try_from(validator_index).ok().filter(|&ix| ix < validators.count())?;
        let pubkey = validators.pubkey(ix);
        let committee_positions = self.positions_of(pubkey);
        (!committee_positions.is_empty()).then_some(SyncDuty {
            pubkey: *pubkey,
            validator_index,
            committee_positions,
        })
    }

    /// Every seat `pubkey` holds, ascending.
    fn positions_of(&self, pubkey: &BLSPubkey) -> Vec<u64> {
        let seated = |&position: &u32| &self.committee.pubkeys[position as usize];
        let from = self.by_pubkey.partition_point(|position| seated(position) < pubkey);
        self.by_pubkey[from..]
            .iter()
            .take_while(|position| seated(position) == pubkey)
            .map(|&position| position as u64)
            .collect()
    }
}

/// `GetSyncCommitteeDutiesBody`: an array of `Uint64` — quoted decimal
/// strings — with `minItems: 1`. Deduplicated, so a validator named twice is
/// answered once.
fn requested_indices(body: &[u8]) -> Result<Vec<u64>, &'static str> {
    let submitted: Vec<&str> = serde_json::from_slice(body).map_err(|_| "invalid request body")?;
    if submitted.is_empty() {
        return Err("no validator index in request body");
    }
    if submitted.len() > MAX_BODY_IDS {
        return Err("too many validator indices in request body");
    }
    let mut indices = submitted
        .iter()
        .map(|text| parse_uint64(text).ok_or("invalid validator index"))
        .collect::<Result<Vec<_>, _>>()?;
    indices.sort_unstable();
    indices.dedup();
    Ok(indices)
}
