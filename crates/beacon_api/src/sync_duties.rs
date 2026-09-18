use silver_beacon_state_data::{
    BLSPubkey, EPOCHS_PER_SYNC_COMMITTEE_PERIOD, Epoch, SYNC_COMMITTEE_SIZE, StateReadView,
};

use crate::{
    duties::{epoch_param, requested_indices},
    ids::ValidatorIndex,
    response::Response,
    router::Request,
    routes::ApiCtx,
};

pub(crate) fn post_sync_duties(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(epoch) = epoch_param(req, resp) else {
        return;
    };
    let Some(indices) = requested_indices(req, resp) else {
        return;
    };
    if !ctx.node_status.is_following() {
        resp.error(503, "api unavailable while the node is syncing");
        return;
    }
    let Some(seats) = ctx.read_state(|view| {
        CommitteePeriod::serving(epoch, view.slot.current_epoch())
            .map(|period| Seats::read(&view, period))
    }) else {
        resp.error(400, "the head state holds no sync committee for this epoch");
        return;
    };

    let execution_optimistic = ctx.node_status.execution_optimistic();
    resp.json_body(|json| {
        ctx.read_state(|view| {
            json.restart();
            json.sync_duties(
                execution_optimistic,
                indices.iter().filter_map(|&ValidatorIndex(index)| seats.duty(&view, index)),
            );
        });
    });
}

/// Which of the two committees the head state holds answers for an epoch.
#[derive(Clone, Copy)]
enum CommitteePeriod {
    Current,
    Next,
}

impl CommitteePeriod {
    /// `None` for a period the state holds no committee for, which is every
    /// period behind the head's and every one past the next.
    fn serving(epoch: Epoch, state_epoch: Epoch) -> Option<Self> {
        let period = |epoch: Epoch| epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        match period(epoch).checked_sub(period(state_epoch))? {
            0 => Some(Self::Current),
            1 => Some(Self::Next),
            _ => None,
        }
    }
}

/// The period's committee inverted for lookup by validator index: a request
/// names its own validators, never the committee, and a validator may sit in
/// more than one seat.
struct Seats {
    /// Sorted, so one validator's seats are a run.
    seats: [Seat; SYNC_COMMITTEE_SIZE],
    len: usize,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
struct Seat {
    validator_index: u64,
    position: u32,
}

impl Seats {
    fn read(view: &StateReadView<'_>, period: CommitteePeriod) -> Self {
        let committees = view.longtail.sync_committees();
        let mut seats = [Seat::default(); SYNC_COMMITTEE_SIZE];
        let mut len = 0;
        for position in 0..SYNC_COMMITTEE_SIZE {
            let validator_index = match period {
                // The promoted committee travels with its registry indices;
                // the one still ahead is pubkeys alone.
                CommitteePeriod::Current => committees.index_at(position).map(u64::from),
                CommitteePeriod::Next => view
                    .validators
                    .find_by_pubkey(&committees.next().pubkeys[position])
                    .map(u64::from),
            };
            if let Some(validator_index) = validator_index {
                seats[len] = Seat { validator_index, position: position as u32 };
                len += 1;
            }
        }

        if len != SYNC_COMMITTEE_SIZE {
            tracing::warn!(
                unresolved = SYNC_COMMITTEE_SIZE - len,
                "sync committee seats with no registry index"
            );
        }
        seats[..len].sort_unstable();
        Self { seats, len }
    }

    fn duty<'a>(&'a self, view: &StateReadView<'a>, validator_index: u64) -> Option<SyncDuty<'a>> {
        let held = self.held_by(validator_index);
        let index =
            usize::try_from(validator_index).ok().filter(|&ix| ix < view.validators.count())?;
        (!held.is_empty()).then(|| SyncDuty {
            pubkey: *view.validators.pubkey(index),
            validator_index,
            seats: held,
        })
    }

    fn held_by(&self, validator_index: u64) -> &[Seat] {
        let seats = &self.seats[..self.len];
        let from = seats.partition_point(|seat| seat.validator_index < validator_index);
        let held = &seats[from..];
        &held[..held.partition_point(|seat| seat.validator_index == validator_index)]
    }
}

/// `SyncCommitteeDuty` (`types/duty.yaml`).
pub(crate) struct SyncDuty<'a> {
    pub(crate) pubkey: BLSPubkey,
    pub(crate) validator_index: u64,
    seats: &'a [Seat],
}

impl SyncDuty<'_> {
    pub(crate) fn positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.seats.iter().map(|seat| u64::from(seat.position))
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, SLOTS_PER_EPOCH, SpecConfig,
        SyncCommittee, SyncCommittees, ValSeed,
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::{
        duties::test_state::{field, indices_body, json, post_duties, pubkey, status_code},
        routes::test_ctx,
    };

    const VALIDATORS: u64 = 6;
    /// Validators `0..IN_COMMITTEE` hold seats; the rest hold none.
    const IN_COMMITTEE: u64 = 5;
    const STATE_EPOCH: u64 = 3 * EPOCHS_PER_SYNC_COMMITTEE_PERIOD + 17;
    const STATE_SLOT: u64 = STATE_EPOCH * SLOTS_PER_EPOCH;

    /// Seat `p` holds validator `(p + offset) % IN_COMMITTEE`, so every holder
    /// sits in a fifth of the seats and the two committees differ.
    fn committee(offset: u64) -> SyncCommittee {
        SyncCommittee {
            pubkeys: std::array::from_fn(|seat| pubkey((seat as u64 + offset) % IN_COMMITTEE)),
            aggregate_pubkey: [0u8; 48],
        }
    }

    fn seat_holders(offset: u64) -> [u32; SYNC_COMMITTEE_SIZE] {
        std::array::from_fn(|seat| ((seat as u64 + offset) % IN_COMMITTEE) as u32)
    }

    fn seats_of(validator_index: u64, offset: u64) -> Vec<u64> {
        (0..SYNC_COMMITTEE_SIZE as u64)
            .filter(|seat| (seat + offset) % IN_COMMITTEE == validator_index)
            .collect()
    }

    /// The period's own committee rotates from validator 0, the next one from
    /// validator 1.
    fn ctx() -> ApiCtx {
        let seeds: Vec<_> =
            (0..VALIDATORS).map(|i| ValSeed { pubkey: pubkey(i), ..ValSeed::default() }).collect();
        let mut state = BeaconState::for_test(EpochStateFinalized::default(), &seeds, STATE_SLOT);
        let mut anchor = state.roll_fresh();
        let mut longtail = state.longtail.roll_fresh();
        let unresolved = [SyncCommittees::unresolved(); SYNC_COMMITTEE_SIZE];
        longtail.rotate_sync_committees(&committee(0), unresolved);
        longtail.rotate_sync_committees(&committee(1), seat_holders(0));
        anchor.longtail_idx = Some(longtail.commit());

        let mut owner = BeaconStateOwner::new(state);
        owner.publish_state_id(anchor);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx
    }

    fn post(ctx: &ApiCtx, epoch: u64, body: &str) -> Vec<u8> {
        post_duties(ctx, &format!("/eth/v1/validator/duties/sync/{epoch}"), body)
    }

    fn next_period_epoch() -> u64 {
        (STATE_EPOCH / EPOCHS_PER_SYNC_COMMITTEE_PERIOD + 1) * EPOCHS_PER_SYNC_COMMITTEE_PERIOD
    }

    fn duty_seats(body: &serde_json::Value, at: usize) -> Vec<u64> {
        body["data"][at]["validator_sync_committee_indices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|seat| seat.as_str().unwrap().parse().unwrap())
            .collect()
    }

    /// Body shape: `apis/validator/duties/sync.yaml`. A member answers with
    /// every seat it holds, and a validator holding none is dropped.
    #[test]
    fn current_period_lists_every_seat_a_member_holds() {
        let ctx = ctx();
        let body = json(&post(&ctx, STATE_EPOCH, &indices_body([5, 2, 2].into_iter())));
        assert_eq!(body["execution_optimistic"], false);
        assert!(body.get("dependent_root").is_none(), "{body}");

        let duties = body["data"].as_array().unwrap();
        assert_eq!(duties.len(), 1);
        assert_eq!(field(&duties[0], "validator_index"), 2);
        assert_eq!(duties[0]["pubkey"], format!("0x{}", hex::encode(pubkey(2))));
        assert_eq!(duty_seats(&body, 0), seats_of(2, 0));
    }

    /// The committee still ahead is pubkeys alone, so this path resolves them
    /// against the registry rather than reading the carried indices.
    #[test]
    fn next_period_reads_the_committee_still_ahead() {
        let ctx = ctx();
        let body = json(&post(&ctx, next_period_epoch(), &indices_body([0, 1].into_iter())));
        let duties = body["data"].as_array().unwrap();
        assert_eq!(duties.len(), 2);
        assert_eq!(field(&duties[0], "validator_index"), 0);
        assert_eq!(duty_seats(&body, 0), seats_of(0, 1));
        assert_eq!(duty_seats(&body, 1), seats_of(1, 1));
    }

    #[test]
    fn every_seat_is_answered_once_across_the_committee() {
        let ctx = ctx();
        let body = json(&post(&ctx, STATE_EPOCH, &indices_body(0..VALIDATORS)));
        let answered: usize =
            (0..body["data"].as_array().unwrap().len()).map(|at| duty_seats(&body, at).len()).sum();
        assert_eq!(answered, SYNC_COMMITTEE_SIZE);
    }

    #[test]
    fn periods_the_state_does_not_hold_and_malformed_bodies_are_400() {
        let ctx = ctx();
        let one_period = EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        for epoch in [STATE_EPOCH - one_period, next_period_epoch() + one_period] {
            assert_eq!(status_code(&post(&ctx, epoch, "[\"0\"]")), "400", "{epoch}");
        }
        for body in ["", "{}", "[]", "[0]", "[\"-1\"]", "[\"a\"]"] {
            assert_eq!(status_code(&post(&ctx, STATE_EPOCH, body)), "400", "{body:?}");
        }
    }

    #[test]
    fn duties_are_503_until_the_node_follows_the_chain() {
        let mut ctx = ctx();
        ctx.node_status.target = None;
        assert_eq!(status_code(&post(&ctx, STATE_EPOCH, "[\"0\"]")), "503");
    }

    /// An unrotated bundle names no holder, rather than naming validator zero
    /// for all 512 seats.
    #[test]
    fn seats_of_an_unrotated_committee_name_nobody() {
        let committees = SyncCommittees::default();
        assert!((0..SYNC_COMMITTEE_SIZE).all(|seat| committees.index_at(seat).is_none()));
    }
}
