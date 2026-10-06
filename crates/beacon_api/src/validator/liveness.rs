use silver_beacon_state_data::{Epoch, StateReadView};

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
    validator::duties::{epoch_param, requested_indices},
};

pub(crate) fn post_liveness(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let Some(epoch) = epoch_param(req, resp) else {
        return;
    };
    let Some(indices) = requested_indices(req, resp) else {
        return;
    };
    let state_epoch = ctx.read_state(|view| view.slot.current_epoch());
    if ParticipationEpoch::serving(epoch, state_epoch).is_none() {
        resp.error(400, "liveness covers the head state's previous, current and next epoch");
        return;
    }

    resp.json_body(|json| {
        ctx.read_state(|view| {
            json.restart();
            let served = ParticipationEpoch::serving(epoch, view.slot.current_epoch());
            debug_assert!(served.is_some(), "the head moved two epochs between reads");
            json.liveness(
                indices.iter().map(|&index| {
                    (index, served.is_some_and(|served| served.is_live(&view, index)))
                }),
            );
        });
    });
}

#[derive(Clone, Copy)]
enum ParticipationEpoch {
    Previous,
    Current,
    /// The epoch after the head state's: no block of it is on the head chain,
    /// so no attestation for it has been included. A validator client on the
    /// wall clock asks for it while the head is still in the epoch before.
    Next,
}

impl ParticipationEpoch {
    fn serving(epoch: Epoch, state_epoch: Epoch) -> Option<Self> {
        if epoch == state_epoch {
            Some(Self::Current)
        } else if epoch + 1 == state_epoch {
            Some(Self::Previous)
        } else if epoch == state_epoch + 1 {
            Some(Self::Next)
        } else {
            None
        }
    }

    /// An index naming no validator is not live, rather than failing the
    /// request: validator clients count a missing entry as an unanswered key.
    fn is_live(self, view: &StateReadView<'_>, index: u64) -> bool {
        let Some(ix) = usize::try_from(index).ok().filter(|&ix| ix < view.validators.count())
        else {
            return false;
        };
        let flags = match self {
            Self::Previous => view.previous_participation.get(ix),
            Self::Current => view.current_participation.get(ix),
            Self::Next => 0,
        };
        flags != 0
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, CurrentParticipationGroup, EpochStateFinalized, HashFormat,
        PreviousParticipationGroup, SLOTS_PER_EPOCH, SpecConfig, ValSeed,
    };
    use silver_common::SyncUpdate;

    use crate::{
        ctx::{ApiCtx, test_ctx},
        testing::{answer, body, posting, status_code},
    };

    const VALIDATORS: usize = 4;
    const STATE_EPOCH: u64 = 300;
    const PREVIOUS_LIVE: u64 = 1;
    const CURRENT_LIVE: u64 = 2;

    fn flags_with(live: u64) -> Vec<u8> {
        let mut flags = vec![0; VALIDATORS];
        flags[live as usize] = 0b001;
        flags
    }

    fn ctx() -> ApiCtx {
        let seeds: Vec<_> = (0..VALIDATORS).map(|_| ValSeed::default()).collect();
        let mut state = BeaconState::for_test(
            EpochStateFinalized::default(),
            &seeds,
            STATE_EPOCH * SLOTS_PER_EPOCH + 5,
        );
        let cap = state.validators.finalized().capacity();
        state.previous_participation = PreviousParticipationGroup::new(
            cap,
            VALIDATORS,
            &flags_with(PREVIOUS_LIVE),
            HashFormat::Fixed,
        )
        .unwrap();
        state.current_participation = CurrentParticipationGroup::new(
            cap,
            VALIDATORS,
            &flags_with(CURRENT_LIVE),
            HashFormat::Fixed,
        )
        .unwrap();

        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx
    }

    fn post(ctx: &ApiCtx, epoch: u64, body: &str) -> Vec<u8> {
        answer(ctx, &posting(&format!("/eth/v1/validator/liveness/{epoch}"), body))
    }

    fn live_set(epoch: u64) -> String {
        let response = post(&ctx(), epoch, r#"["0","1","2","3"]"#);
        assert_eq!(status_code(&response), "200", "{epoch}");
        String::from_utf8(body(&response).to_vec()).unwrap()
    }

    fn expected(live: Option<u64>) -> String {
        let entries: Vec<_> = (0..VALIDATORS as u64)
            .map(|index| format!(r#"{{"index":"{index}","is_live":{}}}"#, Some(index) == live))
            .collect();
        format!(r#"{{"data":[{}]}}"#, entries.join(","))
    }

    #[test]
    fn each_epoch_answers_from_its_participation_column() {
        assert_eq!(live_set(STATE_EPOCH - 1), expected(Some(PREVIOUS_LIVE)));
        assert_eq!(live_set(STATE_EPOCH), expected(Some(CURRENT_LIVE)));
        assert_eq!(live_set(STATE_EPOCH + 1), expected(None));
    }

    #[test]
    fn unknown_indices_answer_not_live() {
        let response = post(&ctx(), STATE_EPOCH, r#"["2","9999"]"#);
        assert_eq!(
            body(&response),
            br#"{"data":[{"index":"2","is_live":true},{"index":"9999","is_live":false}]}"#
        );
    }

    #[test]
    fn epochs_off_the_window_are_400() {
        let ctx = ctx();
        for epoch in [STATE_EPOCH - 2, STATE_EPOCH + 2] {
            assert_eq!(status_code(&post(&ctx, epoch, r#"["0"]"#)), "400", "{epoch}");
        }
    }

    #[test]
    fn liveness_is_503_until_the_node_follows_the_chain() {
        let mut ctx = ctx();
        ctx.node_status.target = None;
        assert_eq!(status_code(&post(&ctx, STATE_EPOCH, r#"["0"]"#)), "503");
    }
}
