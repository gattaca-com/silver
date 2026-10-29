use serde::{Deserialize, Deserializer, de::Error};
use serde_json::value::RawValue;
use silver_beacon_state_data::{
    BLSPubkey, Builder, BuildersView, Epoch, FAR_FUTURE_EPOCH, StateReadView,
};
use silver_common::json_fields::parse_uint64;

use crate::{
    ctx::ApiCtx,
    http::{
        ids::{each_body_entry, parse_pubkey},
        json::Json,
        response::Response,
        router::Request,
    },
};

pub(crate) fn post_state_builders(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let filter = match BuilderFilter::parse(req.body) {
        Ok(filter) => filter,
        Err(message) => return resp.error(400, message),
    };
    ctx.try_state_response(req, resp, |view, json| {
        if !view.is_gloas() {
            return Err((400, "state is prior to Gloas"));
        }
        filter.render(view, json);
        Ok(())
    });
}

/// `{ids, statuses}`; the body, either list, or an empty list selects all.
/// The lists stay slices of the body, checked at parse and read again to
/// render. Ids are answered in the order named: the schema promises no
/// order, and each entry carries both index and pubkey.
#[derive(Deserialize, Default)]
struct BuilderFilter<'a> {
    #[serde(borrow, default)]
    ids: Option<&'a RawValue>,
    #[serde(borrow, default)]
    statuses: Option<&'a RawValue>,
}

impl<'a> BuilderFilter<'a> {
    fn parse(body: &'a [u8]) -> Result<Self, &'static str> {
        let filter: Self = if body.is_empty() {
            Self::default()
        } else {
            serde_json::from_slice(body).map_err(|_| "invalid request body")?
        };
        filter.status_set()?;
        each_listed(filter.ids, |_: BuilderId| {})?;
        Ok(filter)
    }

    /// One bit per status; none set admits every status.
    fn status_set(&self) -> Result<u8, &'static str> {
        let mut set = 0;
        each_listed(self.statuses, |status: BuilderStatus| set |= status.bit())?;
        Ok(set)
    }

    fn render(&self, view: &StateReadView<'_>, json: &mut Json<'_>) {
        let statuses = self.status_set().expect("checked at parse");
        let finalized_epoch = view.epoch.state().finalized_checkpoint.epoch;
        let builders = &view.builders;
        json.begin_array();
        let mut render = |index: usize| {
            let builder = builders.get(index).expect("resolved within the registry");
            let status = BuilderStatus::of(builder, finalized_epoch);
            if statuses == 0 || statuses & status.bit() != 0 {
                json.builder(index as u64, status.name(), builder);
            }
        };
        let named = each_listed(self.ids, |id: BuilderId| {
            if let Some(index) = id.resolve(builders) {
                render(index);
            }
        })
        .expect("checked at parse");
        if named == 0 {
            (0..builders.len()).for_each(render);
        }
        json.end_array();
    }
}

fn each_listed<'a, T: Deserialize<'a>>(
    list: Option<&'a RawValue>,
    mut each: impl FnMut(T),
) -> Result<usize, &'static str> {
    list.map_or(Ok(0), |list| each_body_entry(list.get().as_bytes(), |_, entry| each(entry)))
}

enum BuilderId {
    Index(u64),
    Pubkey(BLSPubkey),
}

impl<'de> Deserialize<'de> for BuilderId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&str>::deserialize(deserializer)?;
        match parse_uint64(text) {
            Some(index) => Ok(Self::Index(index)),
            None => parse_pubkey(text).map(Self::Pubkey).ok_or_else(|| Error::custom("invalid id")),
        }
    }
}

impl BuilderId {
    fn resolve(&self, builders: &BuildersView<'_>) -> Option<usize> {
        match self {
            Self::Index(index) => usize::try_from(*index).ok().filter(|&ix| ix < builders.len()),
            Self::Pubkey(pubkey) => builders.find_by_pubkey(pubkey),
        }
    }
}

/// `types/api.yaml#/BuilderStatus`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum BuilderStatus {
    Pending,
    Active,
    Exited,
}

impl BuilderStatus {
    fn of(builder: &Builder, finalized_epoch: Epoch) -> Self {
        if builder.withdrawable_epoch != FAR_FUTURE_EPOCH {
            Self::Exited
        } else if builder.is_active(finalized_epoch) {
            Self::Active
        } else {
            Self::Pending
        }
    }

    fn bit(self) -> u8 {
        1 << self as u8
    }

    fn name(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Exited => "exited",
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, Checkpoint, EpochState, EpochStateFinalized, Fork,
        SpecConfig, ValSeed, gloas::GLOAS_FORK_VERSION,
    };
    use silver_common::SyncUpdate;

    use super::*;
    use crate::{
        ctx::test_ctx,
        testing::{answer, body, posting, status_code},
    };

    const FINALIZED_EPOCH: Epoch = 10;
    const PATH: &str = "/eth/v1/beacon/states/head/builders";

    fn builder(fill: u8, deposit_epoch: Epoch, withdrawable_epoch: Epoch) -> Builder {
        Builder {
            pubkey: [fill; 48],
            version: 0,
            execution_address: [fill; 20],
            balance: u64::from(fill) * 1_000,
            deposit_epoch,
            withdrawable_epoch,
        }
    }

    /// Index 0 is active, 1 pending (deposit not yet finalized), 2 exited.
    fn ctx(fork_version: [u8; 4]) -> ApiCtx {
        let epoch_state = EpochState {
            fork: Fork { current_version: fork_version, ..Fork::default() },
            finalized_checkpoint: Checkpoint { epoch: FINALIZED_EPOCH, ..Checkpoint::default() },
            ..EpochState::default()
        };
        let seeds = [ValSeed::default()];
        let state = BeaconState::for_test(EpochStateFinalized::from_state(epoch_state), &seeds, 0);
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        let mut fork = owner.apply_block_view(anchor);
        fork.view.builders.push(builder(0xb1, FINALIZED_EPOCH - 1, FAR_FUTURE_EPOCH));
        fork.view.builders.push(builder(0xb2, FINALIZED_EPOCH, FAR_FUTURE_EPOCH));
        fork.view.builders.push(builder(0xb3, 1, FINALIZED_EPOCH + 5));
        let head = fork.commit();
        owner.publish_state_id(head);
        let mut ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        ctx.node_status.target = Some(SyncUpdate::Following);
        ctx
    }

    fn hex(fill: u8, len: usize) -> String {
        format!("0x{}", hex::encode(vec![fill; len]))
    }

    fn entry(index: u64, status: &str, fill: u8, deposit: Epoch, withdrawable: Epoch) -> Value {
        json!({
            "index": index.to_string(),
            "status": status,
            "builder": {
                "pubkey": hex(fill, 48),
                "version": "0",
                "execution_address": hex(fill, 20),
                "balance": (u64::from(fill) * 1_000).to_string(),
                "deposit_epoch": deposit.to_string(),
                "withdrawable_epoch": withdrawable.to_string(),
            },
        })
    }

    fn data(ctx: &ApiCtx, request_body: &str) -> Value {
        let response = answer(ctx, &posting(PATH, request_body));
        assert_eq!(status_code(&response), "200", "{request_body}");
        let envelope: Value = serde_json::from_slice(body(&response)).unwrap();
        envelope["data"].clone()
    }

    #[test]
    fn helix_lookup_by_pubkey_finds_the_active_builder() {
        let ids = json!({ "ids": [hex(0xb1, 48)] }).to_string();
        let active = entry(0, "active", 0xb1, FINALIZED_EPOCH - 1, FAR_FUTURE_EPOCH);
        assert_eq!(data(&ctx(GLOAS_FORK_VERSION), &ids), json!([active]));
    }

    #[test]
    fn statuses_follow_finalization_and_withdrawability() {
        let all = json!([
            entry(0, "active", 0xb1, FINALIZED_EPOCH - 1, FAR_FUTURE_EPOCH),
            entry(1, "pending", 0xb2, FINALIZED_EPOCH, FAR_FUTURE_EPOCH),
            entry(2, "exited", 0xb3, 1, FINALIZED_EPOCH + 5),
        ]);
        let ctx = ctx(GLOAS_FORK_VERSION);
        for request_body in ["", "{}", r#"{"ids":[],"statuses":[]}"#, r#"{"ids":null}"#] {
            assert_eq!(data(&ctx, request_body), all, "{request_body}");
        }
    }

    #[test]
    fn ids_answer_in_order_named_narrowed_by_status_and_unknown_ones_skipped() {
        let ctx = ctx(GLOAS_FORK_VERSION);
        let request_body = json!({
            "ids": ["2", "1", hex(0xb1, 48), "99", hex(0xff, 48), "1"],
            "statuses": ["pending", "exited"],
        });
        let pending = entry(1, "pending", 0xb2, FINALIZED_EPOCH, FAR_FUTURE_EPOCH);
        let exited = entry(2, "exited", 0xb3, 1, FINALIZED_EPOCH + 5);
        let narrowed = json!([exited, pending, pending]);
        assert_eq!(data(&ctx, &request_body.to_string()), narrowed);
    }

    #[test]
    fn syncing_node_refuses_with_503() {
        let mut ctx = ctx(GLOAS_FORK_VERSION);
        ctx.node_status.target = None;
        assert_eq!(status_code(&answer(&ctx, &posting(PATH, "{}"))), "503");
    }

    #[test]
    fn malformed_requests_and_pre_gloas_states_are_400() {
        let ctx = ctx(GLOAS_FORK_VERSION);
        for request_body in
            ["[", r#"{"ids":["0x12"]}"#, r#"{"ids":["-1"]}"#, r#"{"statuses":["active_ongoing"]}"#]
        {
            assert_eq!(
                status_code(&answer(&ctx, &posting(PATH, request_body))),
                "400",
                "{request_body}"
            );
        }
        let pre_gloas = answer(&self::ctx([0; 4]), &posting(PATH, "{}"));
        assert_eq!(status_code(&pre_gloas), "400");
        assert!(std::str::from_utf8(body(&pre_gloas)).unwrap().contains("prior to Gloas"));
    }
}
