use serde::Deserialize;
use silver_beacon_state_data::{
    BLSPubkey, Epoch, FAR_FUTURE_EPOCH, StateReadView, ValidatorsView, Withdrawals,
};
use silver_httpcore::Query;

use crate::{
    ids::{MAX_BODY_IDS, parse_pubkey, parse_uint64},
    json::Json,
    response::Response,
    router::Request,
    routes::ApiCtx,
};

pub(crate) fn get_state_validators(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    respond_selection(req, ctx, resp, Selection::from_query(req.query));
}

pub(crate) fn post_state_validators(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let selection = serde_json::from_slice::<SelectionBody>(req.body)
        .map_err(|_| "invalid request body")
        .and_then(|body| Selection::from_body(&body));
    respond_selection(req, ctx, resp, selection);
}

/// The whole registry is a valid selection the schema allows and no validator
/// client sends: each one names the validators it runs, and the one library
/// that wants every validator downloads the SSZ state instead.
fn respond_selection(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
    selection: Result<Selection, &'static str>,
) {
    let mut selection = match selection {
        Ok(selection) if !selection.ids.is_empty() => selection,
        Ok(_) => {
            resp.error(400, "at least one id is required");
            return;
        }
        Err(rejection) => {
            resp.error(400, rejection);
            return;
        }
    };
    selection.ids.sort_unstable();
    selection.ids.dedup();
    ctx.state_response(req, resp, |view, json| selection.render(view, json));
}

pub(crate) fn state_validator(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let validator_id = req.params.get("validator_id").expect("{validator_id} in the route pattern");
    let Some(id) = ValidatorId::parse(validator_id) else {
        resp.error(400, "invalid validator_id");
        return;
    };
    let Some(state) = ctx.state_read(req, resp, |view| {
        id.resolve(&view.validators)
            .map(|ix| ValidatorRecord::read(&view, view.slot.current_epoch(), ix))
    }) else {
        return;
    };
    match &state.data {
        Some(record) => {
            resp.json_body(|json| json.flagged_envelope(state.flags, |json| json.validator(record)))
        }
        None => resp.error(404, "validator not found"),
    }
}

/// `{ids, statuses}` of `postStateValidators`; each list may be absent or
/// `null`.
#[derive(Deserialize)]
struct SelectionBody<'a> {
    #[serde(borrow, default)]
    ids: Option<Vec<&'a str>>,
    #[serde(borrow, default)]
    statuses: Option<Vec<&'a str>>,
}

#[derive(Default)]
struct Selection {
    ids: Vec<ValidatorId>,
    statuses: StatusSet,
}

impl Selection {
    fn from_query(query: &str) -> Result<Self, &'static str> {
        let mut selection = Self::default();
        for (name, value) in Query::new(query) {
            match &*name {
                "id" => value.split(',').try_for_each(|id| selection.push_id(id))?,
                "status" => {
                    value.split(',').try_for_each(|status| selection.push_status(status))?
                }
                _ => {}
            }
        }
        Ok(selection)
    }

    fn from_body(body: &SelectionBody<'_>) -> Result<Self, &'static str> {
        let mut selection = Self::default();
        body.ids.iter().flatten().try_for_each(|id| selection.push_id(id))?;
        body.statuses.iter().flatten().try_for_each(|status| selection.push_status(status))?;
        Ok(selection)
    }

    fn push_id(&mut self, text: &str) -> Result<(), &'static str> {
        if self.ids.len() == MAX_BODY_IDS {
            return Err("too many ids");
        }
        self.ids.push(ValidatorId::parse(text).ok_or("invalid id")?);
        Ok(())
    }

    fn push_status(&mut self, text: &str) -> Result<(), &'static str> {
        self.statuses = self.statuses.union(StatusSet::parse(text).ok_or("invalid status")?);
        Ok(())
    }

    /// Ids that name no validator are dropped, as the schema asks.
    fn render(&self, view: &StateReadView<'_>, json: &mut Json<'_>) {
        let current_epoch = view.slot.current_epoch();
        json.begin_array();
        for ix in self.ids.iter().filter_map(|id| id.resolve(&view.validators)) {
            let record = ValidatorRecord::read(view, current_epoch, ix);
            if self.statuses.admits(record.status) {
                json.validator(&record);
            }
        }
        json.end_array();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ValidatorId {
    Index(u64),
    Pubkey(BLSPubkey),
}

impl ValidatorId {
    fn parse(text: &str) -> Option<Self> {
        if let Some(index) = parse_uint64(text) {
            return Some(Self::Index(index));
        }
        parse_pubkey(text).map(Self::Pubkey)
    }

    fn resolve(&self, validators: &ValidatorsView<'_>) -> Option<usize> {
        match self {
            Self::Index(index) => {
                let ix = usize::try_from(*index).ok()?;
                (ix < validators.count()).then_some(ix)
            }
            Self::Pubkey(pubkey) => validators.find_by_pubkey(pubkey).map(|ix| ix as usize),
        }
    }
}

/// The `Validator` container beside the index, balance and status
/// `getStateValidator` answers with (`types/validator.yaml`).
pub(crate) struct ValidatorRecord {
    pub(crate) index: u64,
    pub(crate) balance: u64,
    pub(crate) status: ValidatorStatus,
    pub(crate) pubkey: BLSPubkey,
    pub(crate) withdrawal_credentials: Withdrawals,
    pub(crate) effective_balance: u64,
    pub(crate) lifecycle: Lifecycle,
}

impl ValidatorRecord {
    fn read(view: &StateReadView<'_>, current_epoch: Epoch, ix: usize) -> Self {
        let validators = &view.validators;
        let balance = view.balances.get(ix);
        let lifecycle = Lifecycle::read(validators, ix);
        Self {
            index: ix as u64,
            balance,
            status: lifecycle.status(current_epoch, balance),
            pubkey: *validators.pubkey(ix),
            withdrawal_credentials: *validators.credentials(ix),
            effective_balance: validators.effective_balance(ix),
            lifecycle,
        }
    }
}

/// The fields the status specification `types/api.yaml` links derives a
/// status from, beside the epoch and balance it is asked at.
pub(crate) struct Lifecycle {
    pub(crate) slashed: bool,
    pub(crate) activation_eligibility_epoch: Epoch,
    pub(crate) activation_epoch: Epoch,
    pub(crate) exit_epoch: Epoch,
    pub(crate) withdrawable_epoch: Epoch,
}

impl Lifecycle {
    fn read(validators: &ValidatorsView<'_>, ix: usize) -> Self {
        Self {
            slashed: validators.is_slashed(ix),
            activation_eligibility_epoch: validators.activation_eligibility_epoch(ix),
            activation_epoch: validators.activation_epoch(ix),
            exit_epoch: validators.exit_epoch(ix),
            withdrawable_epoch: validators.withdrawable_epoch(ix),
        }
    }

    fn status(&self, current_epoch: Epoch, balance: u64) -> ValidatorStatus {
        if current_epoch < self.activation_epoch {
            if self.activation_eligibility_epoch == FAR_FUTURE_EPOCH {
                ValidatorStatus::PendingInitialized
            } else {
                ValidatorStatus::PendingQueued
            }
        } else if current_epoch < self.exit_epoch {
            if self.exit_epoch == FAR_FUTURE_EPOCH {
                ValidatorStatus::ActiveOngoing
            } else if self.slashed {
                ValidatorStatus::ActiveSlashed
            } else {
                ValidatorStatus::ActiveExiting
            }
        } else if current_epoch < self.withdrawable_epoch {
            if self.slashed {
                ValidatorStatus::ExitedSlashed
            } else {
                ValidatorStatus::ExitedUnslashed
            }
        } else if balance != 0 {
            ValidatorStatus::WithdrawalPossible
        } else {
            ValidatorStatus::WithdrawalDone
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub(crate) enum ValidatorStatus {
    PendingInitialized,
    PendingQueued,
    ActiveOngoing,
    ActiveExiting,
    ActiveSlashed,
    ExitedUnslashed,
    ExitedSlashed,
    WithdrawalPossible,
    WithdrawalDone,
}

impl ValidatorStatus {
    const ALL: [Self; 9] = [
        Self::PendingInitialized,
        Self::PendingQueued,
        Self::ActiveOngoing,
        Self::ActiveExiting,
        Self::ActiveSlashed,
        Self::ExitedUnslashed,
        Self::ExitedSlashed,
        Self::WithdrawalPossible,
        Self::WithdrawalDone,
    ];

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::PendingInitialized => "pending_initialized",
            Self::PendingQueued => "pending_queued",
            Self::ActiveOngoing => "active_ongoing",
            Self::ActiveExiting => "active_exiting",
            Self::ActiveSlashed => "active_slashed",
            Self::ExitedUnslashed => "exited_unslashed",
            Self::ExitedSlashed => "exited_slashed",
            Self::WithdrawalPossible => "withdrawal_possible",
            Self::WithdrawalDone => "withdrawal_done",
        }
    }

    /// The `_`-prefixed family a status belongs to, which the filter also
    /// accepts as a name for the whole family.
    fn family(self) -> &'static str {
        self.name().split_once('_').expect("every status name has a family prefix").0
    }
}

/// One bit per status; the empty set is the absence of a filter.
#[derive(Clone, Copy, Default)]
struct StatusSet(u16);

impl StatusSet {
    fn parse(text: &str) -> Option<Self> {
        let bits = ValidatorStatus::ALL
            .into_iter()
            .filter(|status| status.name() == text || status.family() == text)
            .fold(0, |bits, status| bits | 1 << status as u8);
        (bits != 0).then_some(Self(bits))
    }

    fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    fn admits(self, status: ValidatorStatus) -> bool {
        self.0 == 0 || self.0 & 1 << status as u8 != 0
    }
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, SLOTS_PER_EPOCH, SpecConfig, ValSeed,
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        router::{Outcome, Router},
        routes::{ROUTES, test_ctx},
    };

    const HEAD_SLOT: u64 = 100 * SLOTS_PER_EPOCH;
    const EPOCH: u64 = HEAD_SLOT / SLOTS_PER_EPOCH;

    fn pubkey(fill: u8) -> BLSPubkey {
        [fill; 48]
    }

    fn hex(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    /// Index 0 is active, 1 is still pending, 2 has exited and awaits its
    /// withdrawable epoch.
    fn ctx() -> ApiCtx {
        let seeds = [
            ValSeed {
                pubkey: pubkey(0xa1),
                withdrawal_credentials: Withdrawals([0x01; 32]),
                effective_balance: 32_000_000_000,
                balance: 32_000_000_123,
                activation_epoch: 5,
                exit_epoch: FAR_FUTURE_EPOCH,
            },
            ValSeed {
                pubkey: pubkey(0xa2),
                effective_balance: 32_000_000_000,
                balance: 32_000_000_000,
                activation_epoch: EPOCH + 1,
                exit_epoch: FAR_FUTURE_EPOCH,
                ..ValSeed::default()
            },
            ValSeed {
                pubkey: pubkey(0xa3),
                effective_balance: 0,
                balance: 7,
                activation_epoch: 5,
                exit_epoch: EPOCH - 1,
                ..ValSeed::default()
            },
        ];
        let state = BeaconState::for_test(EpochStateFinalized::default(), &seeds, HEAD_SLOT);
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        test_ctx(&SpecConfig::mainnet(), owner.reader())
    }

    fn dispatch(method: &str, path: &str, query: &str, body: &str) -> Vec<u8> {
        let req = ParsedRequest {
            method,
            path,
            query,
            body: body.as_bytes(),
            accept: None,
            content_type: Some("application/json"),
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        let mut out = Vec::new();
        assert_eq!(Router::new(ROUTES).dispatch(&req, &ctx(), &mut out), Outcome::Response);
        out
    }

    fn get(path: &str, query: &str) -> Vec<u8> {
        dispatch("GET", path, query, "")
    }

    fn post(body: &str) -> Vec<u8> {
        dispatch("POST", "/eth/v1/beacon/states/head/validators", "", body)
    }

    /// The `data` a 200 carries, after the envelope flags.
    fn data(response: &[u8]) -> String {
        let text = std::str::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        let body = &text[text.find("\r\n\r\n").unwrap() + 4..];
        let data = body.find(",\"data\":").unwrap();
        body[data + ",\"data\":".len()..body.len() - 1].to_string()
    }

    fn status_code(response: &[u8]) -> &str {
        std::str::from_utf8(response).unwrap().split(' ').nth(1).unwrap()
    }

    fn record_json(index: u64, balance: u64, status: &str, validator: &str) -> String {
        format!(
            "{{\"index\":\"{index}\",\"balance\":\"{balance}\",\"status\":\"{status}\",\
             \"validator\":{validator}}}"
        )
    }

    fn active_validator() -> String {
        format!(
            "{{\"pubkey\":\"{}\",\"withdrawal_credentials\":\"{}\",\
             \"effective_balance\":\"32000000000\",\"slashed\":false,\
             \"activation_eligibility_epoch\":\"{FAR_FUTURE_EPOCH}\",\"activation_epoch\":\"5\",\
             \"exit_epoch\":\"{FAR_FUTURE_EPOCH}\",\"withdrawable_epoch\":\"{FAR_FUTURE_EPOCH}\"}}",
            hex(&pubkey(0xa1)),
            hex(&[0x01; 32]),
        )
    }

    /// Body shape: `apis/beacon/states/validator.yaml`, resolved by index and
    /// by pubkey alike.
    #[test]
    fn single_validator_by_index_and_pubkey() {
        let expected = record_json(0, 32_000_000_123, "active_ongoing", &active_validator());
        assert_eq!(data(&get("/eth/v1/beacon/states/head/validators/0", "")), expected);
        let by_pubkey = format!("/eth/v1/beacon/states/head/validators/{}", hex(&pubkey(0xa1)));
        assert_eq!(data(&get(&by_pubkey, "")), expected);
    }

    #[test]
    fn single_validator_unknown_is_404_and_malformed_is_400() {
        for id in ["3", &hex(&pubkey(0xff))] {
            let path = format!("/eth/v1/beacon/states/head/validators/{id}");
            assert_eq!(status_code(&get(&path, "")), "404", "{id}");
        }
        for id in ["-1", "0x1234", "head", &hex(&pubkey(0xa1))[2..]] {
            let path = format!("/eth/v1/beacon/states/head/validators/{id}");
            assert_eq!(status_code(&get(&path, "")), "400", "{id}");
        }
        assert_eq!(status_code(&get("/eth/v1/beacon/states/finalized/validators/0", "")), "404");
    }

    /// Indices come first in ascending order, then pubkeys; a repeated id
    /// answers once, while an index and a pubkey naming the same validator
    /// both answer.
    #[test]
    fn list_dedups_repeated_ids_and_skips_unknown_ones() {
        let query =
            format!("id=2&id={},0&id=99&id=0&id={}", hex(&pubkey(0xa1)), hex(&pubkey(0xee)));
        let body = data(&get("/eth/v1/beacon/states/head/validators", &query));
        let indices: Vec<_> =
            body.match_indices("\"index\":\"").map(|(at, _)| &body[at + 9..at + 10]).collect();
        assert_eq!(indices, ["0", "2", "0"]);
    }

    #[test]
    fn list_status_filter_accepts_statuses_and_families() {
        let path = "/eth/v1/beacon/states/head/validators";
        let all = "id=0&id=1&id=2";
        let statuses = |query: &str| -> Vec<String> {
            let body = data(&get(path, query));
            body.match_indices("\"status\":\"")
                .map(|(at, _)| body[at + 10..].split('"').next().unwrap().to_string())
                .collect()
        };
        assert_eq!(statuses(all), ["active_ongoing", "pending_initialized", "exited_unslashed"]);
        assert_eq!(statuses(&format!("{all}&status=active")), ["active_ongoing"]);
        assert_eq!(statuses(&format!("{all}&status=pending_initialized,exited")), [
            "pending_initialized",
            "exited_unslashed"
        ]);
        assert_eq!(statuses(&format!("{all}&status=withdrawal")), Vec::<String>::new());
    }

    #[test]
    fn list_rejects_malformed_filters_and_an_empty_selection() {
        let path = "/eth/v1/beacon/states/head/validators";
        for query in ["id=0&status=running", "id=abc", "id=0&id=0x12", "status=active", ""] {
            assert_eq!(status_code(&get(path, query)), "400", "{query:?}");
        }
    }

    #[test]
    fn post_mirrors_get_and_validates_its_body() {
        let body = format!("{{\"ids\":[\"1\",\"{}\"],\"statuses\":null}}", hex(&pubkey(0xa1)));
        let query = format!("id=1&id={}", hex(&pubkey(0xa1)));
        assert_eq!(data(&post(&body)), data(&get("/eth/v1/beacon/states/head/validators", &query)));

        let filtered = data(&post("{\"ids\":[\"0\",\"1\"],\"statuses\":[\"pending\"]}"));
        assert!(filtered.starts_with("[{\"index\":\"1\","), "{filtered}");
        assert_eq!(filtered.matches("\"index\"").count(), 1);

        for body in
            ["", "[]", "{\"ids\":[\"x\"]}", "{\"ids\":[\"0\"],\"statuses\":[\"nope\"]}", "{}"]
        {
            assert_eq!(status_code(&post(body)), "400", "{body:?}");
        }
    }

    #[test]
    fn status_follows_the_status_specification() {
        let lifecycle = |eligibility, activation, exit, withdrawable, slashed| Lifecycle {
            slashed,
            activation_eligibility_epoch: eligibility,
            activation_epoch: activation,
            exit_epoch: exit,
            withdrawable_epoch: withdrawable,
        };
        let far = FAR_FUTURE_EPOCH;
        let cases = [
            (lifecycle(far, far, far, far, false), 10, 1, ValidatorStatus::PendingInitialized),
            (lifecycle(3, 12, far, far, false), 10, 1, ValidatorStatus::PendingQueued),
            (lifecycle(3, 10, far, far, false), 10, 1, ValidatorStatus::ActiveOngoing),
            (lifecycle(3, 4, 20, 30, false), 10, 1, ValidatorStatus::ActiveExiting),
            (lifecycle(3, 4, 20, 30, true), 10, 1, ValidatorStatus::ActiveSlashed),
            (lifecycle(3, 4, 10, 30, false), 10, 1, ValidatorStatus::ExitedUnslashed),
            (lifecycle(3, 4, 5, 30, true), 10, 1, ValidatorStatus::ExitedSlashed),
            (lifecycle(3, 4, 5, 10, true), 10, 1, ValidatorStatus::WithdrawalPossible),
            (lifecycle(3, 4, 5, 6, false), 10, 0, ValidatorStatus::WithdrawalDone),
        ];
        for (lifecycle, epoch, balance, expected) in cases {
            assert_eq!(lifecycle.status(epoch, balance), expected);
        }
    }
}
