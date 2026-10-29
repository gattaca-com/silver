use serde::Deserialize;
use silver_beacon_state_data::{
    BLSPubkey, Epoch, FAR_FUTURE_EPOCH, PinnedState, StateReadView, ValidatorsView, Withdrawals,
};
use silver_common::json_fields::parse_uint64;
use silver_httpcore::{ChunkedResponse, Query};

use crate::{
    ctx::{ApiCtx, read_flags},
    http::{
        ids::{each_body_entry, parse_pubkey},
        json::Json,
        response::Response,
        router::Request,
    },
};

const MAX_VALIDATOR_IDS: usize = 32 * 1024;

/// About 0.25 MB of JSON and 40 µs of rendering per batch.
const VALIDATORS_PER_BATCH: usize = 512;

/// The longest record [`Json::validator`] writes, with its separator: every
/// number at 20 digits and the longest status.
const MAX_VALIDATOR_JSON: usize = 550;

/// A batch's chunk framing, and the envelope that opens the first batch and
/// closes the last.
const BATCH_OVERHEAD: usize = 128;

const _: () = assert!(
    VALIDATORS_PER_BATCH * MAX_VALIDATOR_JSON + BATCH_OVERHEAD <= ChunkedResponse::PENDING_MAX
);

/// Each open download renders a batch on every pump of the API tile.
const MAX_REGISTRY_DOWNLOADS: usize = 2;

pub(crate) fn get_state_validators(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    respond_validators(req, ctx, resp, Selection::from_query(req.query));
}

pub(crate) fn post_state_validators(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let selection = serde_json::from_slice::<SelectionBody>(req.body)
        .map_err(|_| Rejection::bad_request("invalid request body"))
        .and_then(|body| Selection::from_body(&body));
    respond_validators(req, ctx, resp, selection);
}

/// A status filter alone selects the registry it admits, as helix's relay
/// asks for `active,pending`. On mainnet that body is over 500 MB, so it is
/// streamed.
fn respond_validators(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
    selection: Result<Selection, Rejection>,
) {
    match selection {
        Ok(selection) if selection.ids.is_empty() && selection.statuses.filters() => {
            if ctx.registry_downloads >= MAX_REGISTRY_DOWNLOADS {
                return resp.error(503, "too many registry downloads in progress");
            }
            if let Some(pin) = ctx.pin_state(req, resp) {
                resp.begin_registry_download(RegistryStream::new(pin, selection.statuses));
            }
        }
        selection => respond_selection(req, ctx, resp, selection, Selection::render),
    }
}

pub(crate) fn get_state_validator_balances(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let selection = Selection::ids_from_query(req.query);
    respond_selection(req, ctx, resp, selection, Selection::render_balances);
}

pub(crate) fn post_state_validator_balances(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let selection = Selection::from_id_array(req.body);
    respond_selection(req, ctx, resp, selection, Selection::render_balances);
}

struct Rejection {
    code: u16,
    message: &'static str,
}

impl Rejection {
    fn bad_request(message: &'static str) -> Self {
        Self { code: 400, message }
    }
}

/// The whole registry is a valid selection the schema allows and no validator
/// client sends: each one names the validators it runs, and the one library
/// that wants every validator downloads the SSZ state instead.
fn respond_selection(
    req: &Request<'_>,
    ctx: &ApiCtx,
    resp: &mut Response<'_>,
    selection: Result<Selection, Rejection>,
    render: fn(&Selection, &StateReadView<'_>, &mut Json<'_>),
) {
    if !ctx.follows_chain(resp) {
        return;
    }
    let mut selection = match selection {
        Ok(selection) if !selection.ids.is_empty() => selection,
        Ok(_) => {
            resp.error(400, "at least one id is required");
            return;
        }
        Err(rejection) => {
            resp.error(rejection.code, rejection.message);
            return;
        }
    };
    selection.ids.sort_unstable();
    selection.ids.dedup();
    ctx.state_response(req, resp, |view, json| render(&selection, view, json));
}

/// The registry from one pinned state, rendered a batch at a time so neither
/// the render nor the body holds the tile for the whole registry.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RegistryStream {
    pin: PinnedState,
    statuses: StatusSet,
    next: usize,
    rendered_any: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Batch {
    More,
    Last,
    Superseded,
}

impl RegistryStream {
    fn new(pin: PinnedState, statuses: StatusSet) -> Self {
        Self { pin, statuses, next: 0, rendered_any: false }
    }

    /// Appends the next batch of the body to `out`. `Superseded` means a
    /// finalize ended the pinned state, and the body can no longer be whole.
    pub(crate) fn render_next(&mut self, ctx: &ApiCtx, out: &mut Vec<u8>) -> Batch {
        let rendered = ctx.state.read_pinned(self.pin, |view| {
            if self.next == 0 {
                let mut json = Json::new(out);
                json.begin_flagged_envelope(read_flags(ctx.node_status, &view));
                json.begin_array();
            }
            self.render_batch(&view, out);
            self.next == view.validators.count()
        });
        match rendered {
            None => Batch::Superseded,
            Some(true) => Batch::Last,
            Some(false) => Batch::More,
        }
    }

    /// Batches are framed apart, so `rendered_any` carries the separator
    /// across them.
    fn render_batch(&mut self, view: &StateReadView<'_>, out: &mut Vec<u8>) {
        let current_epoch = view.slot.current_epoch();
        let count = view.validators.count();
        let end = count.min(self.next + VALIDATORS_PER_BATCH);
        for index in self.next..end {
            let record = ValidatorRecord::read(view, current_epoch, index);
            if self.statuses.admits(record.status) {
                if self.rendered_any {
                    out.push(b',');
                }
                Json::new(out).validator(&record);
                self.rendered_any = true;
            }
        }
        self.next = end;
        if end == count {
            let mut json = Json::new(out);
            json.end_array();
            json.end_object();
        }
    }
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
    over_limit: u16,
}

impl Selection {
    fn from_query(query: &str) -> Result<Self, Rejection> {
        let mut selection = Self { over_limit: 414, ..Self::default() };
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

    /// `getStateValidatorBalances` takes ids only; any `status` is ignored.
    fn ids_from_query(query: &str) -> Result<Self, Rejection> {
        let mut selection = Self { over_limit: 414, ..Self::default() };
        for (name, value) in Query::new(query) {
            if name == "id" {
                value.split(',').try_for_each(|id| selection.push_id(id))?;
            }
        }
        Ok(selection)
    }

    /// `postStateValidatorBalances` posts the ids as a bare array.
    fn from_id_array(body: &[u8]) -> Result<Self, Rejection> {
        let mut ids: Vec<&str> = Vec::new();
        each_body_entry(body, |_, id| ids.push(id)).map_err(Rejection::bad_request)?;
        let mut selection = Self { over_limit: 400, ..Self::default() };
        ids.iter().try_for_each(|id| selection.push_id(id))?;
        Ok(selection)
    }

    fn from_body(body: &SelectionBody<'_>) -> Result<Self, Rejection> {
        let mut selection = Self { over_limit: 400, ..Self::default() };
        body.ids.iter().flatten().try_for_each(|id| selection.push_id(id))?;
        body.statuses.iter().flatten().try_for_each(|status| selection.push_status(status))?;
        Ok(selection)
    }

    fn push_id(&mut self, text: &str) -> Result<(), Rejection> {
        if self.ids.len() == MAX_VALIDATOR_IDS {
            return Err(Rejection { code: self.over_limit, message: "too many ids" });
        }
        let id = ValidatorId::parse(text).ok_or(Rejection::bad_request("invalid id"))?;
        self.ids.push(id);
        Ok(())
    }

    fn push_status(&mut self, text: &str) -> Result<(), Rejection> {
        let parsed = StatusSet::parse(text).ok_or(Rejection::bad_request("invalid status"))?;
        self.statuses = self.statuses.union(parsed);
        Ok(())
    }

    /// Ids that name no validator are dropped, as the schema asks.
    fn resolved<'s>(&'s self, view: &'s StateReadView<'_>) -> impl Iterator<Item = usize> + 's {
        self.ids.iter().filter_map(|id| id.resolve(&view.validators))
    }

    fn render(&self, view: &StateReadView<'_>, json: &mut Json<'_>) {
        let current_epoch = view.slot.current_epoch();
        json.begin_array();
        for ix in self.resolved(view) {
            let record = ValidatorRecord::read(view, current_epoch, ix);
            if self.statuses.admits(record.status) {
                json.validator(&record);
            }
        }
        json.end_array();
    }

    fn render_balances(&self, view: &StateReadView<'_>, json: &mut Json<'_>) {
        json.begin_array();
        for ix in self.resolved(view) {
            json.validator_balance(ix as u64, view.balances.get(ix));
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
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
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

    fn filters(self) -> bool {
        self.0 != 0
    }

    fn admits(self, status: ValidatorStatus) -> bool {
        self.0 == 0 || self.0 & 1 << status as u8 != 0
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, SLOTS_PER_EPOCH, SpecConfig, ValSeed,
    };
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::test_ctx,
        http::router::{Outcome, Router},
        routes::ROUTES,
        testing::{self, posting, request, submissions},
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
            eth_builder_url: None,
            eth_blob_data_included: None,
            version: 1,
            keep_alive: true,
        };
        let mut out = Vec::new();
        assert_eq!(
            Router::new(ROUTES).dispatch(&req, &ctx(), &mut submissions(), &mut out),
            Outcome::Response(None)
        );
        out
    }

    fn get(path: &str, query: &str) -> Vec<u8> {
        dispatch("GET", path, query, "")
    }

    /// The `data` of a whole-registry download, rendered batch by batch.
    fn downloaded(ctx: &ApiCtx, req: &ParsedRequest<'_>) -> String {
        let (Outcome::Download(mut registry), head) = testing::dispatch(ctx, req) else {
            panic!("a whole-registry selection downloads")
        };
        assert!(head.ends_with(b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"));
        let mut body = Vec::new();
        while registry.render_next(ctx, &mut body) == Batch::More {}
        let body = String::from_utf8(body).unwrap();
        let data = body.find(",\"data\":").unwrap();
        body[data + ",\"data\":".len()..body.len() - 1].to_string()
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

    /// The housekeeper of helix's relay refreshes its known validators so.
    #[test]
    fn status_filter_alone_selects_the_registry_it_admits() {
        let path = "/eth/v1/beacon/states/head/validators";
        let pending = record_json(
            1,
            32_000_000_000,
            "pending_initialized",
            &format!(
                "{{\"pubkey\":\"{}\",\"withdrawal_credentials\":\"{}\",\
                 \"effective_balance\":\"32000000000\",\"slashed\":false,\
                 \"activation_eligibility_epoch\":\"{FAR_FUTURE_EPOCH}\",\
                 \"activation_epoch\":\"{}\",\"exit_epoch\":\"{FAR_FUTURE_EPOCH}\",\
                 \"withdrawable_epoch\":\"{FAR_FUTURE_EPOCH}\"}}",
                hex(&pubkey(0xa2)),
                hex(&[0; 32]),
                EPOCH + 1,
            ),
        );
        let active = record_json(0, 32_000_000_123, "active_ongoing", &active_validator());
        let get = |query| downloaded(&ctx(), &ParsedRequest { query, ..request("GET", path) });
        assert_eq!(get("status=active,pending"), format!("[{active},{pending}]"));
        assert_eq!(get("status=exited").matches("\"index\"").count(), 1);
        assert_eq!(get("status=withdrawal"), "[]");
        let body = r#"{"statuses":["pending"]}"#;
        assert_eq!(downloaded(&ctx(), &posting(path, body)), format!("[{pending}]"));
    }

    #[test]
    fn registry_downloads_are_capped() {
        let mut ctx = ctx();
        let req = ParsedRequest {
            query: "status=active",
            ..request("GET", "/eth/v1/beacon/states/head/validators")
        };
        ctx.registry_downloads = MAX_REGISTRY_DOWNLOADS - 1;
        assert!(matches!(testing::dispatch(&ctx, &req).0, Outcome::Download(_)));
        ctx.registry_downloads = MAX_REGISTRY_DOWNLOADS;
        assert_eq!(status_code(&testing::dispatch(&ctx, &req).1), "503");
    }

    #[test]
    fn longest_validator_record_is_its_bound() {
        let lifecycle = Lifecycle {
            slashed: false,
            activation_eligibility_epoch: u64::MAX,
            activation_epoch: u64::MAX,
            exit_epoch: u64::MAX,
            withdrawable_epoch: u64::MAX,
        };
        let record = ValidatorRecord {
            index: u64::MAX,
            balance: u64::MAX,
            status: ValidatorStatus::WithdrawalPossible,
            pubkey: [0xff; 48],
            withdrawal_credentials: Withdrawals([0xff; 32]),
            effective_balance: u64::MAX,
            lifecycle,
        };
        let mut out = Vec::new();
        Json::new(&mut out).validator(&record);
        assert_eq!(out.len() + ",".len(), MAX_VALIDATOR_JSON);
    }

    #[test]
    fn download_ends_when_a_finalize_supersedes_its_state() {
        let mut owner = BeaconStateOwner::published_empty_test(HEAD_SLOT);
        let ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        let req = ParsedRequest {
            query: "status=active",
            ..request("GET", "/eth/v1/beacon/states/head/validators")
        };
        let (Outcome::Download(mut registry), _) = testing::dispatch(&ctx, &req) else {
            panic!("a whole-registry selection downloads")
        };
        drop(owner.write());
        assert_eq!(registry.render_next(&ctx, &mut Vec::new()), Batch::Superseded);
    }

    #[test]
    fn list_rejects_malformed_filters_and_an_empty_selection() {
        let path = "/eth/v1/beacon/states/head/validators";
        for query in ["id=0&status=running", "id=abc", "id=0&id=0x12", "status=active,running", ""]
        {
            assert_eq!(status_code(&get(path, query)), "400", "{query:?}");
        }
    }

    #[test]
    fn id_lists_past_the_cap_are_414_on_the_query_and_400_in_the_body() {
        let path = "/eth/v1/beacon/states/head/validators";
        let ids = |count: usize| (0..count).map(|id| id.to_string()).collect::<Vec<_>>();
        let body = |count| format!("{{\"ids\":[\"{}\"]}}", ids(count).join("\",\""));

        assert_eq!(
            status_code(&get(path, &format!("id={}", ids(MAX_VALIDATOR_IDS).join(",")))),
            "200"
        );
        assert_eq!(
            status_code(&get(path, &format!("id={}", ids(MAX_VALIDATOR_IDS + 1).join(",")))),
            "414"
        );
        assert_eq!(status_code(&post(&body(MAX_VALIDATOR_IDS))), "200");
        assert_eq!(status_code(&post(&body(MAX_VALIDATOR_IDS + 1))), "400");
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

    const BALANCES: &str = "/eth/v1/beacon/states/head/validator_balances";

    fn balance_json(index: u64, balance: u64) -> String {
        format!("{{\"index\":\"{index}\",\"balance\":\"{balance}\"}}")
    }

    #[test]
    fn balances_answer_ids_by_index_and_pubkey_and_drop_unknown_ones() {
        let query = format!("id=2,99,{}", hex(&pubkey(0xa1)));
        let expected = format!("[{},{}]", balance_json(2, 7), balance_json(0, 32_000_000_123));
        assert_eq!(data(&get(BALANCES, &query)), expected);
    }

    /// The balances schema has no status filter, so a `status` parameter,
    /// even a malformed one, changes nothing.
    #[test]
    fn balances_ignore_any_status() {
        let expected = format!("[{}]", balance_json(1, 32_000_000_000));
        assert_eq!(data(&get(BALANCES, "id=1&status=exited_slashed")), expected);
        assert_eq!(data(&get(BALANCES, "id=1&status=nonsense")), expected);
    }

    #[test]
    fn balances_post_a_bare_id_array() {
        let body = format!("[\"0\",\"{}\"]", hex(&pubkey(0xa3)));
        let expected = format!("[{},{}]", balance_json(0, 32_000_000_123), balance_json(2, 7));
        assert_eq!(data(&dispatch("POST", BALANCES, "", &body)), expected);
        for body in ["{\"ids\":[\"0\"]}", "[\"x\"]", "nonsense"] {
            assert_eq!(status_code(&dispatch("POST", BALANCES, "", body)), "400", "{body}");
        }
    }

    #[test]
    fn balances_need_at_least_one_id() {
        assert_eq!(status_code(&get(BALANCES, "")), "400");
        assert_eq!(status_code(&dispatch("POST", BALANCES, "", "[]")), "400");
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

    /// Helix's relay asks for the whole active and pending registry every
    /// ten minutes; on mainnet that is about 1.1M validators. Each batch is
    /// as long as the download holds the tile in one go.
    #[test]
    #[ignore = "timing; run with --release --ignored --nocapture"]
    fn registry_download_timing() {
        const VALIDATORS: u64 = 1_100_000;
        let seeds: Vec<_> = (0..VALIDATORS)
            .map(|i| {
                let mut pubkey = [0xa5; 48];
                pubkey[..8].copy_from_slice(&i.to_le_bytes());
                ValSeed {
                    pubkey,
                    withdrawal_credentials: Withdrawals([i as u8; 32]),
                    effective_balance: 32_000_000_000,
                    balance: 32_000_000_000 + i,
                    activation_epoch: 5 + i % EPOCH,
                    exit_epoch: FAR_FUTURE_EPOCH,
                }
            })
            .collect();
        let state = BeaconState::for_test(EpochStateFinalized::default(), &seeds, HEAD_SLOT);
        let mut owner = BeaconStateOwner::new(state);
        let anchor = owner.roll_fresh();
        owner.publish_state_id(anchor);
        let ctx = test_ctx(&SpecConfig::mainnet(), owner.reader());
        let req = ParsedRequest {
            query: "status=active,pending",
            ..request("GET", "/eth/v1/beacon/states/head/validators")
        };

        let mut batch = Vec::new();
        for _ in 0..3 {
            let (Outcome::Download(mut registry), _) = testing::dispatch(&ctx, &req) else {
                panic!("a whole-registry selection downloads")
            };
            let (mut total, mut slowest, mut bytes, mut batches) =
                (Duration::ZERO, Duration::ZERO, 0, 0);
            loop {
                batch.clear();
                let started = Instant::now();
                let rendered = registry.render_next(&ctx, &mut batch);
                let elapsed = started.elapsed();
                total += elapsed;
                slowest = slowest.max(elapsed);
                bytes += batch.len();
                batches += 1;
                if rendered != Batch::More {
                    assert_eq!(rendered, Batch::Last);
                    break;
                }
            }
            println!(
                "{batches} batches, {} MB: total {total:?}, slowest {slowest:?}, largest {} KB",
                bytes / 1_000_000,
                batch.capacity() / 1000,
            );
        }
    }
}
