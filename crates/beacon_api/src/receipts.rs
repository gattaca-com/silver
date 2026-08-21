//! The validator-client POSTs whose success response is a bare
//! acknowledgement. Each carries a preference or a subscription silver has
//! nothing wired to yet, and each schema's own model is fire-and-forget — a
//! subscription "cannot be certain the Beacon node will find peers", a
//! preparation carries "no guarantee that the beacon node will use the
//! supplied fee recipient" — so acknowledging a well-formed body is the whole
//! answer these endpoints owe, and the log line is where the gap shows.

use serde::Deserialize;
use silver_beacon_state_data::{BLSPubkey, BLSSignature, ExecutionAddress};

use crate::{
    ids::{MAX_BODY_IDS, is_hex_bytes, parse_uint64},
    response::Response,
    router::Request,
    routes::ApiCtx,
};

/// The phrase `UnsupportedMediaType` carries in `types/http.yaml`.
const UNSUPPORTED_MEDIA_TYPE: &str = "Cannot read the supplied content type.";

/// `registerValidator` is the only schema here that declares a 415, and the
/// only one that declares an SSZ request body beside the JSON one.
pub(crate) fn post_register_validator(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    if !req.body_is_json() {
        resp.error(415, UNSUPPORTED_MEDIA_TYPE);
        return;
    }
    let Some(registrations) = received(req.body, resp, Registration::well_formed) else {
        return;
    };
    tracing::debug!(
        count = registrations.len(),
        "validator registrations discarded: silver reaches no builder network"
    );
    resp.ok();
}

pub(crate) fn post_prepare_beacon_proposer(
    req: &Request<'_>,
    _ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let Some(preparations) = received(req.body, resp, ProposerPreparation::well_formed) else {
        return;
    };
    tracing::debug!(
        count = preparations.len(),
        "proposer preparations discarded: silver proposes no blocks"
    );
    resp.ok();
}

pub(crate) fn post_beacon_committee_subscriptions(
    req: &Request<'_>,
    _ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let Some(subscriptions) = received(req.body, resp, CommitteeSubscription::well_formed) else {
        return;
    };
    tracing::debug!(
        count = subscriptions.len(),
        aggregators = subscriptions.iter().filter(|entry| entry.is_aggregator).count(),
        "committee subscriptions discarded: silver steers no attestation subnet"
    );
    resp.ok();
}

pub(crate) fn post_sync_committee_subscriptions(
    req: &Request<'_>,
    _ctx: &ApiCtx,
    resp: &mut Response<'_>,
) {
    let Some(subscriptions) = received(req.body, resp, SyncCommitteeSubscription::well_formed)
    else {
        return;
    };
    tracing::debug!(
        count = subscriptions.len(),
        "sync committee subscriptions discarded: silver steers no sync subnet"
    );
    resp.ok();
}

/// The entries a body carries, or `None` having answered the 400 its schema
/// declares. Entries borrow their scalars out of `body`, so an array naming a
/// whole 500k-validator operator costs its `&str` pairs and copies nothing.
fn received<'a, T: Deserialize<'a>>(
    body: &'a [u8],
    resp: &mut Response<'_>,
    well_formed: impl Fn(&T) -> bool,
) -> Option<Vec<T>> {
    let Ok(entries) = serde_json::from_slice::<Vec<T>>(body) else {
        resp.error(400, "invalid request body");
        return None;
    };
    if entries.len() > MAX_BODY_IDS {
        resp.error(400, "too many entries in request body");
        return None;
    }
    if !entries.iter().all(well_formed) {
        resp.error(400, "invalid entry in request body");
        return None;
    }
    Some(entries)
}

/// `SignedValidatorRegistration` (`types/registration.yaml`).
#[derive(Deserialize)]
struct Registration<'a> {
    #[serde(borrow)]
    message: ValidatorRegistration<'a>,
    signature: &'a str,
}

#[derive(Deserialize)]
struct ValidatorRegistration<'a> {
    fee_recipient: &'a str,
    gas_limit: &'a str,
    timestamp: &'a str,
    pubkey: &'a str,
}

impl Registration<'_> {
    fn well_formed(&self) -> bool {
        is_hex_bytes(self.message.fee_recipient, size_of::<ExecutionAddress>()) &&
            parse_uint64(self.message.gas_limit).is_some() &&
            parse_uint64(self.message.timestamp).is_some() &&
            is_hex_bytes(self.message.pubkey, size_of::<BLSPubkey>()) &&
            is_hex_bytes(self.signature, size_of::<BLSSignature>())
    }
}

/// One entry of `prepareBeaconProposer`'s body. An index the registry does not
/// hold is well formed: the schema has it "may become active at a later
/// epoch".
#[derive(Deserialize)]
struct ProposerPreparation<'a> {
    validator_index: &'a str,
    fee_recipient: &'a str,
}

impl ProposerPreparation<'_> {
    fn well_formed(&self) -> bool {
        parse_uint64(self.validator_index).is_some() &&
            is_hex_bytes(self.fee_recipient, size_of::<ExecutionAddress>())
    }
}

/// One entry of `SubscribeToBeaconCommitteeSubnetRequestBody`.
#[derive(Deserialize)]
struct CommitteeSubscription<'a> {
    validator_index: &'a str,
    committee_index: &'a str,
    committees_at_slot: &'a str,
    slot: &'a str,
    is_aggregator: bool,
}

impl CommitteeSubscription<'_> {
    fn well_formed(&self) -> bool {
        [self.validator_index, self.committee_index, self.committees_at_slot, self.slot]
            .iter()
            .all(|text| parse_uint64(text).is_some())
    }
}

/// `Altair.SyncCommitteeSubscription`; the schema puts no minimum on
/// `sync_committee_indices`.
#[derive(Deserialize)]
struct SyncCommitteeSubscription<'a> {
    validator_index: &'a str,
    #[serde(borrow)]
    sync_committee_indices: Vec<&'a str>,
    until_epoch: &'a str,
}

impl SyncCommitteeSubscription<'_> {
    fn well_formed(&self) -> bool {
        parse_uint64(self.validator_index).is_some() &&
            parse_uint64(self.until_epoch).is_some() &&
            self.sync_committee_indices.iter().all(|text| parse_uint64(text).is_some())
    }
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        router::Router,
        routes::{ROUTES, preboot_ctx},
    };

    const REGISTER: &str = "/eth/v1/validator/register_validator";
    const PREPARE: &str = "/eth/v1/validator/prepare_beacon_proposer";
    const COMMITTEE_SUBS: &str = "/eth/v1/validator/beacon_committee_subscriptions";
    const SYNC_SUBS: &str = "/eth/v1/validator/sync_committee_subscriptions";

    const BODYLESS_OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

    const COMMITTEE_SUBSCRIPTION: &str = "{\"validator_index\":\"1\",\"committee_index\":\"2\",\
         \"committees_at_slot\":\"64\",\"slot\":\"12345\",\"is_aggregator\":true}";

    const SYNC_SUBSCRIPTION: &str = "{\"validator_index\":\"1\",\
         \"sync_committee_indices\":[\"0\",\"7\"],\"until_epoch\":\"300\"}";

    fn registration() -> String {
        format!(
            "{{\"message\":{{\"fee_recipient\":\"0x{fee}\",\"gas_limit\":\"30000000\",\
             \"timestamp\":\"1606824023\",\"pubkey\":\"0x{key}\"}},\"signature\":\"0x{sig}\"}}",
            fee = hex::encode([0xab; 20]),
            key = hex::encode([0xcd; 48]),
            sig = hex::encode([0xef; 96]),
        )
    }

    fn preparation() -> String {
        format!("{{\"validator_index\":\"1\",\"fee_recipient\":\"0x{}\"}}", hex::encode([0xab; 20]))
    }

    /// One well-formed entry per endpoint.
    fn entries() -> [(&'static str, String); 4] {
        [
            (REGISTER, registration()),
            (PREPARE, preparation()),
            (COMMITTEE_SUBS, COMMITTEE_SUBSCRIPTION.to_owned()),
            (SYNC_SUBS, SYNC_SUBSCRIPTION.to_owned()),
        ]
    }

    fn dispatch(method: &str, path: &str, content_type: Option<&str>, body: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let req = ParsedRequest {
            method,
            path,
            query: "",
            body: body.as_bytes(),
            accept: None,
            content_type,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        Router::new(ROUTES).dispatch(&req, &preboot_ctx(), &mut out);
        out
    }

    fn post(path: &str, content_type: Option<&str>, body: &str) -> Vec<u8> {
        dispatch("POST", path, content_type, body)
    }

    fn json_post(path: &str, body: &str) -> Vec<u8> {
        post(path, Some("application/json"), body)
    }

    fn assert_bad_request(response: &[u8], message: &str) {
        let text = String::from_utf8_lossy(response);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(text.ends_with(&format!("{{\"code\":400,\"message\":\"{message}\"}}")), "{text}");
    }

    /// Every receipt endpoint answers the same bodyless 200: none of the four
    /// schemas declares content under it. None reads beacon state either, so
    /// the whole suite runs against a node that has published none — which is
    /// when a validator client first sends these.
    #[test]
    fn a_well_formed_body_is_acknowledged_with_a_bodyless_200() {
        for (path, entry) in entries() {
            assert_eq!(json_post(path, &format!("[{entry}]")), BODYLESS_OK, "{path}");
            assert_eq!(json_post(path, &format!("[{entry},{entry}]")), BODYLESS_OK, "{path}");
        }
    }

    /// No schema here puts a `minItems` on its array, so an array naming
    /// nothing is still a body the node has received.
    #[test]
    fn an_empty_array_is_acknowledged_rather_than_refused() {
        for path in [REGISTER, PREPARE, COMMITTEE_SUBS, SYNC_SUBS] {
            assert_eq!(json_post(path, "[]"), BODYLESS_OK, "{path}");
        }
    }

    #[test]
    fn a_body_that_is_not_the_schema_s_array_is_a_400() {
        for path in [REGISTER, PREPARE, COMMITTEE_SUBS, SYNC_SUBS] {
            for body in ["", "not json", "{}", "null", "[[]]", "[1]"] {
                assert_bad_request(&json_post(path, body), "invalid request body");
            }
        }
    }

    /// The entry is the schema's object and its fields are still not the
    /// values the schema's patterns spell. A field left unchecked here is one
    /// the builder or the subnet would have to reject later, by which point
    /// there is no response left to say so through.
    #[test]
    fn an_entry_whose_fields_the_schema_s_patterns_reject_is_a_400() {
        let pubkey = format!("0x{}", hex::encode([0xcd; 48]));
        let short_pubkey = format!("0x{}", hex::encode([0xcd; 47]));
        for (path, entry) in [
            (REGISTER, registration().replace(&pubkey, &short_pubkey)),
            (REGISTER, registration().replace("0xabab", "abab")),
            (REGISTER, registration().replace("\"30000000\"", "\"0x1c9c380\"")),
            (PREPARE, preparation().replace("\"1\"", "\"-1\"")),
            (PREPARE, preparation().replace("\"1\"", "\"+1\"")),
            (PREPARE, preparation().replace("0xabab", "0xzzzz")),
            (COMMITTEE_SUBS, COMMITTEE_SUBSCRIPTION.replace("\"64\"", "\"banana\"")),
            (SYNC_SUBS, SYNC_SUBSCRIPTION.replace("\"7\"", "\"7.0\"")),
        ] {
            let response = json_post(path, &format!("[{entry}]"));
            assert_bad_request(&response, "invalid entry in request body");
        }
    }

    /// A field of the wrong JSON type, or under a name the schema does not
    /// declare, never reaches those checks: the array does not parse.
    #[test]
    fn an_entry_missing_a_field_the_schema_requires_is_a_400() {
        for (path, entry) in [
            (REGISTER, registration().replace("\"30000000\"", "30000000")),
            (REGISTER, registration().replace("\"gas_limit\"", "\"gasLimit\"")),
            (COMMITTEE_SUBS, COMMITTEE_SUBSCRIPTION.replace("true", "\"true\"")),
            (SYNC_SUBS, SYNC_SUBSCRIPTION.replace("\"300\"", "300")),
        ] {
            let response = json_post(path, &format!("[{entry}]"));
            assert_bad_request(&response, "invalid request body");
        }
    }

    /// An SSZ-first client keys its downgrade to JSON on the 415 alone. Teku
    /// carries that downgrade in its registration request behind a flag its
    /// shipped client hardcodes off; were it on, any other code here would
    /// lose the registrations with no retry.
    #[test]
    fn a_non_json_content_type_is_a_415_on_the_one_schema_that_declares_it() {
        let body = format!("[{}]", registration());
        for content_type in ["application/octet-stream", "APPLICATION/OCTET-STREAM", "text/plain"] {
            let response = post(REGISTER, Some(content_type), &body);
            assert!(
                response.starts_with(b"HTTP/1.1 415 Unsupported Media Type\r\n"),
                "{content_type}: {}",
                String::from_utf8_lossy(&response)
            );
            assert!(response.ends_with(
                format!("{{\"code\":415,\"message\":\"{UNSUPPORTED_MEDIA_TYPE}\"}}").as_bytes()
            ));
        }
    }

    /// The other three declare 400 and 500 and nothing else, so an SSZ body
    /// there is answered as the unreadable JSON it is.
    #[test]
    fn a_non_json_content_type_is_never_a_415_where_no_schema_declares_one() {
        for path in [PREPARE, COMMITTEE_SUBS, SYNC_SUBS] {
            let response = post(path, Some("application/octet-stream"), "\u{0}\u{1}\u{2}");
            assert_bad_request(&response, "invalid request body");
        }
    }

    /// A client naming no media type is sending JSON: the one media type worth
    /// a 415 announces itself, and refusing a header-less POST would refuse a
    /// request no schema calls invalid.
    #[test]
    fn a_body_naming_no_media_type_is_read_as_json() {
        for (path, entry) in entries() {
            let body = format!("[{entry}]");
            assert_eq!(post(path, None, &body), BODYLESS_OK, "{path}: absent");
            assert_eq!(post(path, Some(""), &body), BODYLESS_OK, "{path}: empty");
        }
    }

    #[test]
    fn a_json_content_type_carrying_parameters_is_still_json() {
        let body = format!("[{}]", registration());
        for content_type in [
            "application/json; charset=utf-8",
            "application/json;charset=UTF-8",
            "Application/JSON",
        ] {
            assert_eq!(post(REGISTER, Some(content_type), &body), BODYLESS_OK, "{content_type}");
        }
    }

    /// The cap answers before the entries are read, so an array no registry
    /// could hold is refused for its length rather than for the first field in
    /// it that fails.
    #[test]
    fn more_entries_than_the_cap_is_a_400_whatever_the_entries_hold() {
        let entry = "{\"validator_index\":\"1\",\"fee_recipient\":\"0x\"}";
        let past_cap = format!("[{}]", vec![entry; MAX_BODY_IDS + 1].join(","));
        assert_bad_request(&json_post(PREPARE, &past_cap), "too many entries in request body");

        let at_cap = format!("[{}]", vec![entry; MAX_BODY_IDS].join(","));
        assert_bad_request(&json_post(PREPARE, &at_cap), "invalid entry in request body");
    }

    /// Nothing in a JSON body's layout is the schema's: a client is free to
    /// indent it and to emit an object's members in any order, and both are
    /// the same body.
    #[test]
    fn indentation_and_member_order_do_not_change_the_body() {
        let fee_recipient = format!("0x{}", hex::encode([0xab; 20]));
        let pretty = format!(
            "[\n  {{\n    \"fee_recipient\": \"{fee_recipient}\",\n\
             \t\"validator_index\" : \"1\"\n  }}\n]\n"
        );
        assert_eq!(json_post(PREPARE, &pretty), BODYLESS_OK, "{pretty}");
    }

    #[test]
    fn every_receipt_route_takes_post_and_nothing_else() {
        for path in [REGISTER, PREPARE, COMMITTEE_SUBS, SYNC_SUBS] {
            let response = dispatch("GET", path, None, "");
            assert!(response.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"), "{path}");
        }
    }
}
