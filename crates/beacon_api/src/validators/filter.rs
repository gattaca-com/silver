use serde::Deserialize;
use silver_beacon_state_data::{BLSPubkey, ValidatorsView};
use silver_httpcore::Query;

use crate::{
    ids::MAX_BODY_IDS,
    response::Response,
    validators::status::{Status, StatusMask},
};

/// `maxItems` on the GET `id` array (`apis/beacon/states/validators.yaml`).
const MAX_QUERY_IDS: usize = 64;

pub(crate) enum ValidatorId {
    Index(u64),
    Pubkey(BLSPubkey),
}

impl ValidatorId {
    /// `None` for a value that names no validator at all, which the schemas
    /// answer 400 — distinct from a well-formed id no validator carries.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let Some(hex) = text.strip_prefix("0x") else {
            // `u64::from_str` alone also accepts a leading `+`.
            return text
                .bytes()
                .all(|byte| byte.is_ascii_digit())
                .then(|| text.parse().ok())
                .flatten()
                .map(Self::Index);
        };
        let mut pubkey = [0u8; 48];
        hex::decode_to_slice(hex, &mut pubkey).ok()?;
        Some(Self::Pubkey(pubkey))
    }

    pub(crate) fn resolve(&self, validators: &ValidatorsView<'_>) -> Option<u32> {
        match self {
            Self::Index(index) => {
                u32::try_from(*index).ok().filter(|&i| (i as usize) < validators.count())
            }
            Self::Pubkey(pubkey) => validators.find_by_pubkey(pubkey),
        }
    }
}

/// The `id`/`status` pair both list endpoints filter on. Naming no id and no
/// status is the spec's "no filtering on that attribute", which selects the
/// whole registry.
#[derive(Default)]
pub(crate) struct Filter {
    ids: Vec<ValidatorId>,
    statuses: StatusMask,
}

impl Filter {
    /// `id` and `status` repeat, and each occurrence may itself be a
    /// comma-separated list — no id or status value can contain a comma, so
    /// accepting both spellings can never split a legal value.
    pub(crate) fn from_query(query: &str) -> Result<Self, FilterError> {
        let mut filter = Self::default();
        for (name, value) in Query::new(query) {
            match name.as_ref() {
                "id" => {
                    for item in value.split(',') {
                        if filter.ids.len() == MAX_QUERY_IDS {
                            return Err(FilterError::TooManyQueryIds);
                        }
                        filter.ids.push(ValidatorId::parse(item).ok_or(FilterError::InvalidId)?);
                    }
                }
                "status" => {
                    for item in value.split(',') {
                        let mask = StatusMask::parse(item).ok_or(FilterError::InvalidStatus)?;
                        filter.statuses.insert(mask);
                    }
                }
                _ => {}
            }
        }
        Ok(filter)
    }

    pub(crate) fn from_body(body: &[u8]) -> Result<Self, FilterError> {
        let parsed: RequestBody =
            serde_json::from_slice(body).map_err(|_| FilterError::InvalidBody)?;
        let submitted_ids = parsed.ids.unwrap_or_default();
        if submitted_ids.len() > MAX_BODY_IDS {
            return Err(FilterError::TooManyBodyIds);
        }

        let mut filter = Self::default();
        for id in submitted_ids {
            filter.ids.push(ValidatorId::parse(&id).ok_or(FilterError::InvalidId)?);
        }
        for status in parsed.statuses.unwrap_or_default() {
            let mask = StatusMask::parse(&status).ok_or(FilterError::InvalidStatus)?;
            filter.statuses.insert(mask);
        }
        Ok(filter)
    }

    /// The indices this filter's ids name, deduplicated and in registry order;
    /// `None` when it names none, which selects the whole registry. Ids that
    /// resolve to no validator are dropped — the schemas return no information
    /// for them rather than an error.
    pub(crate) fn resolve_ids(&self, validators: &ValidatorsView<'_>) -> Option<Vec<u32>> {
        if self.ids.is_empty() {
            return None;
        }
        let mut indices: Vec<_> = self.ids.iter().filter_map(|id| id.resolve(validators)).collect();
        indices.sort_unstable();
        indices.dedup();
        Some(indices)
    }

    pub(crate) fn accepts(&self, status: Status) -> bool {
        self.statuses.accepts(status)
    }
}

/// A request naming a filter this endpoint cannot answer from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum FilterError {
    InvalidId,
    InvalidStatus,
    TooManyQueryIds,
    TooManyBodyIds,
    InvalidBody,
}

impl FilterError {
    pub(crate) fn respond(self, resp: &mut Response<'_>) {
        match self {
            Self::InvalidId => resp.error(400, "invalid validator id"),
            Self::InvalidStatus => resp.error(400, "invalid validator status"),
            Self::TooManyQueryIds => resp.error(414, "too many validator ids in request"),
            Self::TooManyBodyIds => resp.error(400, "too many validator ids in request body"),
            Self::InvalidBody => resp.error(400, "invalid request body"),
        }
    }
}

/// `postStateValidators`' request body; either list may be absent or `null`.
#[derive(Deserialize)]
struct RequestBody {
    ids: Option<Vec<String>>,
    statuses: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(query: &str) -> Vec<String> {
        Filter::from_query(query)
            .unwrap()
            .ids
            .iter()
            .map(|id| match id {
                ValidatorId::Index(index) => index.to_string(),
                ValidatorId::Pubkey(pubkey) => format!("0x{}", hex::encode(pubkey)),
            })
            .collect()
    }

    fn pubkey_text(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 48]))
    }

    #[test]
    fn ids_repeat_or_come_comma_separated_or_both() {
        assert_eq!(ids("id=1&id=2"), ["1", "2"]);
        assert_eq!(ids("id=1,2,3"), ["1", "2", "3"]);
        assert_eq!(ids("id=1,2&id=3"), ["1", "2", "3"]);
        assert_eq!(ids(""), Vec::<String>::new());
        assert_eq!(ids("status=active"), Vec::<String>::new());
    }

    #[test]
    fn a_pubkey_id_keeps_its_48_bytes_whatever_case_it_arrives_in() {
        let key = pubkey_text(0xab);
        assert_eq!(ids(&format!("id={key}")), [key.clone()]);
        assert_eq!(ids(&format!("id={}", key.to_uppercase().replace("0X", "0x"))), [key]);
    }

    #[test]
    fn a_query_value_reaches_the_filter_percent_decoded() {
        assert_eq!(ids("id=%31%32"), ["12"]);
    }

    #[test]
    fn statuses_repeat_or_come_comma_separated() {
        let filter = Filter::from_query("status=active_ongoing,exited&status=pending").unwrap();
        assert!(filter.accepts(Status::ActiveOngoing));
        assert!(filter.accepts(Status::ExitedSlashed));
        assert!(filter.accepts(Status::PendingQueued));
        assert!(!filter.accepts(Status::WithdrawalDone));
    }

    #[test]
    fn no_status_filter_accepts_every_status() {
        let filter = Filter::from_query("id=1").unwrap();
        assert!(filter.accepts(Status::ActiveOngoing));
        assert!(filter.accepts(Status::WithdrawalDone));
    }

    /// The `status` array carries no `maxItems`, so what bounds the sweep is
    /// that the filter holds a set: a value repeated 100k times leaves the
    /// same mask as naming it once, and the same O(1) test per validator.
    #[test]
    fn a_status_repeated_to_the_size_of_a_request_collapses_to_one_mask() {
        let once = Filter::from_query("status=active").unwrap();
        let repeated = "active,".repeat(100_000);
        let flooded = Filter::from_query(&format!("status={}", repeated.trim_end_matches(',')))
            .expect("every item is a legal status");
        assert_eq!(flooded.statuses, once.statuses);
        assert!(flooded.ids.is_empty());
    }

    /// A value that names no validator is malformed input, not an unknown
    /// validator: the empty item a stray comma or a bare `id=` produces
    /// included, since answering it as "no filter" would serve the whole
    /// registry to a client that asked for nothing.
    #[test]
    fn an_id_that_names_no_validator_at_all_is_rejected() {
        for query in [
            "id=",
            "id=1,,2",
            "id=-1",
            "id=+1",
            "id=1.5",
            "id=abc",
            "id=0x",
            "id=0xzz",
            &format!("id=0x{}", "ab".repeat(47)),
            &format!("id=0x{}", "ab".repeat(49)),
            "id=18446744073709551616",
        ] {
            assert_eq!(Filter::from_query(query).err(), Some(FilterError::InvalidId), "{query}");
        }
    }

    #[test]
    fn a_status_that_is_not_in_the_schema_is_rejected() {
        for query in ["status=", "status=active,bogus", "status=ACTIVE"] {
            assert_eq!(
                Filter::from_query(query).err(),
                Some(FilterError::InvalidStatus),
                "{query}"
            );
        }
    }

    /// `maxItems: 64` on the GET `id` array; the 65th is over the cap however
    /// the client spells the list.
    #[test]
    fn the_65th_query_id_is_a_414() {
        let sixty_four = (0..64).map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        assert_eq!(Filter::from_query(&format!("id={sixty_four}")).unwrap().ids.len(), 64);
        assert_eq!(
            Filter::from_query(&format!("id={sixty_four}&id=64")).err(),
            Some(FilterError::TooManyQueryIds)
        );
        assert_eq!(
            Filter::from_query(&format!("id={sixty_four},64")).err(),
            Some(FilterError::TooManyQueryIds)
        );
    }

    /// The POST body exists to carry lists longer than the GET query allows,
    /// so the 64-id cap is not applied to it — but its own bound is.
    #[test]
    fn the_post_body_takes_far_more_ids_than_a_query_may_and_still_has_a_bound() {
        let list = |count: usize| {
            let many: Vec<String> = (0..count).map(|i| i.to_string()).collect();
            serde_json::json!({ "ids": many }).to_string()
        };
        assert_eq!(Filter::from_body(list(1_000).as_bytes()).unwrap().ids.len(), 1_000);
        assert_eq!(
            Filter::from_body(list(MAX_BODY_IDS).as_bytes()).unwrap().ids.len(),
            MAX_BODY_IDS
        );
        assert_eq!(
            Filter::from_body(list(MAX_BODY_IDS + 1).as_bytes()).err(),
            Some(FilterError::TooManyBodyIds)
        );
    }

    #[test]
    fn an_absent_null_or_empty_body_list_filters_on_nothing() {
        for body in [
            "{}",
            r#"{"ids":null,"statuses":null}"#,
            r#"{"ids":[],"statuses":[]}"#,
            r#"{"ids":[],"unknown_field":3}"#,
        ] {
            let filter = Filter::from_body(body.as_bytes()).expect(body);
            assert!(filter.ids.is_empty(), "{body}");
            assert!(filter.accepts(Status::WithdrawalDone), "{body}");
        }
    }

    #[test]
    fn a_body_that_is_not_the_schema_s_object_is_rejected() {
        for body in ["", "not json", "[]", r#"{"ids":"1"}"#, r#"{"ids":[1]}"#] {
            assert_eq!(Filter::from_body(body.as_bytes()).err(), Some(FilterError::InvalidBody));
        }
    }

    #[test]
    fn body_ids_and_statuses_are_validated_the_same_way_a_query_s_are() {
        assert_eq!(
            Filter::from_body(br#"{"ids":["1","banana"]}"#).err(),
            Some(FilterError::InvalidId)
        );
        assert_eq!(
            Filter::from_body(br#"{"statuses":["nope"]}"#).err(),
            Some(FilterError::InvalidStatus)
        );
    }

    /// 414 is declared on the GET alone, so the bound the body carries has to
    /// answer with a code the POST declares.
    #[test]
    fn each_refusal_answers_with_a_code_the_verb_that_raises_it_declares() {
        let status_line = |error: FilterError| {
            let mut out = Vec::new();
            error.respond(&mut Response::new(&mut out));
            String::from_utf8(out).unwrap().lines().next().unwrap().to_owned()
        };
        assert_eq!(status_line(FilterError::TooManyQueryIds), "HTTP/1.1 414 URI Too Long");
        for error in [
            FilterError::TooManyBodyIds,
            FilterError::InvalidBody,
            FilterError::InvalidId,
            FilterError::InvalidStatus,
        ] {
            assert_eq!(status_line(error), "HTTP/1.1 400 Bad Request", "{error:?}");
        }
    }

    /// Commas separate values in a query string only; a body carries a real
    /// array, so a comma inside one of its strings is part of that string.
    #[test]
    fn a_body_id_is_not_split_on_commas() {
        assert_eq!(Filter::from_body(br#"{"ids":["1,2"]}"#).err(), Some(FilterError::InvalidId));
    }
}
