use crate::{
    ids::{parse_uint64, submitted_indices},
    response::Response,
    router::Request,
    routes::ApiCtx,
};

/// A validator is live when the node has observed it, and silver keeps no
/// record of what it has seen a validator do — so every index comes back
/// not-live, which the schema's "best-effort ... may indicate that a validator
/// is not live when it actually is" makes a legal answer. It is also the
/// dangerous direction: not-live is what clears doppelganger protection, so a
/// validator running twice starts attesting twice on this node's word. Hence
/// the warning on every call.
pub(crate) fn post_liveness(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    let named = req.params.get("epoch").expect("{epoch} in the route pattern");
    let Some(epoch) = parse_uint64(named) else {
        resp.error(400, "invalid epoch");
        return;
    };
    let indices = match submitted_indices(req.body) {
        Ok(indices) => indices,
        Err(message) => {
            resp.error(400, message);
            return;
        }
    };

    tracing::warn!(
        epoch,
        validators = indices.len(),
        "liveness answered not-live for every validator: silver observes none, so a client \
         relying on this for doppelganger detection is not protected"
    );
    resp.json_body(|json| {
        json.data_envelope(|json| {
            json.begin_array();
            for &index in &indices {
                json.liveness(index, false);
            }
            json.end_array()
        })
    });
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use crate::{
        ids::MAX_BODY_IDS,
        router::Router,
        routes::{ROUTES, preboot_ctx},
    };

    fn dispatch(method: &str, epoch: &str, content_type: Option<&str>, body: &str) -> Vec<u8> {
        let path = format!("/eth/v1/validator/liveness/{epoch}");
        let mut out = Vec::new();
        let req = ParsedRequest {
            method,
            path: &path,
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

    fn post(epoch: &str, body: &str) -> Vec<u8> {
        dispatch("POST", epoch, Some("application/json"), body)
    }

    fn ok_body(response: &[u8]) -> String {
        let text = String::from_utf8_lossy(response);
        assert!(
            text.starts_with("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"),
            "{text}"
        );
        text[text.find("\r\n\r\n").unwrap() + 4..].to_owned()
    }

    fn assert_bad_request(response: &[u8], message: &str) {
        let text = String::from_utf8_lossy(response);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{text}");
        assert!(text.ends_with(&format!("{{\"code\":400,\"message\":\"{message}\"}}")), "{text}");
    }

    /// Body shape: `PostLivenessResponseBody` of `apis/validator/liveness.yaml`
    /// — a bare `data` wrapper around one `{index, is_live}` per validator,
    /// the index a quoted decimal string and the flag bare.
    #[test]
    fn the_body_is_one_not_live_entry_per_validator() {
        assert_eq!(
            ok_body(&post("300", "[\"7\",\"0\"]")),
            "{\"data\":[{\"index\":\"0\",\"is_live\":false},{\"index\":\"7\",\"is_live\":false}]}"
        );
        serde_json::from_str::<serde_json::Value>(&ok_body(&post("300", "[\"1\"]")))
            .expect("valid JSON");
    }

    /// One validator named twice is one entry, as it is for the sync duties
    /// the same body shape serves.
    #[test]
    fn a_validator_named_twice_is_answered_once() {
        assert_eq!(
            ok_body(&post("300", "[\"4\",\"4\",\"4\"]")),
            "{\"data\":[{\"index\":\"4\",\"is_live\":false}]}"
        );
    }

    /// The answer is the same constant at every epoch, so refusing one would
    /// refuse a request this node can answer as well as it answers any other.
    /// The spec asks a node to support the current and previous epoch and
    /// leaves earlier ones optional; it draws no upper bound at all.
    #[test]
    fn every_epoch_the_path_can_spell_is_answered() {
        for epoch in ["0", "1", "300", "18446744073709551615"] {
            assert_eq!(
                ok_body(&post(epoch, "[\"1\"]")),
                "{\"data\":[{\"index\":\"1\",\"is_live\":false}]}",
                "{epoch}"
            );
        }
    }

    /// "Invalid epoch: -2" in the schema's own 400 example.
    #[test]
    fn an_epoch_naming_no_epoch_at_all_is_a_400() {
        for epoch in ["-2", "+1", "banana", "", "1.5", "0x1", "18446744073709551616"] {
            assert_bad_request(&post(epoch, "[\"1\"]"), "invalid epoch");
        }
    }

    /// `PostLivenessRequestBody`: an array of `Uint64` with `minItems: 1`,
    /// each a quoted decimal string.
    #[test]
    fn a_body_that_is_not_the_schema_s_index_array_is_a_400() {
        for body in ["", "not json", "{}", "[1]", "[\"1\",2]"] {
            assert_bad_request(&post("300", body), "invalid request body");
        }
        assert_bad_request(&post("300", "[]"), "no validator index in request body");
        assert_bad_request(&post("300", "[\"-1\"]"), "invalid validator index");
    }

    /// The response carries an entry per index, so the cap bounds what one
    /// request can make this node write as well as what it makes it read.
    #[test]
    fn more_indices_than_the_cap_is_a_400() {
        let index = |i: usize| format!("\"{i}\"");
        let at_cap = format!("[{}]", (0..MAX_BODY_IDS).map(index).collect::<Vec<_>>().join(","));
        let past_cap = format!("[{}]", (0..=MAX_BODY_IDS).map(index).collect::<Vec<_>>().join(","));

        assert!(post("300", &at_cap).starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert_bad_request(&post("300", &past_cap), "too many validator indices in request body");
    }

    /// The schema declares no 415, so the content type is not this endpoint's
    /// to judge: a body it can read is a body it answers.
    #[test]
    fn a_non_json_content_type_is_not_refused() {
        let expected = "{\"data\":[{\"index\":\"1\",\"is_live\":false}]}";
        for content_type in [None, Some("application/octet-stream"), Some("text/plain")] {
            let response = dispatch("POST", "300", content_type, "[\"1\"]");
            assert_eq!(ok_body(&response), expected, "{content_type:?}");
        }
    }

    /// The schema declares a 503 for a syncing node, but this answer costs no
    /// state read and would be the same one after the sync — and a 5xx here
    /// takes the node out of a `go-eth2-client` rotation and marks it errored
    /// in Teku.
    #[test]
    fn a_node_with_no_state_published_still_answers_200() {
        assert!(post("300", "[\"1\"]").starts_with(b"HTTP/1.1 200 OK\r\n"));
    }

    #[test]
    fn the_route_takes_post_and_nothing_else() {
        let response = dispatch("GET", "300", None, "");
        assert!(response.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));
    }
}
