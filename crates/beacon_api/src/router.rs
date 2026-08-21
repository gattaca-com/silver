use silver_httpcore::{ParsedRequest, frame_response};

use crate::{response::Response, routes::ApiCtx};

const MAX_PARAMS: usize = 4;

const JSON_MEDIA_TYPE: &str = "application/json";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Method {
    Get,
    Post,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "GET" => Some(Self::Get),
            "POST" => Some(Self::Post),
            _ => None,
        }
    }
}

pub(crate) type Handler = fn(&Request<'_>, &ApiCtx, &mut Response<'_>);

// `method` and `path` become live with a handler that answers on more than the
// route it was dispatched by; until then only tests read them.
#[allow(dead_code)]
pub(crate) struct Request<'a> {
    pub(crate) method: Method,
    pub(crate) path: &'a str,
    pub(crate) params: Params<'a>,
    pub(crate) query: &'a str,
    pub(crate) content_type: Option<&'a str>,
    pub(crate) body: &'a [u8],
}

impl Request<'_> {
    /// Whether the body is one this API will read as JSON — a request naming
    /// no media type included. The schemas that declare a 415 are the ones
    /// that also take an SSZ body, and a client sending SSZ says so: an
    /// SSZ-first client keys its downgrade to JSON on the 415 alone, so any
    /// other answer there loses the body with no retry.
    pub(crate) fn body_is_json(&self) -> bool {
        let Some(media_type) = self.media_type() else {
            return true;
        };
        media_type.eq_ignore_ascii_case(JSON_MEDIA_TYPE)
    }

    /// The `Content-Type` header's media type, without the parameters that may
    /// follow it. `None` for a header that names none at all.
    fn media_type(&self) -> Option<&str> {
        let content_type = self.content_type?;
        let media_type = content_type.split(';').next().unwrap_or_default().trim();
        (!media_type.is_empty()).then_some(media_type)
    }
}

pub(crate) struct Params<'a> {
    entries: [(&'static str, &'a str); MAX_PARAMS],
    len: usize,
}

impl<'a> Params<'a> {
    pub(crate) fn get(&self, name: &str) -> Option<&'a str> {
        self.entries[..self.len].iter().find(|(n, _)| *n == name).map(|&(_, value)| value)
    }

    fn push(&mut self, name: &'static str, value: &'a str) {
        self.entries[self.len] = (name, value);
        self.len += 1;
    }
}

impl Default for Params<'_> {
    fn default() -> Self {
        Self { entries: [("", ""); MAX_PARAMS], len: 0 }
    }
}

enum Seg {
    Lit(&'static str),
    Param(&'static str),
}

struct Route {
    method: Method,
    segs: Vec<Seg>,
    handler: Handler,
}

impl Route {
    fn capture<'p>(&self, path: &'p str) -> Option<Params<'p>> {
        let mut parts = path.strip_prefix('/')?.split('/');
        let mut params = Params::default();
        for seg in &self.segs {
            let part = parts.next()?;
            match seg {
                Seg::Lit(lit) if *lit == part => {}
                Seg::Param(name) => params.push(name, part),
                Seg::Lit(_) => return None,
            }
        }
        parts.next().is_none().then_some(params)
    }
}

pub(crate) struct Router {
    routes: Vec<Route>,
}

impl Router {
    pub(crate) fn new(table: &[(Method, &'static str, Handler)]) -> Self {
        let mut routes: Vec<Route> = Vec::with_capacity(table.len());
        for &(method, pattern, handler) in table {
            let segs = compile(pattern);
            assert!(
                !routes.iter().any(|r| r.method == method && same_match_set(&r.segs, &segs)),
                "duplicate route pattern: {pattern}"
            );
            routes.push(Route { method, segs, handler });
        }
        Self { routes }
    }

    pub(crate) fn dispatch(&self, req: &ParsedRequest<'_>, ctx: &ApiCtx, out: &mut Vec<u8>) {
        let method = Method::parse(req.method);
        let mut path_known = false;
        for route in &self.routes {
            let Some(params) = route.capture(req.path) else { continue };
            if method != Some(route.method) {
                path_known = true;
                continue;
            }
            let request = Request {
                method: route.method,
                path: req.path,
                params,
                query: req.query,
                content_type: req.content_type,
                body: req.body,
            };
            (route.handler)(&request, ctx, &mut Response::new(out));
            return;
        }
        if path_known {
            Response::new(out).error(405, "method not allowed");
        } else {
            tracing::warn!("unknown path: {}", req.path);
            frame_response(out, "404 Not Found", None, b"");
        }
    }
}

fn compile(pattern: &'static str) -> Vec<Seg> {
    let stripped = pattern
        .strip_prefix('/')
        .unwrap_or_else(|| panic!("route pattern must start with '/': {pattern}"));
    let segs: Vec<_> = stripped
        .split('/')
        .map(|seg| match seg.strip_prefix('{') {
            Some(name) => Seg::Param(
                name.strip_suffix('}')
                    .unwrap_or_else(|| panic!("unterminated param in route pattern: {pattern}")),
            ),
            None => Seg::Lit(seg),
        })
        .collect();
    let params = segs.iter().filter(|s| matches!(s, Seg::Param(_))).count();
    assert!(params <= MAX_PARAMS, "route pattern exceeds {MAX_PARAMS} params: {pattern}");
    segs
}

/// Whether two compiled patterns match exactly the same set of paths —
/// param names don't affect matching, so they are ignored.
fn same_match_set(a: &[Seg], b: &[Seg]) -> bool {
    a.len() == b.len() &&
        a.iter().zip(b).all(|pair| match pair {
            (Seg::Lit(x), Seg::Lit(y)) => x == y,
            (Seg::Param(_), Seg::Param(_)) => true,
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::preboot_ctx;

    fn request<'a>(method: &'a str, path: &'a str) -> ParsedRequest<'a> {
        ParsedRequest {
            method,
            path,
            query: "",
            body: b"",
            accept: None,
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        }
    }

    fn dispatch(router: &Router, method: &str, path: &str) -> Vec<u8> {
        let mut out = Vec::new();
        router.dispatch(&request(method, path), &preboot_ctx(), &mut out);
        out
    }

    fn body(response: &[u8]) -> &[u8] {
        let s = std::str::from_utf8(response).unwrap();
        &response[s.find("\r\n\r\n").unwrap() + 4..]
    }

    fn first(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
        resp.json(b"first");
    }

    fn second(_req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
        resp.json(b"second");
    }

    fn echo_params(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
        let mut joined = String::new();
        for name in ["state_id", "epoch", "a", "b", "c", "d"] {
            if let Some(value) = req.params.get(name) {
                joined.push_str(name);
                joined.push('=');
                joined.push_str(value);
                joined.push(';');
            }
        }
        resp.json(joined.as_bytes());
    }

    fn echo_query_body(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
        let mut joined = req.query.as_bytes().to_vec();
        joined.push(b'|');
        joined.extend_from_slice(req.body);
        resp.json(&joined);
    }

    fn echo_media_type(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
        let verdict = if req.body_is_json() { "json" } else { "other" };
        resp.json(format!("{:?}|{verdict}", req.media_type()).as_bytes());
    }

    fn posted_with(content_type: Option<&str>) -> Vec<u8> {
        let router = Router::new(&[(Method::Post, "/submit", echo_media_type)]);
        let mut out = Vec::new();
        let req = ParsedRequest {
            method: "POST",
            path: "/submit",
            query: "",
            body: b"",
            accept: None,
            content_type,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        router.dispatch(&req, &preboot_ctx(), &mut out);
        out
    }

    #[test]
    fn the_content_type_header_reaches_the_handler() {
        assert_eq!(
            body(&posted_with(Some("application/octet-stream"))),
            b"Some(\"application/octet-stream\")|other"
        );
        assert_eq!(body(&posted_with(None)), b"None|json");
    }

    /// RFC 9110 makes the media type case-insensitive and lets parameters
    /// follow it; a header that names none at all leaves the body unlabelled,
    /// which is the same verdict as sending no header.
    #[test]
    fn a_json_media_type_is_recognized_however_it_is_spelled() {
        for header in [
            "application/json",
            "Application/JSON",
            "application/json; charset=utf-8",
            " application/json ",
        ] {
            assert!(body(&posted_with(Some(header))).ends_with(b"|json"), "{header}");
        }
        for header in ["application/octet-stream", "text/plain", "application/jsonx"] {
            assert!(body(&posted_with(Some(header))).ends_with(b"|other"), "{header}");
        }
        assert_eq!(body(&posted_with(Some(""))), b"None|json");
        assert_eq!(body(&posted_with(Some("; charset=utf-8"))), b"None|json");
    }

    #[test]
    fn literal_route_dispatches_matching_handler() {
        let router = Router::new(&[
            (Method::Get, "/eth/v1/node/identity", first),
            (Method::Get, "/metrics", second),
        ]);
        assert_eq!(body(&dispatch(&router, "GET", "/eth/v1/node/identity")), b"first");
        assert_eq!(body(&dispatch(&router, "GET", "/metrics")), b"second");
    }

    #[test]
    fn single_param_extracted_by_name() {
        let router = Router::new(&[(
            Method::Get,
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            echo_params,
        )]);
        let resp = dispatch(&router, "GET", "/eth/v1/beacon/states/head/finality_checkpoints");
        assert_eq!(body(&resp), b"state_id=head;");
    }

    #[test]
    fn two_params_extracted_by_name() {
        let router =
            Router::new(&[(Method::Get, "/eth/v1/states/{state_id}/epochs/{epoch}", echo_params)]);
        let resp = dispatch(&router, "GET", "/eth/v1/states/0xdead/epochs/42");
        assert_eq!(body(&resp), b"state_id=0xdead;epoch=42;");
    }

    #[test]
    fn url_encoded_param_value_passed_through_verbatim() {
        let router = Router::new(&[(Method::Get, "/states/{state_id}", echo_params)]);
        let resp = dispatch(&router, "GET", "/states/0x1234%2Fabc%20d");
        assert_eq!(body(&resp), b"state_id=0x1234%2Fabc%20d;");
    }

    #[test]
    fn query_and_body_reach_handler() {
        let router = Router::new(&[(Method::Post, "/submit", echo_query_body)]);
        let mut out = Vec::new();
        let req = ParsedRequest {
            method: "POST",
            path: "/submit",
            query: "k=v",
            body: b"payload",
            accept: None,
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        router.dispatch(&req, &preboot_ctx(), &mut out);
        assert_eq!(body(&out), b"k=v|payload");
    }

    #[test]
    fn unmatched_path_gets_bare_404() {
        let router = Router::new(&[(
            Method::Get,
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            echo_params,
        )]);
        let expected: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(dispatch(&router, "GET", "/not/real"), expected);
        assert_eq!(dispatch(&router, "GET", "/eth/v1/beacon/states/head"), expected, "prefix");
        assert_eq!(
            dispatch(&router, "GET", "/eth/v1/beacon/states/head/finality_checkpoints/x"),
            expected,
            "longer than pattern"
        );
    }

    #[test]
    fn matched_path_wrong_method_gets_405() {
        let router = Router::new(&[(Method::Get, "/metrics", first)]);
        let resp = dispatch(&router, "POST", "/metrics");
        assert!(resp.starts_with(b"HTTP/1.1 405 Method Not Allowed\r\n"));
        assert_eq!(body(&resp), br#"{"code":405,"message":"method not allowed"}"#);
    }

    #[test]
    fn unknown_method_gets_405_on_known_path_else_404() {
        let router = Router::new(&[(Method::Get, "/metrics", first)]);
        assert!(dispatch(&router, "PUT", "/metrics").starts_with(b"HTTP/1.1 405"));
        assert!(dispatch(&router, "PUT", "/nope").starts_with(b"HTTP/1.1 404"));
    }

    #[test]
    fn same_pattern_distinct_methods_dispatch_by_method() {
        let router = Router::new(&[
            (Method::Get, "/eth/v1/thing", first),
            (Method::Post, "/eth/v1/thing", second),
        ]);
        assert_eq!(body(&dispatch(&router, "GET", "/eth/v1/thing")), b"first");
        assert_eq!(body(&dispatch(&router, "POST", "/eth/v1/thing")), b"second");
    }

    #[test]
    #[should_panic(expected = "duplicate route pattern")]
    fn duplicate_pattern_panics_at_init() {
        Router::new(&[(Method::Get, "/a/b", first), (Method::Get, "/a/b", second)]);
    }

    #[test]
    #[should_panic(expected = "duplicate route pattern")]
    fn duplicate_modulo_param_names_panics_at_init() {
        Router::new(&[(Method::Get, "/a/{x}/c", first), (Method::Get, "/a/{y}/c", second)]);
    }

    #[test]
    fn four_param_pattern_matches() {
        let router = Router::new(&[(Method::Get, "/{a}/{b}/{c}/{d}", echo_params)]);
        let resp = dispatch(&router, "GET", "/1/2/3/4");
        assert_eq!(body(&resp), b"a=1;b=2;c=3;d=4;");
    }

    #[test]
    #[should_panic(expected = "exceeds 4 params")]
    fn fifth_param_panics_at_init() {
        Router::new(&[(Method::Get, "/{a}/{b}/{c}/{d}/{e}", echo_params)]);
    }
}
