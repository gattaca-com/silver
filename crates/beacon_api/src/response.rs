use std::{fmt::Write, str};

use silver_httpcore::frame_response_with_headers;

use crate::json::{Json, json_safe};

const JSON_CONTENT_TYPE: &str = "application/json";

pub(crate) struct Response<'a> {
    out: &'a mut Vec<u8>,
}

/// One entry of a beacon-API `IndexedErrorMessage.failures` list; `index` is
/// the item's position in the submitted list, not a validator index.
pub(crate) struct Failure<'a> {
    pub(crate) index: usize,
    pub(crate) message: &'a str,
}

impl<'a> Response<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }

    pub(crate) fn json(&mut self, body: &[u8]) {
        self.send(200, Some(JSON_CONTENT_TYPE), &[], body);
    }

    /// Renders a body, then frames it: `Content-Length` precedes the body on
    /// the wire, so the render cannot go straight into the response buffer.
    pub(crate) fn json_body(&mut self, render: impl FnOnce(&mut Json<'_>)) {
        let mut body = Vec::new();
        render(&mut Json::new(&mut body));
        self.json(&body);
    }

    pub(crate) fn empty(&mut self, content_type: &str) {
        self.send(200, Some(content_type), &[], b"");
    }

    pub(crate) fn send(
        &mut self,
        code: u16,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        if status_line(code).is_none() {
            tracing::warn!("no reason phrase for status {code}");
        }
        self.frame(code, content_type, headers, body);
    }

    /// Bodyless response under a status silver did not choose: `syncing_status`
    /// lets a client name any code the schema allows, so an unmapped one is
    /// legal input polled every slot rather than the gap in [`status_line`]
    /// that [`Response::send`] warns about.
    pub(crate) fn status_only(&mut self, code: u16) {
        self.frame(code, None, &[], b"");
    }

    fn frame(
        &mut self,
        code: u16,
        content_type: Option<&str>,
        headers: &[(&str, &str)],
        body: &[u8],
    ) {
        debug_assert!((100..=599).contains(&code), "not an HTTP status code: {code}");
        let bare = [
            b'0' + (code / 100) as u8,
            b'0' + (code / 10 % 10) as u8,
            b'0' + (code % 10) as u8,
            b' ',
        ];
        let status = status_line(code)
            .unwrap_or_else(|| str::from_utf8(&bare).expect("three digits and a space"));
        frame_response_with_headers(self.out, status, content_type, headers, body);
    }

    /// Beacon-API error shape: `{"code":<status>,"message":"..."}`.
    pub(crate) fn error(&mut self, code: u16, message: &str) {
        debug_assert!(json_safe(message), "message goes into JSON unescaped");
        let body = format!("{{\"code\":{code},\"message\":\"{message}\"}}");
        self.send(code, Some(JSON_CONTENT_TYPE), &[], body.as_bytes());
    }

    /// Beacon-API `IndexedErrorMessage` shape, for requests carrying a list of
    /// items of which only some failed. The schema requires `failures` but
    /// sets no minimum, so an empty list stays a well-formed body.
    // Live with the first endpoint that validates a submitted list item by item.
    #[allow(dead_code)]
    pub(crate) fn indexed_error(&mut self, code: u16, message: &str, failures: &[Failure<'_>]) {
        debug_assert!(json_safe(message), "message goes into JSON unescaped");
        let mut body = format!("{{\"code\":{code},\"message\":\"{message}\",\"failures\":[");
        for (position, failure) in failures.iter().enumerate() {
            debug_assert!(json_safe(failure.message), "message goes into JSON unescaped");
            if position > 0 {
                body.push(',');
            }
            write!(body, "{{\"index\":{},\"message\":\"{}\"}}", failure.index, failure.message)
                .unwrap();
        }
        body.push_str("]}");
        self.send(code, Some(JSON_CONTENT_TYPE), &[], body.as_bytes());
    }
}

/// `None` for codes this API has no phrase for; those still frame, with the
/// empty reason-phrase RFC 9112 §4.1 permits (the space before it is grammar,
/// not part of the phrase).
fn status_line(code: u16) -> Option<&'static str> {
    Some(match code {
        200 => "200 OK",
        202 => "202 Accepted",
        206 => "206 Partial Content",
        400 => "400 Bad Request",
        404 => "404 Not Found",
        405 => "405 Method Not Allowed",
        406 => "406 Not Acceptable",
        414 => "414 URI Too Long",
        415 => "415 Unsupported Media Type",
        500 => "500 Internal Server Error",
        501 => "501 Not Implemented",
        503 => "503 Service Unavailable",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(write: impl FnOnce(&mut Response<'_>)) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut Response::new(&mut out));
        out
    }

    #[test]
    fn error_writes_status_line_and_json_body() {
        let mut out = Vec::new();
        Response::new(&mut out).error(400, "invalid state_id");
        let expected: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 41\r\n\r\n{\"code\":400,\"message\":\"invalid state_id\"}";
        assert_eq!(out, expected);
    }

    #[test]
    fn json_frames_ok_with_content_type() {
        let mut out = Vec::new();
        Response::new(&mut out).json(b"{\"data\":1}");
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n{\"data\":1}"
        );
    }

    #[test]
    fn empty_frames_ok_with_zero_length_body() {
        let mut out = Vec::new();
        Response::new(&mut out).empty("text/plain");
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn error_frames_any_mapped_status() {
        let out = framed(|resp| resp.error(415, "unsupported media type"));
        let expected: &[u8] = b"HTTP/1.1 415 Unsupported Media Type\r\nContent-Type: application/json\r\nContent-Length: 47\r\n\r\n{\"code\":415,\"message\":\"unsupported media type\"}";
        assert_eq!(out, expected);
    }

    #[test]
    fn send_frames_a_bodyless_status() {
        let out = framed(|resp| resp.send(202, None, &[], b""));
        assert_eq!(out, b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
    }

    #[test]
    fn send_emits_extra_headers_in_order() {
        let out = framed(|resp| {
            resp.send(
                200,
                Some("application/octet-stream"),
                &[("Eth-Consensus-Version", "fulu"), ("Eth-Execution-Payload-Blinded", "false")],
                b"\x01\x02\x03",
            )
        });
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nEth-Consensus-Version: fulu\r\nEth-Execution-Payload-Blinded: false\r\nContent-Length: 3\r\n\r\n\x01\x02\x03"
        );
    }

    #[test]
    fn unmapped_status_frames_with_an_empty_reason_phrase() {
        let out = framed(|resp| resp.send(599, None, &[], b""));
        assert_eq!(out, b"HTTP/1.1 599 \r\nContent-Length: 0\r\n\r\n");
    }

    /// A `syncing_status` a client picked reaches the wire whether or not this
    /// API has a phrase for it, and without the warning a mapped-code gap
    /// deserves.
    #[test]
    fn status_only_frames_a_mapped_or_unmapped_code_the_same_way() {
        assert_eq!(
            framed(|resp| resp.status_only(206)),
            b"HTTP/1.1 206 Partial Content\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(
            framed(|resp| resp.status_only(250)),
            b"HTTP/1.1 250 \r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(
            framed(|resp| resp.status_only(100)),
            b"HTTP/1.1 100 \r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(
            framed(|resp| resp.status_only(599)),
            b"HTTP/1.1 599 \r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn every_mapped_status_line_starts_with_its_own_code() {
        for code in 100..=599u16 {
            let Some(status) = status_line(code) else { continue };
            assert_eq!(status.split(' ').next(), Some(code.to_string().as_str()), "{status}");
            assert!(status.len() > 4, "reason phrase missing from {status}");
        }
    }

    #[test]
    fn indexed_error_lists_every_failure() {
        let out = framed(|resp| {
            resp.indexed_error(400, "some failures", &[
                Failure { index: 1, message: "invalid signature" },
                Failure { index: 3, message: "unknown validator" },
            ])
        });
        let expected: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 135\r\n\r\n{\"code\":400,\"message\":\"some failures\",\"failures\":[{\"index\":1,\"message\":\"invalid signature\"},{\"index\":3,\"message\":\"unknown validator\"}]}";
        assert_eq!(out, expected);
    }

    #[test]
    fn indexed_error_without_failures_keeps_the_required_empty_array() {
        let out = framed(|resp| resp.indexed_error(400, "some failures", &[]));
        let expected: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 52\r\n\r\n{\"code\":400,\"message\":\"some failures\",\"failures\":[]}";
        assert_eq!(out, expected);
    }
}
