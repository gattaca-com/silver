use std::{io::Write, mem, str};

use silver_common::{GossipTopic, LocalGossipFailure, TCacheProducer, TProducer};
use silver_httpcore::{frame_chunked_head, frame_response_with_headers};

use crate::{
    beacon::blocks::BlockRequest,
    events::ChannelSet,
    http::{json::Json, router::Outcome},
    submission::{AcceptedEntry, Submission, SubmissionFailure, failure_message},
    validator::{
        aggregate_attestation::AggregateRequest,
        sync_contribution::SyncCommitteeContributionRequest,
    },
};

const JSON_CONTENT_TYPE: &str = "application/json";

const CONTENT_LENGTH_WIDTH: usize = u64::MAX.ilog10() as usize + 1;

pub(crate) struct Response<'a> {
    out: &'a mut Vec<u8>,
    submissions: &'a mut TProducer,
    outcome: Outcome,
}

impl<'a> Response<'a> {
    /// `submissions` carries what a handler publishes for another tile to read.
    pub(crate) fn new(out: &'a mut Vec<u8>, submissions: &'a mut TProducer) -> Self {
        Self { out, submissions, outcome: Outcome::Response }
    }

    /// Encodes one body entry straight into the submissions tcache and awaits
    /// its verdict on `topic`. An entry the cache has no room for fails.
    pub(crate) fn await_verdict(
        &mut self,
        body_index: usize,
        topic: GossipTopic,
        len: usize,
        encode: impl FnOnce(&mut [u8]),
    ) {
        match self.submissions.write_with(len, encode) {
            Some(ssz) => self.submission().accepted.push(AcceptedEntry { body_index, topic, ssz }),
            None => self.fail_entry(body_index, failure_message(LocalGossipFailure::Internal)),
        }
    }

    pub(crate) fn fail_entry(&mut self, body_index: usize, message: &'static str) {
        self.submission().failures.push(SubmissionFailure { body_index, message });
    }

    fn submission(&mut self) -> &mut Submission {
        if !matches!(self.outcome, Outcome::AwaitingVerdicts(_)) {
            debug_assert!(self.out.is_empty(), "a deferred answer follows no other response");
            self.outcome = Outcome::AwaitingVerdicts(Submission::default());
        }
        let Outcome::AwaitingVerdicts(submission) = &mut self.outcome else { unreachable!() };
        submission
    }

    /// Queues the head and records the subscription; writing begins after
    /// the handler returns.
    pub(crate) fn begin_stream(
        &mut self,
        content_type: &str,
        headers: &[(&str, &str)],
        channels: ChannelSet,
    ) {
        debug_assert!(self.out.is_empty(), "a stream head follows no other response");
        frame_chunked_head(self.out, content_type, headers);
        self.outcome = Outcome::Stream(channels);
    }

    pub(crate) fn request_block(&mut self, request: BlockRequest) {
        debug_assert!(self.out.is_empty(), "a deferred answer follows no other response");
        self.outcome = Outcome::AwaitingBlock(request);
    }

    pub(crate) fn request_aggregate(&mut self, request: AggregateRequest) {
        debug_assert!(self.out.is_empty(), "a deferred answer follows no other response");
        self.outcome = Outcome::AwaitingAggregate(request);
    }

    pub(crate) fn request_contribution(&mut self, request: SyncCommitteeContributionRequest) {
        debug_assert!(self.out.is_empty(), "a deferred answer follows no other response");
        self.outcome = Outcome::AwaitingContribution(request);
    }

    pub(crate) fn indexed_failures(&mut self, failures: &[SubmissionFailure]) {
        self.json_framed(400, &[], |json| json.indexed_failures(failures));
    }

    pub(crate) fn outcome(mut self) -> Outcome {
        match mem::take(&mut self.outcome) {
            Outcome::AwaitingVerdicts(submission) if submission.accepted.is_empty() => {
                self.indexed_failures(&submission.failures);
                Outcome::Response
            }
            outcome @ Outcome::AwaitingVerdicts(_) => {
                self.submissions.publish_head();
                outcome
            }
            outcome => outcome,
        }
    }

    pub(crate) fn json(&mut self, body: &[u8]) {
        self.send(200, Some(JSON_CONTENT_TYPE), &[], body);
    }

    /// Renders the body in place behind its head. `Content-Length` precedes
    /// the body on the wire, so its field is written as the whitespace RFC
    /// 9110 allows before a value, wide enough for any length, and the digits
    /// land once the body is rendered.
    pub(crate) fn json_body(&mut self, render: impl FnOnce(&mut Json<'_>)) {
        self.json_framed(200, &[], render);
    }

    pub(crate) fn versioned_json(&mut self, version: &str, render: impl FnOnce(&mut Json<'_>)) {
        self.json_framed(200, &[("Eth-Consensus-Version", version)], |json| {
            json.versioned_envelope(version, render)
        });
    }

    fn json_framed(
        &mut self,
        code: u16,
        headers: &[(&str, &str)],
        render: impl FnOnce(&mut Json<'_>),
    ) {
        let status = status_line(code).expect("a JSON body is framed under a mapped status");
        write!(self.out, "HTTP/1.1 {status}\r\nContent-Type: {JSON_CONTENT_TYPE}\r\n").unwrap();
        for (name, value) in headers {
            write!(self.out, "{name}: {value}\r\n").unwrap();
        }
        self.out.extend_from_slice(b"Content-Length: ");
        let digits_at = self.out.len();
        self.out.extend_from_slice(&[b' '; CONTENT_LENGTH_WIDTH]);
        self.out.extend_from_slice(b"\r\n\r\n");
        let body_start = self.out.len();

        render(&mut Json::new(self.out));

        let length = self.out.len() - body_start;
        let mut digits = &mut self.out[digits_at..digits_at + CONTENT_LENGTH_WIDTH];
        write!(digits, "{length:>CONTENT_LENGTH_WIDTH$}").unwrap();
    }

    pub(crate) fn empty(&mut self, content_type: &str) {
        self.send(200, Some(content_type), &[], b"");
    }

    /// The success of a schema that declares no content under its 200.
    pub(crate) fn ok(&mut self) {
        self.send(200, None, &[], b"");
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

    /// Messages can include client input, so they need JSON escaping.
    /// An error answers now, superseding any verdicts the handler awaited.
    pub(crate) fn error(&mut self, code: u16, message: &str) {
        self.outcome = Outcome::Response;
        let mut body = format!("{{\"code\":{code},\"message\":").into_bytes();
        Json::new(&mut body).string(message);
        body.push(b'}');
        self.send(code, Some(JSON_CONTENT_TYPE), &[], &body);
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
    use crate::testing::submissions;

    fn framed(write: impl FnOnce(&mut Response<'_>)) -> Vec<u8> {
        let mut out = Vec::new();
        write(&mut Response::new(&mut out, &mut submissions()));
        out
    }

    /// The length field is padded with the whitespace a field value may be
    /// preceded by, so the body can be rendered in place behind it.
    #[test]
    fn json_body_is_framed_once_behind_a_padded_length() {
        let out = framed(|resp| resp.json_body(|json| json.data_envelope(|json| json.u64(7))));
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
              Content-Length:                   10\r\n\r\n{\"data\":7}"
        );
        let mut out = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        let earlier = out.len();
        Response::new(&mut out, &mut submissions()).json_body(|json| json.begin_array());
        assert!(out[earlier..].ends_with(b"Content-Length:                    1\r\n\r\n["));
    }

    #[test]
    fn error_writes_status_line_and_json_body() {
        let mut out = Vec::new();
        Response::new(&mut out, &mut submissions()).error(400, "invalid state_id");
        let expected: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 41\r\n\r\n{\"code\":400,\"message\":\"invalid state_id\"}";
        assert_eq!(out, expected);
    }

    #[test]
    fn error_escapes_client_input_in_the_message() {
        let out = framed(|resp| resp.error(400, "unknown topic: \"he\\ad\"\n"));
        let body = br#"{"code":400,"message":"unknown topic: \"he\\ad\"\n"}"#;
        let mut expected = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        expected.extend_from_slice(body);
        assert_eq!(out, expected, "{}", String::from_utf8_lossy(&out));
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
}
