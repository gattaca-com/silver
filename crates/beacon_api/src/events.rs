use std::io::Write;

use silver_httpcore::Query;

use crate::{response::Response, router::Request, routes::ApiCtx};

const EVENT_STREAM_CONTENT_TYPE: &str = "text/event-stream";
const EVENT_STREAM_HEADERS: &[(&str, &str)] =
    &[("Cache-Control", "no-cache"), ("X-Accel-Buffering", "no")];

pub(crate) const KEEP_ALIVE: &[u8] = b": keep-alive\n\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    Block,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ChannelSet(u32);

impl ChannelSet {
    fn insert(&mut self, channel: Channel) {
        self.0 |= 1 << channel as u32;
    }

    pub(crate) fn contains(self, channel: Channel) -> bool {
        self.0 & (1 << channel as u32) != 0
    }

    fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Reject the whole subscription if any topic is unsupported, so clients
/// are not left waiting for events this server cannot publish.
pub(crate) fn events(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    match topics(req.query) {
        Some(channels) => {
            resp.begin_stream(EVENT_STREAM_CONTENT_TYPE, EVENT_STREAM_HEADERS, channels)
        }
        None => resp.error(400, "invalid topics"),
    }
}

/// Clients send both comma-separated and repeated `topics` parameters.
fn topics(query: &str) -> Option<ChannelSet> {
    let mut channels = ChannelSet::default();
    for (name, value) in Query::new(query) {
        if name != "topics" {
            continue;
        }
        for topic in value.split(',') {
            channels.insert(channel(topic)?);
        }
    }
    (!channels.is_empty()).then_some(channels)
}

fn channel(topic: &str) -> Option<Channel> {
    match topic {
        "block" => Some(Channel::Block),
        _ => None,
    }
}

pub(crate) fn frame(out: &mut Vec<u8>, event: &str, data: &[u8]) {
    debug_assert!(!data.contains(&b'\n'), "a multi-line body needs one data: line per line");
    write!(out, "event: {event}\ndata: ").unwrap();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\n\n");
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        router::{Router, Served},
        routes::{ROUTES, preboot_ctx},
    };

    fn block_only() -> ChannelSet {
        let mut channels = ChannelSet::default();
        channels.insert(Channel::Block);
        channels
    }

    fn dispatch(query: &str) -> (Served, Vec<u8>) {
        let req = ParsedRequest {
            method: "GET",
            path: "/eth/v1/events",
            query,
            body: b"",
            accept: Some("text/event-stream"),
            content_type: None,
            eth_consensus_version: None,
            version: 1,
            keep_alive: true,
        };
        let mut out = Vec::new();
        let served = Router::new(ROUTES).dispatch(&req, &preboot_ctx(), &mut out);
        (served, out)
    }

    #[test]
    fn topics_arrive_comma_joined_or_repeated() {
        assert_eq!(topics("topics=block"), Some(block_only()));
        assert_eq!(topics("topics=block,block"), Some(block_only()));
        assert_eq!(topics("topics=block&topics=block"), Some(block_only()));
        assert_eq!(topics("topics=block%2Cblock"), Some(block_only()), "percent-encoded comma");
    }

    #[test]
    fn a_topic_silver_does_not_serve_refuses_the_whole_subscription() {
        assert_eq!(topics("topics=head"), None);
        assert_eq!(topics("topics=block,head"), None);
        assert_eq!(topics("topics=block&topics=chain_reorg"), None);
    }

    #[test]
    fn no_topic_is_no_subscription() {
        assert_eq!(topics(""), None);
        assert_eq!(topics("topics="), None);
        assert_eq!(topics("other=block"), None);
    }

    #[test]
    fn a_frame_names_its_event_and_carries_one_data_line() {
        let mut out = Vec::new();
        frame(&mut out, "block", br#"{"slot":"1"}"#);
        assert_eq!(out, b"event: block\ndata: {\"slot\":\"1\"}\n\n");
    }

    #[test]
    fn subscribing_frames_the_stream_head_and_hands_the_connection_over() {
        let (served, out) = dispatch("topics=block");
        assert_eq!(served, Served::Stream(block_only()));
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn an_unserved_topic_is_a_400_on_an_ordinary_connection() {
        let (served, out) = dispatch("topics=head");
        assert_eq!(served, Served::Response);
        assert_eq!(
            out,
            b"HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n{\"code\":400,\"message\":\"invalid topics\"}"
        );
    }
}
