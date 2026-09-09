use std::io::Write;

use silver_beacon_state_data::B256;
use silver_common::{HeadRoots, PayloadResolution};
use silver_httpcore::Query;

use crate::{response::Response, router::Request, routes::ApiCtx};

const EVENT_STREAM_CONTENT_TYPE: &str = "text/event-stream";
const EVENT_STREAM_HEADERS: &[(&str, &str)] =
    &[("Cache-Control", "no-cache"), ("X-Accel-Buffering", "no")];

pub(crate) const KEEP_ALIVE: &[u8] = b": keep-alive\n\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    Block,
    Head,
    HeadV2,
}

/// `epoch_transition` compares this head with the publisher's previous
/// complete observation. Only `head_v2` renders `payload`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadEvent {
    pub slot: u64,
    pub block_root: B256,
    pub roots: HeadRoots,
    pub payload: PayloadResolution,
    pub epoch_transition: bool,
    pub execution_optimistic: bool,
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

#[derive(Debug, PartialEq, Eq)]
enum Refused {
    NoTopic,
    Unknown(String),
}

/// Reject the whole subscription if any topic is unsupported, so clients
/// are not left waiting for events this server cannot publish.
pub(crate) fn events(req: &Request<'_>, _ctx: &ApiCtx, resp: &mut Response<'_>) {
    match topics(req.query) {
        Ok(channels) => {
            resp.begin_stream(EVENT_STREAM_CONTENT_TYPE, EVENT_STREAM_HEADERS, channels)
        }
        Err(Refused::NoTopic) => resp.error(400, "no topics"),
        Err(Refused::Unknown(topic)) => resp.error(400, &format!("unknown topic \"{topic}\"")),
    }
}

/// Clients send both comma-separated and repeated `topics` parameters.
fn topics(query: &str) -> Result<ChannelSet, Refused> {
    let mut channels = ChannelSet::default();
    for (name, value) in Query::new(query) {
        if name != "topics" {
            continue;
        }
        for topic in value.split(',') {
            let channel = channel(topic).ok_or_else(|| Refused::Unknown(topic.to_string()))?;
            channels.insert(channel);
        }
    }
    if channels.is_empty() { Err(Refused::NoTopic) } else { Ok(channels) }
}

fn channel(topic: &str) -> Option<Channel> {
    match topic {
        "block" => Some(Channel::Block),
        "head" => Some(Channel::Head),
        "head_v2" => Some(Channel::HeadV2),
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

    fn set(of: &[Channel]) -> ChannelSet {
        let mut channels = ChannelSet::default();
        for &channel in of {
            channels.insert(channel);
        }
        channels
    }

    fn block_only() -> ChannelSet {
        set(&[Channel::Block])
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

    fn bad_request(message_json: &str) -> Vec<u8> {
        let body = format!("{{\"code\":400,\"message\":\"{message_json}\"}}");
        format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    #[test]
    fn topics_arrive_comma_joined_or_repeated() {
        assert_eq!(topics("topics=block"), Ok(block_only()));
        assert_eq!(topics("topics=block,block"), Ok(block_only()));
        assert_eq!(topics("topics=block&topics=block"), Ok(block_only()));
        assert_eq!(topics("topics=block%2Cblock"), Ok(block_only()), "percent-encoded comma");
    }

    #[test]
    fn head_is_served_alone_and_alongside_block() {
        assert_eq!(topics("topics=head"), Ok(set(&[Channel::Head])));
        assert_eq!(topics("topics=block,head"), Ok(set(&[Channel::Block, Channel::Head])));
        assert_eq!(topics("topics=head,block"), Ok(set(&[Channel::Block, Channel::Head])));
        assert_eq!(topics("topics=head&topics=block"), Ok(set(&[Channel::Block, Channel::Head])));
    }

    #[test]
    fn head_v2_is_served_alone_and_alongside_the_other_topics() {
        let all = set(&[Channel::Block, Channel::Head, Channel::HeadV2]);
        assert_eq!(topics("topics=head_v2"), Ok(set(&[Channel::HeadV2])));
        assert_eq!(topics("topics=head_v2,head_v2"), Ok(set(&[Channel::HeadV2])));
        assert_eq!(topics("topics=head,head_v2"), Ok(set(&[Channel::Head, Channel::HeadV2])));
        assert_eq!(topics("topics=block,head,head_v2"), Ok(all));
        assert_eq!(topics("topics=head_v2&topics=block&topics=head"), Ok(all));
    }

    #[test]
    fn a_topic_silver_does_not_serve_refuses_the_whole_subscription_by_name() {
        let unknown = |topic: &str| Err(Refused::Unknown(topic.to_string()));
        assert_eq!(topics("topics=finalized_checkpoint"), unknown("finalized_checkpoint"));
        assert_eq!(topics("topics=block,finalized_checkpoint"), unknown("finalized_checkpoint"));
        assert_eq!(topics("topics=head_v2&topics=chain_reorg"), unknown("chain_reorg"));
    }

    #[test]
    fn no_topic_is_no_subscription() {
        assert_eq!(topics(""), Err(Refused::NoTopic));
        assert_eq!(topics("other=block"), Err(Refused::NoTopic));
    }

    /// Empty entries must not silently turn a malformed list into a valid
    /// subscription.
    #[test]
    fn an_empty_name_is_refused_like_any_unknown_one() {
        let empty = Err(Refused::Unknown(String::new()));
        assert_eq!(topics("topics="), empty);
        assert_eq!(topics("topics=,"), empty);
        assert_eq!(topics("topics=block,"), empty);
        assert_eq!(topics("topics=&topics=block"), empty);
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
    fn an_unserved_topic_is_a_400_naming_it_on_an_ordinary_connection() {
        let (served, out) = dispatch("topics=block,chain_reorg");
        assert_eq!(served, Served::Response);
        assert_eq!(out, bad_request(r#"unknown topic \"chain_reorg\""#));
    }

    #[test]
    fn an_empty_name_is_a_400_showing_the_empty_quotes() {
        let (served, out) = dispatch("topics=block,");
        assert_eq!(served, Served::Response);
        assert_eq!(out, bad_request(r#"unknown topic \"\""#));
    }

    #[test]
    fn a_named_topic_is_json_escaped() {
        let (served, out) = dispatch("topics=%22he%5Cad%22");
        assert_eq!(served, Served::Response);
        assert_eq!(out, bad_request(r#"unknown topic \"\"he\\ad\"\""#));
    }

    #[test]
    fn no_topic_is_a_400() {
        let (served, out) = dispatch("");
        assert_eq!(served, Served::Response);
        assert_eq!(out, bad_request("no topics"));
    }
}
