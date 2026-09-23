pub(crate) mod head_verdict;

use silver_beacon_state_data::B256;
use silver_common::{HeadRoots, PayloadResolution};
use silver_httpcore::Query;

use crate::{
    ctx::ApiCtx,
    http::{response::Response, router::Request},
};

const EVENT_STREAM_CONTENT_TYPE: &str = "text/event-stream";
const EVENT_STREAM_HEADERS: &[(&str, &str)] =
    &[("Cache-Control", "no-cache"), ("X-Accel-Buffering", "no")];

pub(crate) const KEEP_ALIVE: &[u8] = b": keep-alive\n\n";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    Block,
    Head,
    HeadV2,
    BlockGossip,
    DataColumnSidecar,
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
        "block_gossip" => Some(Channel::BlockGossip),
        "data_column_sidecar" => Some(Channel::DataColumnSidecar),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use silver_httpcore::ParsedRequest;

    use super::*;
    use crate::{
        ctx::anchor_ctx,
        http::router::Outcome,
        testing::{dispatch, request},
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

    fn subscribe(query: &str) -> (Outcome, Vec<u8>) {
        let req = ParsedRequest {
            query,
            accept: Some("text/event-stream"),
            ..request("GET", "/eth/v1/events")
        };
        dispatch(&anchor_ctx(), &req)
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
        let mut gossip = ChannelSet::default();
        gossip.insert(Channel::BlockGossip);
        assert_eq!(topics("topics=block_gossip"), Ok(gossip));

        let mut columns = ChannelSet::default();
        columns.insert(Channel::DataColumnSidecar);
        assert_eq!(topics("topics=data_column_sidecar"), Ok(columns));

        let mut all = columns;
        all.insert(Channel::Block);
        all.insert(Channel::BlockGossip);
        for query in [
            "topics=block,block_gossip,data_column_sidecar",
            "topics=data_column_sidecar&topics=block_gossip&topics=block",
            "topics=block%2Cdata_column_sidecar%2Cblock_gossip",
        ] {
            assert_eq!(topics(query), Ok(all), "{query}");
        }

        let every_topic = set(&[
            Channel::Block,
            Channel::Head,
            Channel::HeadV2,
            Channel::BlockGossip,
            Channel::DataColumnSidecar,
        ]);
        for query in [
            "topics=block,head,head_v2,block_gossip,data_column_sidecar",
            "topics=data_column_sidecar&topics=block_gossip&topics=head_v2&topics=head&topics=block",
        ] {
            assert_eq!(topics(query), Ok(every_topic), "{query}");
        }
    }

    #[test]
    fn topic_silver_does_not_serve_refuses_the_whole_subscription_by_name() {
        let unknown = |topic: &str| Err(Refused::Unknown(topic.to_string()));
        assert_eq!(topics("topics=finalized_checkpoint"), unknown("finalized_checkpoint"));
        assert_eq!(topics("topics=block,finalized_checkpoint"), unknown("finalized_checkpoint"));
        assert_eq!(topics("topics=head_v2&topics=chain_reorg"), unknown("chain_reorg"));
    }

    /// Empty entries must not silently turn a malformed list into a valid
    /// subscription.
    #[test]
    fn empty_name_is_refused_like_any_unknown_one() {
        let empty = Err(Refused::Unknown(String::new()));
        assert_eq!(topics("topics="), empty);
        assert_eq!(topics("topics=,"), empty);
        assert_eq!(topics("topics=block,"), empty);
        assert_eq!(topics("topics=&topics=block"), empty);
    }

    #[test]
    fn subscribing_frames_the_stream_head_and_hands_the_connection_over() {
        let (outcome, out) = subscribe("topics=block");
        assert_eq!(outcome, Outcome::Stream(block_only()));
        assert_eq!(
            out,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn no_topic_is_a_400() {
        for query in ["", "other=block"] {
            let (outcome, out) = subscribe(query);
            assert_eq!(outcome, Outcome::Response, "{query}");
            assert_eq!(out, bad_request("no topics"), "{query}");
        }
    }
}
