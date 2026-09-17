//! Beacon-API bodies are written by hand: the spec quotes every integer as a
//! decimal string and every byte array as lowercase `0x`-hex, and the
//! SSZ-backed containers have no Rust struct to hang `Serialize` on.

use std::io::Write;

use silver_beacon_state_data::{B256, BeaconBlockHeader, Checkpoint, Fork, Version};

use crate::{events::HeadEvent, peers::Peer};

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Appends JSON to a buffer the caller owns — fresh or reused is the caller's
/// affair. `start` is where this body begins, so bytes already in the buffer
/// are not siblings of the first value written.
pub(crate) struct Json<'a> {
    out: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> Json<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        let start = out.len();
        Self { out, start }
    }

    pub(crate) fn begin_object(&mut self) {
        self.separate();
        self.out.push(b'{');
    }

    pub(crate) fn end_object(&mut self) {
        self.out.push(b'}');
    }

    pub(crate) fn begin_array(&mut self) {
        self.separate();
        self.out.push(b'[');
    }

    pub(crate) fn end_array(&mut self) {
        self.out.push(b']');
    }

    pub(crate) fn key(&mut self, name: &str) {
        debug_assert!(json_safe(name), "field name goes into JSON unescaped");
        self.separate();
        self.out.push(b'"');
        self.out.extend_from_slice(name.as_bytes());
        self.out.extend_from_slice(b"\":");
    }

    pub(crate) fn quoted_u64(&mut self, value: u64) {
        self.separate();
        let mut digits = [0u8; 20];
        let mut written = 0;
        let mut rest = value;
        loop {
            digits[19 - written] = b'0' + (rest % 10) as u8;
            rest /= 10;
            written += 1;
            if rest == 0 {
                break;
            }
        }
        self.out.push(b'"');
        self.out.extend_from_slice(&digits[20 - written..]);
        self.out.push(b'"');
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.separate();
        let _ = write!(self.out, "{value}");
    }

    pub(crate) fn null(&mut self) {
        self.separate();
        self.out.extend_from_slice(b"null");
    }

    pub(crate) fn hex(&mut self, bytes: &[u8]) {
        self.separate();
        self.out.extend_from_slice(b"\"0x");
        let base = self.out.len();
        self.out.resize(base + bytes.len() * 2, 0);
        hex::encode_to_slice(bytes, &mut self.out[base..]).expect("hex encode_to_slice");
        self.out.push(b'"');
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.separate();
        self.out.extend_from_slice(if value { b"true".as_slice() } else { b"false".as_slice() });
    }

    pub(crate) fn string(&mut self, text: &str) {
        self.separate();
        self.out.push(b'"');
        for byte in text.bytes() {
            match byte {
                b'"' => self.out.extend_from_slice(b"\\\""),
                b'\\' => self.out.extend_from_slice(b"\\\\"),
                0x08 => self.out.extend_from_slice(b"\\b"),
                0x0c => self.out.extend_from_slice(b"\\f"),
                b'\n' => self.out.extend_from_slice(b"\\n"),
                b'\r' => self.out.extend_from_slice(b"\\r"),
                b'\t' => self.out.extend_from_slice(b"\\t"),
                // Everything else below 0x20 has no short escape; multi-byte
                // UTF-8 needs none, since JSON strings carry it verbatim.
                0x00..=0x1f => {
                    self.out.extend_from_slice(b"\\u00");
                    self.out.push(HEX_LOWER[(byte >> 4) as usize]);
                    self.out.push(HEX_LOWER[(byte & 0xf) as usize]);
                }
                _ => self.out.push(byte),
            }
        }
        self.out.push(b'"');
    }

    /// A comma belongs between two siblings and nowhere else, and the previous
    /// byte says which case this is: only `{`, `[` and `:` can be followed by
    /// a value that is not a sibling of one already written.
    fn separate(&mut self) {
        if self.out.len() > self.start && !matches!(self.out.last(), Some(b'{' | b'[' | b':')) {
            self.out.push(b',');
        }
    }
}

/// The three scalars `getGenesis` answers with (`apis/beacon/genesis.yaml`).
pub(crate) struct GenesisData {
    pub(crate) genesis_time: u64,
    pub(crate) genesis_validators_root: B256,
    pub(crate) genesis_fork_version: Version,
}

/// The three `EpochState` checkpoints `getStateFinalityCheckpoints` answers
/// with (`apis/beacon/states/finality_checkpoints.yaml`), split out so a read
/// copies these and not `EpochState`'s 512-byte `proposer_lookahead`.
pub(crate) struct FinalityCheckpoints {
    pub(crate) previous_justified: Checkpoint,
    pub(crate) current_justified: Checkpoint,
    pub(crate) finalized: Checkpoint,
}

/// The five flags and slots `getSyncingStatus` answers with
/// (`apis/node/syncing.yaml`).
pub(crate) struct SyncingData {
    pub(crate) head_slot: u64,
    pub(crate) sync_distance: u64,
    pub(crate) is_syncing: bool,
    pub(crate) is_optimistic: bool,
    pub(crate) el_offline: bool,
}

/// What a read reports about the data it answers with; both flags are
/// required beside `data` by the `states/{state_id}` schemas and by the block
/// reads.
#[derive(Clone, Copy)]
pub(crate) struct ReadFlags {
    pub(crate) execution_optimistic: bool,
    pub(crate) finalized: bool,
}

pub(crate) struct SignedHeader {
    pub(crate) root: B256,
    pub(crate) canonical: bool,
    pub(crate) header: BeaconBlockHeader,
    pub(crate) signature: [u8; 96],
}

/// Containers, in the field order the beacon-API schemas declare.
impl Json<'_> {
    pub(crate) fn peers<'p>(&mut self, peers: impl Iterator<Item = &'p Peer>) {
        self.begin_object();
        self.key("data");
        self.begin_array();
        let mut count = 0;
        for peer in peers {
            self.begin_object();
            self.key("peer_id");
            self.string(&peer.id_string());
            // xatu doesn't read enr so we skip it - updating it properly requires more work
            self.key("enr");
            self.null();
            self.key("last_seen_p2p_address");
            self.string(&peer.multiaddr());
            self.key("state");
            self.string("connected");
            self.key("direction");
            self.string(peer.direction());
            self.end_object();
            count += 1;
        }
        self.end_array();
        self.key("meta");
        self.begin_object();
        self.key("count");
        self.u64(count);
        self.end_object();
        self.end_object();
    }

    pub(crate) fn peer_count(&mut self, connected: u64) {
        self.begin_object();
        for (state, count) in
            [("disconnected", 0), ("connecting", 0), ("connected", connected), ("disconnecting", 0)]
        {
            self.key(state);
            self.quoted_u64(count);
        }
        self.end_object();
    }

    pub(crate) fn data_envelope(&mut self, data: impl FnOnce(&mut Self)) {
        self.begin_object();
        self.key("data");
        data(self);
        self.end_object();
    }

    pub(crate) fn flagged_envelope(&mut self, flags: ReadFlags, data: impl FnOnce(&mut Self)) {
        self.begin_object();
        self.key("execution_optimistic");
        self.bool(flags.execution_optimistic);
        self.key("finalized");
        self.bool(flags.finalized);
        self.key("data");
        data(self);
        self.end_object();
    }

    pub(crate) fn genesis(&mut self, genesis: &GenesisData) {
        self.begin_object();
        self.key("genesis_time");
        self.quoted_u64(genesis.genesis_time);
        self.key("genesis_validators_root");
        self.hex(&genesis.genesis_validators_root);
        self.key("genesis_fork_version");
        self.hex(&genesis.genesis_fork_version);
        self.end_object();
    }

    pub(crate) fn fork(&mut self, fork: &Fork) {
        self.begin_object();
        self.key("previous_version");
        self.hex(&fork.previous_version);
        self.key("current_version");
        self.hex(&fork.current_version);
        self.key("epoch");
        self.quoted_u64(fork.epoch);
        self.end_object();
    }

    pub(crate) fn block_root(&mut self, root: &B256) {
        self.begin_object();
        self.key("root");
        self.hex(root);
        self.end_object();
    }

    pub(crate) fn signed_header(&mut self, signed: &SignedHeader) {
        self.begin_object();
        self.key("root");
        self.hex(&signed.root);
        self.key("canonical");
        self.bool(signed.canonical);
        self.key("header");
        self.begin_object();
        self.key("message");
        self.begin_object();
        self.key("slot");
        self.quoted_u64(signed.header.slot);
        self.key("proposer_index");
        self.quoted_u64(signed.header.proposer_index);
        self.key("parent_root");
        self.hex(&signed.header.parent_root);
        self.key("state_root");
        self.hex(&signed.header.state_root);
        self.key("body_root");
        self.hex(&signed.header.body_root);
        self.end_object();
        self.key("signature");
        self.hex(&signed.signature);
        self.end_object();
        self.end_object();
    }

    pub(crate) fn checkpoint(&mut self, checkpoint: &Checkpoint) {
        self.begin_object();
        self.key("epoch");
        self.quoted_u64(checkpoint.epoch);
        self.key("root");
        self.hex(&checkpoint.root);
        self.end_object();
    }

    pub(crate) fn syncing(&mut self, syncing: &SyncingData) {
        self.begin_object();
        self.key("head_slot");
        self.quoted_u64(syncing.head_slot);
        self.key("sync_distance");
        self.quoted_u64(syncing.sync_distance);
        self.key("is_syncing");
        self.bool(syncing.is_syncing);
        self.key("is_optimistic");
        self.bool(syncing.is_optimistic);
        self.key("el_offline");
        self.bool(syncing.el_offline);
        self.end_object();
    }

    pub(crate) fn block_event(
        &mut self,
        slot: u64,
        block_root: &[u8; 32],
        execution_optimistic: bool,
    ) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(slot);
        self.key("block");
        self.hex(block_root);
        self.key("execution_optimistic");
        self.bool(execution_optimistic);
        self.end_object();
    }

    pub(crate) fn head_event(&mut self, head: &HeadEvent) {
        let roots = ["previous_duty_dependent_root", "current_duty_dependent_root"];
        self.head(head, roots, None);
    }

    pub(crate) fn head_v2_event(&mut self, head: &HeadEvent, fork_name: &str) {
        self.begin_object();
        self.key("version");
        self.string(fork_name);
        self.key("data");
        let roots = ["current_epoch_dependent_root", "next_epoch_dependent_root"];
        self.head(head, roots, Some(head.payload.name()));
        self.end_object();
    }

    fn head(&mut self, head: &HeadEvent, [previous, current]: [&str; 2], payload: Option<&str>) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(head.slot);
        self.key("block");
        self.hex(&head.block_root);
        self.key("state");
        self.hex(&head.roots.state_root);
        if let Some(payload) = payload {
            self.key("payload_status");
            self.string(payload);
        }
        self.key("epoch_transition");
        self.bool(head.epoch_transition);
        self.key(previous);
        self.hex(&head.roots.previous_duty_dependent_root);
        self.key(current);
        self.hex(&head.roots.current_duty_dependent_root);
        self.key("execution_optimistic");
        self.bool(head.execution_optimistic);
        self.end_object();
    }

    pub(crate) fn block_gossip_event(&mut self, slot: u64, block_root: &[u8; 32]) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(slot);
        self.key("block");
        self.hex(block_root);
        self.end_object();
    }

    pub(crate) fn data_column_sidecar_event(
        &mut self,
        block_root: &[u8; 32],
        column_index: u64,
        slot: u64,
    ) {
        self.begin_object();
        self.key("block_root");
        self.hex(block_root);
        self.key("index");
        self.quoted_u64(column_index);
        self.key("slot");
        self.quoted_u64(slot);
        self.end_object();
    }

    pub(crate) fn finality_checkpoints(&mut self, checkpoints: &FinalityCheckpoints) {
        self.begin_object();
        self.key("previous_justified");
        self.checkpoint(&checkpoints.previous_justified);
        self.key("current_justified");
        self.checkpoint(&checkpoints.current_justified);
        self.key("finalized");
        self.checkpoint(&checkpoints.finalized);
        self.end_object();
    }
}

/// Whether `text` survives being spliced into JSON without escaping — the
/// guard for compile-time field names and messages, not for user input
/// ([`Json::string`] escapes).
pub(crate) fn json_safe(text: &str) -> bool {
    !text.contains(['"', '\\'])
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::FAR_FUTURE_EPOCH;

    use super::*;

    fn write(render: impl FnOnce(&mut Json<'_>)) -> String {
        let mut out = Vec::new();
        render(&mut Json::new(&mut out));
        String::from_utf8(out).unwrap()
    }

    /// Byte-exact body plus a parse: a golden that is not valid JSON is a
    /// golden that pinned a bug.
    fn assert_body(render: impl FnOnce(&mut Json<'_>), expected: &str) {
        let body = write(render);
        assert_eq!(body, expected);
        serde_json::from_str::<serde_json::Value>(&body).expect("valid JSON");
    }

    #[test]
    fn integers_are_quoted_decimal_strings() {
        assert_eq!(write(|j| j.quoted_u64(0)), "\"0\"");
        assert_eq!(write(|j| j.quoted_u64(7)), "\"7\"");
        assert_eq!(write(|j| j.quoted_u64(10)), "\"10\"");
        assert_eq!(write(|j| j.quoted_u64(1_606_824_023)), "\"1606824023\"");
        assert_eq!(write(|j| j.quoted_u64(FAR_FUTURE_EPOCH)), "\"18446744073709551615\"");
        assert_eq!(write(|j| j.quoted_u64(u64::MAX)), "\"18446744073709551615\"");
    }

    #[test]
    fn hex_is_lowercase_and_full_width_at_every_spec_size() {
        assert_eq!(write(|j| j.hex(&[])), "\"0x\"");
        assert_eq!(write(|j| j.hex(&[0x00, 0x0a, 0xff, 0xAB])), "\"0x000affab\"");

        for width in [4usize, 20, 32, 48, 96] {
            let bytes = vec![0xdeu8; width];
            let rendered = write(|j| j.hex(&bytes));
            assert_eq!(rendered.len(), width * 2 + 4, "width {width}");
            assert!(rendered.starts_with("\"0x"), "width {width}: {rendered}");
            assert!(rendered.ends_with('"'), "width {width}: {rendered}");
            assert!(rendered[3..rendered.len() - 1].bytes().all(|b| b == b'd' || b == b'e'));
        }
    }

    #[test]
    fn strings_escape_quotes_backslashes_and_control_bytes() {
        assert_eq!(write(|j| j.string("active_ongoing")), "\"active_ongoing\"");
        assert_eq!(write(|j| j.string("")), "\"\"");
        assert_eq!(write(|j| j.string("a\"b")), "\"a\\\"b\"");
        assert_eq!(write(|j| j.string("a\\b")), "\"a\\\\b\"");
        assert_eq!(write(|j| j.string("\n\r\t")), "\"\\n\\r\\t\"");
        assert_eq!(write(|j| j.string("\u{08}\u{0c}")), "\"\\b\\f\"");
        assert_eq!(write(|j| j.string("\u{00}\u{01}\u{1f}")), "\"\\u0000\\u0001\\u001f\"");
        assert_eq!(write(|j| j.string("\u{7f}")), "\"\u{7f}\"");
    }

    #[test]
    fn escaped_strings_round_trip_through_a_parser() {
        let awkward = "silver/v0.1 \"quoted\"\\slashed\ttabbed\nnewline\u{01}\u{7f}é☃";
        let body = write(|j| j.string(awkward));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed.as_str(), Some(awkward));
    }

    #[test]
    fn siblings_are_comma_separated_and_openers_are_not() {
        assert_body(
            |j| {
                j.begin_object();
                j.key("empty_object");
                j.begin_object();
                j.end_object();
                j.key("empty_array");
                j.begin_array();
                j.end_array();
                j.key("values");
                j.begin_array();
                j.quoted_u64(1);
                j.quoted_u64(2);
                j.bool(false);
                j.begin_object();
                j.key("nested");
                j.hex(&[0xab]);
                j.end_object();
                j.end_array();
                j.end_object();
            },
            "{\"empty_object\":{},\"empty_array\":[],\"values\":[\"1\",\"2\",false,{\"nested\":\"0xab\"}]}",
        );
    }

    #[test]
    fn a_body_appended_after_existing_bytes_gets_no_leading_comma() {
        let mut out = b"HTTP-ish prefix}".to_vec();
        let mut json = Json::new(&mut out);
        json.begin_object();
        json.key("epoch");
        json.quoted_u64(3);
        json.end_object();
        assert_eq!(String::from_utf8(out).unwrap(), "HTTP-ish prefix}{\"epoch\":\"3\"}");
    }
}
