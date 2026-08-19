//! Beacon-API bodies are written by hand: the spec quotes every integer as a
//! decimal string and every byte array as lowercase `0x`-hex, and the
//! SSZ-backed containers have no Rust struct to hang `Serialize` on.
//! `serde_json` is reserved for bodies built once at startup (`identity.rs`).

use silver_beacon_state_data::{
    B256, BLSPubkey, BLSSignature, BeaconBlockHeader, Checkpoint, Fork, ValidatorsView, Version,
};

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

/// What a state read reports about the snapshot it came from; both flags are
/// required beside `data` by every `states/{state_id}` schema.
#[derive(Clone, Copy)]
pub(crate) struct StateFlags {
    pub(crate) execution_optimistic: bool,
    pub(crate) finalized: bool,
}

/// Containers, in the field order the beacon-API schemas declare.
impl Json<'_> {
    pub(crate) fn state_envelope(&mut self, flags: StateFlags, data: impl FnOnce(&mut Self)) {
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

    pub(crate) fn checkpoint(&mut self, checkpoint: &Checkpoint) {
        self.begin_object();
        self.key("epoch");
        self.quoted_u64(checkpoint.epoch);
        self.key("root");
        self.hex(&checkpoint.root);
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

/// The containers no endpoint calls yet, in the same schema field order. Each
/// lands ahead of the endpoint commit that calls it; the allow stops here so
/// dead-code checking stays real for the writers already wired up.
#[allow(dead_code)]
impl Json<'_> {
    pub(crate) fn block_header(&mut self, header: &BeaconBlockHeader) {
        self.begin_object();
        self.key("slot");
        self.quoted_u64(header.slot);
        self.key("proposer_index");
        self.quoted_u64(header.proposer_index);
        self.key("parent_root");
        self.hex(&header.parent_root);
        self.key("state_root");
        self.hex(&header.state_root);
        self.key("body_root");
        self.hex(&header.body_root);
        self.end_object();
    }

    pub(crate) fn signed_block_header(
        &mut self,
        header: &BeaconBlockHeader,
        signature: &BLSSignature,
    ) {
        self.begin_object();
        self.key("message");
        self.block_header(header);
        self.key("signature");
        self.hex(signature);
        self.end_object();
    }

    pub(crate) fn validator(&mut self, validators: &ValidatorsView<'_>, index: usize) {
        self.begin_object();
        self.key("pubkey");
        self.hex(validators.pubkey(index));
        self.key("withdrawal_credentials");
        self.hex(&validators.credentials(index).0);
        self.key("effective_balance");
        self.quoted_u64(validators.effective_balance(index));
        self.key("slashed");
        self.bool(validators.is_slashed(index));
        self.key("activation_eligibility_epoch");
        self.quoted_u64(validators.activation_eligibility_epoch(index));
        self.key("activation_epoch");
        self.quoted_u64(validators.activation_epoch(index));
        self.key("exit_epoch");
        self.quoted_u64(validators.exit_epoch(index));
        self.key("withdrawable_epoch");
        self.quoted_u64(validators.withdrawable_epoch(index));
        self.end_object();
    }

    pub(crate) fn validator_entry(
        &mut self,
        validators: &ValidatorsView<'_>,
        index: usize,
        balance: u64,
        status: &str,
    ) {
        self.begin_object();
        self.key("index");
        self.quoted_u64(index as u64);
        self.key("balance");
        self.quoted_u64(balance);
        self.key("status");
        self.string(status);
        self.key("validator");
        self.validator(validators, index);
        self.end_object();
    }

    pub(crate) fn proposer_duty(&mut self, pubkey: &BLSPubkey, validator_index: u64, slot: u64) {
        self.begin_object();
        self.key("pubkey");
        self.hex(pubkey);
        self.key("validator_index");
        self.quoted_u64(validator_index);
        self.key("slot");
        self.quoted_u64(slot);
        self.end_object();
    }

    pub(crate) fn sync_duty(
        &mut self,
        pubkey: &BLSPubkey,
        validator_index: u64,
        committee_indices: &[u64],
    ) {
        self.begin_object();
        self.key("pubkey");
        self.hex(pubkey);
        self.key("validator_index");
        self.quoted_u64(validator_index);
        self.key("validator_sync_committee_indices");
        self.begin_array();
        for &position in committee_indices {
            self.quoted_u64(position);
        }
        self.end_array();
        self.end_object();
    }

    pub(crate) fn liveness(&mut self, index: u64, is_live: bool) {
        self.begin_object();
        self.key("index");
        self.quoted_u64(index);
        self.key("is_live");
        self.bool(is_live);
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
    use silver_beacon_state_data::{
        BeaconState, BeaconStateOwner, EpochStateFinalized, FAR_FUTURE_EPOCH, StateId, ValSeed,
        Withdrawals,
    };

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
    fn leading_zero_bytes_survive_hex_encoding() {
        let mut root = [0u8; 32];
        root[31] = 1;
        assert_eq!(
            write(|j| j.hex(&root)),
            "\"0x0000000000000000000000000000000000000000000000000000000000000001\""
        );
    }

    #[test]
    fn bools_are_json_literals_not_strings() {
        assert_eq!(write(|j| j.bool(true)), "true");
        assert_eq!(write(|j| j.bool(false)), "false");
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

    #[test]
    fn sibling_objects_in_an_array_are_comma_separated() {
        let mut out = Vec::new();
        let mut json = Json::new(&mut out);
        json.begin_array();
        for epoch in 1..=2 {
            json.begin_object();
            json.key("epoch");
            json.quoted_u64(epoch);
            json.end_object();
        }
        json.begin_object();
        json.end_object();
        json.end_array();
        assert_eq!(String::from_utf8(out).unwrap(), "[{\"epoch\":\"1\"},{\"epoch\":\"2\"},{}]");
    }

    /// Field names/order: `GenesisData`, `apis/beacon/genesis.yaml`.
    #[test]
    fn genesis_golden() {
        let genesis = GenesisData {
            genesis_time: 1_606_824_023,
            genesis_validators_root: [0x4b; 32],
            genesis_fork_version: [0x00, 0x00, 0x00, 0x01],
        };
        assert_body(
            |j| j.genesis(&genesis),
            "{\"genesis_time\":\"1606824023\",\"genesis_validators_root\":\"0x4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b\",\"genesis_fork_version\":\"0x00000001\"}",
        );
    }

    /// Field names/order: SSZ `Fork` container
    /// (`apis/config/fork_schedule.yaml` and `apis/beacon/states/fork.yaml`
    /// share it).
    #[test]
    fn fork_golden() {
        let fork = Fork {
            previous_version: [0x05, 0x00, 0x00, 0x00],
            current_version: [0x06, 0x00, 0x00, 0x00],
            epoch: 269_568,
        };
        assert_body(
            |j| j.fork(&fork),
            "{\"previous_version\":\"0x05000000\",\"current_version\":\"0x06000000\",\"epoch\":\"269568\"}",
        );
    }

    /// Field names/order: SSZ `Checkpoint` container, as used by
    /// `apis/beacon/states/finality_checkpoints.yaml`.
    #[test]
    fn checkpoint_golden() {
        let checkpoint = Checkpoint { epoch: 12_345, root: [0xa1; 32] };
        assert_body(
            |j| j.checkpoint(&checkpoint),
            "{\"epoch\":\"12345\",\"root\":\"0xa1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1\"}",
        );
    }

    fn checkpoints() -> FinalityCheckpoints {
        FinalityCheckpoints {
            previous_justified: Checkpoint { epoch: 12_344, root: [0x01; 32] },
            current_justified: Checkpoint { epoch: 12_345, root: [0x02; 32] },
            finalized: Checkpoint { epoch: 12_343, root: [0x03; 32] },
        }
    }

    /// Field names/order: `apis/beacon/states/finality_checkpoints.yaml` — the
    /// one body that calls a container writer more than once.
    #[test]
    fn finality_checkpoints_golden() {
        assert_body(
            |j| j.finality_checkpoints(&checkpoints()),
            "{\"previous_justified\":{\"epoch\":\"12344\",\
             \"root\":\"0x0101010101010101010101010101010101010101010101010101010101010101\"},\
             \"current_justified\":{\"epoch\":\"12345\",\
             \"root\":\"0x0202020202020202020202020202020202020202020202020202020202020202\"},\
             \"finalized\":{\"epoch\":\"12343\",\
             \"root\":\"0x0303030303030303030303030303030303030303030303030303030303030303\"}}",
        );
    }

    /// Field names/order: `GetStateForkResponse` and its siblings, which
    /// require both flags beside `data`.
    #[test]
    fn state_envelope_golden() {
        let flags = StateFlags { execution_optimistic: false, finalized: true };
        assert_body(
            |j| j.state_envelope(flags, |j| j.checkpoint(&Checkpoint::default())),
            "{\"execution_optimistic\":false,\"finalized\":true,\"data\":{\"epoch\":\"0\",\
             \"root\":\"0x0000000000000000000000000000000000000000000000000000000000000000\"}}",
        );
    }

    /// The envelope's `finalized` is its own flag: a `data` field of the same
    /// name must not overwrite or be overwritten by it.
    #[test]
    fn envelope_flags_and_data_of_the_same_name_both_survive() {
        let flags = StateFlags { execution_optimistic: true, finalized: false };
        let body = write(|j| j.state_envelope(flags, |j| j.finality_checkpoints(&checkpoints())));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["execution_optimistic"], true);
        assert_eq!(parsed["finalized"], false);
        assert_eq!(parsed["data"]["finalized"]["epoch"], "12343");
    }

    /// Field names/order: SSZ `BeaconBlockHeader` / `SignedBeaconBlockHeader`,
    /// as used by `apis/beacon/blocks/header.yaml`.
    #[test]
    fn signed_block_header_golden() {
        let header = BeaconBlockHeader {
            slot: 7_654_321,
            proposer_index: 4_242,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        };
        assert_body(
            |j| j.signed_block_header(&header, &[0x44; 96]),
            "{\"message\":{\"slot\":\"7654321\",\"proposer_index\":\"4242\",\
             \"parent_root\":\"0x1111111111111111111111111111111111111111111111111111111111111111\",\
             \"state_root\":\"0x2222222222222222222222222222222222222222222222222222222222222222\",\
             \"body_root\":\"0x3333333333333333333333333333333333333333333333333333333333333333\"},\
             \"signature\":\"0x444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444\"}",
        );
    }

    /// One validator with every field distinct, so a golden catches a
    /// swapped pair as well as a renamed key.
    fn state_with_one_validator() -> (BeaconStateOwner, StateId) {
        let mut pubkey = [0u8; 48];
        pubkey[0] = 0x93;
        pubkey[47] = 0x07;
        let seeds = [ValSeed {
            pubkey,
            withdrawal_credentials: Withdrawals::eth1(&[0xab; 20]),
            effective_balance: 32_000_000_000,
            balance: 32_500_000_000,
            activation_epoch: 10,
            exit_epoch: FAR_FUTURE_EPOCH,
        }];
        let mut owner =
            BeaconStateOwner::new(BeaconState::for_test(EpochStateFinalized::default(), &seeds, 0));
        let anchor = owner.roll_fresh();
        let (mut writer, _, _) = owner.apply_block_view(anchor);
        writer.validators.set_slashed(0, true);
        writer.validators.set_activation_eligibility_epoch(0, 9);
        writer.validators.set_withdrawable_epoch(0, 8_192);
        let head = writer.commit(None, None);
        (owner, head)
    }

    /// Field names/order: SSZ `Validator` container, as inlined by
    /// `apis/beacon/states/validators.yaml`.
    #[test]
    fn validator_golden() {
        let (owner, head) = state_with_one_validator();
        let view = owner.read_view(head);
        assert_body(
            |j| j.validator(&view.validators, 0),
            "{\"pubkey\":\"0x930000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007\",\
             \"withdrawal_credentials\":\"0x010000000000000000000000abababababababababababababababababababab\",\
             \"effective_balance\":\"32000000000\",\"slashed\":true,\
             \"activation_eligibility_epoch\":\"9\",\"activation_epoch\":\"10\",\
             \"exit_epoch\":\"18446744073709551615\",\"withdrawable_epoch\":\"8192\"}",
        );
    }

    /// Field names/order: `ValidatorResponse` of
    /// `apis/beacon/states/validators.yaml`.
    #[test]
    fn validator_entry_golden() {
        let (owner, head) = state_with_one_validator();
        let view = owner.read_view(head);
        let body =
            write(|j| j.validator_entry(&view.validators, 0, 32_500_000_000, "active_slashed"));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["index"], "0");
        assert_eq!(parsed["balance"], "32500000000");
        assert_eq!(parsed["status"], "active_slashed");
        assert_eq!(parsed["validator"]["effective_balance"], "32000000000");
        assert!(body.starts_with(
            "{\"index\":\"0\",\"balance\":\"32500000000\",\"status\":\"active_slashed\",\"validator\":{"
        ));
    }

    /// Field names/order: `ProposerDuty` of
    /// `apis/validator/duties/proposer.yaml`.
    #[test]
    fn proposer_duty_golden() {
        let mut pubkey = [0u8; 48];
        pubkey[0] = 0xb0;
        assert_body(
            |j| j.proposer_duty(&pubkey, 17, 4_096),
            "{\"pubkey\":\"0xb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\
             \"validator_index\":\"17\",\"slot\":\"4096\"}",
        );
    }

    /// Field names/order: `SyncCommitteeDuty` of
    /// `apis/validator/duties/sync.yaml` — the committee positions are a
    /// list of quoted integers.
    #[test]
    fn sync_duty_golden() {
        let mut pubkey = [0u8; 48];
        pubkey[0] = 0xb0;
        assert_body(
            |j| j.sync_duty(&pubkey, 17, &[3, 511]),
            "{\"pubkey\":\"0xb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\
             \"validator_index\":\"17\",\"validator_sync_committee_indices\":[\"3\",\"511\"]}",
        );
    }

    #[test]
    fn sync_duty_with_no_committee_positions_keeps_an_empty_array() {
        let pubkey = [0u8; 48];
        let body = write(|j| j.sync_duty(&pubkey, 17, &[]));
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert_eq!(parsed["validator_sync_committee_indices"].as_array().unwrap().len(), 0);
    }

    /// Field names: `apis/validator/liveness.yaml`.
    #[test]
    fn liveness_golden() {
        assert_body(|j| j.liveness(17, false), "{\"index\":\"17\",\"is_live\":false}");
        assert_body(|j| j.liveness(0, true), "{\"index\":\"0\",\"is_live\":true}");
    }

    #[test]
    fn json_safe_rejects_what_would_break_an_unescaped_splice() {
        assert!(json_safe("active_ongoing"));
        assert!(!json_safe("say \"hi\""));
        assert!(!json_safe("back\\slash"));
    }
}
