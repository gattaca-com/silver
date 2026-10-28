use std::{fmt, fmt::Write as _, io::Write as _};

use serde::Deserialize;
use silver_beacon_state_data::{BLSPubkey, MIN_SEED_LOOKAHEAD, SLOTS_PER_EPOCH};
use silver_common::json_fields::{BoundedHex, bytes, each_array_entry, uint64};

use crate::{
    builder_config::{
        ListElements, MAX_BUILDER_AUTH_DATA_SIZE, MAX_BUILDER_ENTRIES, MAX_BUILDER_URL_SIZE,
        SignedRequestAuth, offset_at, u64_at,
    },
    header_fetch::write_hex,
};

pub(crate) const MAX_PREFERENCES: usize =
    MAX_BUILDER_ENTRIES * (MIN_SEED_LOOKAHEAD as usize + 1) * SLOTS_PER_EPOCH as usize;
/// `proposer_pubkey`, the `url` and `auth` offsets, `max_execution_payment`.
const ENTRY_FIXED: usize = 48 + 4 + 4 + 8;
/// `BuilderPreferences` (`max_execution_payment`), the `auth` offset.
const PREFERENCES_REQUEST_FIXED: usize = 8 + 4;

/// A `builder_preferences` body that decodes: the SSZ list of
/// `BuilderPreferencesEntry`, or the same list as JSON. What an entry says is
/// left to its consumer.
#[derive(Clone, Copy, Debug)]
pub enum PreferencesBody<'a> {
    Ssz(&'a [u8]),
    Json(&'a [u8]),
}

impl<'a> PreferencesBody<'a> {
    /// The body and its entry count, `None` when it does not decode or breaks
    /// a bound.
    pub fn parse(body: &'a [u8], is_json: bool) -> Option<(Self, usize)> {
        if is_json {
            let mut urls_fit = true;
            let count = each_array_entry(body, MAX_PREFERENCES, |_, entry: JsonEntry<'_>| {
                urls_fit &= entry.url.len() <= MAX_BUILDER_URL_SIZE;
            });
            return count.ok().filter(|_| urls_fit).map(|count| (Self::Json(body), count));
        }
        let mut count = 0;
        let framed = ListElements::parse(body, MAX_PREFERENCES)?.all(|entry| {
            count += 1;
            BuilderPreferencesEntry::parse(entry).is_some()
        });
        framed.then_some((Self::Ssz(body), count))
    }

    /// Hands `each` every entry with its index. A JSON entry is encoded into
    /// `scratch` first.
    pub(crate) fn for_each_entry(
        &self,
        scratch: &mut Vec<u8>,
        mut each: impl FnMut(usize, BuilderPreferencesEntry<'_>),
    ) {
        match *self {
            Self::Ssz(ssz) => {
                let entries = ListElements::parse(ssz, MAX_PREFERENCES).expect("checked at parse");
                for (index, entry) in entries.enumerate() {
                    each(index, BuilderPreferencesEntry::parse(entry).expect("checked at parse"));
                }
            }
            Self::Json(json) => {
                each_array_entry(json, MAX_PREFERENCES, |index, entry: JsonEntry<'_>| {
                    scratch.clear();
                    entry.encode(scratch);
                    each(index, BuilderPreferencesEntry::parse(scratch).expect("encoded above"));
                })
                .expect("checked at parse");
            }
        }
    }
}

/// `url` is borrowed, so a URL written with JSON escapes does not decode.
#[derive(Deserialize)]
struct JsonEntry<'a> {
    #[serde(deserialize_with = "bytes")]
    proposer_pubkey: BLSPubkey,
    url: &'a str,
    auth: JsonAuth,
    #[serde(deserialize_with = "uint64")]
    max_execution_payment: u64,
}

#[derive(Deserialize)]
struct JsonAuth {
    message: JsonAuthMessage,
    #[serde(deserialize_with = "bytes")]
    signature: [u8; 96],
}

#[derive(Deserialize)]
struct JsonAuthMessage {
    data: BoundedHex<MAX_BUILDER_AUTH_DATA_SIZE>,
    #[serde(deserialize_with = "uint64")]
    slot: u64,
}

impl JsonEntry<'_> {
    fn encode(&self, out: &mut Vec<u8>) {
        let url = self.url.as_bytes();
        out.extend_from_slice(&self.proposer_pubkey);
        out.extend_from_slice(&(ENTRY_FIXED as u32).to_le_bytes());
        out.extend_from_slice(&((ENTRY_FIXED + url.len()) as u32).to_le_bytes());
        out.extend_from_slice(&self.max_execution_payment.to_le_bytes());
        out.extend_from_slice(url);
        let JsonAuth { message, signature } = &self.auth;
        SignedRequestAuth::encode(message.data.as_bytes(), message.slot, signature, out);
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BuilderPreferencesEntry<'a> {
    bytes: &'a [u8],
    fixed: &'a [u8],
    url: &'a [u8],
    auth: SignedRequestAuth<'a>,
}

impl<'a> BuilderPreferencesEntry<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Option<Self> {
        let fixed = bytes.get(..ENTRY_FIXED)?;
        let [url_at, auth_at] = [48, 52].map(|at| offset_at(fixed, at));
        if url_at != ENTRY_FIXED || auth_at < url_at {
            return None;
        }
        let url = bytes.get(url_at..auth_at)?;
        let auth = SignedRequestAuth::parse(bytes.get(auth_at..)?)?;
        (url.len() <= MAX_BUILDER_URL_SIZE).then_some(Self { bytes, fixed, url, auth })
    }

    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn proposer_pubkey(&self) -> &'a BLSPubkey {
        self.fixed[..48].try_into().expect("48 bytes")
    }

    /// UTF-8 bytes of the builder's URL, exactly as the VC sent them.
    pub fn url(&self) -> &'a [u8] {
        self.url
    }

    pub fn max_execution_payment(&self) -> u64 {
        u64_at(self.fixed, 56)
    }

    /// The SSZ `BuilderPreferencesRequest` the builder receives, its auth
    /// the bytes the VC signed.
    pub(crate) fn write_request(&self, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(&self.max_execution_payment().to_le_bytes());
        out.extend_from_slice(&(PREFERENCES_REQUEST_FIXED as u32).to_le_bytes());
        out.extend_from_slice(self.auth.bytes());
    }

    /// The same request as JSON, for a builder that refuses SSZ.
    pub(crate) fn write_request_json(&self, out: &mut String) {
        out.clear();
        write!(
            out,
            r#"{{"preferences":{{"max_execution_payment":"{}"}},"auth":{{"message":{{"data":""#,
            self.max_execution_payment()
        )
        .unwrap();
        write_hex(out, self.auth.data());
        write!(out, r#"","slot":"{}"}},"signature":""#, self.auth.slot()).unwrap();
        write_hex(out, self.auth.signature());
        out.push_str(r#""}}"#);
    }
}

/// The entries a `builder_preferences` request could not submit, each framed
/// as its `u32` body index, the message's `u32` length and the message.
#[derive(Clone, Copy, Debug)]
pub struct PreferenceFailures<'a>(&'a [u8]);

impl<'a> PreferenceFailures<'a> {
    pub fn new(frame: &'a [u8]) -> Self {
        Self(frame)
    }

    pub fn write(out: &mut Vec<u8>, index: usize, message: fmt::Arguments<'_>) {
        out.extend_from_slice(&(index as u32).to_le_bytes());
        let len_at = out.len();
        out.extend_from_slice(&[0; 4]);
        out.write_fmt(message).expect("writes to a Vec");
        let len = (out.len() - len_at - 4) as u32;
        out[len_at..len_at + 4].copy_from_slice(&len.to_le_bytes());
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &'a str)> + use<'a> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            let index = offset_at(rest.get(..4)?, 0);
            let len = offset_at(rest, 4);
            let message = str::from_utf8(&rest[8..8 + len]).expect("written from a str");
            rest = &rest[8 + len..];
            Some((index, message))
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::builder_config::tests::auth_ssz;

    pub(crate) fn entry(pubkey: u8, url: &str, max_execution_payment: u64) -> Vec<u8> {
        let mut ssz = vec![pubkey; 48];
        ssz.extend_from_slice(&(ENTRY_FIXED as u32).to_le_bytes());
        ssz.extend_from_slice(&((ENTRY_FIXED + url.len()) as u32).to_le_bytes());
        ssz.extend_from_slice(&max_execution_payment.to_le_bytes());
        ssz.extend_from_slice(url.as_bytes());
        ssz.extend_from_slice(&auth_ssz(b"builder.example", 9));
        ssz
    }

    pub(crate) fn list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut ssz = Vec::new();
        let mut offset = entries.len() * 4;
        for entry in entries {
            ssz.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += entry.len();
        }
        entries.iter().for_each(|entry| ssz.extend_from_slice(entry));
        ssz
    }

    /// Each entry's index, proposer, URL and SSZ builder request.
    fn requests(body: &[u8], is_json: bool) -> Vec<(usize, BLSPubkey, Vec<u8>, Vec<u8>)> {
        let (body, _) = PreferencesBody::parse(body, is_json).expect("decodes");
        let mut requests = Vec::new();
        body.for_each_entry(&mut Vec::new(), |index, entry| {
            let mut request = Vec::new();
            entry.write_request(&mut request);
            requests.push((index, *entry.proposer_pubkey(), entry.url().to_vec(), request));
        });
        requests
    }

    #[test]
    fn entries_read_back_and_render_the_builder_request() {
        let ssz = list(&[entry(1, "https://a", 7), entry(2, "", 0)]);
        assert_eq!(PreferencesBody::parse(&ssz, false).unwrap().1, 2);
        let auth = auth_ssz(b"builder.example", 9);
        let request = |max: u64| [&max.to_le_bytes()[..], &12u32.to_le_bytes(), &auth].concat();
        assert_eq!(requests(&ssz, false), [
            (0, [1; 48], b"https://a".to_vec(), request(7)),
            (1, [2; 48], Vec::new(), request(0)),
        ]);

        let (body, _) = PreferencesBody::parse(&ssz, false).unwrap();
        let mut json = String::new();
        body.for_each_entry(&mut Vec::new(), |index, entry| {
            if index == 0 {
                entry.write_request_json(&mut json);
            }
        });
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["preferences"]["max_execution_payment"], "7");
        assert_eq!(parsed["auth"]["message"]["data"], "0x6275696c6465722e6578616d706c65");
        assert_eq!(parsed["auth"]["message"]["slot"], "9");
        assert_eq!(parsed["auth"]["signature"], format!("0x{}", "aa".repeat(96)));
    }

    fn entry_json(pubkey: u8, url: &str, max_execution_payment: u64) -> String {
        format!(
            r#"{{"proposer_pubkey":"0x{}","url":"{url}","auth":{{"message":{{"data":"0x{}","slot":"9"}},"signature":"0x{}"}},"max_execution_payment":"{max_execution_payment}"}}"#,
            format!("{pubkey:02x}").repeat(48),
            hex::encode(b"builder.example"),
            "aa".repeat(96),
        )
    }

    #[test]
    fn json_entries_match_their_ssz() {
        let json = format!("[{},{}]", entry_json(1, "https://a", 7), entry_json(2, "", 0));
        let ssz = list(&[entry(1, "https://a", 7), entry(2, "", 0)]);
        assert_eq!(PreferencesBody::parse(json.as_bytes(), true).unwrap().1, 2);
        assert_eq!(requests(json.as_bytes(), true), requests(&ssz, false));
        assert_eq!(PreferencesBody::parse(b"[]", true).unwrap().1, 0);
    }

    #[test]
    fn failures_read_back_as_written() {
        let mut frame = Vec::new();
        PreferenceFailures::write(&mut frame, 3, format_args!("builder answered {}", 415));
        PreferenceFailures::write(&mut frame, 0, format_args!(""));
        let failures = PreferenceFailures::new(&frame);
        assert_eq!(failures.iter().collect::<Vec<_>>(), [(3, "builder answered 415"), (0, "")]);
        assert!(PreferenceFailures::new(&[]).is_empty());
    }

    #[test]
    fn json_that_is_not_an_entry_list_is_refused() {
        let long_url = "a".repeat(MAX_BUILDER_URL_SIZE + 1);
        let bodies = [
            "{}".to_owned(),
            "[{}]".to_owned(),
            format!("[{}", entry_json(1, "http://a", 0)),
            format!("[{}]", entry_json(1, &long_url, 0)),
            format!("[{}]", entry_json(1, "http://a", 0).replace(r#""slot":"9""#, r#""slot":9"#)),
            format!("[{}]", entry_json(1, r"http:\/\/a", 0)),
        ];
        for body in bodies {
            assert!(PreferencesBody::parse(body.as_bytes(), true).is_none(), "{body}");
        }
    }

    #[test]
    fn framing_errors_fail_the_list() {
        let good = entry(1, "http://a", 0);
        let torn_auth = good[..ENTRY_FIXED + "http://a".len() + 50].to_vec();
        let mut bad_url_offset = good.clone();
        bad_url_offset[48..52].copy_from_slice(&(ENTRY_FIXED as u32 + 1).to_le_bytes());
        let long_url = "a".repeat(MAX_BUILDER_URL_SIZE + 1);

        let bodies = [
            list(&[good[..ENTRY_FIXED - 1].to_vec()]),
            list(&[torn_auth]),
            list(&[bad_url_offset]),
            list(&[entry(1, &long_url, 0)]),
            list(&vec![good; MAX_PREFERENCES + 1]),
        ];
        for (i, body) in bodies.iter().enumerate() {
            assert!(PreferencesBody::parse(body, false).is_none(), "case {i}");
        }
        assert_eq!(PreferencesBody::parse(&[], false).unwrap().1, 0);
    }
}
