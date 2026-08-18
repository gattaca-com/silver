use std::borrow::Cow;

pub struct Query<'a> {
    rest: &'a str,
}

impl<'a> Query<'a> {
    pub fn new(raw: &'a str) -> Self {
        Self { rest: raw }
    }
}

impl<'a> Iterator for Query<'a> {
    type Item = (Cow<'a, str>, Cow<'a, str>);

    fn next(&mut self) -> Option<Self::Item> {
        while !self.rest.is_empty() {
            let (pair, rest) = self.rest.split_once('&').unwrap_or((self.rest, ""));
            self.rest = rest;
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            return Some((percent_decode(key), percent_decode(value)));
        }
        None
    }
}

// `+` stays literal: the `+`-means-space rule is HTML form encoding, and no
// validator client sends a form body here — beacon-API query values are hex
// strings, validator statuses and graffiti, escaped per RFC 3986.
fn percent_decode(raw: &str) -> Cow<'_, str> {
    let Some(first_escape) = raw.find('%') else {
        return Cow::Borrowed(raw);
    };
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    out.extend_from_slice(&bytes[..first_escape]);

    let mut i = first_escape;
    while i < bytes.len() {
        match decode_escape(&bytes[i..]) {
            Some(byte) => {
                out.push(byte);
                i += 3;
            }
            None => {
                out.push(bytes[i]);
                i += 1;
            }
        }
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

fn decode_escape(bytes: &[u8]) -> Option<u8> {
    let &[b'%', high, low, ..] = bytes else { return None };
    let digit = |byte: u8| (byte as char).to_digit(16);
    Some((digit(high)? * 16 + digit(low)?) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(raw: &str) -> Vec<(String, String)> {
        Query::new(raw).map(|(k, v)| (k.into_owned(), v.into_owned())).collect()
    }

    #[test]
    fn plain_pairs_split_on_ampersand_and_equals() {
        assert_eq!(pairs("id=1&status=active_ongoing"), [
            ("id".to_string(), "1".to_string()),
            ("status".to_string(), "active_ongoing".to_string()),
        ]);
    }

    #[test]
    fn escape_free_pairs_borrow_the_raw_query() {
        let (key, value) = Query::new("status=active_ongoing").next().unwrap();
        assert!(matches!(key, Cow::Borrowed(_)));
        assert!(matches!(value, Cow::Borrowed(_)));
    }

    #[test]
    fn percent_escapes_decoded_in_key_and_value() {
        assert_eq!(pairs("a%20b=c%2Fd%20e"), [("a b".to_string(), "c/d e".to_string())]);
    }

    #[test]
    fn lowercase_hex_escape_decoded() {
        assert_eq!(pairs("g=%2f%7e"), [("g".to_string(), "/~".to_string())]);
    }

    #[test]
    fn plus_stays_literal_rather_than_becoming_a_space() {
        assert_eq!(pairs("graffiti=a+b"), [("graffiti".to_string(), "a+b".to_string())]);
    }

    #[test]
    fn malformed_escape_kept_literally() {
        assert_eq!(pairs("a=%zz&b=%4&c=100%&d=%"), [
            ("a".to_string(), "%zz".to_string()),
            ("b".to_string(), "%4".to_string()),
            ("c".to_string(), "100%".to_string()),
            ("d".to_string(), "%".to_string()),
        ]);
    }

    #[test]
    fn escape_decoding_to_invalid_utf8_does_not_panic() {
        assert_eq!(pairs("a=%ff%fe"), [("a".to_string(), "\u{fffd}\u{fffd}".to_string())]);
    }

    #[test]
    fn empty_query_yields_nothing() {
        assert!(pairs("").is_empty());
    }

    #[test]
    fn empty_segments_skipped() {
        assert_eq!(pairs("&&a=1&&"), [("a".to_string(), "1".to_string())]);
    }

    #[test]
    fn key_without_equals_yields_empty_value() {
        assert_eq!(pairs("skip_randao_verification&slot=7"), [
            ("skip_randao_verification".to_string(), String::new()),
            ("slot".to_string(), "7".to_string()),
        ]);
    }

    #[test]
    fn repeated_key_yields_every_occurrence() {
        assert_eq!(pairs("id=1&id=2"), [
            ("id".to_string(), "1".to_string()),
            ("id".to_string(), "2".to_string()),
        ]);
    }
}
