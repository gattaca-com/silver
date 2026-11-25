use std::str;

/// An `engine_getClientVersionV1` identity, reduced to what block graffiti
/// carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientVersion {
    pub code: [u8; 2],
    /// Lowercase hex of the commit's first four bytes. A shorter or missing
    /// commit is padded with `0`.
    pub commit: [u8; 8],
}

impl ClientVersion {
    pub fn silver(commit: &str) -> Self {
        Self::parse("SV", commit).expect("SV is a client code")
    }

    /// `None` for a code that is not two ASCII letters.
    pub fn parse(code: &str, commit: &str) -> Option<Self> {
        let code: [u8; 2] = code.as_bytes().try_into().ok()?;
        if !code.iter().all(u8::is_ascii_alphabetic) {
            return None;
        }
        let mut hex = [b'0'; 8];
        let digits = commit.strip_prefix("0x").unwrap_or(commit).bytes();
        for (slot, digit) in hex.iter_mut().zip(digits.take_while(u8::is_ascii_hexdigit)) {
            *slot = digit.to_ascii_lowercase();
        }
        Some(Self { code, commit: hex })
    }

    pub fn code_str(&self) -> &str {
        str::from_utf8(&self.code).expect("ascii letters")
    }

    pub fn commit_str(&self) -> &str {
        str::from_utf8(&self.commit).expect("ascii hex")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_keeps_the_leading_hex_of_any_spelling() {
        assert_eq!(ClientVersion::silver("0xFA4FF922aa").commit_str(), "fa4ff922");
        assert_eq!(ClientVersion::silver("abc1234-dirty").commit_str(), "abc12340");
        assert_eq!(ClientVersion::silver("unknown").commit_str(), "00000000");
    }

    #[test]
    fn code_is_two_letters() {
        assert_eq!(ClientVersion::parse("GE", "").map(|v| v.code), Some(*b"GE"));
        assert!(ClientVersion::parse("G", "").is_none());
        assert!(ClientVersion::parse("G1", "").is_none());
    }
}
