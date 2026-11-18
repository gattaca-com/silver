//! Reading the `ethereum/EthLib` test vectors that `make -C crates/crypto_simd`
//! fetches: one `data.yaml` per case under
//! `cryptography-specs-tests/<dir>/<name>/`.

use std::{fs, path::PathBuf};

pub(crate) fn suite(dir: &str, name: &str) -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("cryptography-specs-tests")
        .join(dir)
        .join(name);
    let mut cases: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}; run `make -C crates/crypto_simd`", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .map(|path| {
            let data = fs::read_to_string(path.join("data.yaml")).unwrap();
            (path.file_name().unwrap().to_string_lossy().into_owned(), data)
        })
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "{} has no cases", dir.display());
    cases
}

/// The text of `key`'s value: from the key to the next key at the same or lower
/// indentation.
pub(crate) fn field<'a>(data: &'a str, key: &str) -> &'a str {
    let marker = format!("{key}:");
    let start = data.find(&marker).unwrap_or_else(|| panic!("no {key}")) + marker.len();
    let rest = &data[start..];
    let end = rest
        .match_indices('\n')
        .map(|(i, _)| i + 1)
        .find(|&i| {
            let line = &rest[i..];
            let indent = line.len() - line.trim_start_matches(' ').len();
            indent <= 2 && line.trim_start().contains(':') && !line.trim_start().starts_with('-')
        })
        .unwrap_or(rest.len());
    &rest[..end]
}

pub(crate) fn hex_items(text: &str) -> Vec<Vec<u8>> {
    text.split("0x")
        .skip(1)
        .map(|item| {
            let digits: String = item.chars().take_while(char::is_ascii_hexdigit).collect();
            assert!(digits.len().is_multiple_of(2), "odd-length hex");
            (0..digits.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

pub(crate) fn integers(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect()
}

pub(crate) fn fixed<const N: usize>(items: Vec<Vec<u8>>) -> Option<Vec<[u8; N]>> {
    items.into_iter().map(|item| item.try_into().ok()).collect()
}
