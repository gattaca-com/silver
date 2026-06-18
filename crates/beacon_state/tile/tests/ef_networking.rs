#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::spec_tests_dir;
use silver_common::{NUMBER_OF_CUSTODY_GROUPS, NodeId};
use silver_ssz::ssz_view::NUMBER_OF_COLUMNS;

#[test]
fn get_custody_groups() {
    let base =
        spec_tests_dir().join("tests/mainnet/fulu/networking/get_custody_groups/pyspec_tests");
    let Ok(cases) = fs::read_dir(&base) else {
        eprintln!("get_custody_groups: no test cases, skipping");
        return;
    };

    let mut pass = 0;
    let mut fail = 0;
    for case in cases.flatten() {
        if !case.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(meta) = fs::read_to_string(case.path().join("meta.yaml")) else { continue };

        let node_id = NodeId::new(&parse_u256_be(field_after(&meta, "node_id:")));
        let count = first_uint(field_after(&meta, "custody_group_count:")) as u8;
        let expected = parse_uint_list(field_after(&meta, "result:"));

        // Bit `g` of the mask set => node custodies group `g`; spec result is
        // the ascending group list.
        let mask = node_id.custody_groups(count);
        let got: Vec<u64> = (0..u32::from(NUMBER_OF_CUSTODY_GROUPS))
            .filter(|g| mask & (1u128 << g) != 0)
            .map(u64::from)
            .collect();

        if got == expected {
            pass += 1;
        } else {
            fail += 1;
            let name = case.file_name().to_string_lossy().to_string();
            eprintln!("{name}: groups mismatch\n  got: {got:?}\n  exp: {expected:?}");
        }
    }
    eprintln!("get_custody_groups: {pass} passed, {fail} failed");
    assert_eq!(fail, 0, "get_custody_groups: {fail} test(s) failed");
}

#[test]
fn compute_columns_for_custody_group() {
    let base = spec_tests_dir()
        .join("tests/mainnet/fulu/networking/compute_columns_for_custody_group/pyspec_tests");
    let Ok(cases) = fs::read_dir(&base) else {
        eprintln!("compute_columns_for_custody_group: no test cases, skipping");
        return;
    };

    let mut pass = 0;
    let mut fail = 0;
    for case in cases.flatten() {
        if !case.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(meta) = fs::read_to_string(case.path().join("meta.yaml")) else { continue };

        let group = first_uint(field_after(&meta, "custody_group:"));
        let expected = parse_uint_list(field_after(&meta, "result:"));
        let got = columns_for_custody_group(group);

        if got == expected {
            pass += 1;
        } else {
            fail += 1;
            let name = case.file_name().to_string_lossy().to_string();
            eprintln!("{name}: columns mismatch\n  got: {got:?}\n  exp: {expected:?}");
        }
    }
    eprintln!("compute_columns_for_custody_group: {pass} passed, {fail} failed");
    assert_eq!(fail, 0, "compute_columns_for_custody_group: {fail} test(s) failed");
}

/// silver folds custody groups and columns 1:1 (`NUMBER_OF_COLUMNS ==
/// NUMBER_OF_CUSTODY_GROUPS`, so `columns_per_group == 1`) and treats the
/// custody-group mask directly as a column mask. This mirrors the spec formula
/// and guards that invariant against the official vectors.
fn columns_for_custody_group(group: u64) -> Vec<u64> {
    let per_group = (NUMBER_OF_COLUMNS / NUMBER_OF_CUSTODY_GROUPS as usize) as u64;
    (0..per_group).map(|i| group * per_group + i).collect()
}

/// Substring following the first occurrence of `key`.
fn field_after<'a>(yaml: &'a str, key: &str) -> &'a str {
    let pos = yaml.find(key).unwrap_or_else(|| panic!("missing key {key}"));
    &yaml[pos + key.len()..]
}

/// First run of ASCII digits in `s`.
fn first_digits(s: &str) -> &str {
    let bytes = s.as_bytes();
    let start = bytes.iter().position(u8::is_ascii_digit).unwrap();
    let end =
        bytes[start..].iter().position(|b| !b.is_ascii_digit()).map_or(bytes.len(), |e| start + e);
    &s[start..end]
}

fn first_uint(s: &str) -> u64 {
    first_digits(s).parse().unwrap()
}

/// YAML flow sequence of unsigned ints `[a, b, c]` (may span lines).
fn parse_uint_list(s: &str) -> Vec<u64> {
    let start = s.find('[').unwrap();
    let end = s.find(']').unwrap();
    s[start + 1..end].split(',').filter_map(|t| t.trim().parse().ok()).collect()
}

/// Decimal u256 -> 32-byte big-endian (matches `NodeId.raw` byte order).
fn parse_u256_be(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for digit in first_digits(s).bytes().map(|b| u16::from(b - b'0')) {
        let mut carry = digit;
        for byte in out.iter_mut().rev() {
            let v = u16::from(*byte) * 10 + carry;
            *byte = v as u8;
            carry = v >> 8;
        }
        // Inputs fit in 256 bits; any carry past the top byte is dropped.
    }
    out
}
