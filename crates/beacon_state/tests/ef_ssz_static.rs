#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{snappy_decode, spec_tests_dir};
use silver_beacon_state::ssz_hash::{self, compute_zero_hashes};

fn run_ssz_static(type_name: &str, hash_fn: impl Fn(&[u8]) -> [u8; 32]) {
    let base = spec_tests_dir().join("tests/mainnet/fulu/ssz_static").join(type_name);
    let Ok(suites) = fs::read_dir(&base) else {
        eprintln!("{type_name}: no test dir, skipping");
        return;
    };

    let mut pass = 0;
    let mut fail = 0;
    for suite in suites.flatten() {
        if !suite.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let Ok(cases) = fs::read_dir(suite.path()) else { continue };
        for case in cases.flatten() {
            if !case.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let dir = case.path();
            let roots_path = dir.join("roots.yaml");
            let ssz_path = dir.join("serialized.ssz_snappy");
            if !roots_path.exists() || !ssz_path.exists() {
                continue;
            }

            let ssz = snappy_decode(&ssz_path);
            let our_root = hash_fn(&ssz);

            let roots_yaml = fs::read_to_string(&roots_path).unwrap();
            let expected = parse_root(&roots_yaml);

            if our_root == expected {
                pass += 1;
            } else {
                fail += 1;
                let name = format!(
                    "{}/{}",
                    suite.file_name().to_string_lossy(),
                    case.file_name().to_string_lossy()
                );
                eprintln!("{type_name}/{name}: got {} expected {}", hex(&our_root), hex(&expected));
            }
        }
    }
    eprintln!("{type_name}: {pass} passed, {fail} failed");
    assert_eq!(fail, 0, "{type_name}: {fail} test(s) failed");
}

fn parse_root(yaml: &str) -> [u8; 32] {
    for line in yaml.lines() {
        if let Some(val) = line.strip_prefix("root:") {
            let hex_str = val.trim().trim_matches('\'').strip_prefix("0x").unwrap_or("");
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
            }
            return out;
        }
    }
    [0u8; 32]
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn beacon_block_body() {
    let zh = compute_zero_hashes();
    run_ssz_static("BeaconBlockBody", move |ssz| ssz_hash::hash_tree_root_body(ssz, &zh));
}

#[test]
fn beacon_block_header() {
    let zh = compute_zero_hashes();
    run_ssz_static("BeaconBlockHeader", move |ssz| {
        let h = silver_beacon_state::types::BeaconBlockHeader {
            slot: u64::from_le_bytes(ssz[0..8].try_into().unwrap()),
            proposer_index: u64::from_le_bytes(ssz[8..16].try_into().unwrap()),
            parent_root: ssz[16..48].try_into().unwrap(),
            state_root: ssz[48..80].try_into().unwrap(),
            body_root: ssz[80..112].try_into().unwrap(),
        };
        ssz_hash::hash_tree_root_block_header(&h, &zh)
    });
}
