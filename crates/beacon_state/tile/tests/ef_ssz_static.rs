#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{snappy_decode, spec_tests_dir};
use silver_beacon_state::ssz_hash::{self};
use silver_common::{
    merkle::FixedContainer,
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        AttestationView, AttesterSlashingView, BeaconBlockBodyGloasView, ExecutionPayloadBidView,
        IndexedAttestationView, PayloadAttestationView, SignedExecutionPayloadBidView,
    },
};

fn run_ssz_static(fork: &str, type_name: &str, hash_fn: impl Fn(&[u8]) -> [u8; 32]) {
    let base = spec_tests_dir().join("tests/mainnet").join(fork).join("ssz_static").join(type_name);
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
                eprintln!(
                    "{fork}/{type_name}/{name}: got {} expected {}",
                    hex(&our_root),
                    hex(&expected)
                );
            }
        }
    }
    eprintln!("{fork}/{type_name}: {pass} passed, {fail} failed");
    assert_eq!(fail, 0, "{fork}/{type_name}: {fail} test(s) failed");
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
fn fulu_beacon_block_body() {
    run_ssz_static("fulu", "BeaconBlockBody", move |ssz| ssz_hash::hash_tree_root_body_fulu(ssz));
}

#[test]
fn fulu_attestation() {
    run_ssz_static("fulu", "Attestation", move |ssz| ssz_hash::hash_attestation(ssz));
}

#[test]
fn fulu_indexed_attestation() {
    run_ssz_static("fulu", "IndexedAttestation", move |ssz| {
        ssz_hash::hash_indexed_attestation(ssz)
    });
}

#[test]
fn fulu_attester_slashing() {
    run_ssz_static("fulu", "AttesterSlashing", move |ssz| ssz_hash::hash_attester_slashing(ssz));
}

#[test]
fn gloas_beacon_block_body() {
    run_ssz_static("gloas", "BeaconBlockBody", move |ssz| {
        BeaconBlockBodyGloasView::hash_tree_root(ssz)
    });
}

#[test]
fn gloas_attestation() {
    run_ssz_static("gloas", "Attestation", move |ssz| AttestationView::hash_tree_root_gloas(ssz));
}

#[test]
fn gloas_indexed_attestation() {
    run_ssz_static("gloas", "IndexedAttestation", move |ssz| {
        IndexedAttestationView::hash_tree_root_gloas(ssz)
    });
}

#[test]
fn gloas_attester_slashing() {
    run_ssz_static("gloas", "AttesterSlashing", move |ssz| {
        AttesterSlashingView::hash_tree_root_gloas(ssz)
    });
}

#[test]
fn gloas_execution_payload_bid() {
    run_ssz_static("gloas", "ExecutionPayloadBid", move |ssz| {
        ExecutionPayloadBidView::hash_tree_root(ssz)
    });
}

#[test]
fn gloas_signed_execution_payload_bid() {
    run_ssz_static("gloas", "SignedExecutionPayloadBid", move |ssz| {
        SignedExecutionPayloadBidView::hash_tree_root(ssz)
    });
}

#[test]
fn gloas_payload_attestation() {
    run_ssz_static("gloas", "PayloadAttestation", move |ssz| {
        PayloadAttestationView::hash_tree_root(ssz)
    });
}

#[test]
fn gloas_execution_requests() {
    run_ssz_static("gloas", "ExecutionRequests", move |ssz| {
        ExecutionRequestsView::hash_tree_root(ssz)
    });
}

#[test]
fn fulu_beacon_block_header() {
    run_ssz_static("fulu", "BeaconBlockHeader", move |ssz| {
        let h = silver_beacon_state_data::BeaconBlockHeader {
            slot: u64::from_le_bytes(ssz[0..8].try_into().unwrap()),
            proposer_index: u64::from_le_bytes(ssz[8..16].try_into().unwrap()),
            parent_root: ssz[16..48].try_into().unwrap(),
            state_root: ssz[48..80].try_into().unwrap(),
            body_root: ssz[80..112].try_into().unwrap(),
        };
        ssz_hash::hash_tree_root_block_header(&h)
    });
}
