#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{snappy_decode, spec_tests_dir};
use silver_beacon_state::{
    ssz_hash::{self},
    stf,
};
use silver_common::{
    merkle::FixedContainer,
    ssz_hash_gloas::ExecutionRequestsView,
    ssz_view::{
        AttestationView, AttesterSlashingView, BEACON_BLOCK_BODY_FIXED, BeaconBlockBodyFuluView,
        BeaconBlockBodyGloasView, ExecutionPayloadBidView, ExecutionPayloadEnvelopeView,
        ExecutionPayloadView, IndexedAttestationView, PayloadAttestationView,
        ProposerPreferencesView, SignedExecutionPayloadBidView, SignedExecutionPayloadEnvelopeView,
        SignedProposerPreferencesView,
    },
};
use silver_ssz::{
    block_body::{BeaconBlockBodyFulu, BeaconBlockBodyGloas},
    body_offsets::{BodyFork, BodyOffsets},
};

fn run_ssz_static(fork: &str, type_name: &str, hash_fn: impl Fn(&[u8]) -> [u8; 32]) {
    let base = spec_tests_dir().join("tests/mainnet").join(fork).join("ssz_static").join(type_name);
    let suites = fs::read_dir(&base)
        .unwrap_or_else(|e| panic!("{fork}/{type_name}: no ssz_static vectors at {base:?}: {e}"));

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
    assert!(pass > 0, "{fork}/{type_name}: vector dir exists but no cases ran");
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

/// Rebuilt from its fields, every body is byte-identical and keeps its root.
#[test]
fn fulu_beacon_block_body_encodes_from_its_fields() {
    run_ssz_static("fulu", "BeaconBlockBody", |ssz| {
        let encoded = encoded(&reencode_fulu_body(ssz));
        assert_eq!(encoded, ssz);
        ssz_hash::hash_tree_root_body_fulu(&encoded)
    });
}

/// Hashed from its fixed part and its fields, apart, every body keeps its root.
#[test]
fn fulu_beacon_block_body_hashes_from_its_parts() {
    run_ssz_static("fulu", "BeaconBlockBody", |ssz| {
        let body = reencode_fulu_body(ssz);
        let mut fixed = [0; BEACON_BLOCK_BODY_FIXED];
        let parts = body.write_fixed(&mut fixed).unwrap();
        ssz_hash::hash_tree_root_body_fulu_with_roots(&parts).0
    });
}

/// Rebuilt from its fields, every body is byte-identical and keeps its root.
#[test]
fn gloas_beacon_block_body_encodes_from_its_fields() {
    run_ssz_static("gloas", "BeaconBlockBody", |ssz| {
        let body = reencode_gloas_body(ssz);
        let mut encoded = vec![0; body.ssz_len()];
        body.encode(&mut encoded);
        assert_eq!(encoded, ssz);
        BeaconBlockBodyGloasView::hash_tree_root(&encoded)
    });
}

/// Encoded, parsed and hashed as block production does, every body keeps its
/// root.
#[test]
fn gloas_beacon_block_body_hashes_as_production_does() {
    run_ssz_static("gloas", "BeaconBlockBody", |ssz| {
        let body = reencode_gloas_body(ssz);
        let mut encoded = vec![0; body.ssz_len()];
        body.encode(&mut encoded);
        let offsets = BodyOffsets::validated(&encoded, BodyFork::Gloas).unwrap();
        stf::hash_body(&offsets).0
    });
}

/// The Gloas fixed part keeps Fulu's offset positions.
fn reencode_gloas_body(ssz: &[u8]) -> BeaconBlockBodyGloas<'_> {
    let starts = BeaconBlockBodyFuluView::VARIABLE_OFFSETS
        .map(|at| u32::from_le_bytes(ssz[at..at + 4].try_into().unwrap()) as usize);
    let field = |i: usize| &ssz[starts[i]..starts.get(i + 1).copied().unwrap_or(ssz.len())];
    BeaconBlockBodyGloas {
        randao_reveal: BeaconBlockBodyGloasView::randao_reveal(ssz),
        eth1_data: BeaconBlockBodyGloasView::eth1_data(ssz),
        graffiti: BeaconBlockBodyGloasView::graffiti(ssz),
        proposer_slashings: field(0),
        attester_slashings: field(1),
        attestations: field(2),
        deposits: field(3),
        voluntary_exits: field(4),
        sync_aggregate: BeaconBlockBodyGloasView::sync_aggregate(ssz),
        bls_to_execution_changes: field(5),
        signed_execution_payload_bid: field(6),
        payload_attestations: field(7),
        parent_execution_requests: field(8),
    }
}

fn reencode_fulu_body(ssz: &[u8]) -> BeaconBlockBodyFulu<'_> {
    let starts = BeaconBlockBodyFuluView::VARIABLE_OFFSETS
        .map(|at| u32::from_le_bytes(ssz[at..at + 4].try_into().unwrap()) as usize);
    let field = |i: usize| &ssz[starts[i]..starts.get(i + 1).copied().unwrap_or(ssz.len())];
    BeaconBlockBodyFulu {
        randao_reveal: BeaconBlockBodyFuluView::randao_reveal(ssz),
        eth1_data: BeaconBlockBodyFuluView::eth1_data(ssz),
        graffiti: BeaconBlockBodyFuluView::graffiti(ssz),
        proposer_slashings: field(0),
        attester_slashings: field(1),
        attestations: field(2),
        deposits: field(3),
        voluntary_exits: field(4),
        sync_aggregate: BeaconBlockBodyFuluView::sync_aggregate(ssz),
        execution_payload: field(5),
        bls_to_execution_changes: field(6),
        blob_kzg_commitments: field(7),
        execution_requests: field(8),
    }
}

fn encoded(body: &BeaconBlockBodyFulu<'_>) -> Vec<u8> {
    let mut out = vec![0; body.ssz_len()];
    body.encode(&mut out);
    out
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
fn gloas_proposer_preferences() {
    run_ssz_static("gloas", "ProposerPreferences", move |ssz| {
        ProposerPreferencesView::hash_tree_root(ssz.try_into().unwrap())
    });
}

#[test]
fn gloas_signed_proposer_preferences() {
    run_ssz_static("gloas", "SignedProposerPreferences", move |ssz| {
        SignedProposerPreferencesView::hash_tree_root(ssz.try_into().unwrap())
    });
}

#[test]
fn gloas_signed_execution_payload_bid() {
    run_ssz_static("gloas", "SignedExecutionPayloadBid", move |ssz| {
        SignedExecutionPayloadBidView::hash_tree_root(ssz)
    });
}

#[test]
fn gloas_execution_payload() {
    run_ssz_static("gloas", "ExecutionPayload", move |ssz| {
        ExecutionPayloadView::hash_tree_root_gloas(ssz)
    });
}

#[test]
fn gloas_execution_payload_envelope() {
    run_ssz_static("gloas", "ExecutionPayloadEnvelope", move |ssz| {
        ExecutionPayloadEnvelopeView::hash_tree_root(ssz)
    });
}

#[test]
fn gloas_signed_execution_payload_envelope() {
    run_ssz_static("gloas", "SignedExecutionPayloadEnvelope", move |ssz| {
        SignedExecutionPayloadEnvelopeView::hash_tree_root(ssz)
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
