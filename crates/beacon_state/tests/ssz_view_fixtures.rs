//! Field-level verification of ssz_view accessors against EF consensus-spec
//! ssz_static fixtures (mainnet/fulu).

mod common;

use std::{fs, path::PathBuf};

use common::{snappy_decode, spec_tests_dir};
use serde_yml::Value;
use silver_common::ssz_view::*;

fn cases_for(container: &str) -> Vec<(PathBuf, Vec<u8>, Value)> {
    let dir =
        spec_tests_dir().join("tests/mainnet/fulu/ssz_static").join(container).join("ssz_random");
    let mut dirs: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|e| e.ok().map(|e| e.path()).filter(|p| p.is_dir()))
        .collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "{}: no cases", dir.display());

    dirs.into_iter()
        .map(|case| {
            let bytes = snappy_decode(&case.join("serialized.ssz_snappy"));
            let yaml = fs::read_to_string(case.join("value.yaml"))
                .unwrap_or_else(|e| panic!("{}: {e}", case.display()));
            let v: Value =
                serde_yml::from_str(&yaml).unwrap_or_else(|e| panic!("{}: {e}", case.display()));
            (case, bytes, v)
        })
        .collect()
}

fn u(v: &Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| panic!("not a u64: {v:?}"))
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("bad hex nibble: {c}"),
    }
}

fn hex_decode_0x(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").expect("missing 0x prefix");
    assert!(s.len().is_multiple_of(2), "odd hex length");
    let bytes = s.as_bytes();
    (0..bytes.len())
        .step_by(2)
        .map(|i| (hex_nibble(bytes[i]) << 4) | hex_nibble(bytes[i + 1]))
        .collect()
}

fn b(v: &Value, len: usize) -> Vec<u8> {
    let out = b_any(v);
    assert_eq!(out.len(), len, "hex {} != expected {}", out.len(), len);
    out
}

fn b_any(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap_or_else(|| panic!("not a string: {v:?}"));
    hex_decode_0x(s)
}

fn b20(v: &Value) -> [u8; 20] {
    b(v, 20).try_into().unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    b(v, 32).try_into().unwrap()
}
fn b48(v: &Value) -> [u8; 48] {
    b(v, 48).try_into().unwrap()
}
fn b96(v: &Value) -> [u8; 96] {
    b(v, 96).try_into().unwrap()
}

/// Concat YAML list of `0x…` hex strings, each exactly `elem_len` bytes.
fn hex_list_concat(v: &Value, elem_len: usize) -> Vec<u8> {
    let seq = v.as_sequence().unwrap_or_else(|| panic!("not a list: {v:?}"));
    let mut out = Vec::with_capacity(seq.len() * elem_len);
    for e in seq {
        out.extend_from_slice(&b(e, elem_len));
    }
    out
}

/// Concat YAML list of u64s as LE bytes (SSZ list of fixed-size uints).
fn u64_list_le(v: &Value) -> Vec<u8> {
    let seq = v.as_sequence().unwrap_or_else(|| panic!("not a list: {v:?}"));
    let mut out = Vec::with_capacity(seq.len() * 8);
    for e in seq {
        out.extend_from_slice(&u(e).to_le_bytes());
    }
    out
}

#[test]
fn single_attestation() {
    for (case, bytes, v) in cases_for("SingleAttestation") {
        let buf: &[u8; SINGLE_ATT_SIZE] = bytes
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| panic!("{}: wrong len {}", case.display(), bytes.len()));
        assert_eq!(SingleAttestationView::committee_index(buf), u(&v["committee_index"]));
        assert_eq!(SingleAttestationView::attester_index(buf), u(&v["attester_index"]));
        let d = &v["data"];
        assert_eq!(SingleAttestationView::slot(buf), u(&d["slot"]));
        assert_eq!(SingleAttestationView::data_index(buf), u(&d["index"]));
        assert_eq!(*SingleAttestationView::beacon_block_root(buf), b32(&d["beacon_block_root"]));
        assert_eq!(SingleAttestationView::source_epoch(buf), u(&d["source"]["epoch"]));
        assert_eq!(*SingleAttestationView::source_root(buf), b32(&d["source"]["root"]));
        assert_eq!(SingleAttestationView::target_epoch(buf), u(&d["target"]["epoch"]));
        assert_eq!(*SingleAttestationView::target_root(buf), b32(&d["target"]["root"]));
        assert_eq!(*SingleAttestationView::signature(buf), b96(&v["signature"]));
    }
}

#[test]
fn proposer_slashing() {
    for (case, bytes, v) in cases_for("ProposerSlashing") {
        let buf: &[u8; PROPOSER_SLASHING_SIZE] =
            bytes.as_slice().try_into().unwrap_or_else(|_| panic!("{}: wrong len", case.display()));
        let (h1, h2) = (&v["signed_header_1"], &v["signed_header_2"]);
        let (m1, m2) = (&h1["message"], &h2["message"]);

        assert_eq!(ProposerSlashingView::h1_slot(buf), u(&m1["slot"]));
        assert_eq!(ProposerSlashingView::h1_proposer_index(buf), u(&m1["proposer_index"]));
        assert_eq!(*ProposerSlashingView::h1_parent_root(buf), b32(&m1["parent_root"]));
        assert_eq!(*ProposerSlashingView::h1_state_root(buf), b32(&m1["state_root"]));
        assert_eq!(*ProposerSlashingView::h1_body_root(buf), b32(&m1["body_root"]));
        assert_eq!(*ProposerSlashingView::h1_signature(buf), b96(&h1["signature"]));

        assert_eq!(ProposerSlashingView::h2_slot(buf), u(&m2["slot"]));
        assert_eq!(ProposerSlashingView::h2_proposer_index(buf), u(&m2["proposer_index"]));
        assert_eq!(*ProposerSlashingView::h2_parent_root(buf), b32(&m2["parent_root"]));
        assert_eq!(*ProposerSlashingView::h2_state_root(buf), b32(&m2["state_root"]));
        assert_eq!(*ProposerSlashingView::h2_body_root(buf), b32(&m2["body_root"]));
        assert_eq!(*ProposerSlashingView::h2_signature(buf), b96(&h2["signature"]));
    }
}

#[test]
fn signed_voluntary_exit() {
    for (case, bytes, v) in cases_for("SignedVoluntaryExit") {
        let buf: &[u8; SIGNED_VOLUNTARY_EXIT_SIZE] =
            bytes.as_slice().try_into().unwrap_or_else(|_| panic!("{}: wrong len", case.display()));
        let m = &v["message"];
        assert_eq!(SignedVoluntaryExitView::epoch(buf), u(&m["epoch"]));
        assert_eq!(SignedVoluntaryExitView::validator_index(buf), u(&m["validator_index"]));
        assert_eq!(*SignedVoluntaryExitView::signature(buf), b96(&v["signature"]));
    }
}

#[test]
fn sync_committee_message() {
    for (case, bytes, v) in cases_for("SyncCommitteeMessage") {
        let buf: &[u8; SYNC_COMMITTEE_MSG_SIZE] =
            bytes.as_slice().try_into().unwrap_or_else(|_| panic!("{}: wrong len", case.display()));
        assert_eq!(SyncCommitteeView::slot(buf), u(&v["slot"]));
        assert_eq!(*SyncCommitteeView::beacon_block_root(buf), b32(&v["beacon_block_root"]));
        assert_eq!(SyncCommitteeView::validator_index(buf), u(&v["validator_index"]));
        assert_eq!(*SyncCommitteeView::signature(buf), b96(&v["signature"]));
    }
}

#[test]
fn signed_contribution_and_proof() {
    for (case, bytes, v) in cases_for("SignedContributionAndProof") {
        let buf: &[u8; SIGNED_CONTRIBUTION_AND_PROOF_SIZE] =
            bytes.as_slice().try_into().unwrap_or_else(|_| panic!("{}: wrong len", case.display()));
        let m = &v["message"];
        let c = &m["contribution"];

        assert_eq!(
            SignedContributionAndProofView::aggregator_index(buf),
            u(&m["aggregator_index"])
        );
        assert_eq!(SignedContributionAndProofView::slot(buf), u(&c["slot"]));
        assert_eq!(
            *SignedContributionAndProofView::beacon_block_root(buf),
            b32(&c["beacon_block_root"])
        );
        assert_eq!(
            SignedContributionAndProofView::subcommittee_index(buf),
            u(&c["subcommittee_index"])
        );
        // Bitvector[SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT = 128] → 16 B
        assert_eq!(
            SignedContributionAndProofView::aggregation_bits(buf)[..],
            b(&c["aggregation_bits"], 16)[..]
        );
        assert_eq!(
            *SignedContributionAndProofView::contribution_signature(buf),
            b96(&c["signature"])
        );
        assert_eq!(
            *SignedContributionAndProofView::selection_proof(buf),
            b96(&m["selection_proof"])
        );
        assert_eq!(*SignedContributionAndProofView::signature(buf), b96(&v["signature"]));
    }
}

#[test]
fn signed_bls_to_execution_change() {
    for (case, bytes, v) in cases_for("SignedBLSToExecutionChange") {
        let buf: &[u8; SIGNED_BLS_CHANGE_SIZE] =
            bytes.as_slice().try_into().unwrap_or_else(|_| panic!("{}: wrong len", case.display()));
        let m = &v["message"];
        assert_eq!(SignedBlsToExecutionChangeView::validator_index(buf), u(&m["validator_index"]));
        assert_eq!(
            *SignedBlsToExecutionChangeView::from_bls_pubkey(buf),
            b48(&m["from_bls_pubkey"])
        );
        assert_eq!(
            *SignedBlsToExecutionChangeView::to_execution_address(buf),
            b20(&m["to_execution_address"])
        );
        assert_eq!(*SignedBlsToExecutionChangeView::signature(buf), b96(&v["signature"]));
    }
}

#[test]
fn blob_identifier() {
    for (case, bytes, v) in cases_for("BlobIdentifier") {
        let buf: &[u8; BLOB_IDENTIFIER_SIZE] =
            bytes.as_slice().try_into().unwrap_or_else(|_| panic!("{}: wrong len", case.display()));
        assert_eq!(*BlobIdentifierView::block_root(buf), b32(&v["block_root"]));
        assert_eq!(BlobIdentifierView::index(buf), u(&v["index"]));
    }
}

#[test]
fn signed_beacon_block() {
    for (_case, bytes, v) in cases_for("SignedBeaconBlock") {
        let buf = bytes.as_slice();
        let m = &v["message"];

        // Outer: offset to message (==100); body offset at [180..184) (== 84).
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(buf[180..184].try_into().unwrap()), 84);

        assert_eq!(*SignedBeaconBlockView::signature(buf), b96(&v["signature"]));
        assert_eq!(SignedBeaconBlockView::slot(buf), u(&m["slot"]));
        assert_eq!(SignedBeaconBlockView::proposer_index(buf), u(&m["proposer_index"]));
        assert_eq!(*SignedBeaconBlockView::parent_root(buf), b32(&m["parent_root"]));
        assert_eq!(*SignedBeaconBlockView::state_root(buf), b32(&m["state_root"]));
        assert_eq!(SignedBeaconBlockView::body(buf).len(), buf.len() - 184);
    }
}

#[test]
fn signed_aggregate_and_proof() {
    for (_case, bytes, v) in cases_for("SignedAggregateAndProof") {
        let buf = bytes.as_slice();
        let m = &v["message"];
        let a = &m["aggregate"];
        let d = &a["data"];

        // Layout invariants: outer message offset 100, inner aggregate offset
        // 108 (rel. to 100), aggregation_bits offset 236 (rel. to 208).
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 100);
        assert_eq!(u32::from_le_bytes(buf[108..112].try_into().unwrap()), 108);
        assert_eq!(u32::from_le_bytes(buf[208..212].try_into().unwrap()), 236);

        assert_eq!(*SignedAggregateAndProofView::signature(buf), b96(&v["signature"]));
        assert_eq!(SignedAggregateAndProofView::aggregator_index(buf), u(&m["aggregator_index"]));
        assert_eq!(*SignedAggregateAndProofView::selection_proof(buf), b96(&m["selection_proof"]));
        assert_eq!(SignedAggregateAndProofView::agg_slot(buf), u(&d["slot"]));
        assert_eq!(SignedAggregateAndProofView::agg_data_index(buf), u(&d["index"]));
        assert_eq!(
            *SignedAggregateAndProofView::agg_beacon_block_root(buf),
            b32(&d["beacon_block_root"])
        );
        assert_eq!(SignedAggregateAndProofView::agg_source_epoch(buf), u(&d["source"]["epoch"]));
        assert_eq!(*SignedAggregateAndProofView::agg_source_root(buf), b32(&d["source"]["root"]));
        assert_eq!(SignedAggregateAndProofView::agg_target_epoch(buf), u(&d["target"]["epoch"]));
        assert_eq!(*SignedAggregateAndProofView::agg_target_root(buf), b32(&d["target"]["root"]));
        assert_eq!(*SignedAggregateAndProofView::agg_signature(buf), b96(&a["signature"]));
        assert_eq!(
            SignedAggregateAndProofView::agg_committee_bits(buf)[..],
            b(&a["committee_bits"], 8)[..]
        );
        assert_eq!(
            SignedAggregateAndProofView::agg_aggregation_bits(buf),
            &b_any(&a["aggregation_bits"])[..]
        );
    }
}

#[test]
fn attester_slashing() {
    for (_case, bytes, v) in cases_for("AttesterSlashing") {
        let buf = bytes.as_slice();

        // Layout invariants: att_1 offset 8; att_2 offset monotonic;
        // each IndexedAttestation's attesting_indices offset is 228.
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 8);
        let att2_off = u32::from_le_bytes(buf[4..8].try_into().unwrap()) as usize;
        assert!(att2_off >= 8 + 228 && att2_off <= buf.len());
        assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), 228);
        assert_eq!(u32::from_le_bytes(buf[att2_off..att2_off + 4].try_into().unwrap()), 228);

        let a1 = &v["attestation_1"];
        let a2 = &v["attestation_2"];
        let d1 = &a1["data"];
        let d2 = &a2["data"];

        // att_1
        assert_eq!(AttesterSlashingView::att1_slot(buf), u(&d1["slot"]));
        assert_eq!(AttesterSlashingView::att1_data_index(buf), u(&d1["index"]));
        assert_eq!(
            *AttesterSlashingView::att1_beacon_block_root(buf),
            b32(&d1["beacon_block_root"])
        );
        assert_eq!(AttesterSlashingView::att1_source_epoch(buf), u(&d1["source"]["epoch"]));
        assert_eq!(*AttesterSlashingView::att1_source_root(buf), b32(&d1["source"]["root"]));
        assert_eq!(AttesterSlashingView::att1_target_epoch(buf), u(&d1["target"]["epoch"]));
        assert_eq!(*AttesterSlashingView::att1_target_root(buf), b32(&d1["target"]["root"]));
        assert_eq!(*AttesterSlashingView::att1_signature(buf), b96(&a1["signature"]));
        assert_eq!(
            AttesterSlashingView::att1_attesting_indices(buf),
            u64_list_le(&a1["attesting_indices"])
        );

        // att_2
        assert_eq!(AttesterSlashingView::att2_slot(buf), u(&d2["slot"]));
        assert_eq!(AttesterSlashingView::att2_data_index(buf), u(&d2["index"]));
        assert_eq!(
            *AttesterSlashingView::att2_beacon_block_root(buf),
            b32(&d2["beacon_block_root"])
        );
        assert_eq!(AttesterSlashingView::att2_source_epoch(buf), u(&d2["source"]["epoch"]));
        assert_eq!(*AttesterSlashingView::att2_source_root(buf), b32(&d2["source"]["root"]));
        assert_eq!(AttesterSlashingView::att2_target_epoch(buf), u(&d2["target"]["epoch"]));
        assert_eq!(*AttesterSlashingView::att2_target_root(buf), b32(&d2["target"]["root"]));
        assert_eq!(*AttesterSlashingView::att2_signature(buf), b96(&a2["signature"]));
        assert_eq!(
            AttesterSlashingView::att2_attesting_indices(buf),
            u64_list_le(&a2["attesting_indices"])
        );
    }
}

#[test]
fn data_column_sidecar() {
    for (_case, bytes, v) in cases_for("DataColumnSidecar") {
        let buf = bytes.as_slice();
        let sbh = &v["signed_block_header"];
        let m = &sbh["message"];

        assert_eq!(DataColumnSidecarView::index(buf), u(&v["index"]));
        assert_eq!(DataColumnSidecarView::slot(buf), u(&m["slot"]));
        assert_eq!(DataColumnSidecarView::proposer_index(buf), u(&m["proposer_index"]));
        assert_eq!(*DataColumnSidecarView::parent_root(buf), b32(&m["parent_root"]));
        assert_eq!(*DataColumnSidecarView::state_root(buf), b32(&m["state_root"]));
        assert_eq!(*DataColumnSidecarView::body_root(buf), b32(&m["body_root"]));
        assert_eq!(*DataColumnSidecarView::block_signature(buf), b96(&sbh["signature"]));
        let inc_proof = hex_list_concat(&v["kzg_commitments_inclusion_proof"], 32);
        assert_eq!(inc_proof.len(), 128);
        assert_eq!(DataColumnSidecarView::inclusion_proof(buf)[..], inc_proof[..]);

        // Variable: column is a List[Cell=2048B]; kzg_commitments / kzg_proofs are
        // Lists of 48B.
        assert_eq!(
            DataColumnSidecarView::column(buf),
            hex_list_concat(&v["column"], BYTES_PER_CELL)
        );
        assert_eq!(
            DataColumnSidecarView::kzg_commitments(buf),
            hex_list_concat(&v["kzg_commitments"], BYTES_PER_KZG_COMMITMENT)
        );
        assert_eq!(
            DataColumnSidecarView::kzg_proofs(buf),
            hex_list_concat(&v["kzg_proofs"], BYTES_PER_KZG_PROOF)
        );
    }
}

#[test]
fn data_columns_by_root_identifier() {
    for (_case, bytes, v) in cases_for("DataColumnsByRootIdentifier") {
        let buf = bytes.as_slice();
        assert_eq!(*DataColumnsByRootIdentifierView::block_root(buf), b32(&v["block_root"]));
        // columns: List[ColumnIndex (u64)]; raw bytes == LE concatenation.
        assert_eq!(DataColumnsByRootIdentifierView::columns(buf), u64_list_le(&v["columns"]));
    }
}
