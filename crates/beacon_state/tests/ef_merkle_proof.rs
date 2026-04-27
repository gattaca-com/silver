#![cfg(feature = "ef_tests")]

use std::fs;

mod ef_common;

use ef_common::{snappy_decode, spec_tests_dir};
use silver_beacon_state::ssz_hash::{self, compute_zero_hashes, sha256};

#[test]
fn single_merkle_proof() {
    let base = spec_tests_dir()
        .join("tests/mainnet/fulu/merkle_proof/single_merkle_proof/BeaconBlockBody");
    let Ok(entries) = fs::read_dir(&base) else {
        eprintln!("merkle_proof: no test cases, skipping");
        return;
    };

    let mut pass = 0;
    let mut fail = 0;
    for entry in entries.flatten() {
        if !entry.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let dir = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();

        let object_path = dir.join("object.ssz_snappy");
        let proof_path = dir.join("proof.yaml");
        if !object_path.exists() || !proof_path.exists() {
            continue;
        }

        // Load object and compute its hash_tree_root.
        let body_ssz = snappy_decode(&object_path);
        let zh = compute_zero_hashes();
        let object_root = ssz_hash::hash_tree_root_body(&body_ssz, &zh);

        // Parse proof.yaml.
        let proof_yaml = fs::read_to_string(&proof_path).unwrap();
        let (leaf, leaf_index, branch) = parse_proof(&proof_yaml);

        // Verify: walk from leaf up the branch to reconstruct the root.
        let computed_root = compute_root_from_proof(&leaf, leaf_index, &branch);

        if computed_root == object_root {
            pass += 1;
        } else {
            fail += 1;
            eprintln!("{name}: root mismatch");
            eprintln!("  computed: {}", hex(&computed_root));
            eprintln!("  expected: {}", hex(&object_root));
        }
    }
    eprintln!("merkle_proof: {pass} passed, {fail} failed");
    assert_eq!(fail, 0, "merkle_proof: {fail} test(s) failed");
}

fn compute_root_from_proof(leaf: &[u8; 32], index: u64, branch: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *leaf;
    let mut idx = index;
    for sibling in branch {
        let mut buf = [0u8; 64];
        if idx % 2 == 0 {
            // Current is left child.
            buf[..32].copy_from_slice(&current);
            buf[32..].copy_from_slice(sibling);
        } else {
            // Current is right child.
            buf[..32].copy_from_slice(sibling);
            buf[32..].copy_from_slice(&current);
        }
        current = sha256(&buf);
        idx /= 2;
    }
    current
}

fn parse_proof(yaml: &str) -> ([u8; 32], u64, Vec<[u8; 32]>) {
    let mut leaf = [0u8; 32];
    let mut leaf_index = 0u64;
    let mut branch = Vec::new();
    let mut in_branch = false;

    for line in yaml.lines() {
        let trimmed = line.trim();
        if let Some(val) = trimmed.strip_prefix("leaf:") {
            leaf = parse_hex32(val.trim().trim_matches('\''));
        } else if let Some(val) = trimmed.strip_prefix("leaf_index:") {
            leaf_index = val.trim().parse().unwrap();
        } else if trimmed == "branch:" {
            in_branch = true;
        } else if in_branch && trimmed.starts_with("- '0x") {
            branch.push(parse_hex32(trimmed.trim_start_matches("- ").trim_matches('\'')));
        }
    }
    (leaf, leaf_index, branch)
}

fn parse_hex32(s: &str) -> [u8; 32] {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn hex(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
