//! Reference vectors from `ethereum/EthLib`, fetched by
//! `make -C crates/crypto_simd`. An expected error (`null`) counts as false.
//! Inputs with sizes incompatible with the Rust types cannot reach the
//! verifier; those vectors must expect an error.

use std::{fs, path::PathBuf};

use crate::{
    bls::COMPRESSED_LEN,
    kzg::{
        BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB,
        CellBatchVerifier, CellExtender, blst_ops::fr_from_bytes, challenge::Preimage,
        verify::Deduplicated,
    },
};

fn suite(name: &str) -> Vec<(String, String)> {
    let dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cryptography-specs-tests/kzg").join(name);
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
fn field<'a>(data: &'a str, key: &str) -> &'a str {
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

fn hex_items(text: &str) -> Vec<Vec<u8>> {
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

fn integers(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().unwrap())
        .collect()
}

fn fixed<const N: usize>(items: Vec<Vec<u8>>) -> Option<Vec<[u8; N]>> {
    items.into_iter().map(|item| item.try_into().ok()).collect()
}

#[test]
fn verify_cell_kzg_proof_batch_vectors() {
    let mut verifier = CellBatchVerifier::new();
    let mut unrepresentable = 0;
    for (name, data) in suite("verify_cell_kzg_proof_batch") {
        let expected = match field(&data, "output").trim() {
            "true" => Some(true),
            "false" => Some(false),
            "null" => None,
            other => panic!("{name}: output {other}"),
        };
        let commitments = fixed::<COMPRESSED_LEN>(hex_items(field(&data, "commitments")));
        let cells = fixed::<BYTES_PER_CELL>(hex_items(field(&data, "cells")));
        let proofs = fixed::<COMPRESSED_LEN>(hex_items(field(&data, "proofs")));
        let cell_indices = integers(field(&data, "cell_indices"));
        let (Some(commitments), Some(cells), Some(proofs)) = (commitments, cells, proofs) else {
            assert_eq!(expected, None, "{name}: an unrepresentable input must be an error");
            unrepresentable += 1;
            continue;
        };
        let got = verifier.verify(&commitments, &cell_indices, &cells, &proofs);
        assert_eq!(got, expected == Some(true), "{name}");
    }
    assert!(unrepresentable < 10, "most vectors reach the verifier: {unrepresentable} did not");
}

#[test]
fn challenge_vectors() {
    let mut preimage = Preimage::new();
    for (name, data) in suite("compute_verify_cell_kzg_proof_batch_challenge") {
        let commitments = fixed::<COMPRESSED_LEN>(hex_items(field(&data, "commitments"))).unwrap();
        let commitment_of_cell: Vec<usize> =
            integers(field(&data, "commitment_indices")).into_iter().map(|i| i as usize).collect();
        let cell_indices = integers(field(&data, "cell_indices"));
        let evaluations = hex_items(field(&data, "cosets_evals"));
        let cells: Vec<[u8; BYTES_PER_CELL]> = evaluations
            .chunks(BYTES_PER_CELL / BYTES_PER_FIELD_ELEMENT)
            .map(|cell| cell.concat().try_into().unwrap())
            .collect();
        let proofs = fixed::<COMPRESSED_LEN>(hex_items(field(&data, "proofs"))).unwrap();
        assert_eq!(cells.len(), cell_indices.len(), "{name}");
        let expected: [u8; 32] = hex_items(field(&data, "output")).remove(0).try_into().unwrap();
        let got =
            preimage.challenge(&commitments, &commitment_of_cell, &cell_indices, &cells, &proofs);
        assert_eq!(Some(got), fr_from_bytes(&expected), "{name}");
    }
}

/// The vectors list unique commitments and each cell's index into them.
/// Expanding them to one commitment per cell and deduplicating again must give
/// the same lists back, whenever the vector numbers commitments in
/// first-occurrence order and uses each of them.
#[test]
fn deduplication_reproduces_challenge_vectors() {
    let mut deduplicated = Deduplicated::default();
    let mut reproduced = 0;
    for (name, data) in suite("compute_verify_cell_kzg_proof_batch_challenge") {
        let commitments = fixed::<COMPRESSED_LEN>(hex_items(field(&data, "commitments"))).unwrap();
        let index_of_cell: Vec<usize> =
            integers(field(&data, "commitment_indices")).into_iter().map(|i| i as usize).collect();
        let per_cell: Vec<_> = index_of_cell.iter().map(|&i| commitments[i]).collect();
        deduplicated.fill(&per_cell);
        for (k, commitment) in per_cell.iter().enumerate() {
            assert_eq!(&deduplicated.unique[deduplicated.index_of_cell[k]], commitment, "{name}");
        }
        let mut next = 0;
        let first_occurrence = index_of_cell.iter().all(|&i| {
            let fresh = i == next;
            next += fresh as usize;
            i < next
        }) && next == commitments.len();
        if first_occurrence {
            assert_eq!(deduplicated.unique, commitments, "{name}");
            assert_eq!(deduplicated.index_of_cell, index_of_cell, "{name}");
            reproduced += 1;
        }
    }
    assert!(reproduced >= 8, "most vectors are in first-occurrence order: {reproduced}");
}

#[test]
fn compute_cells_vectors() {
    let mut extender = CellExtender::new();
    let mut cells = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
    let mut unrepresentable = 0;
    for (name, data) in suite("compute_cells") {
        let output = field(&data, "output");
        let expected =
            (output.trim() != "null").then(|| fixed::<BYTES_PER_CELL>(hex_items(output)).unwrap());
        let Some(blob) = fixed::<BYTES_PER_BLOB>(hex_items(field(&data, "blob"))) else {
            assert_eq!(expected, None, "{name}: an unrepresentable input must be an error");
            unrepresentable += 1;
            continue;
        };
        let accepted = extender.compute(&blob[0], &mut cells);
        assert_eq!(accepted, expected.is_some(), "{name}");
        if let Some(expected) = expected {
            assert!(cells[..] == expected[..], "{name}");
        }
    }
    assert!(unrepresentable < 4, "most vectors reach the extender: {unrepresentable} did not");
}
