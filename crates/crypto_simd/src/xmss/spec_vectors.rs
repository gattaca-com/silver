//! EthLib's leanXMSS vectors, fetched by `make -C crates/crypto_simd`. An
//! output of `null` marks an input EthLib rejects; here those have the wrong
//! length, so they never fit the fixed-size arrays and are checked to expect
//! `null`.

use std::collections::HashMap;

use crate::{
    spec_vectors::{field, hex_items, integers, suite},
    xmss::{
        BottomTree, HEIGHT, Item, SIGNATURE_LEN, SecretKey, get_public_key, leaf_index, verify,
        verify_batch,
    },
};

fn input<const N: usize>(data: &str, key: &str) -> Option<[u8; N]> {
    hex_items(field(data, key)).remove(0).try_into().ok()
}

fn output(data: &str) -> &str {
    field(data, "output").trim()
}

#[test]
fn key_gen_vectors() {
    for (name, data) in suite("xmss", "key_gen") {
        let expected = output(&data);
        match input::<32>(&data, "seed") {
            Some(seed) => assert_eq!(hex_items(expected), [get_public_key(&seed)], "{name}"),
            None => assert_eq!(expected, "null", "{name}"),
        }
    }
}

#[test]
fn sign_vectors() {
    let mut keys: HashMap<[u8; 32], (SecretKey, HashMap<u32, BottomTree>)> = HashMap::new();
    for (name, data) in suite("xmss", "sign") {
        let expected = output(&data);
        let idx = integers(field(&data, "leaf_index"))[0];
        let (Some(seed), Some(message), Ok(idx)) =
            (input::<32>(&data, "seed"), input::<32>(&data, "message"), u32::try_from(idx))
        else {
            assert_eq!(expected, "null", "{name}");
            continue;
        };
        let (key, bottoms) =
            keys.entry(seed).or_insert_with(|| (SecretKey::new(&seed), HashMap::new()));
        let bottom = bottoms.entry(idx >> HEIGHT).or_insert_with(|| key.bottom_tree(idx >> HEIGHT));
        let sig = key.sign(bottom, &message, idx);
        assert_eq!(hex_items(expected)[0], sig, "{name}");
    }
}

#[test]
fn verify_vectors() {
    let mut batch = Vec::new();
    for (name, data) in suite("xmss", "verify") {
        let expected = output(&data).to_owned();
        match (
            input::<32>(&data, "public_key"),
            input::<32>(&data, "message"),
            input::<SIGNATURE_LEN>(&data, "signature"),
        ) {
            (Some(pk), Some(message), Some(sig)) => {
                let idx = u64::from(leaf_index(&sig));
                assert_eq!(verify(&pk, idx, &message, &sig).to_string(), expected, "{name}");
                if expected == "true" {
                    assert!(!verify(&pk, idx + 1, &message, &sig), "{name} at the next leaf");
                    assert!(!verify(&pk, idx | 1 << 32, &message, &sig), "{name} past u32");
                }
                batch.push((name, pk, message, sig, expected));
            }
            _ => assert_eq!(expected, "null", "{name}"),
        }
    }

    // The same cases as one batch, and as every group size below `LANES`.
    let items: Vec<_> = batch
        .iter()
        .map(|(_, pk, message, sig, _)| Item {
            public_key: pk,
            leaf_index: u64::from(leaf_index(sig)),
            message,
            signature: sig,
        })
        .collect();
    for n in 1..=items.len() {
        let mut ok = vec![false; n];
        verify_batch(&items[..n], &mut ok);
        for (ok, (name, .., expected)) in ok.iter().zip(&batch) {
            assert_eq!(ok.to_string(), *expected, "{name} in a batch of {n}");
        }
    }
}

#[test]
fn signature_index_vectors() {
    for (name, data) in suite("xmss", "signature_index") {
        let expected = output(&data);
        match input::<SIGNATURE_LEN>(&data, "signature") {
            Some(sig) => {
                let idx = u32::from_le_bytes(sig[..4].try_into().unwrap());
                assert_eq!(idx.to_string(), expected, "{name}");
            }
            None => assert_eq!(expected, "null", "{name}"),
        }
    }
}
