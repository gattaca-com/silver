//! Timing, `cargo test --release --all-features xmss::bench -- --ignored
//! --nocapture`. Min over trials, a trial being `ITERS` calls; stops after a
//! second without a new min.

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use crate::xmss::{
    keccak::{keccak256, permutation},
    lanes::{LANES, Lanes, permutation_lanes},
};

const ITERS: u32 = 200;

fn min_ns<T>(mut f: impl FnMut() -> T) -> f64 {
    let mut best = f64::MAX;
    let mut since = Instant::now();
    while since.elapsed() < Duration::from_secs(1) {
        let start = Instant::now();
        for _ in 0..ITERS {
            black_box(f());
        }
        let ns = start.elapsed().as_nanos() as f64 / f64::from(ITERS);
        if ns < best {
            best = ns;
            since = Instant::now();
        }
    }
    best
}

fn report(what: &str, ns: f64) {
    eprintln!("{what:<32} {ns:>10.1} ns");
}

#[test]
#[ignore]
fn keccak() {
    let mut state = [0u64; 25];
    // A/A: the same function twice gives the noise floor.
    report("permutation", min_ns(|| permutation(black_box(&mut state))));
    report("permutation (again)", min_ns(|| permutation(black_box(&mut state))));
    report("keccak256 64 bytes", min_ns(|| keccak256(black_box(&[7u8; 64]))));
    report("keccak256 80 bytes", min_ns(|| keccak256(black_box(&[7u8; 80]))));
    report("keccak256 960 bytes", min_ns(|| keccak256(black_box(&[7u8; 960]))));
    let mut lanes: Lanes = [[0u64; LANES]; 25];
    let per8 = min_ns(|| permutation_lanes(black_box(&mut lanes)));
    report("permutation x8", per8);
    report("permutation x8, per lane", per8 / LANES as f64);
    black_box((state, lanes));
}

#[cfg(feature = "spec_vectors")]
#[test]
#[ignore]
fn verify() {
    use crate::{
        spec_vectors::{field, hex_items, suite},
        xmss::{SIGNATURE_LEN, leaf_index, verify},
    };
    let (_, data) = suite("xmss", "verify")
        .into_iter()
        .find(|(name, _)| name == "verify_valid_known_answer")
        .unwrap();
    let pk: [u8; 32] = hex_items(field(&data, "public_key")).remove(0).try_into().unwrap();
    let message: [u8; 32] = hex_items(field(&data, "message")).remove(0).try_into().unwrap();
    let sig: [u8; SIGNATURE_LEN] =
        hex_items(field(&data, "signature")).remove(0).try_into().unwrap();
    let idx = u64::from(leaf_index(&sig));
    assert!(verify(&pk, idx, &message, &sig));
    report("verify (186 permutations)", min_ns(|| verify(&pk, idx, &message, &sig)));

    use crate::xmss::{Item, verify_batch};
    let items: Vec<_> = (0..8)
        .map(|_| Item { public_key: &pk, leaf_index: idx, message: &message, signature: &sig })
        .collect();
    let mut ok = [false; 8];
    for n in [1, 2, 4, 8] {
        let per_batch = min_ns(|| verify_batch(&items[..n], &mut ok[..n]));
        report(&format!("verify_batch of {n}, per signature"), per_batch / n as f64);
    }
    assert!(ok.iter().all(|&ok| ok));
}

// Builds the top tree and one bottom tree (~6 s), then times bottom-layer
// signing alone.
#[test]
#[ignore]
fn sign() {
    use crate::xmss::SecretKey;
    let key = SecretKey::new(&[0; 32]);
    let bottom = key.bottom_tree(0);
    let mut idx = 0u32;
    let mut message = [0u8; 32];
    // A fresh leaf and message each call: grinding cost is what varies.
    let ns = min_ns(|| {
        idx += 1;
        message[0] = idx as u8;
        key.sign(&bottom, &message, idx)
    });
    report("sign, bottom tree built (min)", ns);
    let start = Instant::now();
    for i in 0..64u32 {
        black_box(key.sign(&bottom, &[i as u8; 32], 1000 + i));
    }
    report("sign, bottom tree built (mean of 64)", start.elapsed().as_nanos() as f64 / 64.0);
}
