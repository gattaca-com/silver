use std::time::Instant;

use super::{
    CHAIN, NODE, Secret, SecretKey, address, get_public_key, hi, th,
    tree::{Tree, fold},
    verify,
    wots::ots_leaf,
};

const SEED: [u8; 32] = [0; 32];

#[test]
fn address_layout() {
    // enc(1, 2, 0x8000ab, 0x01020304): LE32(lo) ∥ LE24(hi) ∥ LE8(τ + 32µ) ∥ 0^64.
    let a = address(CHAIN, 2, hi(1, 0xab), 0x01020304);
    assert_eq!(a, [4, 3, 2, 1, 0xab, 0, 0x80, 1 + 64, 0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn tree_root_matches_spec_formula() {
    let secret = Secret::new(&SEED);
    let leaves: [[u8; 16]; 4] = [[1; 16], [2; 16], [3; 16], [4; 16]];
    let tree = Tree::build(&secret.p, 1, 0, &leaves);

    let node = |level, j, l: &[u8; 16], r: &[u8; 16]| {
        let m: Vec<u8> = [l.as_slice(), r.as_slice()].concat();
        th(&secret.p, &address(NODE, 0, hi(1, level), j), &m)
    };
    let x10 = node(1, 0, &leaves[0], &leaves[1]);
    let x11 = node(1, 1, &leaves[2], &leaves[3]);
    assert_eq!(*tree.root(), node(2, 0, &x10, &x11));
}

#[test]
fn path_folds_to_root() {
    let secret = Secret::new(&SEED);
    let leaves: [[u8; 16]; 8] = std::array::from_fn(|i| [i as u8; 16]);
    let tree = Tree::build(&secret.p, 0, 0, &leaves);
    for e in 0..8 {
        let mut path = [[0u8; 16]; 3];
        tree.path(e, &mut path);
        assert_eq!(fold(&secret.p, 0, e, leaves[e as usize], &path), *tree.root(), "leaf {e}");
        assert_ne!(fold(&secret.p, 0, e ^ 1, leaves[e as usize], &path), *tree.root());
    }
}

#[test]
fn leaf_is_deterministic_and_distinct_per_key() {
    let secret = Secret::new(&SEED);
    assert_eq!(ots_leaf(&secret, 1, 7), ots_leaf(&secret, 1, 7));
    assert_ne!(ots_leaf(&secret, 1, 7), ots_leaf(&secret, 1, 8));
    assert_ne!(ots_leaf(&secret, 0, 7), ots_leaf(&secret, 1, 7));
}

// ~14M permutations; run with --release. Vectors from EthLib
// `tests/cryptography/xmss`.
#[test]
#[ignore]
fn public_key_full_tree() {
    let start = Instant::now();
    let pk = get_public_key(&SEED);
    eprintln!("get_public_key: {:?}", start.elapsed());
    assert_eq!(hex(&pk), "54622451a82ab400e3878419201f08be1fb401e26e452b3bd8362803470f2ae9");

    let seed = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let pk = get_public_key(&seed);
    assert_eq!(hex(&pk), "4066673001949b6ff8b9299fd4ea17d28787ad501aafe4b64e2488107b5e3ec3");
}

// Key generation, one bottom tree, two signatures: ~2 minutes in release.
#[test]
#[ignore]
fn sign_then_verify() {
    let key = SecretKey::new(&SEED);
    let pk = key.public_key();
    let bottom = key.bottom_tree(3);
    let message = [7u8; 32];
    let idx = 3 << 16 | 5;
    let sig = key.sign(&bottom, &message, idx);
    assert!(verify(&pk, u64::from(idx), &message, &sig));
    assert!(!verify(&pk, u64::from(idx) + 1, &message, &sig));
    assert!(!verify(&pk, u64::from(idx) + (1 << 32), &message, &sig));
    assert_eq!(sig, key.sign(&bottom, &message, idx), "deterministic");

    let mut wrong_message = message;
    wrong_message[0] ^= 1;
    assert!(!verify(&pk, u64::from(idx), &wrong_message, &sig));
    let mut moved = sig;
    moved[..4].copy_from_slice(&(idx + 1).to_le_bytes());
    assert!(!verify(&pk, u64::from(idx) + 1, &message, &moved));
    let mut tampered = sig;
    tampered[4 + 16] ^= 1;
    assert!(!verify(&pk, u64::from(idx), &message, &tampered));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
