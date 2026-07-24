use super::*;

fn hex_b32(s: &str) -> B256 {
    assert_eq!(s.len(), 64);
    let b = s.as_bytes();
    let n = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!(),
        }
    };
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (n(b[i * 2]) << 4) | n(b[i * 2 + 1]);
    }
    out
}

/// Anchor against the spec-published zero-subtree roots.
#[test]
fn zero_hashes_match_spec() {
    assert_eq!(ZERO_HASHES[0], [0u8; 32]);
    let expected: &[(usize, &str)] = &[
        (1, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
        (2, "db56114e00fdd4c1f85c892bf35ac9a89289aaecb1ebd0a96cde606a748b5d71"),
        (3, "c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c"),
        (4, "536d98837f2dd165a55d5eeae91485954472d56f246df256bf3cae19352a123c"),
        (5, "9efde052aa15429fae05bad4d0b1d7c64da64d03d7a1854a588c2cb8430c0d30"),
        (6, "d88ddfeed400a8755596b21942c1497e114c302e6118290f91e6772976041fa1"),
        (7, "87eb0ddba57e35f6d286673802a4af5975e22506c7cf4c64bb6be5ee11527f2c"),
        (8, "26846476fd5fc54a5d43385167c95144f2643f533cc85bb9d16b782f8d7db193"),
        (9, "506d86582d252405b840018792cad2bf1259f1ef5aa5f887e13cb2f0094f51e1"),
        (10, "ffff0ad7e659772f9534c195c815efc4014ef1e1daed4404c06385d11192e92b"),
    ];
    for &(i, hex) in expected {
        assert_eq!(ZERO_HASHES[i], hex_b32(hex), "zh[{i}]");
    }
}

/// The inline fast path must match the general stack-machine merkleize for
/// every chunk count it handles (full power-of-two and padded alike).
#[test]
fn merkleize_inline_matches_stack_machine() {
    for n in 0..=40usize {
        let chunks: Vec<B256> = (0..n).map(|i| uint64_chunk(i as u64 + 1)).collect();
        let leaf_count = n.next_power_of_two().max(1);
        let expected = merkleize_padded(&chunks, leaf_count);
        assert_eq!(merkleize(&chunks), expected, "n={n}");
    }
}

#[test]
fn uint64_chunk_encoding() {
    let c = uint64_chunk(0x0102030405060708);
    assert_eq!(c[0], 0x08);
    assert_eq!(c[7], 0x01);
    assert_eq!(c[8..], [0u8; 24]);
}

/// Element: 28 bytes of 0xFF + 4-byte LE int. Matches spec's e(v).
fn e(v: u32) -> B256 {
    let mut chunk = [0xFF; 32];
    chunk[28..32].copy_from_slice(&v.to_le_bytes());
    chunk
}

fn z(i: usize) -> B256 {
    ZERO_HASHES[i]
}

fn h(a: B256, b: B256) -> B256 {
    hash_concat(&a, &b)
}

#[test]
fn spec_merkleize_vectors() {
    let cases: Vec<(usize, usize, B256)> = vec![
        (0, 0, z(0)),
        (0, 1, z(0)),
        (1, 1, e(0)),
        (0, 2, h(z(0), z(0))),
        (1, 2, h(e(0), z(0))),
        (2, 2, h(e(0), e(1))),
        (0, 4, h(h(z(0), z(0)), z(1))),
        (1, 4, h(h(e(0), z(0)), z(1))),
        (2, 4, h(h(e(0), e(1)), z(1))),
        (3, 4, h(h(e(0), e(1)), h(e(2), z(0)))),
        (4, 4, h(h(e(0), e(1)), h(e(2), e(3)))),
        (0, 8, h(h(h(z(0), z(0)), z(1)), z(2))),
        (1, 8, h(h(h(e(0), z(0)), z(1)), z(2))),
        (2, 8, h(h(h(e(0), e(1)), z(1)), z(2))),
        (3, 8, h(h(h(e(0), e(1)), h(e(2), z(0))), z(2))),
        (4, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), z(2))),
        (5, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), z(0)), z(1)))),
        (6, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(z(0), z(0))))),
        (7, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), z(0))))),
        (8, 8, h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7))))),
        (0, 16, h(h(h(h(z(0), z(0)), z(1)), z(2)), z(3))),
        (1, 16, h(h(h(h(e(0), z(0)), z(1)), z(2)), z(3))),
        (4, 16, h(h(h(h(e(0), e(1)), h(e(2), e(3))), z(2)), z(3))),
        (
            9,
            16,
            h(
                h(h(h(e(0), e(1)), h(e(2), e(3))), h(h(e(4), e(5)), h(e(6), e(7)))),
                h(h(h(e(8), z(0)), z(1)), z(2)),
            ),
        ),
    ];

    for (i, (count, limit, expected)) in cases.iter().enumerate() {
        let chunks: Vec<B256> = (0..*count as u32).map(e).collect();
        let limit_pow2 = if *limit == 0 { 1 } else { limit.next_power_of_two() };
        let result = merkleize_padded(&chunks, limit_pow2);
        assert_eq!(result, *expected, "case {i}: count={count} limit={limit}");
    }
}

/// Build a depth-D balanced Merkle tree over `leaves` (zero-padded to
/// 2^D), returning (root, per-leaf-proof-bytes). Each proof is D*32 bytes
/// of siblings ascending from leaf level.
fn build_tree(leaves: &[B256], depth: u32) -> (B256, Vec<Vec<u8>>) {
    let cap = 1usize << depth;
    assert!(leaves.len() <= cap);
    let mut level: Vec<B256> = leaves.to_vec();
    level.resize(cap, ZERO_HASH);

    let mut layers: Vec<Vec<B256>> = Vec::with_capacity(depth as usize + 1);
    layers.push(level);
    for _ in 0..depth {
        let prev = layers.last().unwrap();
        let mut next = Vec::with_capacity(prev.len() / 2);
        for pair in prev.chunks_exact(2) {
            next.push(hash_concat(&pair[0], &pair[1]));
        }
        layers.push(next);
    }
    let root = layers.last().unwrap()[0];

    let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(cap);
    for idx in 0..cap {
        let mut proof = Vec::with_capacity((depth as usize) * 32);
        for d in 0..depth as usize {
            let sib = (idx >> d) ^ 1;
            proof.extend_from_slice(&layers[d][sib]);
        }
        proofs.push(proof);
    }
    (root, proofs)
}

#[test]
fn merkle_branch_valid_at_every_leaf() {
    let depth: u32 = 4;
    let cap = 1usize << depth;
    let leaves: Vec<B256> = (0..cap as u32).map(e).collect();
    let (root, proofs) = build_tree(&leaves, depth);
    for i in 0..cap {
        assert!(is_valid_merkle_branch(&leaves[i], &proofs[i], depth, i as u64, &root));
    }
}

#[test]
fn merkle_branch_rejects_corrupted_proof() {
    let depth: u32 = 5;
    let leaves: Vec<B256> = (0..(1u32 << depth)).map(e).collect();
    let (root, proofs) = build_tree(&leaves, depth);
    let idx = 7usize;
    let mut bad = proofs[idx].clone();
    bad[0] ^= 0x01;
    assert!(!is_valid_merkle_branch(&leaves[idx], &bad, depth, idx as u64, &root));
}

#[test]
fn merkle_branch_rejects_wrong_root() {
    let depth: u32 = 3;
    let leaves: Vec<B256> = (0..(1u32 << depth)).map(e).collect();
    let (mut root, proofs) = build_tree(&leaves, depth);
    let idx = 2usize;
    root[0] ^= 0xFF;
    assert!(!is_valid_merkle_branch(&leaves[idx], &proofs[idx], depth, idx as u64, &root));
}

#[test]
fn merkle_branch_index_sensitive() {
    let depth: u32 = 3;
    let leaves: Vec<B256> = (0..(1u32 << depth)).map(e).collect();
    let (root, proofs) = build_tree(&leaves, depth);
    let idx = 3usize;
    assert!(is_valid_merkle_branch(&leaves[idx], &proofs[idx], depth, idx as u64, &root));
    assert!(!is_valid_merkle_branch(&leaves[idx], &proofs[idx], depth, (idx as u64) + 1, &root));
}

#[test]
fn variable_containers_rejects_malformed_offsets() {
    // Short input (< 4 bytes for the first offset): yields nothing, no panic.
    assert_eq!(variable_containers(&[0x08, 0x00]).count(), 0);
    // First offset overruns the data: yields nothing, no panic.
    assert_eq!(variable_containers(&[0x40, 0x00, 0x00, 0x00, 0xaa, 0xbb]).count(), 0);

    // Well-formed single-element list yields one element.
    let got: Vec<_> = variable_containers(&[0x04, 0x00, 0x00, 0x00, 0xaa]).collect();
    assert_eq!(got, vec![Some(&[0xaa][..])]);
}

#[test]
fn merkle_branch_rejects_short_branch() {
    let depth: u32 = 4;
    let leaf = e(0);
    let branch = vec![0u8; (depth as usize - 1) * 32];
    assert!(!is_valid_merkle_branch(&leaf, &branch, depth, 0, &ZERO_HASH));
}
