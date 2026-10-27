use rand::{Rng, SeedableRng, rngs::StdRng};

use super::{AVX512_GROUP, hash_concat_many};

#[test]
fn hash_concat_many_matches_sha256() {
    let mut rng = StdRng::seed_from_u64(7);
    for n in (0..=3 * AVX512_GROUP + 1).chain([100, 1000, 4096 + 5]) {
        let pairs: Vec<_> = (0..2 * n).map(|_| rng.r#gen()).collect();
        let mut out = vec![[0u8; 32]; n];
        hash_concat_many(&mut out, &pairs);
        for (i, digest) in out.iter().enumerate() {
            let expected = sha2_const_stable::Sha256::new()
                .update(&pairs[2 * i])
                .update(&pairs[2 * i + 1])
                .finalize();
            assert_eq!(*digest, expected, "{n} pairs, pair {i}");
        }
    }
}
