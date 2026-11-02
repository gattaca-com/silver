use super::{
    BLST_ERROR, CheckedSignature, DST, G2_POINT_AT_INFINITY, PublicKey, SigBatch,
    test_keys::{pubkey_pk, sign},
    verify_one_checked,
};

#[test]
fn checked_signature_verdict_matches_blst() {
    let message = [31u8; 32];
    let other = [32u8; 32];
    let mut infinity = [0u8; 48];
    infinity[0] = 0xc0;
    let infinity = PublicKey::from_bytes(&infinity).unwrap();
    let valid = CheckedSignature::parse(&sign(0, &message)).unwrap();
    assert!(verify_one_checked(&pubkey_pk(0), &valid, &message));

    // Through the batch, each root is hashed once and then read from its cache.
    let mut batch = SigBatch::new();
    for key in [pubkey_pk(0), pubkey_pk(1), infinity] {
        for bytes in [sign(0, &message), sign(1, &message), G2_POINT_AT_INFINITY] {
            let signature = CheckedSignature::parse(&bytes).unwrap();
            for root in [message, other] {
                let previous = signature.into_sig().verify(false, &root, DST, &[], &key, false);
                let expected = previous == BLST_ERROR::BLST_SUCCESS;
                assert_eq!(verify_one_checked(&key, &signature, &root), expected);
                assert_eq!(batch.verify_one(&key, &signature, &root), expected);
            }
        }
    }
    let signature = CheckedSignature::parse(&G2_POINT_AT_INFINITY).unwrap();
    assert!(!verify_one_checked(&infinity, &signature, &message));
}
