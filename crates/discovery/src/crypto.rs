use aes_gcm::{Aes128Gcm, aead::KeyInit};
use flux::utils::ArrayVec;
use hkdf::Hkdf;
use secp256k1::{PublicKey, SECP256K1, SecretKey, ecdh::shared_secret_point, ecdsa::Signature};
use sha2::{Digest, Sha256};
use silver_common::NodeId;

pub const MAX_PACKET_SIZE: usize = 1280;

const KEY_AGREEMENT_INFO_PREFIX: &[u8] = b"discovery v5 key agreement";
const ID_SIGNATURE_PREFIX: &[u8] = b"discovery v5 identity proof";

pub type SessionCipher = Aes128Gcm;

pub fn make_cipher(key: &[u8; 16]) -> SessionCipher {
    Aes128Gcm::new_from_slice(key).expect("key is 16 bytes")
}

/// Static ECDH: scalar multiply `remote_pk` by `local_sk`, return compressed
/// point.
pub fn ecdh(remote_pk: &PublicKey, local_sk: &SecretKey) -> [u8; 33] {
    let xy = shared_secret_point(remote_pk, local_sk);
    let mut compressed = [0u8; 33];
    // Parity byte: 0x02 if y is even, 0x03 if odd.
    compressed[0] = if xy[63] & 1 == 0 { 0x02 } else { 0x03 };
    compressed[1..].copy_from_slice(&xy[..32]);
    compressed
}

/// HKDF-SHA256 key derivation per discv5 spec.
/// `first_id` = initiator, `second_id` = responder.
/// Returns `(initiator_key, recipient_key)`.
pub fn derive_session_keys(
    secret: &[u8],
    first_id: &NodeId,
    second_id: &NodeId,
    challenge_data: &[u8],
) -> ([u8; 16], [u8; 16]) {
    let mut info = [0u8; 90]; // 26 + 32 + 32
    info[..26].copy_from_slice(KEY_AGREEMENT_INFO_PREFIX);
    info[26..58].copy_from_slice(&first_id.raw());
    info[58..].copy_from_slice(&second_id.raw());

    let hk = Hkdf::<Sha256>::new(Some(challenge_data), secret);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).expect("32 bytes is valid HKDF output");

    let mut k1 = [0u8; 16];
    let mut k2 = [0u8; 16];
    k1.copy_from_slice(&okm[..16]);
    k2.copy_from_slice(&okm[16..]);
    (k1, k2)
}

/// Generate ephemeral keypair, ECDH with remote's permanent pubkey, derive
/// initiator session keys. Returns `(ephem_pk_bytes, initiator_key,
/// recipient_key)`.
pub fn ecdh_generate_and_derive(
    remote_pubkey: &[u8; 33],
    local_id: &NodeId,
    remote_id: &NodeId,
    challenge_data: &[u8],
) -> Option<([u8; 33], [u8; 16], [u8; 16])> {
    let remote_pk = PublicKey::from_slice(remote_pubkey).ok()?;
    let ephem_sk = SecretKey::new(&mut rand::thread_rng());
    let ephem_pk_bytes = ephem_sk.public_key(SECP256K1).serialize();
    let secret = ecdh(&remote_pk, &ephem_sk);
    let (initiator_key, recipient_key) =
        derive_session_keys(&secret, local_id, remote_id, challenge_data);
    Some((ephem_pk_bytes, initiator_key, recipient_key))
}

/// ECDH on responder side: local static key x peer's ephemeral pubkey.
/// Returns `(initiator_key, recipient_key)`.
pub fn ecdh_and_derive_keys_responder(
    local_sk: &SecretKey,
    ephem_pubkey: &[u8; 33],
    initiator_id: &NodeId,
    responder_id: &NodeId,
    challenge_data: &[u8],
) -> Option<([u8; 16], [u8; 16])> {
    let ephem_pk = PublicKey::from_slice(ephem_pubkey).ok()?;
    let secret = ecdh(&ephem_pk, local_sk);
    Some(derive_session_keys(&secret, initiator_id, responder_id, challenge_data))
}

pub fn sign_id_nonce(
    local_sk: &SecretKey,
    challenge_data: &[u8],
    ephem_pubkey: &[u8; 33],
    dst_id: &NodeId,
) -> Option<[u8; 64]> {
    let hash = Sha256::new()
        .chain_update(ID_SIGNATURE_PREFIX)
        .chain_update(challenge_data)
        .chain_update(ephem_pubkey)
        .chain_update(dst_id.raw())
        .finalize();
    let msg = secp256k1::Message::from_digest_slice(&hash).ok()?;
    let sig = SECP256K1.sign_ecdsa(&msg, local_sk);
    Some(sig.serialize_compact())
}

pub fn verify_id_nonce_sig(
    remote_pubkey: &[u8; 33],
    challenge_data: &[u8],
    ephem_pubkey: &[u8; 33],
    dst_id: &NodeId,
    sig: &[u8; 64],
) -> bool {
    let Ok(pk) = PublicKey::from_slice(remote_pubkey) else { return false };
    let Ok(signature) = Signature::from_compact(sig) else { return false };
    let hash = Sha256::new()
        .chain_update(ID_SIGNATURE_PREFIX)
        .chain_update(challenge_data)
        .chain_update(ephem_pubkey)
        .chain_update(dst_id.raw())
        .finalize();
    let Ok(msg) = secp256k1::Message::from_digest_slice(&hash) else { return false };
    SECP256K1.verify_ecdsa(&msg, &signature, &pk).is_ok()
}

pub fn encrypt_message(
    cipher: &SessionCipher,
    nonce: &[u8; 12],
    aad: &[u8],
    msg: &[u8],
) -> Option<ArrayVec<u8, MAX_PACKET_SIZE>> {
    use aes_gcm::aead::{Aead, Payload};
    let ct = cipher.encrypt(&(*nonce).into(), Payload { msg, aad }).ok()?;
    let mut out = ArrayVec::new();
    out.extend(ct.iter().copied());
    Some(out)
}

pub fn decrypt_message(
    cipher: &SessionCipher,
    nonce: &[u8; 12],
    aad: &[u8],
    msg: &[u8],
) -> Option<ArrayVec<u8, MAX_PACKET_SIZE>> {
    use aes_gcm::aead::{Aead, Payload};
    let pt = cipher.decrypt(&(*nonce).into(), Payload { msg, aad }).ok()?;
    let mut out = ArrayVec::new();
    out.extend(pt.iter().copied());
    Some(out)
}

#[cfg(test)]
mod tests {
    use silver_common::NodeId;

    use super::*;

    fn h(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn ecdh_matches_spec() {
        let sk = SecretKey::from_slice(&h(
            "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
        ))
        .unwrap();
        let remote_pk = PublicKey::from_slice(&h(
            "039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231",
        ))
        .unwrap();
        let expected = h("033b11a2a1f214567e1537ce5e509ffd9b21373247f2a3ff6841f4976f53165e7e");
        assert_eq!(ecdh(&remote_pk, &sk).as_slice(), expected.as_slice());
    }

    #[test]
    fn key_derivation_matches_spec() {
        let ephem_sk = SecretKey::from_slice(&h(
            "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
        ))
        .unwrap();
        let dest_pk = PublicKey::from_slice(&h(
            "0317931e6e0840220642f230037d285d122bc59063221ef3226b1f403ddc69ca91",
        ))
        .unwrap();
        let node_id_a = NodeId::new(
            &h("aaaa8419e9f49d0083561b48287df592939a8d19947d8c0ef88f2a4856a69fbb")
                .try_into()
                .unwrap(),
        );
        let node_id_b = NodeId::new(
            &h("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9")
                .try_into()
                .unwrap(),
        );
        let challenge_data = h(
            "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000",
        );

        let secret = ecdh(&dest_pk, &ephem_sk);
        let (ik, rk) = derive_session_keys(&secret, &node_id_a, &node_id_b, &challenge_data);

        assert_eq!(ik.as_slice(), h("dccc82d81bd610f4f76d3ebe97a40571").as_slice());
        assert_eq!(rk.as_slice(), h("ac74bb8773749920b0d3a8881c173ec5").as_slice());
    }

    #[test]
    fn id_nonce_sig_verifies_spec_vector() {
        let sk = SecretKey::from_slice(&h(
            "fb757dc581730490a1d7a00deea65e9b1936924caaea8f44d476014856b68736",
        ))
        .unwrap();
        let challenge_data = h(
            "000000000000000000000000000000006469736376350001010102030405060708090a0b0c00180102030405060708090a0b0c0d0e0f100000000000000000",
        );
        let ephem_pubkey: [u8; 33] =
            h("039961e4c2356d61bedb83052c115d311acb3a96f5777296dcf297351130266231")
                .try_into()
                .unwrap();
        let dst_id = NodeId::new(
            &h("bbbb9d047f0488c0b5a93c1c3f2d8bafc7c8ff337024a55434a0d0555de64db9")
                .try_into()
                .unwrap(),
        );
        let expected_sig: [u8; 64] = h("94852a1e2318c4e5e9d422c98eaf19d1d90d876b29cd06ca7cb7546d0fff7b484fe86c09a064fe72bdbef73ba8e9c34df0cd2b53e9d65528c2c7f336d5dfc6e6")
            .try_into()
            .unwrap();

        let static_pk = sk.public_key(SECP256K1).serialize();

        assert!(verify_id_nonce_sig(
            &static_pk,
            &challenge_data,
            &ephem_pubkey,
            &dst_id,
            &expected_sig
        ));

        let produced = sign_id_nonce(&sk, &challenge_data, &ephem_pubkey, &dst_id).unwrap();
        assert_eq!(produced, expected_sig);
    }

    #[test]
    fn aes_gcm_encrypt_matches_spec() {
        let key: [u8; 16] = h("9f2d77db7004bf8a1a85107ac686990b").try_into().unwrap();
        let nonce: [u8; 12] = h("27b5af763c446acd2749fe8e").try_into().unwrap();
        let pt = h("01c20101");
        let ad = h("93a7400fa0d6a694ebc24d5cf570f65d04215b6ac00757875e3f3a5f42107903");
        let expected_ct = h("a5d12a2d94b8ccb3ba55558229867dc13bfa3648");

        let cipher = make_cipher(&key);
        let ct = encrypt_message(&cipher, &nonce, &ad, &pt).unwrap();
        assert_eq!(ct.as_slice(), expected_ct.as_slice());

        let cipher2 = make_cipher(&key);
        let recovered = decrypt_message(&cipher2, &nonce, &ad, &ct).unwrap();
        assert_eq!(recovered.as_slice(), pt.as_slice());
    }
}
