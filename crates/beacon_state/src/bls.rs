use blst::{
    BLST_ERROR,
    min_pk::{AggregatePublicKey, PublicKey, Signature},
};

use crate::{
    shuffling::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO},
    ssz_hash::{self, hash_tree_root_block_header},
    types::{
        self, B256, BLSPubkey, BeaconBlockHeader, Epoch, Fork, Immutable, SLOTS_PER_EPOCH,
        ValidatorIdentity,
    },
};

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Compute the 32-byte domain for a given domain type, fork version, and
/// genesis validators root.
/// domain[0..4] = domain_type LE, domain[4..32] = fork_data_root[0..28].
fn compute_domain(
    domain_type: u32,
    fork_version: [u8; 4],
    genesis_validators_root: B256,
    zh: &[B256],
) -> B256 {
    // ForkData: current_version(4B padded to 32) + genesis_validators_root(32B).
    let mut version_chunk = [0u8; 32];
    version_chunk[..4].copy_from_slice(&fork_version);
    let fork_data_root = ssz_hash::merkleize(&[version_chunk, genesis_validators_root], zh);

    let mut domain = [0u8; 32];
    domain[0..4].copy_from_slice(&domain_type.to_le_bytes());
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

/// Compute signing root = hash_tree_root(SigningData { object_root, domain }).
/// SigningData is a 2-field container → hash_concat(object_root, domain).
fn compute_signing_root(object_root: B256, domain: B256, zh: &[B256]) -> B256 {
    ssz_hash::merkleize(&[object_root, domain], zh)
}

/// Get the fork version for a given epoch from the Fork struct.
fn get_fork_version(fork: &Fork, epoch: Epoch) -> [u8; 4] {
    if epoch < fork.epoch { fork.previous_version } else { fork.current_version }
}

/// Verify the proposer's BLS signature on a signed beacon block.
/// `block_bytes` is the full SignedBeaconBlock SSZ.
#[allow(clippy::too_many_arguments)]
pub fn verify_block_signature(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    block_bytes: &[u8],
    block_slot: u64,
    proposer_index: u64,
    body_root: B256,
    zh: &[B256],
) -> bool {
    if block_bytes.len() < 184 {
        return false;
    }

    let vi = proposer_index as usize;
    if vi >= vid.validator_cnt {
        return false;
    }

    let sig_bytes = &block_bytes[4..100];
    let parent_root: B256 = block_bytes[116..148].try_into().unwrap();
    let state_root: B256 = block_bytes[148..180].try_into().unwrap();

    let header =
        BeaconBlockHeader { slot: block_slot, proposer_index, parent_root, state_root, body_root };
    let object_root = hash_tree_root_block_header(&header, zh);

    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    let fork_version = get_fork_version(&imm.fork, block_epoch);
    let domain =
        compute_domain(DOMAIN_BEACON_PROPOSER, fork_version, imm.genesis_validators_root, zh);
    let signing_root = compute_signing_root(object_root, domain, zh);

    verify_signature(&vid.val_pubkey[vi], sig_bytes, &signing_root)
}

/// Verify the RANDAO reveal signature.
/// The message is the epoch (uint64), signed by the proposer.
pub fn verify_randao_reveal(
    imm: &Immutable,
    vid: &ValidatorIdentity,
    reveal: &[u8],
    block_slot: u64,
    proposer_index: u64,
    zh: &[B256],
) -> bool {
    let vi = proposer_index as usize;
    if vi >= vid.validator_cnt || reveal.len() != 96 {
        return false;
    }

    let block_epoch = block_slot / SLOTS_PER_EPOCH;
    // Message = hash_tree_root(epoch). Epoch is a uint64 → 32-byte LE-padded chunk.
    let mut epoch_chunk = [0u8; 32];
    epoch_chunk[..8].copy_from_slice(&block_epoch.to_le_bytes());

    let fork_version = get_fork_version(&imm.fork, block_epoch);
    let domain = compute_domain(DOMAIN_RANDAO, fork_version, imm.genesis_validators_root, zh);
    let signing_root = compute_signing_root(epoch_chunk, domain, zh);

    verify_signature(&vid.val_pubkey[vi], reveal, &signing_root)
}

/// Aggregate an array of BLS pubkeys into a single pubkey
/// (eth_aggregate_pubkeys). Returns all-zeros if any key is invalid.
pub fn aggregate_pubkeys(pubkeys: &[BLSPubkey; types::SYNC_COMMITTEE_SIZE]) -> BLSPubkey {
    let mut iter = pubkeys.iter();
    let Some(first_bytes) = iter.next() else { return [0u8; 48] };
    let Ok(first_pk) = PublicKey::from_bytes(first_bytes) else { return [0u8; 48] };
    let mut agg = AggregatePublicKey::from_public_key(&first_pk);
    for pk_bytes in iter {
        let Ok(pk) = PublicKey::from_bytes(pk_bytes) else { return [0u8; 48] };
        if agg.add_public_key(&pk, true).is_err() {
            return [0u8; 48];
        }
    }
    agg.to_public_key().to_bytes()
}

/// Verify a deposit BLS signature (proof of possession).
pub fn verify_deposit_signature(
    pubkey_bytes: &[u8; 48],
    sig_bytes: &[u8; 96],
    message: &B256,
) -> bool {
    verify_signature(pubkey_bytes, sig_bytes, message)
}

fn verify_signature(pubkey_bytes: &BLSPubkey, sig_bytes: &[u8], message: &B256) -> bool {
    let pk = match PublicKey::from_bytes(pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    let sig = match Signature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig.verify(true, message, DST, &[], &pk, true) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use blst::min_pk::SecretKey;

    use super::*;

    // Spec test private keys (from
    // consensus-specs/tests/core/.../bls/constants.py).
    const PRIVKEY_HEX: [&str; 3] = [
        "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
    ];

    fn privkey(idx: usize) -> SecretKey {
        let bytes = hex_to_bytes(PRIVKEY_HEX[idx]);
        SecretKey::from_bytes(&bytes).unwrap()
    }

    fn pubkey(idx: usize) -> BLSPubkey {
        let sk = privkey(idx);
        let pk = sk.sk_to_pk();
        let b = pk.to_bytes();
        b
    }

    fn sign(sk_idx: usize, message: &[u8]) -> [u8; 96] {
        let sk = privkey(sk_idx);
        let sig = sk.sign(message, DST, &[]);
        sig.to_bytes()
    }

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).unwrap();
            out[i] = u8::from_str_radix(s, 16).unwrap();
        }
        out
    }

    #[test]
    fn single_signature_valid() {
        let pk = pubkey(0);
        let message = [0x00u8; 32];
        let sig = sign(0, &message);

        assert!(verify_signature(&pk, &sig, &message));
    }

    #[test]
    fn zero_signature_rejected() {
        let pk = pubkey(0);
        let message = [0x00u8; 32];
        let zero_sig = [0u8; 96];
        assert!(!verify_signature(&pk, &zero_sig, &message));
    }

    #[test]
    fn zero_pubkey_rejected() {
        let zero_pk = [0u8; 48];
        let message = [0x00u8; 32];
        let sig = sign(0, &message);
        assert!(!verify_signature(&zero_pk, &sig, &message));
    }
}
