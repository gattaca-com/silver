use blst::min_pk::{PublicKey, SecretKey};

use super::DST;

/// Spec test private keys (consensus-specs/tests/core/.../bls/constants.py).
pub const PRIVKEY_HEX: [&str; 3] = [
    "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
    "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
    "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
];

/// Past the spec keys, the scalar `idx + 1`.
pub fn privkey(idx: usize) -> SecretKey {
    let mut scalar = [0u8; 32];
    match PRIVKEY_HEX.get(idx) {
        Some(hex) => {
            for (byte, pair) in scalar.iter_mut().zip(hex.as_bytes().chunks(2)) {
                *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
            }
        }
        None => scalar[24..].copy_from_slice(&(idx as u64 + 1).to_be_bytes()),
    }
    SecretKey::from_bytes(&scalar).unwrap()
}

pub fn pubkey_pk(idx: usize) -> PublicKey {
    privkey(idx).sk_to_pk()
}

pub fn sign(sk_idx: usize, message: &[u8]) -> [u8; 96] {
    privkey(sk_idx).sign(message, DST, &[]).to_bytes()
}
