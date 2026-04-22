//! Gossipsub message-id hashing (Altair+ rules).
//!
//! Spec: `consensus-specs/specs/altair/p2p-interface.md` §Topics and messages.
//! Per phase0/p2p-interface.md:403-404 clients MUST reject msg ids whose
//! length is not [`MESSAGE_ID_LEN`].

use std::{hash::Hasher, ops::Deref};

use ring::digest::{Context, SHA256};

/// 4-byte domain tag for successfully-decompressed snappy payloads.
pub const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// 4-byte domain tag for payloads that failed snappy decompression.
pub const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// Truncated SHA-256 output length used as the wire message-id.
pub const MESSAGE_ID_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(C)]
pub struct MessageId {
    pub id: [u8; MESSAGE_ID_LEN],
}

impl Deref for MessageId {
    type Target = [u8; MESSAGE_ID_LEN];

    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

/// Altair+ msg-id for a payload that snappy-decompressed cleanly. `topic` is
/// the full wire string `/eth2/{fork_digest_hex}/{name}/ssz_snappy`;
/// `decompressed` is the SSZ-encoded payload after snappy decompression.
#[inline]
pub fn msg_id_valid_snappy(topic: &str, decompressed: &[u8]) -> MessageId {
    hash_id(&MESSAGE_DOMAIN_VALID_SNAPPY, topic.as_bytes(), decompressed)
}

/// Altair+ msg-id for a payload that failed snappy decompression. `data` is
/// the raw (still compressed / corrupted) `Message.data` bytes.
#[inline]
pub fn msg_id_invalid_snappy(topic: &str, data: &[u8]) -> MessageId {
    hash_id(&MESSAGE_DOMAIN_INVALID_SNAPPY, topic.as_bytes(), data)
}

#[inline]
fn hash_id(domain: &[u8; 4], topic: &[u8], body: &[u8]) -> MessageId {
    let mut ctx = Context::new(&SHA256);
    ctx.update(domain);
    ctx.update(&(topic.len() as u64).to_le_bytes());
    ctx.update(topic);
    ctx.update(body);
    let digest = ctx.finish();
    let mut out = [0u8; MESSAGE_ID_LEN];
    out.copy_from_slice(&digest.as_ref()[..MESSAGE_ID_LEN]);
    MessageId { id: out }
}

// MessageId = [u8; 20] is already a SHA-256 truncation — skip re-hashing and
// take the first 8 bytes as the u64. `Hasher::write` is also invoked via
// `write_u64` when the hashed key is a plain u64 (e.g. the fast-dedup cache),
// so accept both 8- and 20-byte writes.
#[derive(Default)]
pub struct MessageIdHasher(u64);
impl Hasher for MessageIdHasher {
    fn write(&mut self, bytes: &[u8]) {
        debug_assert!(bytes.len() >= 8, "MessageIdHasher: write of <8 bytes");
        self.0 = u64::from_ne_bytes(bytes[..8].try_into().unwrap());
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

    #[test]
    fn deterministic() {
        let a = msg_id_valid_snappy(TOPIC, b"payload");
        let b = msg_id_valid_snappy(TOPIC, b"payload");
        assert_eq!(a, b);
    }

    #[test]
    fn domain_separates_valid_invalid() {
        // Same topic + same bytes must yield distinct ids across the two
        // domain tags — this is the whole point of the domain split.
        let v = msg_id_valid_snappy(TOPIC, b"same");
        let i = msg_id_invalid_snappy(TOPIC, b"same");
        assert_ne!(v, i);
    }

    #[test]
    fn topic_bound() {
        let a = msg_id_valid_snappy(TOPIC, b"x");
        let b = msg_id_valid_snappy("/eth2/deadbeef/beacon_block/ssz_snappy", b"x");
        assert_ne!(a, b);
    }

    #[test]
    fn known_vector() {
        // SHA256(0x01000000 || u64_le(0) || "" || "") truncated to 20 bytes.
        // Computed independently via:
        //   python3 -c 'import hashlib; print(hashlib.sha256(
        //       bytes([1,0,0,0]) + (0).to_bytes(8,"little")).hexdigest()[:40])'
        let id = msg_id_valid_snappy("", b"");
        let expected = hex_to_bytes("ca888f40c3caca805b37a5434c75de5550616e07");
        assert_eq!(id.deref(), expected.as_slice());
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
}
