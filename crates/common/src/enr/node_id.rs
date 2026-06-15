// Adapted from https://github.com/sigp/enr (MIT License)

use secp256k1::{
    Error as KeyError, PublicKey,
    hashes::{Hash, sha256},
};
use serde::{Deserialize, Serialize};

use super::{Enr, digest, keys};
use crate::PeerId;

type RawNodeId = [u8; 32];

/// Number of custody groups, per consensus-specs/fulu/das-core.md. The
/// custody bitmask returned by [`NodeId::custody_groups`] uses one bit
/// per group, so this MUST be ≤ 128 for the `u128` return type to fit.
pub const NUMBER_OF_CUSTODY_GROUPS: u8 = 128;

/// Minimum samples per slot, per consensus-specs/fulu/das-core.md. Silver
/// floors `custody_group_count` at this so the custody set always covers the
/// full sample set (`sampling_size = max(SAMPLES_PER_SLOT, cgc)`), removing
/// the need for beyond-custody sampling.
pub const SAMPLES_PER_SLOT: u8 = 8;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId {
    #[serde(with = "serde_hex_prfx")]
    raw: RawNodeId,
}

impl NodeId {
    pub const fn new(raw_input: &[u8; 32]) -> Self {
        Self { raw: *raw_input }
    }

    pub fn random() -> Self {
        Self { raw: rand::random() }
    }

    pub const fn raw(&self) -> RawNodeId {
        self.raw
    }

    /// Deterministic custody-group set for this node, given the count of
    /// groups to custody. Returns a 128-bit mask where bit `g` is set iff
    /// the node is responsible for custody group `g`. Per
    /// consensus-specs/fulu/das-core.md `get_custody_groups`.
    ///
    /// `count == NUMBER_OF_CUSTODY_GROUPS` short-circuits to `u128::MAX`
    /// (supernode). Panics if `count` exceeds `NUMBER_OF_CUSTODY_GROUPS`.
    pub fn custody_groups(&self, count: u8) -> u128 {
        assert!(count <= NUMBER_OF_CUSTODY_GROUPS, "count > NUMBER_OF_CUSTODY_GROUPS");

        if count == NUMBER_OF_CUSTODY_GROUPS {
            return u128::MAX;
        }

        // `current` holds the spec's `current_id` as a 256-bit big-endian
        // integer (which matches the natural byte order of NodeId.raw).
        // Hashing input is the little-endian serialisation of that
        // integer; collisions reroll by incrementing `current` with wrap.
        let mut current = self.raw;
        let mut mask: u128 = 0;
        let mut chosen: u8 = 0;
        while chosen < count {
            let mut le = current;
            le.reverse();
            let h = sha256::Hash::hash(&le);
            let prefix = u64::from_le_bytes(h.as_byte_array()[..8].try_into().unwrap());
            let group = (prefix % NUMBER_OF_CUSTODY_GROUPS as u64) as u8;
            let bit = 1u128 << group;
            if mask & bit == 0 {
                mask |= bit;
                chosen += 1;
            }
            // current += 1 with 256-bit wrap. Least-significant byte is
            // the last byte in big-endian storage; carry propagates up.
            for byte in current.iter_mut().rev() {
                let (next, carry) = byte.overflowing_add(1);
                *byte = next;
                if !carry {
                    break;
                }
            }
        }
        mask
    }
}

impl<'a> From<&'a NodeId> for NodeId {
    fn from(id: &'a NodeId) -> Self {
        *id
    }
}

impl From<PublicKey> for NodeId {
    fn from(public_key: PublicKey) -> Self {
        Self::new(&digest(&keys::encode_uncompressed(&public_key)))
    }
}

impl From<Enr> for NodeId {
    fn from(enr: Enr) -> Self {
        enr.node_id()
    }
}

impl From<&Enr> for NodeId {
    fn from(enr: &Enr) -> Self {
        enr.node_id()
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.raw[..]
    }
}

impl PartialEq<RawNodeId> for NodeId {
    fn eq(&self, other: &RawNodeId) -> bool {
        self.raw.eq(other)
    }
}

impl From<RawNodeId> for NodeId {
    fn from(raw: RawNodeId) -> Self {
        Self { raw }
    }
}

impl TryFrom<&[u8]> for NodeId {
    type Error = &'static str;

    fn try_from(raw_input: &[u8]) -> Result<Self, Self::Error> {
        raw_input.try_into().map(Self::new).map_err(|_| "NodeId must be exactly 32 bytes")
    }
}

impl TryFrom<&PeerId> for NodeId {
    type Error = KeyError;

    fn try_from(value: &PeerId) -> Result<Self, Self::Error> {
        Ok(PublicKey::from_slice(value.pubkey())?.into())
    }
}

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let hex_encode = hex::encode(self.raw);
        write!(f, "0x{}..{}", &hex_encode[0..4], &hex_encode[hex_encode.len() - 4..])
    }
}

impl std::fmt::Debug for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{}", hex::encode(self.raw))
    }
}

/// Serialize with the 0x prefix.
mod serde_hex_prfx {

    pub fn serialize<T: AsRef<[u8]> + hex::ToHex, S: serde::Serializer>(
        data: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let dst = format!("0x{}", hex::encode(data));
        serializer.serialize_str(&dst)
    }

    /// Deserialize with the 0x prefix.
    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::Deserializer<'de>,
        T: hex::FromHex,
        <T as hex::FromHex>::Error: std::fmt::Display,
    {
        /// Helper struct to obtain a owned string when necessary (using
        /// [`serde_json`], for example) or a borrowed string with the
        /// appropriate lifetime (most the time).
        // NOTE: see https://github.com/serde-rs/serde/issues/1413#issuecomment-494892266 and
        // https://github.com/sigp/enr/issues/62
        #[derive(serde::Deserialize)]
        struct CowNodeId<'a>(#[serde(borrow)] std::borrow::Cow<'a, str>);

        let CowNodeId::<'de>(raw) = serde::Deserialize::deserialize(deserializer)?;

        let src = raw.strip_prefix("0x").unwrap_or(&raw);
        hex::FromHex::from_hex(src).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_node_raw_node() {
        let node = NodeId::random();
        let raw = node.raw;
        assert_eq!(node, raw);
        assert_eq!(node.as_ref(), &raw[..]);
    }

    #[test]
    fn test_serde_str() {
        let node = NodeId::random();
        let json_string = serde_json::to_string(&node).unwrap();
        assert_eq!(node, serde_json::from_str::<NodeId>(&json_string).unwrap());
    }

    #[test]
    fn test_serde_slice() {
        let node = NodeId::random();
        let json_bytes = serde_json::to_vec(&node).unwrap();
        assert_eq!(node, serde_json::from_slice::<NodeId>(&json_bytes).unwrap());
    }

    #[test]
    fn test_serde_value() {
        let node = NodeId::random();
        let value = serde_json::to_value(node).unwrap();
        assert_eq!(node, serde_json::from_value::<NodeId>(value).unwrap());
    }

    #[test]
    fn test_serde_0x() {
        let raw = [
            154, 95, 80, 100, 224, 32, 222, 137, 157, 219, 197, 24, 45, 143, 90, 106, 99, 12, 9,
            93, 44, 66, 196, 203, 35, 233, 26, 59, 50, 128, 168, 180,
        ];
        let node = NodeId::new(&raw);
        let json_string = serde_json::to_string(&node).unwrap();
        assert_eq!(
            json_string,
            "\"0x9a5f5064e020de899ddbc5182d8f5a6a630c095d2c42c4cb23e91a3b3280a8b4\""
        );
        let snode = serde_json::from_str::<NodeId>(&json_string).unwrap();
        assert_eq!(node, snode);
    }

    #[test]
    fn test_serde_as_hashmap_key() {
        use std::collections::HashMap;

        let mut responses: HashMap<NodeId, u8> = HashMap::default();
        responses.insert(NodeId::random(), 1);
        let _ = serde_json::json!(responses);
    }

    // ---- custody_groups ----

    #[test]
    fn custody_groups_zero_is_empty() {
        let node = NodeId::random();
        assert_eq!(node.custody_groups(0), 0);
    }

    #[test]
    fn custody_groups_full_is_all_ones() {
        // Short-circuit for `count == NUMBER_OF_CUSTODY_GROUPS`.
        let node = NodeId::random();
        assert_eq!(node.custody_groups(NUMBER_OF_CUSTODY_GROUPS), u128::MAX);
    }

    #[test]
    fn custody_groups_popcount_matches_count() {
        // Bitmask popcount must equal the requested count for any
        // sub-full request. Tests both the loop termination and the
        // duplicate-rejection logic.
        let node = NodeId::random();
        for count in [1, 4, 8, 16, 32, 64, 127] {
            let mask = node.custody_groups(count);
            assert_eq!(mask.count_ones(), count as u32, "count={count}");
        }
    }

    #[test]
    fn custody_groups_deterministic() {
        // Same input → same output, across two invocations.
        let raw = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0,
            0xd0, 0xe0, 0xf0, 0x01,
        ];
        let node = NodeId::new(&raw);
        assert_eq!(node.custody_groups(4), node.custody_groups(4));
        assert_eq!(node.custody_groups(64), node.custody_groups(64));
    }

    #[test]
    fn custody_groups_monotone_subset() {
        // The spec promises: get_custody_groups(node, x) ⊂
        // get_custody_groups(node, y) for x < y. Bitmask form: x & y == x.
        let node = NodeId::random();
        let small = node.custody_groups(4);
        let medium = node.custody_groups(16);
        let large = node.custody_groups(64);
        assert_eq!(small & medium, small, "4-group set ⊂ 16-group set");
        assert_eq!(medium & large, medium, "16-group set ⊂ 64-group set");
    }

    #[test]
    fn custody_groups_distinct_per_node() {
        // Two distinct nodes almost never produce identical custody
        // masks at non-trivial counts; a collision would indicate a
        // broken permutation. Use a moderate count so the probability of
        // accidental match is negligible.
        let a = NodeId::random();
        let mut b_raw = a.raw;
        b_raw[0] ^= 0x01;
        let b = NodeId::new(&b_raw);
        assert_ne!(a.custody_groups(16), b.custody_groups(16));
    }
}
