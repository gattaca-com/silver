use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

use crate::{bls, ssz_hash};

/// Honest gossip converges on 1-3 distinct AttestationData per slot and the
/// floor retains two slots; the rest is headroom. Adversarial distinct-value
/// spray past the cap only costs the recompute it would cost without a memo.
const MAX_ENTRIES: usize = 64;

struct Roots {
    data_root: B256,
    /// Signing root paired with the exact domain it was derived under: the
    /// attester domain changes across fork versions, so the cached root is
    /// served only when the caller's domain matches, else re-derived from
    /// `data_root`.
    signing: Option<(B256, B256)>,
}

/// Memo of `hash_attestation_data` + `compute_signing_root` keyed on the full
/// 128-byte AttestationData. Post-Electra all single attestations of a slot
/// share a handful of distinct values, so the ~10-compression derivation runs
/// once per value instead of once per message.
pub struct AttestationRootMemo {
    entries: FxHashMap<[u8; ATTESTATION_DATA_SIZE], Roots>,
    floor: Slot,
}

impl Default for AttestationRootMemo {
    fn default() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            floor: 0,
        }
    }
}

impl AttestationRootMemo {
    /// `(data_root, signing_root)` for `data` under the attester `domain`.
    pub fn roots(&mut self, data: &[u8; ATTESTATION_DATA_SIZE], domain: &B256) -> (B256, B256) {
        if let Some(entry) = self.entries.get_mut(data) {
            let signing_root = match entry.signing {
                Some((cached_domain, signing_root)) if cached_domain == *domain => signing_root,
                _ => {
                    let signing_root = bls::compute_signing_root(&entry.data_root, domain);
                    entry.signing = Some((*domain, signing_root));
                    signing_root
                }
            };
            return (entry.data_root, signing_root);
        }

        let data_root = ssz_hash::hash_attestation_data(data);
        let signing_root = bls::compute_signing_root(&data_root, domain);
        self.insert(data, Roots { data_root, signing: Some((*domain, signing_root)) });
        (data_root, signing_root)
    }

    /// Data-root-only lookup for callers with no domain in hand (the aggregate
    /// coverage key precedes any state read); a later `roots` call fills in
    /// the signing half.
    pub fn data_root(&mut self, data: &[u8; ATTESTATION_DATA_SIZE]) -> B256 {
        if let Some(entry) = self.entries.get(data) {
            return entry.data_root;
        }

        let data_root = ssz_hash::hash_attestation_data(data);
        self.insert(data, Roots { data_root, signing: None });
        data_root
    }

    fn insert(&mut self, data: &[u8; ATTESTATION_DATA_SIZE], roots: Roots) {
        if slot_of(data) < self.floor || self.entries.len() >= MAX_ENTRIES {
            return;
        }
        self.entries.insert(*data, roots);
    }

    pub fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        self.entries.retain(|data, _| slot_of(data) >= floor);
    }
}

fn slot_of(data: &[u8; ATTESTATION_DATA_SIZE]) -> Slot {
    u64::from_le_bytes(data[..8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN_A: B256 = [0xA1; 32];
    const DOMAIN_B: B256 = [0xB2; 32];

    fn data(slot: Slot, tag: u8) -> [u8; ATTESTATION_DATA_SIZE] {
        let mut d = [0u8; ATTESTATION_DATA_SIZE];
        d[..8].copy_from_slice(&slot.to_le_bytes());
        d[16] = tag; // beacon_block_root[0]
        d
    }

    fn direct(d: &[u8; ATTESTATION_DATA_SIZE], domain: &B256) -> (B256, B256) {
        let data_root = ssz_hash::hash_attestation_data(d);
        (data_root, bls::compute_signing_root(&data_root, domain))
    }

    #[test]
    fn miss_then_hit_agree_with_direct() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 1);
        assert_eq!(memo.roots(&d, &DOMAIN_A), direct(&d, &DOMAIN_A));
        assert_eq!(memo.entries.len(), 1);
        assert_eq!(memo.roots(&d, &DOMAIN_A), direct(&d, &DOMAIN_A));
        assert_eq!(memo.entries.len(), 1);
    }

    #[test]
    fn data_root_lookup_then_roots_fills_signing() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 2);
        assert_eq!(memo.data_root(&d), direct(&d, &DOMAIN_A).0);
        assert_eq!(memo.roots(&d, &DOMAIN_A), direct(&d, &DOMAIN_A));
        assert_eq!(memo.entries.len(), 1);
        assert_eq!(memo.data_root(&d), direct(&d, &DOMAIN_A).0);
    }

    #[test]
    fn domain_change_never_serves_stale_signing_root() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 3);
        let (_, sr_a) = memo.roots(&d, &DOMAIN_A);
        assert_eq!(memo.roots(&d, &DOMAIN_B), direct(&d, &DOMAIN_B));
        assert_ne!(memo.roots(&d, &DOMAIN_B).1, sr_a);
        // Flipping back re-derives rather than serving DOMAIN_A's stale cache.
        assert_eq!(memo.roots(&d, &DOMAIN_A), direct(&d, &DOMAIN_A));
    }

    #[test]
    fn cap_stops_inserts_but_still_computes() {
        let mut memo = AttestationRootMemo::default();
        for i in 0..MAX_ENTRIES {
            memo.roots(&data(5, i as u8), &DOMAIN_A);
        }
        assert_eq!(memo.entries.len(), MAX_ENTRIES);

        let overflow = data(6, 0xFF);
        assert_eq!(memo.roots(&overflow, &DOMAIN_A), direct(&overflow, &DOMAIN_A));
        assert_eq!(memo.entries.len(), MAX_ENTRIES);
        assert!(!memo.entries.contains_key(&overflow));
    }

    #[test]
    fn prune_drops_expired_and_floors_inserts() {
        let mut memo = AttestationRootMemo::default();
        let old = data(4, 1);
        let kept = data(5, 1);
        memo.roots(&old, &DOMAIN_A);
        memo.roots(&kept, &DOMAIN_A);

        memo.prune_before(5);
        assert_eq!(memo.entries.len(), 1);
        assert!(memo.entries.contains_key(&kept));

        // Below-floor values still compute correctly but are not re-admitted.
        assert_eq!(memo.roots(&old, &DOMAIN_A), direct(&old, &DOMAIN_A));
        assert_eq!(memo.entries.len(), 1);
    }
}
