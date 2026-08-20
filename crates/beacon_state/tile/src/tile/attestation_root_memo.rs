use rustc_hash::FxHashMap;
use silver_beacon_state_data::{B256, Slot};
use silver_common::ssz_view::ATTESTATION_DATA_SIZE;

use crate::{bls, counters::BeaconStateCounters, ssz_hash};

/// Honest gossip converges on 1-3 distinct AttestationData per slot and the
/// floor retains two slots; the rest is headroom. Adversarial distinct-value
/// spray past the cap only costs the recompute it would cost without a memo.
const MAX_ENTRIES: usize = 64;
const _: () = assert!(MAX_ENTRIES <= u64::BITS as usize);

struct Roots {
    data_root: B256,
    group: AttestationRootGroup,
    /// Signing root paired with the exact domain it was derived under: the
    /// attester domain changes across fork versions, so the cached root is
    /// served only when the caller's domain matches, else re-derived from
    /// `data_root`.
    signing: Option<(B256, B256)>,
}

/// Memo of `hash_attestation_data` + `compute_signing_root` keyed on the full
/// 128-byte AttestationData. Post-Electra all single attestations of a slot
/// share a handful of distinct values, so the ~10-compression derivation runs
/// once per value instead of once per message. Entries are admitted before
/// signature verification — harmless, since values are deterministic hashes
/// of the key and the cap bounds memory.
pub struct AttestationRootMemo {
    entries: FxHashMap<[u8; ATTESTATION_DATA_SIZE], Roots>,
    floor: Slot,
    free_groups: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttestationRootGroup(u8);

impl AttestationRootGroup {
    pub(crate) const COUNT: usize = MAX_ENTRIES;

    pub(crate) fn index(self) -> usize {
        usize::from(self.0)
    }

    #[cfg(test)]
    pub(crate) const fn for_test(index: u8) -> Self {
        Self(index)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootLookup {
    pub data_root: B256,
    pub signing_root: B256,
    pub group: Option<AttestationRootGroup>,
}

impl Default for AttestationRootMemo {
    fn default() -> Self {
        Self {
            entries: FxHashMap::with_capacity_and_hasher(MAX_ENTRIES, Default::default()),
            floor: 0,
            free_groups: u64::MAX,
        }
    }
}

impl AttestationRootMemo {
    /// Roots and a dense identity for memo-admitted `data` under the attester
    /// `domain`.
    pub fn roots(&mut self, data: &[u8; ATTESTATION_DATA_SIZE], domain: &B256) -> RootLookup {
        if let Some(entry) = self.entries.get_mut(data) {
            BeaconStateCounters::AttestationRootMemoHit.inc();
            let signing_root = match entry.signing {
                Some((cached_domain, signing_root)) if cached_domain == *domain => signing_root,
                _ => {
                    let signing_root = bls::compute_signing_root(&entry.data_root, domain);
                    entry.signing = Some((*domain, signing_root));
                    signing_root
                }
            };
            return RootLookup {
                data_root: entry.data_root,
                signing_root,
                group: Some(entry.group),
            };
        }

        BeaconStateCounters::AttestationRootMemoMiss.inc();
        let data_root = ssz_hash::hash_attestation_data(data);
        let signing_root = bls::compute_signing_root(&data_root, domain);
        let group = self.insert(data, data_root, Some((*domain, signing_root)));
        RootLookup { data_root, signing_root, group }
    }

    /// Data-root-only lookup for callers with no domain in hand (the aggregate
    /// coverage key precedes any state read); a later `roots` call fills in
    /// the signing half.
    pub fn data_root(&mut self, data: &[u8; ATTESTATION_DATA_SIZE]) -> B256 {
        if let Some(entry) = self.entries.get(data) {
            BeaconStateCounters::AttestationRootMemoHit.inc();
            return entry.data_root;
        }

        BeaconStateCounters::AttestationRootMemoMiss.inc();
        let data_root = ssz_hash::hash_attestation_data(data);
        self.insert(data, data_root, None);
        data_root
    }

    fn insert(
        &mut self,
        data: &[u8; ATTESTATION_DATA_SIZE],
        data_root: B256,
        signing: Option<(B256, B256)>,
    ) -> Option<AttestationRootGroup> {
        if slot_of(data) < self.floor {
            return None;
        }
        if self.entries.len() >= MAX_ENTRIES {
            BeaconStateCounters::AttestationRootMemoFull.inc();
            return None;
        }
        let index = self.free_groups.trailing_zeros() as u8;
        debug_assert!(usize::from(index) < MAX_ENTRIES);
        self.free_groups &= !(1u64 << index);
        let group = AttestationRootGroup(index);
        self.entries.insert(*data, Roots { data_root, group, signing });
        Some(group)
    }

    pub fn prune_before(&mut self, floor: Slot) {
        self.floor = floor;
        let free_groups = &mut self.free_groups;
        self.entries.retain(|data, roots| {
            let retain = slot_of(data) >= floor;
            if !retain {
                *free_groups |= 1u64 << roots.group.0;
            }
            retain
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
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

    fn assert_roots(
        memo: &mut AttestationRootMemo,
        d: &[u8; ATTESTATION_DATA_SIZE],
        domain: &B256,
    ) -> RootLookup {
        let lookup = memo.roots(d, domain);
        let (data_root, signing_root) = direct(d, domain);
        assert_eq!((lookup.data_root, lookup.signing_root), (data_root, signing_root));
        lookup
    }

    #[test]
    fn miss_then_hit_agree_with_direct() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 1);
        assert_roots(&mut memo, &d, &DOMAIN_A);
        assert_eq!(memo.len(), 1);
        assert_roots(&mut memo, &d, &DOMAIN_A);
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn varied_data_agrees_with_direct_on_miss_and_hit() {
        let mut memo = AttestationRootMemo::default();
        let mut inputs = Vec::new();
        for i in 0..24u8 {
            let mut d = data(7, i);
            d[8..16].copy_from_slice(&(i as u64).to_le_bytes()); // index
            d[48] = i.wrapping_mul(37); // source checkpoint byte
            d[127] = 0xFF - i; // last target-root byte
            inputs.push(d);
        }
        for d in &inputs {
            assert_roots(&mut memo, d, &DOMAIN_A);
        }
        assert_eq!(memo.len(), inputs.len());
        for d in &inputs {
            assert_roots(&mut memo, d, &DOMAIN_A);
        }
        assert_eq!(memo.len(), inputs.len());
    }

    #[test]
    fn data_root_lookup_then_roots_fills_signing() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 2);
        assert_eq!(memo.data_root(&d), direct(&d, &DOMAIN_A).0);
        assert_roots(&mut memo, &d, &DOMAIN_A);
        assert_eq!(memo.len(), 1);
        assert_eq!(memo.data_root(&d), direct(&d, &DOMAIN_A).0);
    }

    #[test]
    fn roots_then_data_root_reuses_entry() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 4);
        assert_roots(&mut memo, &d, &DOMAIN_A);
        assert_eq!(memo.data_root(&d), direct(&d, &DOMAIN_A).0);
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn repeated_data_keeps_group_and_signing_root() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 3);
        let first = memo.roots(&d, &DOMAIN_A);
        let repeated = memo.roots(&d, &DOMAIN_A);
        assert_eq!(repeated, first);
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn domain_change_never_serves_stale_signing_root() {
        let mut memo = AttestationRootMemo::default();
        let d = data(5, 3);
        let sr_a = memo.roots(&d, &DOMAIN_A);
        assert_roots(&mut memo, &d, &DOMAIN_B);
        assert_ne!(memo.roots(&d, &DOMAIN_B).signing_root, sr_a.signing_root);
        // Flipping back re-derives rather than serving DOMAIN_A's stale cache.
        assert_roots(&mut memo, &d, &DOMAIN_A);
        // Domain churn updates the entry in place, never grows the map.
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn cap_stops_inserts_but_still_computes() {
        let mut memo = AttestationRootMemo::default();
        for i in 0..MAX_ENTRIES {
            memo.roots(&data(5, i as u8), &DOMAIN_A);
        }
        assert_eq!(memo.len(), MAX_ENTRIES);

        let overflow = data(6, 0xFF);
        assert_eq!(assert_roots(&mut memo, &overflow, &DOMAIN_A).group, None);
        assert_eq!(memo.len(), MAX_ENTRIES);
        assert!(!memo.entries.contains_key(&overflow));

        // Capped-out values keep computing correctly on repeat misses.
        assert_roots(&mut memo, &overflow, &DOMAIN_A);
        assert_eq!(memo.data_root(&overflow), direct(&overflow, &DOMAIN_A).0);
    }

    #[test]
    fn same_slot_spray_is_bounded_by_cap() {
        let mut memo = AttestationRootMemo::default();
        for i in 0..1000u64 {
            let mut d = data(5, 0);
            d[24..32].copy_from_slice(&i.to_le_bytes());
            assert_roots(&mut memo, &d, &DOMAIN_A);
        }
        assert_eq!(memo.len(), MAX_ENTRIES);
    }

    #[test]
    fn prune_drops_expired_and_floors_inserts() {
        let mut memo = AttestationRootMemo::default();
        let old = data(4, 1);
        let kept = data(5, 1);
        memo.roots(&old, &DOMAIN_A);
        memo.roots(&kept, &DOMAIN_A);

        memo.prune_before(5);
        assert_eq!(memo.len(), 1);
        assert!(memo.entries.contains_key(&kept));

        // Below-floor values still compute correctly but are not re-admitted.
        assert_roots(&mut memo, &old, &DOMAIN_A);
        assert_eq!(memo.len(), 1);
    }

    #[test]
    fn prune_frees_capacity_for_new_slots() {
        let mut memo = AttestationRootMemo::default();
        for i in 0..MAX_ENTRIES {
            memo.roots(&data(5, i as u8), &DOMAIN_A);
        }
        let refused = data(6, 0);
        memo.roots(&refused, &DOMAIN_A);
        assert!(!memo.entries.contains_key(&refused));

        memo.prune_before(6);
        assert_eq!(memo.len(), 0);
        memo.roots(&refused, &DOMAIN_A);
        assert!(memo.entries.contains_key(&refused));
    }

    #[test]
    fn group_identity_is_stable_distinct_and_reused_after_prune() {
        let mut memo = AttestationRootMemo::default();
        let first = data(5, 1);
        let second = data(5, 2);
        let first_lookup = assert_roots(&mut memo, &first, &DOMAIN_A);
        let first_group = first_lookup.group.unwrap();
        let repeated = assert_roots(&mut memo, &first, &DOMAIN_A);
        assert_eq!(
            (repeated.group, repeated.signing_root),
            (Some(first_group), first_lookup.signing_root)
        );
        assert_ne!(assert_roots(&mut memo, &second, &DOMAIN_A).group, Some(first_group));

        memo.prune_before(6);
        let replacement = data(6, 3);
        assert_eq!(assert_roots(&mut memo, &replacement, &DOMAIN_A).group, Some(first_group));
    }

    #[test]
    fn slot_extraction_is_little_endian_prefix() {
        let mut memo = AttestationRootMemo::default();
        let d = data(0x0102030405060708, 0);
        memo.roots(&d, &DOMAIN_A);
        memo.prune_before(0x0102030405060708);
        assert_eq!(memo.len(), 1);
        memo.prune_before(0x0102030405060709);
        assert_eq!(memo.len(), 0);
    }
}
