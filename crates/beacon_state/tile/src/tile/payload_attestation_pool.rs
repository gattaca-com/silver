use blst::min_pk::{AggregateSignature, Signature};
use silver_beacon_state_data::{B256, Slot};
use silver_common::ssz_view::{
    MAX_PAYLOAD_ATTESTATIONS, PAYLOAD_ATTESTATION_DATA_SIZE, PAYLOAD_ATTESTATION_SIZE,
};

use super::gossip::PTC_MASK_WORDS;

/// Verified payload attestation messages, aggregated per
/// `PayloadAttestationData`. A slot's PTC splits over at most four data
/// variants per block root, so the aggregates stay few.
#[derive(Default)]
pub(super) struct PayloadAttestationPool {
    aggregates: Vec<Aggregate>,
}

struct Aggregate {
    data: [u8; PAYLOAD_ATTESTATION_DATA_SIZE],
    positions: [u64; PTC_MASK_WORDS],
    signature: AggregateSignature,
}

impl PayloadAttestationPool {
    /// `signature` is one PTC member's, verified, over `data`; `positions`
    /// are every PTC position the member holds.
    pub fn insert(
        &mut self,
        block_root: &B256,
        slot: Slot,
        present: bool,
        da: bool,
        positions: &[u64; PTC_MASK_WORDS],
        signature: &Signature,
    ) {
        let data = encode_data(block_root, slot, present, da);
        // `get_indexed_payload_attestation` names a member once per position,
        // and the aggregate verifies against every naming.
        let namings = positions.iter().map(|word| word.count_ones()).sum::<u32>();
        debug_assert!(namings > 0, "a PTC member holds a position");
        let mut contribution = AggregateSignature::from_signature(signature);
        for _ in 1..namings {
            contribution.add_signature(signature, false).expect("no group check");
        }

        let Some(held) = self.aggregates.iter_mut().find(|aggregate| aggregate.data == data) else {
            self.aggregates.push(Aggregate {
                data,
                positions: *positions,
                signature: contribution,
            });
            return;
        };
        if held.positions.iter().zip(positions).any(|(held, new)| held & new != 0) {
            return;
        }
        held.signature.add_aggregate(&contribution);
        for (held, new) in held.positions.iter_mut().zip(positions) {
            *held |= new;
        }
    }

    /// Appends the SSZ `PayloadAttestation`s a block at `slot` on
    /// `parent_root` may carry: those of the slot before, on the parent.
    #[allow(dead_code)] // packed by the Gloas proposal path
    pub fn select(&self, parent_root: &B256, slot: Slot, out: &mut Vec<u8>) {
        let Some(attested_slot) = slot.checked_sub(1) else { return };
        let data = |present, da| encode_data(parent_root, attested_slot, present, da);
        let variants = [data(false, false), data(false, true), data(true, false), data(true, true)];
        let selected = self
            .aggregates
            .iter()
            .filter(|aggregate| variants.contains(&aggregate.data))
            .take(MAX_PAYLOAD_ATTESTATIONS);
        for aggregate in selected {
            out.reserve(PAYLOAD_ATTESTATION_SIZE);
            out.extend(aggregate.positions.iter().flat_map(|word| word.to_le_bytes()));
            out.extend_from_slice(&aggregate.data);
            out.extend_from_slice(&aggregate.signature.to_signature().to_bytes());
        }
    }

    pub fn prune_before(&mut self, slot: Slot) {
        self.aggregates.retain(|aggregate| slot_of(&aggregate.data) >= slot);
    }
}

fn encode_data(
    block_root: &B256,
    slot: Slot,
    present: bool,
    da: bool,
) -> [u8; PAYLOAD_ATTESTATION_DATA_SIZE] {
    let mut data = [0; PAYLOAD_ATTESTATION_DATA_SIZE];
    data[..32].copy_from_slice(block_root);
    data[32..40].copy_from_slice(&slot.to_le_bytes());
    data[40] = present as u8;
    data[41] = da as u8;
    data
}

fn slot_of(data: &[u8; PAYLOAD_ATTESTATION_DATA_SIZE]) -> Slot {
    u64::from_le_bytes(data[32..40].try_into().expect("eight bytes"))
}

#[cfg(test)]
mod tests {
    use blst::BLST_ERROR;
    use silver_common::ssz_view::{PAYLOAD_ATTESTATION_SIZE, PayloadAttestationView};

    use super::*;
    use crate::{bls::DST, test_signing::privkey};

    const ROOT: B256 = [3; 32];
    const MESSAGE: B256 = [9; 32];

    fn mask(positions: &[usize]) -> [u64; PTC_MASK_WORDS] {
        let mut mask = [0; PTC_MASK_WORDS];
        for &position in positions {
            mask[position / 64] |= 1 << (position % 64);
        }
        mask
    }

    fn signed(key: usize) -> Signature {
        privkey(key).sign(&MESSAGE, DST, &[])
    }

    fn selected(pool: &PayloadAttestationPool, parent: &B256, slot: Slot) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        pool.select(parent, slot, &mut out);
        out.chunks_exact(PAYLOAD_ATTESTATION_SIZE).map(<[u8]>::to_vec).collect()
    }

    /// The spec's indexed form names a member once per PTC position, so the
    /// aggregate verifies only with its pubkey repeated as often.
    #[test]
    fn a_member_signs_once_per_position_it_holds() {
        let mut pool = PayloadAttestationPool::default();
        pool.insert(&ROOT, 10, true, true, &mask(&[3, 70]), &signed(0));
        pool.insert(&ROOT, 10, true, true, &mask(&[5]), &signed(1));

        let [attestation] = &selected(&pool, &ROOT, 11)[..] else { panic!("one aggregate") };
        let attestation: &[u8; PAYLOAD_ATTESTATION_SIZE] = attestation[..].try_into().unwrap();
        assert_eq!(PayloadAttestationView::aggregation_bits(attestation)[..], {
            let bits: Vec<u8> = mask(&[3, 5, 70]).iter().flat_map(|w| w.to_le_bytes()).collect();
            bits
        });
        assert_eq!(*PayloadAttestationView::data(attestation), encode_data(&ROOT, 10, true, true));

        let signature =
            Signature::from_bytes(PayloadAttestationView::signature(attestation)).unwrap();
        let [first, second] = [privkey(0).sk_to_pk(), privkey(1).sk_to_pk()];
        let verify = |pubkeys: &[&_]| signature.fast_aggregate_verify(true, &MESSAGE, DST, pubkeys);
        assert_eq!(verify(&[&first, &first, &second]), BLST_ERROR::BLST_SUCCESS);
        assert_ne!(verify(&[&first, &second]), BLST_ERROR::BLST_SUCCESS);
    }

    #[test]
    fn a_counted_position_is_not_added_twice() {
        let mut pool = PayloadAttestationPool::default();
        pool.insert(&ROOT, 10, true, true, &mask(&[3]), &signed(0));
        pool.insert(&ROOT, 10, true, true, &mask(&[3]), &signed(1));
        let [attestation] = &selected(&pool, &ROOT, 11)[..] else { panic!("one aggregate") };
        let signature = Signature::from_bytes(PayloadAttestationView::signature(
            attestation[..].try_into().unwrap(),
        ))
        .unwrap();
        assert_eq!(
            signature.verify(true, &MESSAGE, DST, &[], &privkey(0).sk_to_pk(), true),
            BLST_ERROR::BLST_SUCCESS
        );
    }

    /// A block carries only the parent's attestations from the slot before,
    /// one aggregate per data variant.
    #[test]
    fn selection_takes_the_parent_slot_variants_until_pruned() {
        let mut pool = PayloadAttestationPool::default();
        for (n, (present, da)) in
            [(false, false), (false, true), (true, false), (true, true)].into_iter().enumerate()
        {
            pool.insert(&ROOT, 10, present, da, &mask(&[n]), &signed(0));
        }
        pool.insert(&[4; 32], 10, true, true, &mask(&[9]), &signed(0));
        pool.insert(&ROOT, 9, true, true, &mask(&[9]), &signed(0));

        assert_eq!(selected(&pool, &ROOT, 11).len(), MAX_PAYLOAD_ATTESTATIONS);
        assert_eq!(selected(&pool, &ROOT, 12).len(), 0, "not the slot before");

        pool.prune_before(10);
        assert_eq!(selected(&pool, &ROOT, 10).len(), 0, "slot 9 pruned");
        pool.prune_before(11);
        assert!(selected(&pool, &ROOT, 11).is_empty());
    }
}
