use core::ptr;

use blst::{
    BLST_ERROR, MultiPoint, Pairing, blst_aggregated_in_g2, blst_fp12, blst_hash_to_g2, blst_p2,
    blst_p2_affine, blst_p2_to_affine,
};
use flux_profiler::timed;
use ring::rand::{SecureRandom, SystemRandom};
use silver_beacon_state_data::B256;

use super::{
    CheckedSignature, DST, G2_POINT_AT_INFINITY, PublicKey, Signature,
    aggregator::{PubkeyAggregator, pk_affine, sig_affine},
};

// N.B. batching is only safe where NBITS < 144-bit GLS threshold.
const NBITS: usize = 64;
const RAND_BYTES: usize = NBITS / 8;

pub struct SigBatch {
    msgs: Vec<B256>,
    pks: Vec<PublicKey>,
    sigs: Vec<Signature>,
    /// Per-tuple 64-bit random scalars, packed as little-endian bytes.
    /// Pre-allocated to `SIG_BATCH_CAP * 8`; resized (no realloc) per call.
    rand_bytes: Vec<u8>,
    /// Tuple indices sorted by message — equal-message runs become the
    /// pairing groups.
    order: Vec<u32>,
    /// `pks` / `rand_bytes` permuted into `order`, so each group is a
    /// contiguous slice for the multi-scalar mult.
    grouped_pks: Vec<PublicKey>,
    grouped_scalars: Vec<u8>,
    /// Multi-pairing accumulator.
    pairing: Pairing,
    aggregator: PubkeyAggregator,
    poisoned: bool,
}

/// Capacity for the per-block sig batch. Worst-case Fulu block envelope at
/// the spec's MAX_* limits: 1 (block) + 1 (randao) + 16×2 (proposer
/// slashings) + 1×2 (attester slashings) + 8 (attestations) + 16 (exits) +
/// 16 (bls_changes) + 1 (sync_aggregate) = 77. Round up.
const SIG_BATCH_CAP: usize = 128;

impl Default for SigBatch {
    fn default() -> Self {
        Self::new()
    }
}

impl SigBatch {
    pub fn new() -> Self {
        Self {
            msgs: Vec::with_capacity(SIG_BATCH_CAP),
            pks: Vec::with_capacity(SIG_BATCH_CAP),
            sigs: Vec::with_capacity(SIG_BATCH_CAP),
            rand_bytes: Vec::with_capacity(SIG_BATCH_CAP * RAND_BYTES),
            order: Vec::with_capacity(SIG_BATCH_CAP),
            grouped_pks: Vec::with_capacity(SIG_BATCH_CAP),
            grouped_scalars: Vec::with_capacity(SIG_BATCH_CAP * 8),
            pairing: Pairing::new(true, DST),
            aggregator: PubkeyAggregator::default(),
            poisoned: false,
        }
    }

    #[inline]
    pub fn poison(&mut self) {
        self.poisoned = true;
    }

    pub fn clear(&mut self) {
        self.msgs.clear();
        self.pks.clear();
        self.sigs.clear();
        self.rand_bytes.clear();
        self.poisoned = false;
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.msgs.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.msgs.is_empty()
    }

    pub fn push_one(&mut self, pubkey: &PublicKey, sig: &[u8; 96], signing_root: B256) {
        let Some(sig) = CheckedSignature::parse(sig) else {
            self.poisoned = true;
            return;
        };
        self.push_parsed(pubkey, sig, signing_root);
    }

    pub fn push_parsed(&mut self, pubkey: &PublicKey, sig: CheckedSignature, signing_root: B256) {
        self.msgs.push(signing_root);
        self.pks.push(*pubkey);
        self.sigs.push(*sig.as_sig());
    }

    pub fn push_aggregate<'a, I>(&mut self, participants: I, sig: &[u8; 96], signing_root: B256)
    where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        match self.aggregator.aggregate(participants) {
            Some(pk) => self.push_one(&pk, sig, signing_root),
            None => self.poisoned = true,
        }
    }

    /// Subtracts the missing members from the committee aggregates rather than
    /// summing every attester — see [`PubkeyAggregator::aggregate_subtracted`].
    /// Poisons when nobody attested.
    #[timed]
    pub fn push_aggregate_subtracted<'a>(
        &mut self,
        committees: impl IntoIterator<Item = &'a PublicKey>,
        missing: impl IntoIterator<Item = &'a PublicKey>,
        sig: &[u8; 96],
        signing_root: B256,
    ) {
        match self.aggregator.aggregate_subtracted(committees, missing) {
            Some(pk) => self.push_one(&pk, sig, signing_root),
            None => self.poisoned = true,
        }
    }

    /// Sync-aggregate semantics: empty participants accepted iff sig is
    /// G2 infinity. The empty-with-infinity case verifies trivially without
    /// pushing anything; non-infinity empty poisons the batch.
    pub fn push_eth_aggregate<'a, I>(
        &mut self,
        participant_count: usize,
        participants: I,
        sig: &[u8; 96],
        signing_root: B256,
    ) where
        I: IntoIterator<Item = &'a PublicKey>,
    {
        if participant_count == 0 {
            if *sig != G2_POINT_AT_INFINITY {
                self.poisoned = true;
            }
            return;
        }
        self.push_aggregate(participants, sig, signing_root);
    }

    /// Verify all collected entries.
    ///
    /// - 0 entries → trivially true.
    /// - 1 entry → single pre-aggregated verify (avoids the multi-pairing setup
    ///   cost for the common case of a single sig).
    /// - 2+ entries → grouped multi-pairing with random per-tuple scalars.
    #[timed]
    pub fn verify_all(&mut self) -> bool {
        if self.poisoned {
            return false;
        }
        match self.msgs.len() {
            0 => true,
            1 => {
                // No sig group check: entries enter via `CheckedSignature`.
                self.sigs[0].fast_aggregate_verify_pre_aggregated(
                    false,
                    &self.msgs[0],
                    DST,
                    &self.pks[0],
                ) == BLST_ERROR::BLST_SUCCESS
            }
            _ => self.verify_batch(),
        }
    }

    /// Verify each entry as an independent single-sig verify. Bench-only
    /// baseline for comparing against multi-pairing `verify_all` — pre-batch
    /// verification cost was N × ~1 ms; `verify_all` collapses that to one
    /// final exponentiation. Don't use on the hot path.
    pub fn verify_each_sequential(&self) -> bool {
        if self.poisoned {
            return false;
        }
        for ((pk, sig), msg) in self.pks.iter().zip(self.sigs.iter()).zip(self.msgs.iter()) {
            if sig.verify(true, msg, DST, &[], pk, false) != BLST_ERROR::BLST_SUCCESS {
                return false;
            }
        }
        true
    }

    /// Batch verify grouped by message: checks
    /// `Π_g e(Σ rᵢ·PKᵢ, H(m_g)) == e(G1, Σ rᵢ·sigᵢ)`.
    ///
    /// Gossip attestations share `AttestationData` across a slot's
    /// committees, so a full batch typically carries a handful of distinct
    /// signing roots — hash-to-G2 and the Miller loop scale with distinct
    /// messages, leaving one 64-bit scalar mult per tuple and side.
    ///
    /// Random per-tuple scalars defend against rogue-aggregate attacks:
    /// without them, an adversary could split one invalid sig across two
    /// crafted sigs that cancel in the pairing sum. Every entry was
    /// subgroup-checked at construction (`CheckedSignature`) — a check on
    /// the weighted sum would not do: it misses a rogue component of order
    /// d whenever d | rᵢ, and the G2 cofactor has small factors
    /// (h₂ = 13²·23²·2713·11953·262069·p₄₄₈), so an order-13 component
    /// slips through ~1/13 of the time — retryable, and the raw sig points
    /// are reused downstream in aggregates. `pks` are admission-time
    /// validated, so no G1 checks.
    fn verify_batch(&mut self) -> bool {
        let n = self.msgs.len();

        self.rand_bytes.resize(n * RAND_BYTES, 0);
        if SystemRandom::new().fill(&mut self.rand_bytes).is_err() {
            return false;
        }
        // Patch any all-zero chunk: a zero scalar would null this tuple's
        // contribution to the pairing sum, so the tuple wouldn't actually be
        // checked. Probability is ~n·2⁻⁶⁴ but the scan is free.
        for c in self.rand_bytes.chunks_exact_mut(RAND_BYTES) {
            if c.iter().all(|&b| b == 0) {
                c[0] = 1;
            }
        }

        let sig_sum = self.sigs.mult(&self.rand_bytes, NBITS).to_signature();

        let SigBatch {
            msgs, pks, rand_bytes, order, grouped_pks, grouped_scalars, pairing, ..
        } = self;

        order.clear();
        order.extend(0..n as u32);
        order.sort_unstable_by(|&a, &b| msgs[a as usize].cmp(&msgs[b as usize]));

        grouped_pks.clear();
        grouped_scalars.clear();
        for &i in order.iter() {
            grouped_pks.push(pks[i as usize]);
            grouped_scalars.extend_from_slice(&rand_bytes[i as usize * 8..(i as usize + 1) * 8]);
        }

        // Re-init the existing pairing buffer.
        pairing.init(true, DST);
        let mut start = 0;
        while start < n {
            let msg = &msgs[order[start] as usize];
            let mut end = start + 1;
            while end < n && msgs[order[end] as usize] == *msg {
                end += 1;
            }
            let pk_sum = grouped_pks[start..end].mult(&grouped_scalars[start * 8..end * 8], NBITS);
            pairing.raw_aggregate(&hash_to_g2_affine(msg), pk_affine(&pk_sum.to_public_key()));
            start = end;
        }
        pairing.commit();

        let mut gtsig = blst_fp12::default();
        unsafe { blst_aggregated_in_g2(&mut gtsig, sig_affine(&sig_sum)) };
        pairing.finalverify(Some(&gtsig))
    }
}

fn hash_to_g2_affine(msg: &B256) -> blst_p2_affine {
    let mut q = blst_p2::default();
    let mut affine = blst_p2_affine::default();
    unsafe {
        blst_hash_to_g2(&mut q, msg.as_ptr(), msg.len(), DST.as_ptr(), DST.len(), ptr::null(), 0);
        blst_p2_to_affine(&mut affine, &q);
    }
    affine
}

#[cfg(test)]
mod tests {
    use blst::{
        blst_p2_add_or_double_affine, blst_p2_affine_in_g2, blst_p2_compress, blst_p2_from_affine,
        blst_p2_is_inf, blst_p2_mult, blst_p2_uncompress,
    };

    use super::*;
    use crate::test_signing::{pubkey_pk, sign};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// Big-endian long division by 13; returns (quotient, remainder).
    fn div13(be: &[u8]) -> (Vec<u8>, u32) {
        let mut rem = 0u32;
        let q = be
            .iter()
            .map(|&b| {
                let cur = rem * 256 + b as u32;
                rem = cur % 13;
                (cur / 13) as u8
            })
            .collect();
        (q, rem)
    }

    /// h₂'s smallest factor is 13: a signature carrying an order-13 rogue
    /// component on top of a valid r-torsion part cancels out of a
    /// weighted-sum subgroup check whenever 13 | rᵢ (~1/13 of runs, so this
    /// test flaked green against the old sum-only check). Per-sig subgroup
    /// checks must reject it deterministically.
    #[test]
    fn sig_batch_rejects_low_order_rogue_component() {
        // Deterministic non-subgroup point on the twist: scan x = (i, 0)
        // compressed encodings until one lands on the curve.
        let mut cand = [0u8; 96];
        cand[0] = 0x80;
        let mut aff = blst_p2_affine::default();
        let found = (1..=255u8).any(|i| {
            cand[95] = i;
            unsafe {
                blst_p2_uncompress(&mut aff, cand.as_ptr()) == BLST_ERROR::BLST_SUCCESS &&
                    !blst_p2_affine_in_g2(&aff)
            }
        });
        assert!(found);

        let r_be = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        let h2_be = hex(
            "05d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef2\
             1537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5",
        );
        // 13² | h₂, so divide both factors out — (h₂/13)·r would still
        // annihilate an order-13 component.
        let (q1, rem1) = div13(&h2_be);
        let (k_be, rem2) = div13(&q1);
        assert_eq!((rem1, rem2), (0, 0), "13² must divide the G2 cofactor");
        let r_le: Vec<u8> = r_be.iter().rev().copied().collect();
        let k_le: Vec<u8> = k_be.iter().rev().copied().collect();

        // u = (h₂/13²)·r·P: order divides 13². Take u or 13·u, whichever
        // has order exactly 13.
        let mut p = blst_p2::default();
        let mut t = blst_p2::default();
        let mut u = blst_p2::default();
        let mut u13 = blst_p2::default();
        let mut u169 = blst_p2::default();
        let rogue;
        unsafe {
            blst_p2_from_affine(&mut p, &aff);
            blst_p2_mult(&mut t, &p, r_le.as_ptr(), r_le.len() * 8);
            blst_p2_mult(&mut u, &t, k_le.as_ptr(), k_le.len() * 8);
            blst_p2_mult(&mut u13, &u, [13u8].as_ptr(), 8);
            blst_p2_mult(&mut u169, &u13, [13u8].as_ptr(), 8);
            assert!(!blst_p2_is_inf(&u), "13-part vanished; pick another x");
            assert!(blst_p2_is_inf(&u169), "constants wrong: order does not divide 13²");
            rogue = if blst_p2_is_inf(&u13) { u } else { u13 };
        }

        let msg0 = [0x01u8; 32];
        let sig0 = sign(0, &msg0);
        let mut sig0_aff = blst_p2_affine::default();
        let mut tampered = blst_p2::default();
        let mut tampered_bytes = [0u8; 96];
        unsafe {
            assert_eq!(blst_p2_uncompress(&mut sig0_aff, sig0.as_ptr()), BLST_ERROR::BLST_SUCCESS);
            blst_p2_add_or_double_affine(&mut tampered, &rogue, &sig0_aff);
            blst_p2_compress(tampered_bytes.as_mut_ptr(), &tampered);
        }

        let msg1 = [0x02u8; 32];
        let sig1 = sign(1, &msg1);
        let mut batch = SigBatch::new();
        batch.push_one(&pubkey_pk(0), &tampered_bytes, msg0);
        batch.push_one(&pubkey_pk(1), &sig1, msg1);
        assert!(!batch.verify_all());
    }

    /// SigBatch eth-aggregate — empty participants accepted iff sig is
    /// G2 infinity (sync-aggregate semantics).
    #[test]
    fn sig_batch_eth_aggregate_empty_infinity() {
        let msg = [0u8; 32];
        let mut batch = SigBatch::new();
        let empty: [PublicKey; 0] = [];
        batch.push_eth_aggregate(0, empty.iter(), &G2_POINT_AT_INFINITY, msg);
        assert!(batch.verify_all());
    }

    #[test]
    fn sig_batch_eth_aggregate_empty_nonzero_rejected() {
        let msg = [0u8; 32];
        let sig = sign(0, &msg);
        let mut batch = SigBatch::new();
        let empty: [PublicKey; 0] = [];
        batch.push_eth_aggregate(0, empty.iter(), &sig, msg);
        assert!(!batch.verify_all());
    }

    /// Mixed batch with 3 distinct (pk, msg, sig) tuples — every group is a
    /// singleton. All valid → accept.
    #[test]
    fn sig_batch_multi_valid_accepts() {
        let msg0 = [0x01u8; 32];
        let msg1 = [0x02u8; 32];
        let msg2 = [0x03u8; 32];
        let sig0 = sign(0, &msg0);
        let sig1 = sign(1, &msg1);
        let sig2 = sign(2, &msg2);

        let mut batch = SigBatch::new();
        batch.push_one(&pubkey_pk(0), &sig0, msg0);
        batch.push_one(&pubkey_pk(1), &sig1, msg1);
        batch.push_one(&pubkey_pk(2), &sig2, msg2);
        assert!(batch.verify_all());
    }

    /// Multi batch where one tuple's sig was signed under the wrong
    /// message → batch must reject. Pins basic reject behaviour of the
    /// grouped-pairing + `finalverify` path. (Does not specifically
    /// probe rogue-aggregate resistance; that requires two crafted sigs
    /// summing to cancel — left untested.)
    #[test]
    fn sig_batch_multi_one_bad_sig_rejects() {
        let msg0 = [0x01u8; 32];
        let msg1 = [0x02u8; 32];
        let msg2 = [0x03u8; 32];
        let sig0 = sign(0, &msg0);
        // sig_for_msg0 signed under pk0 — wrong message context for tuple 1.
        let bad_sig1 = sign(1, &msg0);
        let sig2 = sign(2, &msg2);

        let mut batch = SigBatch::new();
        batch.push_one(&pubkey_pk(0), &sig0, msg0);
        batch.push_one(&pubkey_pk(1), &bad_sig1, msg1);
        batch.push_one(&pubkey_pk(2), &sig2, msg2);
        assert!(!batch.verify_all());
    }

    /// Shared-message grouping: 3 signers over one message plus a singleton
    /// group over another. Exercises a multi-tuple group's weighted pk sum.
    #[test]
    fn sig_batch_shared_message_accepts() {
        let shared = [0x0au8; 32];
        let other = [0x0bu8; 32];

        let mut batch = SigBatch::new();
        for sk_idx in 0..3 {
            batch.push_one(&pubkey_pk(sk_idx), &sign(sk_idx, &shared), shared);
        }
        batch.push_one(&pubkey_pk(0), &sign(0, &other), other);
        assert!(batch.verify_all());
    }

    /// One tuple inside a shared-message group claims pk2 but carries pk1's
    /// sig — the per-tuple random scalars must keep it from hiding in the
    /// group sum.
    #[test]
    fn sig_batch_shared_message_forged_signer_rejects() {
        let shared = [0x0au8; 32];

        let mut batch = SigBatch::new();
        batch.push_one(&pubkey_pk(0), &sign(0, &shared), shared);
        batch.push_one(&pubkey_pk(1), &sign(1, &shared), shared);
        batch.push_one(&pubkey_pk(2), &sign(1, &shared), shared);
        assert!(!batch.verify_all());
    }
}
