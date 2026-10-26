use core::mem;

use blst::{BLST_ERROR, MultiPoint, blst_p2_affine_is_inf};
use flux_profiler::timed;
use ring::rand::{SecureRandom, SystemRandom};
use rustc_hash::FxHashMap;
use silver_beacon_state_data::B256;
use silver_crypto_simd::bls::{G1Point, G2Point, PairingProduct};

use super::{
    CheckedSignature, DST, G2_POINT_AT_INFINITY, PublicKey, Signature,
    aggregator::PubkeyAggregator, checked_public_key,
};

// N.B. batching is only safe where NBITS < 144-bit GLS threshold.
const NBITS: usize = 64;
const RAND_BYTES: usize = NBITS / 8;

pub struct SigBatch {
    msgs: Vec<B256>,
    pks: Vec<PublicKey>,
    sigs: Vec<G2Point>,
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
    pairing: PairingProduct,
    hashed_msgs: HashedMsgs,
    aggregator: PubkeyAggregator,
    poisoned: bool,
}

/// Capacity for the per-block sig batch. Worst-case Fulu block envelope at
/// the spec's MAX_* limits: 1 (block) + 1 (randao) + 16×2 (proposer
/// slashings) + 1×2 (attester slashings) + 8 (attestations) + 16 (exits) +
/// 16 (bls_changes) + 1 (sync_aggregate) = 77. Round up.
/// But for batched attestations this can be much larger..
const SIG_BATCH_CAP: usize = 1024;

/// Signing roots the hash-to-G2 cache keeps. A block signs about 13 of them,
/// and a slot of gossip adds a handful more.
const MAX_HASHED_MSGS: usize = 256;

/// `H(msg)` in G2, cached by signing root.
///
/// Hashing one root to the curve costs ~98 µs. The same root is signed many
/// times over. Every attester in a slot signs one `AttestationData`. A block's
/// randao signs its epoch. A block's attestations arrived over gossip first.
/// One cache serves every batch the tile verifies, so each root is hashed once.
#[derive(Default)]
pub struct HashedMsgs {
    live: FxHashMap<B256, G2Point>,
    /// The generation `live` replaced. Still read, and promoted back on a hit.
    prev: FxHashMap<B256, G2Point>,
}

impl HashedMsgs {
    fn get(&mut self, msg: &B256) -> G2Point {
        if let Some(&point) = self.live.get(msg) {
            return point;
        }
        let point = self.prev.get(msg).copied().unwrap_or_else(|| G2Point::hash_to_curve(msg, DST));
        // Retire the older generation instead of emptying the cache.
        // Emptying it made the next block re-hash all ~13 of its roots at
        // once. Flooding the cache with fresh roots only costs the hashing it
        // would have cost anyway.
        if self.live.len() >= MAX_HASHED_MSGS {
            self.prev.clear();
            mem::swap(&mut self.prev, &mut self.live);
        }
        self.live.insert(*msg, point);
        point
    }
}

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
            pairing: PairingProduct::with_capacity(16),
            hashed_msgs: HashedMsgs::default(),
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

    /// Subgroup-checked, like every signature the batch holds.
    pub fn last_signature(&self) -> Option<Signature> {
        self.sigs.last().map(|sig| sig.into_blst().into())
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
        self.sigs.push(sig.0);
    }

    pub fn contains(&self, pubkey: &PublicKey, sig: CheckedSignature, signing_root: &B256) -> bool {
        (0..self.msgs.len()).any(|index| {
            &self.msgs[index] == signing_root &&
                &self.pks[index] == pubkey &&
                self.sigs[index].as_blst() == sig.0.as_blst()
        })
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
    /// - 1 entry → one pairing against the cached `H(msg)`.
    /// - 2+ entries → grouped multi-pairing with random per-tuple scalars.
    #[timed]
    pub fn verify_all(&mut self) -> bool {
        if self.poisoned {
            return false;
        }
        match self.msgs.len() {
            0 => true,
            // One signature is the grouped path with one group. It needs no
            // random scalar, because a rogue component has nothing to cancel
            // against on its own. Signatures are subgroup-checked on the way
            // in, by `CheckedSignature`.
            1 => {
                let hashed = self.hashed_msgs.get(&self.msgs[0]);
                let SigBatch { pks, sigs, pairing, .. } = self;
                pairing.clear();
                let Some(pk) = checked_public_key(&pks[0]) else { return false };
                pairing.push(&pk, &hashed);
                pairing_matches_signature(pairing, &sigs[0])
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
            let sig = Signature::from(sig.into_blst());
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
    /// are reused downstream in aggregates.
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

        let sig_sum = G2Point::weighted_sum(&self.sigs, &self.rand_bytes);

        let SigBatch {
            msgs,
            pks,
            rand_bytes,
            order,
            grouped_pks,
            grouped_scalars,
            pairing,
            hashed_msgs,
            ..
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

        pairing.clear();
        let mut start = 0;
        while start < n {
            let msg = msgs[order[start] as usize];
            let mut end = start + 1;
            while end < n && msgs[order[end] as usize] == msg {
                end += 1;
            }
            let pk_sum = grouped_pks[start..end].mult(&grouped_scalars[start * 8..end * 8], NBITS);
            let Some(pk_sum) = checked_public_key(&pk_sum.to_public_key()) else { return false };
            pairing.push(&pk_sum, &hashed_msgs.get(&msg));
            start = end;
        }
        pairing_matches_signature(pairing, &sig_sum)
    }
}

/// Pairing the signature with `-G1` lets verification compare the product
/// against one.
fn pairing_matches_signature(pairing: &mut PairingProduct, sig: &G2Point) -> bool {
    // Reject an infinite weighted signature, even when valid weighted signatures
    // cancel.
    if unsafe { blst_p2_affine_is_inf(sig.as_blst()) } {
        return false;
    }
    pairing.push(&G1Point::negative_generator(), sig);
    pairing.is_one()
}

#[cfg(test)]
mod tests {
    use blst::{
        Pairing, blst_fp_cneg, blst_fp2_cneg, blst_p1_affine_is_inf, blst_p2,
        blst_p2_add_or_double_affine, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_compress,
        blst_p2_from_affine, blst_p2_is_inf, blst_p2_mult, blst_p2_uncompress,
    };

    use super::*;
    use crate::{
        bls::{
            SignatureChecker,
            aggregator::{pk_affine, sig_affine},
        },
        test_signing::{pubkey_pk, sign},
    };

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
    /// A root the memo has served survives the generation that displaces it,
    /// where a full clear made every live root re-hash at once.
    #[test]
    fn hashed_msgs_keeps_a_root_across_one_eviction() {
        let mut memo = HashedMsgs::default();
        let kept: B256 = [0xAB; 32];
        let first = memo.get(&kept);

        for i in 0..MAX_HASHED_MSGS as u32 {
            let mut other = [0u8; 32];
            other[..4].copy_from_slice(&i.to_le_bytes());
            memo.get(&other);
        }

        assert!(!memo.live.contains_key(&kept), "the filling roots displaced it");
        assert_eq!(
            memo.get(&kept).into_blst(),
            first.into_blst(),
            "still served from the retired generation"
        );
        assert!(memo.live.contains_key(&kept), "and promoted back");
    }

    #[test]
    fn contains_matches_only_the_exact_pubkey_signature_and_root() {
        let root: B256 = [7; 32];
        let other_root: B256 = [8; 32];
        let signature = CheckedSignature::parse(&sign(0, &root)).unwrap();
        let mut batch = SigBatch::new();
        batch.push_parsed(&pubkey_pk(0), signature, root);

        assert!(batch.contains(&pubkey_pk(0), signature, &root));
        assert!(!batch.contains(&pubkey_pk(1), signature, &root));
        assert!(!batch.contains(&pubkey_pk(0), signature, &other_root));
        let other = CheckedSignature::parse(&sign(0, &other_root)).unwrap();
        assert!(!batch.contains(&pubkey_pk(0), other, &root));
    }

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

        assert!(Signature::from_bytes(&tampered_bytes).is_ok());
        assert!(CheckedSignature::parse(&tampered_bytes).is_none());
        assert!(CheckedSignature::parse(&sig0).is_some());
        assert!(CheckedSignature::parse(&G2_POINT_AT_INFINITY).is_some());

        let inputs = [tampered_bytes, sig0, G2_POINT_AT_INFINITY, tampered_bytes];
        let mut checker = SignatureChecker::with_capacity(inputs.len());
        let mut accepted = Vec::new();
        checker.check_all(&inputs, |sig| accepted.push(sig.map(CheckedSignature::into_sig)));
        assert_eq!(accepted, [
            None,
            Signature::from_bytes(&sig0).ok(),
            Signature::from_bytes(&G2_POINT_AT_INFINITY).ok(),
            None
        ]);

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

    /// `P + (−P) = ∞` and `e(∞, H(m)) = e(G1, ∞)`: without the aggregator's
    /// infinity rejection an infinite signature verifies for any message.
    #[test]
    fn sig_batch_rejects_infinite_aggregate_pubkey() {
        let pk = pubkey_pk(1);
        let msg = [7u8; 32];

        let mut single = SigBatch::new();
        single.push_aggregate_subtracted([&pk], [&pk], &G2_POINT_AT_INFINITY, msg);
        assert!(!single.verify_all());

        let mut batched = SigBatch::new();
        batched.push_aggregate_subtracted([&pk], [&pk], &G2_POINT_AT_INFINITY, msg);
        let other = [9u8; 32];
        batched.push_one(&pubkey_pk(2), &sign(2, &other), other);
        assert!(!batched.verify_all());
    }

    #[test]
    fn sig_batch_single_entry_verifies_only_its_message() {
        let msg = [0x01u8; 32];

        let mut valid = SigBatch::new();
        valid.push_one(&pubkey_pk(0), &sign(0, &msg), msg);
        assert!(valid.verify_all());

        let mut wrong_message = SigBatch::new();
        wrong_message.push_one(&pubkey_pk(0), &sign(0, &msg), [0x02u8; 32]);
        assert!(!wrong_message.verify_all());
    }

    /// Infinity passes the subgroup check, so rejection must happen during
    /// verification.
    #[test]
    fn sig_batch_rejects_infinite_signature() {
        let mut single = SigBatch::new();
        single.push_one(&pubkey_pk(1), &G2_POINT_AT_INFINITY, [7u8; 32]);
        assert_eq!(single.len(), 1);
        assert!(!single.verify_all());

        let mut summed = SigBatch::new();
        summed.push_one(&pubkey_pk(1), &G2_POINT_AT_INFINITY, [7u8; 32]);
        summed.push_one(&pubkey_pk(2), &G2_POINT_AT_INFINITY, [9u8; 32]);
        assert_eq!(summed.len(), 2);
        assert!(!summed.verify_all());
    }

    #[test]
    fn infinite_key_sum_matches_blst_pairing() {
        // Use the private check because batch weights come from SystemRandom.
        let shared = [11u8; 32];
        let other = [12u8; 32];
        let pk = pubkey_pk(0);
        let mut inverse_pk = *pk_affine(&pk);
        unsafe { blst_fp_cneg(&mut inverse_pk.y, &inverse_pk.y, true) };
        let inverse_pk = PublicKey::from(inverse_pk);
        assert!(pk.validate().is_ok() && inverse_pk.validate().is_ok());

        let signature = Signature::from_bytes(&sign(0, &shared)).unwrap();
        let mut inverse_signature = *sig_affine(&signature);
        unsafe { blst_fp2_cneg(&mut inverse_signature.y, &inverse_signature.y, true) };
        let inverse_signature = Signature::from(inverse_signature);
        assert!(inverse_signature.validate(false).is_ok());
        let neg_g1 = G1Point::negative_generator();

        for weight in [1u64, 7, u64::MAX] {
            let scalars = weight.to_le_bytes().repeat(3);
            let cancelled =
                [pk, inverse_pk].mult(&scalars[..2 * RAND_BYTES], NBITS).to_public_key();
            assert!(unsafe { blst_p1_affine_is_inf(pk_affine(&cancelled)) });
            let remaining = [pubkey_pk(1)].mult(&scalars[..RAND_BYTES], NBITS).to_public_key();

            for valid in [true, false] {
                let message = if valid { other } else { shared };
                let third = Signature::from_bytes(&sign(1, &message)).unwrap();
                let sum =
                    [signature, inverse_signature, third].mult(&scalars, NBITS).to_signature();
                assert!(!unsafe { blst_p2_affine_is_inf(sig_affine(&sum)) });

                let mut product = PairingProduct::default();
                let mut previous = Pairing::new(true, DST);
                for (key, message) in [(cancelled, shared), (remaining, other)] {
                    let hashed = G2Point::hash_to_curve(&message, DST);
                    product.push(&checked_public_key(&key).unwrap(), &hashed);
                    previous.raw_aggregate(hashed.as_blst(), pk_affine(&key));
                }
                previous.raw_aggregate(sig_affine(&sum), neg_g1.as_blst());
                previous.commit();
                assert_eq!(previous.finalverify(None), valid, "unfiltered blst verdict");
                let sum = G2Point::from_blst(*sig_affine(&sum)).unwrap();
                assert_eq!(pairing_matches_signature(&mut product, &sum), valid);
            }

            let sum = [signature, inverse_signature]
                .mult(&scalars[..2 * RAND_BYTES], NBITS)
                .to_signature();
            assert!(unsafe { blst_p2_affine_is_inf(sig_affine(&sum)) });
            let mut product = PairingProduct::default();
            product.push(
                &checked_public_key(&cancelled).unwrap(),
                &G2Point::hash_to_curve(&shared, DST),
            );
            let sum = G2Point::from_blst(*sig_affine(&sum)).unwrap();
            assert!(!pairing_matches_signature(&mut product, &sum));
        }
    }

    #[test]
    fn sig_batch_reuses_pairing_across_lane_boundaries() {
        let mut batch = SigBatch::new();
        for count in [1, 7, 8, 15, 16, 19] {
            batch.clear();
            for index in 0..count {
                let message = [index as u8; 32];
                batch.push_one(&pubkey_pk(0), &sign(0, &message), message);
            }
            assert!(batch.verify_all());
            assert!(batch.verify_all());
            batch.push_one(&pubkey_pk(0), &sign(0, &[42u8; 32]), [43u8; 32]);
            assert!(!batch.verify_all());
        }
        batch.poison();
        assert!(!batch.verify_all());
        batch.clear();
        assert!(batch.verify_all());
        batch.poison();
        assert!(!batch.verify_all());
    }
}
