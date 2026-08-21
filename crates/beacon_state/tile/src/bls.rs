use blst::{
    BLST_ERROR, Pairing, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_cneg,
    blst_p1_to_affine, blst_p1s_add, blst_p2_affine,
    min_pk::{AggregatePublicKey, PublicKey, Signature},
};
use flux_profiler::timed;
use ring::rand::{SecureRandom, SystemRandom};
use silver_beacon_state_data::{B256, BLSPubkey, BeaconBlockHeader, SYNC_COMMITTEE_SIZE};
use silver_common::ssz_view::{
    SIGNED_BEACON_BLOCK_MIN, SINGLE_ATT_SIZE, SignedBeaconBlockView, SingleAttestationView,
};

use crate::{
    merkle,
    ssz_hash::{self, hash_tree_root_block_header},
};

// `verify_batch` casts `&PublicKey -> &blst_p1_affine` and
// `&Signature -> &blst_p2_affine`. blst-rs declares both as
// `#[repr(transparent)]` single-field wrappers
const _: () = {
    use core::mem::{align_of, size_of};
    assert!(size_of::<PublicKey>() == size_of::<blst_p1_affine>());
    assert!(align_of::<PublicKey>() == align_of::<blst_p1_affine>());
    assert!(size_of::<Signature>() == size_of::<blst_p2_affine>());
    assert!(align_of::<Signature>() == align_of::<blst_p2_affine>());
};

/// Reusable pointer table for `blst_p1s_add`. The pointers are only live
/// inside the single `sum` call that fills the table (cleared on entry), so
/// moving the idle buffer across threads is sound despite the raw pointers.
#[derive(Default)]
pub(crate) struct PubkeyAggregator(Vec<*const blst_p1_affine>);
unsafe impl Send for PubkeyAggregator {}

impl PubkeyAggregator {
    /// Batched affine addition — one shared inversion for the whole set,
    /// ~1.8× the serial `AggregatePublicKey::add_public_key` loop. `None`
    /// for an empty set (no identity element to report).
    #[timed]
    fn sum<'a>(&mut self, pks: impl IntoIterator<Item = &'a PublicKey>) -> Option<blst_p1> {
        self.0.clear();
        self.0.extend(pks.into_iter().map(|pk| pk as *const PublicKey as *const blst_p1_affine));
        (!self.0.is_empty()).then(|| {
            let mut sum = blst_p1::default();
            unsafe { blst_p1s_add(&mut sum, self.0.as_ptr(), self.0.len()) };
            sum
        })
    }

    fn to_public_key(sum: blst_p1) -> PublicKey {
        let mut affine = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut affine, &sum) };
        unsafe { std::mem::transmute::<blst_p1_affine, PublicKey>(affine) }
    }

    pub(crate) fn aggregate<'a>(
        &mut self,
        pks: impl IntoIterator<Item = &'a PublicKey>,
    ) -> Option<PublicKey> {
        self.sum(pks).map(Self::to_public_key)
    }

    /// `Σ committees − Σ missing = Σ present`: the same group element as
    /// summing the attesters directly, but the point work scales with the
    /// (typically 2-5%) missing fraction. Both iterators must cover the same
    /// committees.
    pub(crate) fn aggregate_subtracted<'a>(
        &mut self,
        committees: impl IntoIterator<Item = &'a PublicKey>,
        missing: impl IntoIterator<Item = &'a PublicKey>,
    ) -> Option<PublicKey> {
        let mut sum = self.sum(committees)?;
        if let Some(mut missing) = self.sum(missing) {
            unsafe {
                blst_p1_cneg(&mut missing, true);
                blst_p1_add_or_double(&mut sum, &sum, &missing);
            }
        }
        Some(Self::to_public_key(sum))
    }

    /// Identity for an empty set, for position-indexed tables where every
    /// entry must hold a valid point.
    pub(crate) fn aggregate_or_identity<'a>(
        &mut self,
        pks: impl IntoIterator<Item = &'a PublicKey>,
    ) -> PublicKey {
        Self::to_public_key(self.sum(pks).unwrap_or_default())
    }
}

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// G2 point at infinity (compressed). Spec: a sync_aggregate over an empty
/// participant set verifies iff the signature is this value.
pub(crate) const G2_POINT_AT_INFINITY: [u8; 96] = {
    let mut s = [0u8; 96];
    s[0] = 0xc0;
    s
};

pub const DOMAIN_BEACON_PROPOSER: u32 = 0x0000_0000;
pub const DOMAIN_BEACON_ATTESTER: u32 = 0x0000_0001;
pub const DOMAIN_RANDAO: u32 = 0x0000_0002;
pub const DOMAIN_DEPOSIT: u32 = 0x0000_0003;
pub const DOMAIN_VOLUNTARY_EXIT: u32 = 0x0000_0004;
pub const DOMAIN_SELECTION_PROOF: u32 = 0x0000_0005;
pub const DOMAIN_AGGREGATE_AND_PROOF: u32 = 0x0000_0006;
pub const DOMAIN_SYNC_COMMITTEE: u32 = 0x0000_0007;
pub const DOMAIN_BLS_TO_EXECUTION_CHANGE: u32 = 0x0000_000a;
// Gloas
pub const DOMAIN_BEACON_BUILDER: u32 = 0x0000_000b;
pub const DOMAIN_PTC_ATTESTER: u32 = 0x0000_000c;
pub const DOMAIN_BUILDER_DEPOSIT: u32 = 0x0000_000e;

#[timed]
pub fn compute_domain(
    domain_type: u32,
    fork_version: [u8; 4],
    genesis_validators_root: &B256,
) -> B256 {
    let fork_data_root = ssz_hash::hash_tree_root_fork_data(fork_version, genesis_validators_root);
    domain_from_fork_data(domain_type, &fork_data_root)
}

pub fn domain_from_fork_data(domain_type: u32, fork_data_root: &B256) -> B256 {
    let mut domain = [0u8; 32];
    domain[0..4].copy_from_slice(&domain_type.to_le_bytes());
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

pub fn compute_signing_root(object_root: &B256, domain: &B256) -> B256 {
    merkle::hash_concat(object_root, domain)
}

#[inline]
pub fn fork_version_at_epoch(
    fork_epoch: u64,
    previous_version: [u8; 4],
    current_version: [u8; 4],
    epoch: u64,
) -> [u8; 4] {
    if epoch < fork_epoch { previous_version } else { current_version }
}

/// Single-key BLS verify over an arbitrary 32-byte message. Caller passes
/// a decompressed pubkey (from `vid.val_pubkey_decompressed`) — pubkeys are
/// admission-validated, so we skip `pk_validate` and only group-check the
/// signature. For one-shot paths where only the compressed bytes are
/// available (e.g. `verify_deposit_signature`), use `verify_one_compressed`.
pub(crate) fn verify_one(pk: &PublicKey, sig: &[u8; 96], message: &B256) -> bool {
    let Ok(sig) = Signature::from_bytes(sig) else { return false };
    verify_one_parsed(pk, &sig, message)
}

fn verify_one_parsed(pk: &PublicKey, sig: &Signature, message: &B256) -> bool {
    sig.verify(true, message, DST, &[], pk, false) == BLST_ERROR::BLST_SUCCESS
}

/// Same as `verify_one` but decompresses the pubkey inline. Used at
/// admission time (deposit pop) before the cache exists.
pub(crate) fn verify_one_compressed(pubkey: &BLSPubkey, sig: &[u8; 96], message: &B256) -> bool {
    let Ok(pk) = PublicKey::key_validate(pubkey) else { return false };
    verify_one(&pk, sig, message)
}

pub struct SigBatch {
    msgs: Vec<B256>,
    pks: Vec<PublicKey>,
    sigs: Vec<Signature>,
    /// Per-tuple 64-bit random scalars, packed as little-endian bytes.
    /// Pre-allocated to `SIG_BATCH_CAP * 8`; resized (no realloc) per call.
    rand_bytes: Vec<u8>,
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
            rand_bytes: Vec::with_capacity(SIG_BATCH_CAP * 8),
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
        let Ok(sig) = Signature::from_bytes(sig) else {
            self.poisoned = true;
            return;
        };
        self.msgs.push(signing_root);
        self.pks.push(*pubkey);
        self.sigs.push(sig);
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
    /// - 2+ entries → one multi-Miller-loop with random per-tuple scalars to
    ///   prevent rogue-key attacks. Roughly 10–30× faster than the per-tuple
    ///   loop for a busy block.
    #[timed]
    pub fn verify_all(&mut self) -> bool {
        if self.poisoned {
            return false;
        }
        match self.msgs.len() {
            0 => true,
            1 => {
                self.sigs[0].fast_aggregate_verify_pre_aggregated(
                    true,
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

    /// Multi-pairing batch verify with random 64-bit scalars per tuple.
    /// Random scalars are required to defend against rogue-aggregate
    /// attacks: without them, an adversarial proposer could split one
    /// invalid sig across two crafted sigs that cancel in the multi-pairing
    /// sum. `pks` are admission-time validated, so `pks_validate=false`.
    fn verify_batch(&mut self) -> bool {
        let n = self.msgs.len();

        self.rand_bytes.resize(n * 8, 0);
        if SystemRandom::new().fill(&mut self.rand_bytes).is_err() {
            return false;
        }
        // Patch any all-zero chunk: a zero scalar would null this tuple's
        // contribution to the pairing sum, so the tuple wouldn't actually be
        // checked. Probability is ~n·2⁻⁶⁴ but the scan is free.
        for c in self.rand_bytes.chunks_exact_mut(8) {
            if c.iter().all(|&b| b == 0) {
                c[0] = 1;
            }
        }

        // Re-init the existing pairing buffer.
        let SigBatch { msgs, pks, sigs, rand_bytes, pairing, .. } = self;
        pairing.init(true, DST);

        for (((pk, sig), msg), rand) in
            pks.iter().zip(sigs.iter()).zip(msgs.iter()).zip(rand_bytes.chunks_exact(8))
        {
            let pk_pt: &blst_p1_affine =
                unsafe { &*(pk as *const PublicKey as *const blst_p1_affine) };
            let sig_pt: &blst_p2_affine =
                unsafe { &*(sig as *const Signature as *const blst_p2_affine) };
            if pairing.mul_n_aggregate(pk_pt, false, sig_pt, true, rand, 64, msg, &[]) !=
                BLST_ERROR::BLST_SUCCESS
            {
                return false;
            }
        }
        pairing.commit();
        pairing.finalverify(None)
    }
}

pub fn aggregate_pubkeys(pubkeys: &[BLSPubkey; SYNC_COMMITTEE_SIZE]) -> BLSPubkey {
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

pub fn verify_block_signature(
    block_ssz: &[u8],
    proposer_pubkey: &PublicKey,
    body_root: &B256,
    domain: &B256,
) -> bool {
    if block_ssz.len() < SIGNED_BEACON_BLOCK_MIN {
        return false;
    }

    let sig = SignedBeaconBlockView::signature(block_ssz);
    let header = BeaconBlockHeader {
        slot: SignedBeaconBlockView::slot(block_ssz),
        proposer_index: SignedBeaconBlockView::proposer_index(block_ssz),
        parent_root: *SignedBeaconBlockView::parent_root(block_ssz),
        state_root: *SignedBeaconBlockView::state_root(block_ssz),
        body_root: *body_root,
    };
    let object_root = hash_tree_root_block_header(&header);
    let signing_root = compute_signing_root(&object_root, domain);

    verify_one(proposer_pubkey, sig, &signing_root)
}

/// Verify a deposit proof-of-possession. Pubkey comes from the deposit
/// data (not yet a registered validator) so we decompress inline.
pub fn verify_deposit_signature(pubkey: &BLSPubkey, sig: &[u8; 96], signing_root: &B256) -> bool {
    verify_one_compressed(pubkey, sig, signing_root)
}

/// Signature is subgroup-checked by the verify, so downstream aggregation
/// may add it without a second group check.
pub struct VerifiedSingleAttestation {
    pub data_root: B256,
    pub signature: Signature,
}

/// Verify a single-attester `SingleAttestation` (gossip subnet form) against
/// caller-derived roots (they repeat across a slot's attestations, so the
/// caller memoizes them). The body-included aggregate path goes through
/// `stf::validate_attestations` + `SigBatch`.
#[timed]
pub fn verify_single_attestation(
    att: &[u8; SINGLE_ATT_SIZE],
    attester_pubkey: &PublicKey,
    data_root: B256,
    signing_root: &B256,
) -> Option<VerifiedSingleAttestation> {
    let signature = Signature::from_bytes(SingleAttestationView::signature(att)).ok()?;

    verify_one_parsed(attester_pubkey, &signature, signing_root)
        .then_some(VerifiedSingleAttestation { data_root, signature })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_signing::{pubkey_pk, sign};

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

    /// Mixed batch with 3 distinct (pk, msg, sig) tuples — exercises the
    /// `verify_multiple_aggregate_signatures` path. All valid → accept.
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
    /// `mul_n_aggregate` + `finalverify` path. (Does not specifically
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
}
