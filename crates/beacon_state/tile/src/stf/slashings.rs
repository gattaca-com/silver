use core::cmp::max;

use silver_beacon_state_data::{
    B256, BalancesWriteView, BeaconBlockHeader, BuilderPendingPayment, EPOCHS_PER_SLASHINGS_VECTOR,
    EpochView, Immutable, SLOTS_PER_EPOCH, SlotStateWriteView, SpecConfig, StateReadView,
    StateWriterView, ValidatorsView, ValidatorsWriteView,
};
use silver_common::ssz_view::{
    ATTESTATION_DATA_SIZE, AttestationDataView, BEACON_BLOCK_HEADER_SIZE, BeaconBlockHeaderView,
    PROPOSER_SLASHING_SIZE, ProposerSlashingView,
};
use silver_ssz::ssz_view::{IndexedAttestationView, MAX_ATTESTING_INDICES};

use crate::{
    bls::{self, SigBatch},
    error::{AttesterSlashingError, ProposerSlashingError, Result},
    ssz_hash::{self, hash_tree_root_block_header},
    stf::{
        for_each_ssz_list_item, get_beacon_proposer_index, initiate_validator_exit,
        is_slashable_validator,
    },
    validate,
};

const WHISTLEBLOWER_REWARD_QUOTIENT: u64 = 4096;

/// Parse + validate an AttesterSlashing's two inner IndexedAttestation
/// offsets.
fn attester_slashing_inner_offsets(
    slashing: &[u8],
) -> std::result::Result<(usize, usize), AttesterSlashingError> {
    if slashing.len() < 8 {
        return Err(AttesterSlashingError::TooShort { len: slashing.len(), min: 8 });
    }
    let off1 = u32::from_le_bytes(slashing[0..4].try_into().unwrap()) as usize;
    let off2 = u32::from_le_bytes(slashing[4..8].try_into().unwrap()) as usize;
    if off1 + 132 > slashing.len() || off2 + 132 > slashing.len() || off2 < off1 + 132 {
        return Err(AttesterSlashingError::BadInnerOffsets {
            off1,
            off2,
            slashing_len: slashing.len(),
        });
    }
    Ok((off1, off2))
}

/// Pass 1 — push both header sigs per slashing entry.
pub fn collect_sigs_proposer_slashings(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    data: &[u8],
    sig_batch: &mut SigBatch,
) -> Result<(), ProposerSlashingError> {
    let (fork_epoch, prev_ver, cur_ver, gvr) = epoch.fork_descriptor(imm.genesis_validators_root);
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = validators.count();
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        let vi = ProposerSlashingView::h1_proposer_index(s) as u32;
        if (vi as usize) >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi: vi as usize, count: n });
        }
        let h1_slot = ProposerSlashingView::h1_slot(s);
        let h2_slot = ProposerSlashingView::h2_slot(s);
        let fv1 =
            bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, h1_slot / SLOTS_PER_EPOCH);
        let fv2 =
            bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, h2_slot / SLOTS_PER_EPOCH);
        let sr1 = signing_root_for_block_header(&s[0..208], fv1, &gvr);
        let sr2 = signing_root_for_block_header(&s[208..416], fv2, &gvr);
        let sig1 = ProposerSlashingView::h1_signature(s);
        let sig2 = ProposerSlashingView::h2_signature(s);
        let pk = validators.pubkey_decompressed(vi as usize);
        sig_batch.push_one(pk, sig1, sr1);
        sig_batch.push_one(pk, sig2, sr2);
    }
    Ok(())
}

/// Pass 2 — validate per-entry preconditions and slash. BLS already
/// verified. `is_slashable_validator` re-check picks up within-block
/// mutations (a same-vi double slashing rejects on the second entry
/// because the first one already set the slashed flag).
pub fn process_proposer_slashings(
    view: &mut StateWriterView,
    epoch: EpochView,
    cfg: &SpecConfig,
    data: &[u8],
) -> Result<(), ProposerSlashingError> {
    let is_gloas = epoch.is_gloas(view.imm.gloas_fork_version);
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &mut view.balances;
    let count = data.len() / PROPOSER_SLASHING_SIZE;
    let n = validators.count();
    let proposer_index = get_beacon_proposer_index(slot, epoch);
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    for i in 0..count {
        let s: &[u8; PROPOSER_SLASHING_SIZE] =
            data[i * PROPOSER_SLASHING_SIZE..(i + 1) * PROPOSER_SLASHING_SIZE].try_into().unwrap();
        validate::validate_proposer_slashing(s)?;
        let vi = ProposerSlashingView::h1_proposer_index(s) as u32;
        if (vi as usize) >= n {
            return Err(ProposerSlashingError::ValidatorOutOfRange { vi: vi as usize, count: n });
        }
        if !is_slashable_validator(&validators.reader(), vi, current_epoch) {
            return Err(ProposerSlashingError::NotSlashable {
                vi: vi as usize,
                pubkey: *validators.pubkey(vi as usize),
                epoch: current_epoch,
            });
        }
        if is_gloas {
            clear_builder_payment_on_slash(
                slot,
                ProposerSlashingView::h1_slot(s),
                vi,
                current_epoch,
            );
        }
        slash_validator(cfg, slot, validators, balances, vi, proposer_index);
    }
    Ok(())
}

fn clear_builder_payment_on_slash(
    slot: &mut SlotStateWriteView,
    proposal_slot: u64,
    proposer_index: u32,
    current_epoch: u64,
) {
    let spe = SLOTS_PER_EPOCH as usize;
    let proposal_epoch = proposal_slot / SLOTS_PER_EPOCH;
    let slot_in_epoch = proposal_slot as usize % spe;
    let ring = if proposal_epoch == current_epoch {
        spe + slot_in_epoch
    } else if current_epoch > 0 && proposal_epoch == current_epoch - 1 {
        slot_in_epoch
    } else {
        return;
    };
    if slot.state().builder_pending_payments[ring].proposer_index == proposer_index as u64 {
        slot.state_mut().builder_pending_payments[ring] = BuilderPendingPayment::default();
    }
}

/// Compute signing root for a `BeaconBlockHeader` (208-byte SSZ): slot,
/// proposer_index, parent_root, state_root, body_root.
pub(crate) fn signing_root_for_block_header(
    header: &[u8],
    fork_version: [u8; 4],
    genesis_validators_root: &B256,
) -> B256 {
    let hb: &[u8; BEACON_BLOCK_HEADER_SIZE] =
        header[..BEACON_BLOCK_HEADER_SIZE].try_into().unwrap();
    let h = BeaconBlockHeader {
        slot: BeaconBlockHeaderView::slot(hb),
        proposer_index: BeaconBlockHeaderView::proposer_index(hb),
        parent_root: *BeaconBlockHeaderView::parent_root(hb),
        state_root: *BeaconBlockHeaderView::state_root(hb),
        body_root: *BeaconBlockHeaderView::body_root(hb),
    };
    let object_root = hash_tree_root_block_header(&h);
    let domain =
        bls::compute_domain(bls::DOMAIN_BEACON_PROPOSER, fork_version, genesis_validators_root);
    bls::compute_signing_root(&object_root, &domain)
}

/// Pass 1 — push both IndexedAttestation aggregate sigs per slashing entry.
pub fn collect_sigs_attester_slashings(
    imm: &Immutable,
    epoch: &EpochView,
    validators: &ValidatorsView,
    data: &[u8],
    active_scratch: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> Result<(), AttesterSlashingError> {
    let (fork_epoch, prev_ver, cur_ver, gvr) = epoch.fork_descriptor(imm.genesis_validators_root);
    for_each_ssz_list_item(
        data,
        |start, end| AttesterSlashingError::BadOffsets { start, end, parent_len: data.len() },
        |slashing| {
            let (off1, off2) = attester_slashing_inner_offsets(slashing)?;
            let i1 = attesting_indices_bytes(slashing, off1, off2);
            let i2 = attesting_indices_bytes(slashing, off2, slashing.len());

            for (ia_off, ia_end, indices) in [(off1, off2, i1), (off2, slashing.len(), i2)] {
                let ia = &slashing[ia_off..ia_end];
                let target_epoch = IndexedAttestationView::target_epoch(ia);
                let fv = bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, target_epoch);
                active_scratch.clear();
                let n_idx = indices.len() / 8;
                let count = validators.count();
                for k in 0..n_idx {
                    let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap());
                    if vi as usize >= count {
                        return Err(AttesterSlashingError::ValidatorOutOfRange {
                            vi: vi as usize,
                            count,
                        });
                    }
                    active_scratch.push(vi as u32);
                }
                let data_chunk: &[u8; 128] = IndexedAttestationView::data(ia);
                let sig: &[u8; 96] = IndexedAttestationView::signature(ia);
                let object_root = ssz_hash::hash_attestation_data(data_chunk);
                let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &gvr);
                let signing_root = bls::compute_signing_root(&object_root, &domain);
                sig_batch.push_aggregate(
                    active_scratch.iter().map(|&vi| validators.pubkey_decompressed(vi as usize)),
                    sig,
                    signing_root,
                );
            }
            Ok(())
        },
    )
}

/// Walk two strictly-ascending u64-LE-packed lists in lockstep, invoking
/// `f(vi)` for each value present in both. O(n+m). Returning `true` from
/// `f` short-circuits — used by the gossip path on first slashable match;
/// the block path always returns `false` and traverses the full intersection.
pub(crate) fn for_each_sorted_intersection(i1: &[u8], i2: &[u8], mut f: impl FnMut(usize) -> bool) {
    let read = |s: &[u8], i: usize| u64::from_le_bytes(s[i * 8..i * 8 + 8].try_into().unwrap());
    let (n1, n2) = (i1.len() / 8, i2.len() / 8);
    let (mut a, mut b) = (0usize, 0usize);
    while a < n1 && b < n2 {
        let x = read(i1, a);
        let y = read(i2, b);
        match x.cmp(&y) {
            core::cmp::Ordering::Less => a += 1,
            core::cmp::Ordering::Greater => b += 1,
            core::cmp::Ordering::Equal => {
                if f(x as usize) {
                    return;
                }
                a += 1;
                b += 1;
            }
        }
    }
}

/// Pass 2 — validate data + state, slash the intersection. BLS verified.
///
/// `scratch` is a u32 scratch that holds the slashable-intersection
/// indices between read-phase and mutate-phase. Caller-provided so the
/// allocation amortises; bounded by `MAX_ATTESTING_INDICES`.
pub fn process_attester_slashings(
    view: &mut StateWriterView,
    epoch: EpochView,
    cfg: &SpecConfig,
    data: &[u8],
    scratch: &mut Vec<u32>,
    slashed_sink: &mut Vec<u32>,
) -> Result<(), AttesterSlashingError> {
    if data.is_empty() {
        return Ok(());
    }
    let slot = &mut view.slot;
    let validators = &mut view.validators;
    let balances = &mut view.balances;
    let proposer_index = get_beacon_proposer_index(slot, epoch);
    let n = validators.count();
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;

    for_each_ssz_list_item(
        data,
        |start, end| AttesterSlashingError::BadOffsets { start, end, parent_len: data.len() },
        |slashing| {
            let (off1, off2) = attester_slashing_inner_offsets(slashing)?;
            let d1 = &slashing[off1 + 4..off1 + 132];
            let d2 = &slashing[off2 + 4..off2 + 132];
            if !is_slashable_attestation_data(d1, d2) {
                return Err(AttesterSlashingError::NotSlashableData);
            }
            let i1 = attesting_indices_bytes(slashing, off1, off2);
            let i2 = attesting_indices_bytes(slashing, off2, slashing.len());
            if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
                return Err(AttesterSlashingError::IndicesNotSorted);
            }

            // Spec requires ≥1 currently-slashable validator in the
            // intersection; a no-op slashing makes the block invalid.
            let mut slashed_any = false;
            // Collect slashable indices first to avoid holding `view` while
            // calling the mutating `slash_validator`.
            scratch.clear();
            {
                let v = validators.reader();
                for_each_sorted_intersection(i1, i2, |vi| {
                    let vi32 = vi as u32;
                    if vi < n && is_slashable_validator(&v, vi32, current_epoch) {
                        scratch.push(vi32);
                    }
                    false
                });
            }
            for &vi in scratch.iter() {
                // Re-check slashability after each prior slash mutation in the
                // loop.
                if is_slashable_validator(&validators.reader(), vi, current_epoch) {
                    slash_validator(cfg, slot, validators, balances, vi, proposer_index);
                    slashed_sink.push(vi);
                    slashed_any = true;
                }
            }
            if !slashed_any {
                return Err(AttesterSlashingError::NoSlashedIntersection);
            }
            Ok(())
        },
    )
}

/// Gossip-side `AttesterSlashing` validator (single slashing, not the
/// block-body list form).
/// On success, `equivocating_out` is filled with the in-range intersection of
/// the two attestations' indices (the validators to mark equivocating in fork
/// choice). Its contents are meaningless when this returns `false`.
pub fn validate_attester_slashing_for_gossip(
    view: &StateReadView,
    slashing: &[u8],
    equivocating_out: &mut Vec<u32>,
    sig_batch: &mut SigBatch,
) -> bool {
    let (fork_epoch, prev_ver, cur_ver, gvr) =
        view.epoch.fork_descriptor(view.imm.genesis_validators_root);
    let Ok((off1, off2)) = attester_slashing_inner_offsets(slashing) else {
        return false;
    };
    let d1 = &slashing[off1 + 4..off1 + 132];
    let d2 = &slashing[off2 + 4..off2 + 132];
    if !is_slashable_attestation_data(d1, d2) {
        return false;
    }
    let i1 = attesting_indices_bytes(slashing, off1, off2);
    let i2 = attesting_indices_bytes(slashing, off2, slashing.len());
    if i1.len() / 8 > MAX_ATTESTING_INDICES || i2.len() / 8 > MAX_ATTESTING_INDICES {
        return false;
    }
    if !indices_sorted_unique(i1) || !indices_sorted_unique(i2) {
        return false;
    }

    let current_epoch = view.slot.current_epoch();
    let count = view.validators.count();
    let validators = view.validators;
    equivocating_out.clear();
    let mut any_slashable = false;
    for_each_sorted_intersection(i1, i2, |vi| {
        let vi32 = vi as u32;
        if vi < count {
            equivocating_out.push(vi32);
            if is_slashable_validator(&validators, vi32, current_epoch) {
                any_slashable = true;
            }
        }
        false
    });
    if !any_slashable {
        return false;
    }

    sig_batch.clear();
    for (ia_off, ia_end, indices) in [(off1, off2, i1), (off2, slashing.len(), i2)] {
        let ia = &slashing[ia_off..ia_end];
        let target_epoch = IndexedAttestationView::target_epoch(ia);
        let fv = bls::fork_version_at_epoch(fork_epoch, prev_ver, cur_ver, target_epoch);
        let n_idx = indices.len() / 8;
        for k in 0..n_idx {
            let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as usize;
            if vi >= count {
                return false;
            }
        }
        let data_chunk: &[u8; 128] = IndexedAttestationView::data(ia);
        let sig: &[u8; 96] = IndexedAttestationView::signature(ia);
        let object_root = ssz_hash::hash_attestation_data(data_chunk);
        let domain = bls::compute_domain(bls::DOMAIN_BEACON_ATTESTER, fv, &gvr);
        let signing_root = bls::compute_signing_root(&object_root, &domain);
        sig_batch.push_aggregate(
            (0..n_idx).map(|k| {
                let vi = u64::from_le_bytes(indices[k * 8..k * 8 + 8].try_into().unwrap()) as u32;
                view.validators.pubkey_decompressed(vi as usize)
            }),
            sig,
            signing_root,
        );
    }
    sig_batch.verify_all()
}

/// View an IndexedAttestation's attesting_indices SSZ bytes (skips the 228
/// byte fixed part: indices_offset(4) + data(128) + sig(96)).
#[inline]
pub(crate) fn attesting_indices_bytes(data: &[u8], start: usize, end: usize) -> &[u8] {
    if start + 228 > end || end > data.len() {
        return &[];
    }
    let slice = &data[start + 228..end];
    let whole = slice.len() - slice.len() % 8;
    &slice[..whole]
}

fn slash_validator(
    cfg: &SpecConfig,
    slot: &mut SlotStateWriteView,
    validators: &mut ValidatorsWriteView,
    balances: &mut BalancesWriteView,
    vi: u32,
    proposer_index: u32,
) {
    let current_epoch = slot.state().slot / SLOTS_PER_EPOCH;
    let effective_balance = validators.effective_balance(vi as usize);

    initiate_validator_exit(cfg, slot, validators, vi, current_epoch);
    validators.set_slashed(vi, true);
    let prev_wd = validators.withdrawable_epoch(vi as usize);
    let new_wd = max(prev_wd, current_epoch + EPOCHS_PER_SLASHINGS_VECTOR as u64);
    validators.set_withdrawable_epoch(vi, new_wd);

    // Per-block accumulator for the in-progress epoch (flushed at the boundary
    // by process_slashings_reset into `epoch.slashings`).
    let acc = slot.state_mut().current_epoch_slashings.saturating_add(effective_balance);
    slot.state_mut().current_epoch_slashings = acc;

    let penalty = effective_balance / cfg.min_slashing_penalty_quotient;
    let bal_vi = balances.get(vi as usize);
    balances.set(vi, bal_vi.saturating_sub(penalty));

    // Spec: increase_balance(proposer, proposer_reward); increase_balance(
    // whistleblower, whistleblower_reward - proposer_reward). With no
    // explicit whistleblower (block-included slashings), whistleblower_index
    // defaults to proposer_index, so the proposer receives the full
    // whistleblower_reward.
    let whistleblower_reward = effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT;
    let bal_pi = balances.get(proposer_index as usize);
    balances.set(proposer_index, bal_pi.saturating_add(whistleblower_reward));
}

pub(crate) fn is_slashable_attestation_data(d1: &[u8], d2: &[u8]) -> bool {
    if d1.len() < ATTESTATION_DATA_SIZE || d2.len() < ATTESTATION_DATA_SIZE {
        return false;
    }
    let d1f: &[u8; ATTESTATION_DATA_SIZE] = d1[..ATTESTATION_DATA_SIZE].try_into().unwrap();
    let d2f: &[u8; ATTESTATION_DATA_SIZE] = d2[..ATTESTATION_DATA_SIZE].try_into().unwrap();
    let s1 = AttestationDataView::source_epoch(d1f);
    let t1 = AttestationDataView::target_epoch(d1f);
    let s2 = AttestationDataView::source_epoch(d2f);
    let t2 = AttestationDataView::target_epoch(d2f);

    // Double vote: distinct data, same target epoch.
    if d1 != d2 && t1 == t2 {
        return true;
    }
    // Surround vote: data_1 surrounds data_2.
    s1 < s2 && t2 < t1
}

/// Spec: SSZ List[uint64] invariant — strictly ascending.
pub(crate) fn indices_sorted_unique(indices: &[u8]) -> bool {
    let n = indices.len() / 8;
    if n < 2 {
        return true;
    }
    let read = |i: usize| u64::from_le_bytes(indices[i * 8..i * 8 + 8].try_into().unwrap());
    let mut prev = read(0);
    for i in 1..n {
        let curr = read(i);
        if curr <= prev {
            return false;
        }
        prev = curr;
    }
    true
}
