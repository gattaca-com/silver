//! BLS verify benches.
//!
//! Run: cargo bench -p silver_beacon_state --bench bls_verify

use std::path::{Path, PathBuf};

use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use silver_beacon_state::{
    bls::{self, DOMAIN_BEACON_ATTESTER, DST, SigBatch},
    shuffling,
    ssz_hash::hash_attestation_data,
    state_transition::{
        self, ShufflingRef, collect_sigs_attestations, collect_sigs_attester_slashings,
        collect_sigs_bls_to_execution_changes, collect_sigs_proposer_slashings,
        collect_sigs_randao, collect_sigs_sync_aggregate, collect_sigs_voluntary_exits,
    },
};
use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH, SpecConfig, StateReadView};
use silver_common::ssz_view::{
    BLOCK_SYNC_AGGREGATE_SIZE, BeaconBlockBodyView, SINGLE_ATT_SIZE, SignedBeaconBlockView,
};

fn keypair(seed: u64) -> (SecretKey, PublicKey) {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    (sk, pk)
}

// ---- (1) Gossip single-attestation verify ---------------------------------

fn bench_verify_single_attestation(c: &mut Criterion) {
    let (sk, pk) = keypair(0);
    let gvr: B256 = [0u8; 32];
    let fork_version = [0u8; 4];

    let mut buf = [0u8; SINGLE_ATT_SIZE];
    buf[16..24].copy_from_slice(&100u64.to_le_bytes()); // slot
    buf[32] = 0xAA; // beacon_block_root[0]
    let data: &[u8; 128] = buf[16..144].try_into().unwrap();
    let object_root = hash_attestation_data(data);
    let domain = bls::compute_domain(DOMAIN_BEACON_ATTESTER, fork_version, &gvr);
    let signing_root = bls::compute_signing_root(&object_root, &domain);
    buf[144..240].copy_from_slice(&sk.sign(&signing_root, DST, &[]).to_bytes());

    c.bench_function("verify_single_attestation", |b| {
        b.iter(|| bls::verify_single_attestation(&buf, &pk, fork_version, &gvr))
    });
}

// ---- (2) Synthetic worst-case envelope ------------------------------------

/// Aggregate N signers into one (pk, sig) over `msg`.
fn aggregate(signers: &[(SecretKey, PublicKey)], msg: B256) -> (PublicKey, [u8; 96]) {
    let sigs: Vec<Signature> = signers.iter().map(|(sk, _)| sk.sign(&msg, DST, &[])).collect();
    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let sig = AggregateSignature::aggregate(&sig_refs, true).unwrap().to_signature().to_bytes();
    let pk_refs: Vec<&PublicKey> = signers.iter().map(|(_, pk)| pk).collect();
    let pk = AggregatePublicKey::aggregate(&pk_refs, false).unwrap().to_public_key();
    (pk, sig)
}

fn push(batch: &mut SigBatch, signers: &[(SecretKey, PublicKey)], msg: B256) {
    let (pk, sig) = aggregate(signers, msg);
    batch.push_one(&pk, &sig, msg);
}

/// Spec MAX_* shape: 1 randao + 16·2 proposer-slashing sigs + 16·2 attester-
/// slashing IAs (8 participants each) + 8 attestations (128 each) + 16 exits
/// + 16 bls_changes + 1 sync_aggregate (256) = 106 batch entries.
fn build_synthetic_envelope() -> SigBatch {
    let mut batch = SigBatch::new();
    let mut next = 0u64;
    let mut keys = |n: u64| -> Vec<(SecretKey, PublicKey)> {
        let s = next;
        next += n;
        (s..s + n).map(keypair).collect()
    };
    let msg = |tag: u8, idx: u8| -> B256 {
        let mut m = [0u8; 32];
        m[0] = tag;
        m[1] = idx;
        m
    };

    push(&mut batch, &keys(1), msg(0x01, 0)); // randao

    for s in 0..16u8 {
        let signers = keys(1); // same validator signs both headers
        push(&mut batch, &signers, msg(0x10, s));
        push(&mut batch, &signers, msg(0x11, s));
    }
    for s in 0..16u8 {
        for ia in 0..2u8 {
            push(&mut batch, &keys(8), msg(0x30 + s, ia));
        }
    }
    for a in 0..8u8 {
        push(&mut batch, &keys(128), msg(0x50, a));
    }
    for e in 0..16u8 {
        push(&mut batch, &keys(1), msg(0x60, e));
    }
    for c in 0..16u8 {
        push(&mut batch, &keys(1), msg(0x70, c));
    }
    push(&mut batch, &keys(256), [0xFFu8; 32]); // sync_aggregate

    batch
}

// ---- (3) EF block envelope from a real spec-test fixture ------------------

fn spec_tests_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("consensus-spec-tests")
}

#[path = "../tests/support/loaded_state.rs"]
mod loaded_state;
use loaded_state::{load_state, snappy_decode};

fn load_pre_at(dir: &Path) -> loaded_state::LoadedState {
    load_state(&dir.join("pre.ssz_snappy"))
}

fn shuffle_for_epoch(view: &StateReadView, e: u64) -> (Vec<u32>, usize) {
    let seed = shuffling::get_seed_from_state(
        &view.epoch,
        &view.slot,
        e,
        shuffling::DOMAIN_BEACON_ATTESTER,
    );
    let mut active = Vec::new();
    shuffling::get_active_validator_indices_into(&view.validators, e, &mut active);
    let committees_per_slot = shuffling::committees_per_slot(active.len());
    shuffling::shuffle_list(&mut active, &seed);
    (active, committees_per_slot)
}

fn build_ef_block() -> SigBatch {
    let dir = spec_tests_dir().join("tests/mainnet/fulu/sanity/blocks/pyspec_tests/attestation");
    let mut s = load_pre_at(&dir);
    let block = snappy_decode(&dir.join("blocks_0.ssz_snappy"));

    let block_slot = SignedBeaconBlockView::slot(&block);
    let proposer_index = SignedBeaconBlockView::proposer_index(&block);
    let body = SignedBeaconBlockView::body(&block);

    let cfg = SpecConfig::mainnet();
    let sid = s.state_id;
    let (mut view, epoch_group, longtail_group) = s.view();

    let mut scratch = state_transition::StfScratch::new(0);
    let (epoch_idx, longtail_idx) = if block_slot > view.slot.state().slot {
        state_transition::process_slots(
            &cfg,
            &mut view,
            epoch_group,
            longtail_group,
            sid,
            block_slot,
            &mut scratch,
        )
    } else {
        (sid.epoch_idx, sid.longtail_idx)
    };

    let rv = view.read(epoch_group.view_opt(epoch_idx), longtail_group.view_opt(longtail_idx));
    let validators = rv.validators;

    let curr_epoch = block_slot / SLOTS_PER_EPOCH;
    let prev_epoch = curr_epoch.saturating_sub(1);
    let (curr_shuffled, curr_committees_per_slot) = shuffle_for_epoch(&rv, curr_epoch);
    let (prev_shuffled, prev_committees_per_slot) = shuffle_for_epoch(&rv, prev_epoch);
    let sref = ShufflingRef {
        curr_epoch,
        curr_shuffled: &curr_shuffled,
        curr_committees_per_slot,
        prev_epoch,
        prev_shuffled: &prev_shuffled,
        prev_committees_per_slot,
    };

    let ps = BeaconBlockBodyView::proposer_slashings_offset(body) as usize;
    let at_s = BeaconBlockBodyView::attester_slashings_offset(body) as usize;
    let att = BeaconBlockBodyView::attestations_offset(body) as usize;
    let dep = BeaconBlockBodyView::deposits_offset(body) as usize;
    let ve = BeaconBlockBodyView::voluntary_exits_offset(body) as usize;
    let exec = BeaconBlockBodyView::execution_payload_offset(body) as usize;
    let bls_ = BeaconBlockBodyView::bls_to_execution_changes_offset(body) as usize;
    let blob = BeaconBlockBodyView::blob_kzg_commitments_offset(body) as usize;

    let mut batch = SigBatch::new();
    let mut scratch = Vec::new();
    let imm = rv.imm;
    let proposer_pk = validators.pubkey_decompressed(proposer_index as usize);

    collect_sigs_randao(imm, body, block_slot, proposer_pk, &mut batch);
    let _ = collect_sigs_proposer_slashings(imm, &validators, &body[ps..at_s], &mut batch);
    let _ = collect_sigs_attester_slashings(
        imm,
        &validators,
        &body[at_s..att],
        &mut scratch,
        &mut batch,
    );
    let _ = collect_sigs_attestations(
        imm,
        &validators,
        &body[att..dep],
        block_slot,
        Some(&sref),
        &mut scratch,
        &mut batch,
    );
    // deposits skipped — verified inline in apply_deposit.
    collect_sigs_voluntary_exits(imm, &validators, &body[ve..exec], &mut batch);
    let _ = collect_sigs_bls_to_execution_changes(imm, &validators, &body[bls_..blob], &mut batch);
    collect_sigs_sync_aggregate(
        &rv,
        &body[220..220 + BLOCK_SYNC_AGGREGATE_SIZE],
        block_slot,
        &mut scratch,
        &mut batch,
    );

    batch
}

// ---- (4) Top-level registration -------------------------------------------

fn bench_pair<F: Fn() -> SigBatch>(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    build: F,
) {
    let mut for_batch = build();
    let for_seq = build();
    assert!(for_batch.verify_all() && for_seq.verify_each_sequential(), "pre-flight verify failed",);
    eprintln!("  {} entries", for_batch.len());
    group.bench_function("batch", move |b| b.iter(|| for_batch.verify_all()));
    group.bench_function("sequential", move |b| b.iter(|| for_seq.verify_each_sequential()));
}

fn bench_envelopes(c: &mut Criterion) {
    {
        let mut g = c.benchmark_group("synthetic_envelope");
        bench_pair(&mut g, build_synthetic_envelope);
    }
    {
        let mut g = c.benchmark_group("ef_block_envelope");
        bench_pair(&mut g, build_ef_block);
    }
}

criterion_group!(benches, bench_verify_single_attestation, bench_envelopes);
criterion_main!(benches);
