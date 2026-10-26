//! Checks the AVX-512 IFMA decompression + membership path against blst on
//! every KZG proof and commitment in the DA capture, then times both on the
//! slot with the most blobs.
//!
//!   cargo run --release -p silver_e2e --example kzg_simd_check

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use blst::{BLST_ERROR, blst_p1_affine_in_g1, blst_p1_uncompress};
use silver_common::ssz_view::{BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView};
use silver_crypto_simd::{
    bls::{COMPRESSED_LEN, G1Point, blst_p1_affine, uncompress_in_g1},
    ifma_available,
};
use silver_e2e::da_capture::ColumnFixtures;

const REPS: usize = 5;

/// `Some` iff blst accepts the encoding as a point of G1.
fn uncompress_in_g1_blst(bytes: &[u8; COMPRESSED_LEN]) -> Option<blst_p1_affine> {
    let mut point = blst_p1_affine::default();
    // SAFETY: both pointers are valid for the lengths blst reads and writes.
    let member = unsafe {
        blst_p1_uncompress(&mut point, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS &&
            blst_p1_affine_in_g1(&point)
    };
    member.then_some(point)
}

fn best_of<R>(mut f: impl FnMut() -> R) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPS {
        let t = Instant::now();
        black_box(f());
        best = best.min(t.elapsed());
    }
    best
}

fn encodings(sidecar: &[u8]) -> impl Iterator<Item = [u8; COMPRESSED_LEN]> + '_ {
    DataColumnSidecarFuluView::kzg_proofs(sidecar)
        .chunks_exact(COMPRESSED_LEN)
        .chain(DataColumnSidecarFuluView::kzg_commitments(sidecar).chunks_exact(COMPRESSED_LEN))
        .map(|c| c.try_into().expect("48 bytes"))
}

fn serialized(p: &Option<blst_p1_affine>) -> Option<[u64; 12]> {
    p.map(|p| {
        let mut out = [0u64; 12];
        out[..6].copy_from_slice(&p.x.l);
        out[6..].copy_from_slice(&p.y.l);
        out
    })
}

fn main() {
    assert!(ifma_available(), "this CPU has no avx512ifma; nothing to check");
    let cap = ColumnFixtures::da().load();

    let mut all: Vec<[u8; COMPRESSED_LEN]> = Vec::new();
    for slot in cap.slots.values() {
        for sidecar in slot.sidecars.values() {
            all.extend(encodings(sidecar));
        }
    }
    // Corrupt a spread of copies so the rejecting paths are compared too.
    let clean = all.len();
    for i in (0..clean).step_by(97) {
        let mut bad = all[i];
        bad[1 + (i % 40)] ^= 0x40;
        all.push(bad);
    }

    let mut simd = vec![None; all.len()];
    uncompress_in_g1(&all, &mut simd);
    let mut mismatches = 0;
    let mut accepted = 0;
    for (i, input) in all.iter().enumerate() {
        let want = uncompress_in_g1_blst(input);
        accepted += want.is_some() as usize;
        if serialized(&simd[i].map(G1Point::into_blst)) != serialized(&want) {
            mismatches += 1;
            if mismatches <= 5 {
                eprintln!(
                    "mismatch at {i}: simd {:?} blst {:?}",
                    simd[i].is_some(),
                    want.is_some()
                );
            }
        }
    }
    println!(
        "{} encodings from {} slots ({clean} genuine, {} corrupted): blst accepted {accepted}, \
         mismatches {mismatches}",
        all.len(),
        cap.slots.len(),
        all.len() - clean
    );
    assert_eq!(mismatches, 0);

    let (slot, capture) = cap
        .slots
        .iter()
        .max_by_key(|(_, c)| {
            DataColumnSidecarFuluView::kzg_commitments(c.sidecars.values().next().unwrap()).len()
        })
        .unwrap();
    let proofs: Vec<[u8; COMPRESSED_LEN]> = capture
        .sidecars
        .values()
        .flat_map(|s| {
            DataColumnSidecarFuluView::kzg_proofs(s)
                .chunks_exact(COMPRESSED_LEN)
                .map(|c| c.try_into().expect("48 bytes"))
        })
        .collect();
    let blobs = DataColumnSidecarFuluView::kzg_commitments(
        capture.sidecars.values().next().unwrap(),
    )
    .len() /
        BYTES_PER_KZG_COMMITMENT;
    let n = proofs.len();
    let scalar = best_of(|| {
        for proof in &proofs {
            black_box(uncompress_in_g1_blst(proof));
        }
    });
    let mut out = vec![None; n];
    let vector = best_of(|| {
        uncompress_in_g1(&proofs, &mut out);
        black_box(&out);
    });
    println!(
        "slot {slot}: {blobs} blobs, {n} proofs (uncompress + subgroup check), best of {REPS}"
    );
    println!(
        "  blst scalar   {:8.2} ms  {:6.2} us/pt",
        scalar.as_secs_f64() * 1e3,
        scalar.as_secs_f64() * 1e6 / n as f64
    );
    println!(
        "  avx512 ifma   {:8.2} ms  {:6.2} us/pt  ({:.2}x)",
        vector.as_secs_f64() * 1e3,
        vector.as_secs_f64() * 1e6 / n as f64,
        scalar.as_secs_f64() / vector.as_secs_f64()
    );
}
