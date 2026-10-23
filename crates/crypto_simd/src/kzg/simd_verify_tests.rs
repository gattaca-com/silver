use c_kzg::{KzgSettings, ethereum_kzg_settings};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::simd_available,
    kzg::{
        BYTES_PER_CELL, CELLS_PER_EXT_BLOB, CellBatchVerifier, SimdCellBatchVerifier,
        tests::{Batch, BlobFixture, add_modulus, blobs, random_batch},
    },
};

const SEED: u64 = 0x5349_4d44_7665_7269;
const DA_BLOBS: usize = 18;

fn simd_verifier() -> Option<SimdCellBatchVerifier> {
    let verifier = SimdCellBatchVerifier::new();
    assert!(
        verifier.is_some() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    assert_eq!(verifier.is_some(), simd_available());
    verifier
}

struct Verifiers {
    simd: SimdCellBatchVerifier,
    scalar: CellBatchVerifier,
    settings: &'static KzgSettings,
}

impl Verifiers {
    fn new() -> Option<Self> {
        Some(Self {
            simd: simd_verifier()?,
            scalar: CellBatchVerifier::new(),
            settings: ethereum_kzg_settings(0),
        })
    }

    /// The verdict, after asserting that all three verifiers give it.
    fn verdict(&mut self, batch: &Batch, name: &str) -> bool {
        let expected = batch.ckzg(self.settings);
        assert_eq!(batch.ours(&mut self.scalar), expected, "{name}: CellBatchVerifier");
        let simd =
            self.simd.verify(&batch.commitments, &batch.cell_indices, &batch.cells, &batch.proofs);
        assert_eq!(simd, expected, "{name}: SimdCellBatchVerifier");
        expected
    }
}

fn da_batch(blobs: &[BlobFixture], columns: &[usize]) -> Batch {
    let mut batch = Batch::default();
    for &column in columns {
        for blob in blobs {
            batch.push(blob, column);
        }
    }
    batch
}

#[test]
fn valid_batches_verify() {
    let Some(mut verifiers) = Verifiers::new() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let blobs = blobs(&mut rng, verifiers.settings, 3);

    let mut sizes: Vec<usize> = (0..=17).collect();
    sizes.extend([64, 129]);
    for size in sizes {
        let batch = random_batch(&mut rng, &blobs, size);
        assert!(verifiers.verdict(&batch, &format!("size {size}")), "size {size}");
    }

    let mut whole = Batch::default();
    for cell in 0..CELLS_PER_EXT_BLOB {
        whole.push(&blobs[0], cell);
    }
    assert!(verifiers.verdict(&whole, "every cell of one blob"));
}

#[test]
fn da_shaped_batches_verify() {
    let Some(mut verifiers) = Verifiers::new() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    let blobs = blobs(&mut rng, verifiers.settings, DA_BLOBS);
    for count in [1, 2, 4, 8, 64] {
        let columns: Vec<usize> = (0..count).map(|i| (i * 37 + 5) % CELLS_PER_EXT_BLOB).collect();
        let batch = da_batch(&blobs, &columns);
        assert!(verifiers.verdict(&batch, &format!("{count} columns")), "{count} columns");

        let mut corrupted = batch.clone();
        let k = rng.gen_range(0..corrupted.cells.len());
        corrupted.cells[k][rng.gen_range(0..BYTES_PER_CELL)] ^= 1;
        assert!(!verifiers.verdict(&corrupted, &format!("{count} columns, corrupted")));
    }
}

#[test]
fn corrupted_batches_match() {
    let Some(mut verifiers) = Verifiers::new() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    let blobs = blobs(&mut rng, verifiers.settings, 2);

    let mut rejected = 0;
    for case in 0..108 {
        let size = rng.gen_range(1..12);
        let mut batch = random_batch(&mut rng, &blobs, size);
        let k = rng.gen_range(0..batch.cells.len());
        match case % 9 {
            0 => batch.cells[k][rng.gen_range(0..BYTES_PER_CELL)] ^= 1 << rng.gen_range(0..8),
            1 => batch.cells[k][32 * rng.gen_range(0..64)] = 0xff,
            2 => batch.proofs[k][rng.gen_range(0..48)] ^= 1 << rng.gen_range(0..8),
            3 => batch.commitments[k][rng.gen_range(0..48)] ^= 1 << rng.gen_range(0..8),
            4 => batch.cell_indices[k] = (batch.cell_indices[k] + 1) % CELLS_PER_EXT_BLOB as u64,
            5 => batch.cell_indices[k] = CELLS_PER_EXT_BLOB as u64 + rng.gen_range(0..1000),
            6 => {
                let other = random_batch(&mut rng, &blobs, 1);
                batch.proofs[k] = other.proofs[0];
            }
            7 => {
                batch.cells.pop();
            }
            _ => {
                let at = 32 * rng.gen_range(0..64);
                add_modulus(&mut batch.cells[k][at..at + 32]);
            }
        }
        rejected += !verifiers.verdict(&batch, &format!("case {case}")) as usize;
    }
    assert!(rejected > 90, "most corruptions are rejected: {rejected}");
}

#[test]
fn repeated_cells_and_negated_proofs() {
    let Some(mut verifiers) = Verifiers::new() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let blobs = blobs(&mut rng, verifiers.settings, 2);

    let mut twice = Batch::default();
    twice.push(&blobs[0], 7);
    twice.push(&blobs[0], 7);
    assert!(verifiers.verdict(&twice, "the same cell twice"));

    let mut negated = Batch::default();
    negated.push(&blobs[0], 7);
    negated.push(&blobs[0], 7);
    negated.proofs[1][0] ^= 0x20;
    assert!(!verifiers.verdict(&negated, "a proof and its negation"));

    let mut mixed = random_batch(&mut rng, &blobs, 9);
    mixed.push(&blobs[1], 3);
    mixed.push(&blobs[1], 3);
    mixed.proofs[10][0] ^= 0x20;
    verifiers.verdict(&mixed, "a negated proof among others");
}

#[test]
fn one_instance_serves_many_batches() {
    let Some(mut verifiers) = Verifiers::new() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 4);
    let blobs = blobs(&mut rng, verifiers.settings, 3);
    for size in [20, 1, 0, 70, 3, 1] {
        let batch = random_batch(&mut rng, &blobs, size);
        assert!(verifiers.verdict(&batch, &format!("size {size}")));
    }
}

#[test]
fn few_and_many_columns_verify_alike() {
    let Some(mut verifiers) = Verifiers::new() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 5);
    let blobs = blobs(&mut rng, verifiers.settings, 6);
    for count in 1..=8 {
        let columns: Vec<usize> = (0..count).map(|i| (i * 19 + 3) % CELLS_PER_EXT_BLOB).collect();
        let batch = da_batch(&blobs, &columns);
        assert!(verifiers.verdict(&batch, &format!("{count} columns")), "{count} columns");

        let mut corrupted = batch.clone();
        let k = rng.gen_range(0..corrupted.cells.len());
        corrupted.proofs[k][rng.gen_range(1..48)] ^= 1 << rng.gen_range(0..8);
        verifiers.verdict(&corrupted, &format!("{count} columns, corrupted proof"));

        let mut swapped = batch.clone();
        let k = rng.gen_range(1..swapped.cells.len());
        swapped.commitments.swap(0, k);
        swapped.cell_indices.swap(0, k);
        swapped.cells.swap(0, k);
        swapped.proofs.swap(0, k);
        assert!(verifiers.verdict(&swapped, &format!("{count} columns, cells reordered")));
    }
}
