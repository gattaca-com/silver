//! Times `silver_crypto_simd::kzg` against silver's c-kzg paths on the DA
//! capture, after checking that both give the same verdicts and cells.
//!
//!   cargo run --release -p silver_e2e --example kzg_simd_vs_ckzg
//!
//! Verification runs on growing batches of the sidecars of the slot with the
//! most blobs, in arrival order. Both sides gather the batch from the sidecars
//! inside the timed call, as silver does. Cells are computed for every blob of
//! the capture, each rebuilt from its first 64 cells.

use std::{
    hint::black_box,
    iter::repeat_n,
    time::{Duration, Instant},
};

use silver_common::{
    column_util::{
        CellScratch, KzgBatchEntry, KzgScratch, cell_bytes, kzg_verify_batch_multi,
        warm_kzg_settings,
    },
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DataColumnSidecarFuluView,
    },
};
use silver_crypto_simd::{
    bls::simd_available,
    kzg::{BYTES_PER_BLOB, CELLS_PER_EXT_BLOB, CellBatchVerifier, CellExtender},
};
use silver_e2e::da_capture::ColumnFixtures;
use silver_metrics::table::{Column, Table};

const REPS: usize = 5;

fn best_of<R>(mut f: impl FnMut() -> R) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPS {
        let t = Instant::now();
        black_box(f());
        best = best.min(t.elapsed());
    }
    best
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn ckzg_verify(sidecars: &[&[u8]], scratch: &mut KzgScratch) -> bool {
    kzg_verify_batch_multi(
        sidecars.iter().map(|s| KzgBatchEntry {
            column: DataColumnSidecarFuluView::column(s),
            commitments: DataColumnSidecarFuluView::kzg_commitments(s),
            proofs: DataColumnSidecarFuluView::kzg_proofs(s),
            index: DataColumnSidecarFuluView::index(s),
        }),
        scratch,
    )
}

/// A batch in `CellBatchVerifier`'s layout, one entry per cell.
#[derive(Default)]
struct Gathered {
    commitments: Vec<[u8; BYTES_PER_KZG_COMMITMENT]>,
    cell_indices: Vec<u64>,
    cells: Vec<[u8; BYTES_PER_CELL]>,
    proofs: Vec<[u8; BYTES_PER_KZG_PROOF]>,
}

impl Gathered {
    fn verify(&mut self, sidecars: &[&[u8]], verifier: &mut CellBatchVerifier) -> bool {
        self.commitments.clear();
        self.cell_indices.clear();
        self.cells.clear();
        self.proofs.clear();
        for s in sidecars {
            let column = DataColumnSidecarFuluView::column(s);
            let cells = column.chunks_exact(BYTES_PER_CELL);
            self.cell_indices.extend(repeat_n(DataColumnSidecarFuluView::index(s), cells.len()));
            self.cells.extend(cells.map(|c| <[u8; BYTES_PER_CELL]>::try_from(c).unwrap()));
            self.commitments.extend(
                DataColumnSidecarFuluView::kzg_commitments(s)
                    .chunks_exact(BYTES_PER_KZG_COMMITMENT)
                    .map(|c| <[u8; BYTES_PER_KZG_COMMITMENT]>::try_from(c).unwrap()),
            );
            self.proofs.extend(
                DataColumnSidecarFuluView::kzg_proofs(s)
                    .chunks_exact(BYTES_PER_KZG_PROOF)
                    .map(|p| <[u8; BYTES_PER_KZG_PROOF]>::try_from(p).unwrap()),
            );
        }
        verifier.verify(&self.commitments, &self.cell_indices, &self.cells, &self.proofs)
    }
}

/// Blob b is the concatenation of cell b of columns 0 to 63.
fn blobs(sidecars: &[&[u8]]) -> Vec<Box<[u8; BYTES_PER_BLOB]>> {
    let count = DataColumnSidecarFuluView::column(sidecars[0]).len() / BYTES_PER_CELL;
    (0..count)
        .map(|b| {
            let mut blob = Box::new([0u8; BYTES_PER_BLOB]);
            for (k, chunk) in blob.chunks_exact_mut(BYTES_PER_CELL).enumerate() {
                let column = DataColumnSidecarFuluView::column(sidecars[k]);
                chunk.copy_from_slice(&column[b * BYTES_PER_CELL..(b + 1) * BYTES_PER_CELL]);
            }
            blob
        })
        .collect()
}

fn main() {
    assert!(simd_available(), "this CPU has no avx512ifma; crypto_simd would not use its kernel");
    let capture = ColumnFixtures::da().load();
    warm_kzg_settings();
    let mut verifier = CellBatchVerifier::new();
    let mut extender = CellExtender::new();

    let (slot, largest) = capture
        .slots
        .iter()
        .max_by_key(|(_, c)| {
            DataColumnSidecarFuluView::kzg_commitments(c.sidecars.values().next().unwrap()).len()
        })
        .unwrap();
    let by_arrival: Vec<&[u8]> =
        largest.arrivals.iter().map(|a| largest.sidecars[&a.index].as_slice()).collect();
    let blob_count =
        DataColumnSidecarFuluView::kzg_commitments(by_arrival[0]).len() / BYTES_PER_KZG_COMMITMENT;
    println!(
        "verify: slot {slot}, {blob_count} blobs, {} columns, best of {REPS}",
        by_arrival.len()
    );

    let mut scratch = KzgScratch::default();
    let mut gathered = Gathered::default();
    let mut corrupted = by_arrival[0].to_vec();
    let first_cell = DataColumnSidecarFuluView::column(by_arrival[0]).as_ptr().addr() -
        by_arrival[0].as_ptr().addr();
    corrupted[first_cell + BYTES_PER_CELL - 1] ^= 1;
    assert!(!ckzg_verify(&[&corrupted], &mut scratch), "c-kzg rejects a corrupted cell");
    assert!(!gathered.verify(&[&corrupted], &mut verifier), "crypto_simd rejects it");

    let mut table = Table::new(vec![
        Column::right("columns"),
        Column::right("cells"),
        Column::right("c-kzg"),
        Column::right("crypto_simd"),
        Column::right("speed-up"),
    ]);
    for columns in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        let batch = &by_arrival[..columns];
        assert!(ckzg_verify(batch, &mut scratch), "c-kzg accepts {columns} columns");
        assert!(gathered.verify(batch, &mut verifier), "crypto_simd accepts {columns} columns");
        let ckzg = best_of(|| ckzg_verify(batch, &mut scratch));
        let ours = best_of(|| gathered.verify(batch, &mut verifier));
        table.row(vec![
            columns.to_string(),
            (columns * blob_count).to_string(),
            format!("{:.2}ms", ms(ckzg)),
            format!("{:.2}ms", ms(ours)),
            format!("{:.2}x", ckzg.as_secs_f64() / ours.as_secs_f64()),
        ]);
    }
    print!("{}", table.render());

    let mut all_blobs = Vec::new();
    for slot in capture.slots.values() {
        let mut columns: Vec<_> = slot.sidecars.iter().collect();
        columns.sort_by_key(|(index, _)| **index);
        let sidecars: Vec<&[u8]> = columns.iter().map(|(_, s)| s.as_slice()).collect();
        assert!(sidecars.len() == CELLS_PER_EXT_BLOB, "slot holds every column");
        all_blobs.extend(blobs(&sidecars));
    }

    let mut ckzg_cells = CellScratch::default();
    let mut cells = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
    for (b, blob) in all_blobs.iter().enumerate() {
        let expected = ckzg_cells.compute(blob).expect("c-kzg accepts a captured blob");
        assert!(extender.compute(blob, &mut cells), "crypto_simd accepts blob {b}");
        for (k, cell) in cells.iter().enumerate() {
            assert!(cell == cell_bytes(&expected[k]), "blob {b}, cell {k}");
        }
    }
    let ckzg = best_of(|| {
        for blob in &all_blobs {
            black_box(ckzg_cells.compute(blob).unwrap());
        }
    });
    let ours = best_of(|| {
        for blob in &all_blobs {
            assert!(extender.compute(blob, &mut cells));
            black_box(&cells);
        }
    });
    let per_blob = |d: Duration| d.as_secs_f64() * 1e6 / all_blobs.len() as f64;
    println!(
        "cells: {} blobs from {} slots, best of {REPS}: c-kzg {:.1}us, crypto_simd {:.1}us per \
         blob ({:.2}x)",
        all_blobs.len(),
        capture.slots.len(),
        per_blob(ckzg),
        per_blob(ours),
        ckzg.as_secs_f64() / ours.as_secs_f64()
    );
}
