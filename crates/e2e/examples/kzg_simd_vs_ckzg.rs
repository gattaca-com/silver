//! Times silver's KZG paths, which use `silver_crypto_simd::kzg`, against
//! c-kzg on the DA capture, after checking that both give the same verdicts
//! and cells.
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
    slice,
    time::{Duration, Instant},
};

use c_kzg::{Blob, Bytes48, Cell, CkzgError, KzgProof, KzgSettings, ethereum_kzg_settings};
use silver_common::{
    column_util::{CellScratch, KzgBatchEntry, KzgScratch, kzg_verify_batch_multi},
    ssz_view::{BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, DataColumnSidecarFuluView},
};
use silver_crypto_simd::{
    ifma_available,
    kzg::{BYTES_PER_BLOB, CELLS_PER_EXT_BLOB},
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

fn silver_verify(sidecars: &[&[u8]], scratch: &mut KzgScratch) -> bool {
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

/// c-kzg's flat staging buffers, as silver gathered them before using
/// `silver_crypto_simd::kzg`.
#[derive(Default)]
struct CkzgScratch {
    cells: Vec<u8>,
    commitments: Vec<u8>,
    proofs: Vec<u8>,
    indices: Vec<u64>,
}

impl CkzgScratch {
    fn verify(&mut self, sidecars: &[&[u8]]) -> bool {
        self.cells.clear();
        self.commitments.clear();
        self.proofs.clear();
        self.indices.clear();
        for s in sidecars {
            let column = DataColumnSidecarFuluView::column(s);
            self.cells.extend_from_slice(column);
            self.commitments.extend_from_slice(DataColumnSidecarFuluView::kzg_commitments(s));
            self.proofs.extend_from_slice(DataColumnSidecarFuluView::kzg_proofs(s));
            self.indices.extend(repeat_n(
                DataColumnSidecarFuluView::index(s),
                column.len() / BYTES_PER_CELL,
            ));
        }
        let n = self.indices.len();
        if n == 0 {
            return true;
        }
        // SAFETY: `Cell` and `Bytes48` are `#[repr(C)]` byte arrays (align 1),
        // and each buffer holds exactly `n` of them.
        let (cells, commitments, proofs) = unsafe {
            (
                slice::from_raw_parts(self.cells.as_ptr() as *const Cell, n),
                slice::from_raw_parts(self.commitments.as_ptr() as *const Bytes48, n),
                slice::from_raw_parts(self.proofs.as_ptr() as *const Bytes48, n),
            )
        };
        matches!(
            ethereum_kzg_settings(0).verify_cell_kzg_proof_batch(
                commitments,
                &self.indices,
                cells,
                proofs
            ),
            Ok(true)
        )
    }
}

unsafe extern "C" {
    fn compute_cells_and_kzg_proofs(
        cells: *mut Cell,
        proofs: *mut KzgProof,
        blob: *const Blob,
        settings: *const KzgSettings,
    ) -> CkzgError;
}

/// c-kzg's cells into a reused array, as silver computed them before using
/// `silver_crypto_simd::kzg`. `KzgSettings::compute_cells` would box a fresh
/// array per blob; the binding keeps this C entry point private, and
/// `extern "C"` does not check its signature against c-kzg's.
struct CkzgCells(Box<[Cell; CELLS_PER_EXT_BLOB]>);

impl Default for CkzgCells {
    fn default() -> Self {
        let cells = vec![Cell::default(); CELLS_PER_EXT_BLOB].into_boxed_slice();
        Self(cells.try_into().unwrap_or_else(|_| unreachable!()))
    }
}

impl CkzgCells {
    fn compute(&mut self, blob: &[u8; BYTES_PER_BLOB]) -> Option<&[Cell; CELLS_PER_EXT_BLOB]> {
        // SAFETY: Blob is repr(C) over [u8; BYTES_PER_BLOB]; null proofs are skipped.
        let result = unsafe {
            compute_cells_and_kzg_proofs(
                self.0.as_mut_ptr(),
                std::ptr::null_mut(),
                blob.as_ptr().cast(),
                ethereum_kzg_settings(0),
            )
        };
        matches!(result, CkzgError::C_KZG_OK).then_some(&*self.0)
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
    assert!(ifma_available(), "this CPU has no avx512ifma; crypto_simd would not use its kernel");
    let capture = ColumnFixtures::da().load();
    ethereum_kzg_settings(0);

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
    let mut ckzg = CkzgScratch::default();
    let mut corrupted = by_arrival[0].to_vec();
    let first_cell = DataColumnSidecarFuluView::column(by_arrival[0]).as_ptr().addr() -
        by_arrival[0].as_ptr().addr();
    corrupted[first_cell + BYTES_PER_CELL - 1] ^= 1;
    assert!(!ckzg.verify(&[&corrupted]), "c-kzg rejects a corrupted cell");
    assert!(!silver_verify(&[&corrupted], &mut scratch), "crypto_simd rejects it");

    let mut table = Table::new(vec![
        Column::right("columns"),
        Column::right("cells"),
        Column::right("c-kzg"),
        Column::right("crypto_simd"),
        Column::right("speed-up"),
    ]);
    for columns in [1usize, 2, 4, 8, 16, 32, 64, 128] {
        let batch = &by_arrival[..columns];
        assert!(ckzg.verify(batch), "c-kzg accepts {columns} columns");
        assert!(silver_verify(batch, &mut scratch), "crypto_simd accepts {columns} columns");
        let theirs = best_of(|| ckzg.verify(batch));
        let ours = best_of(|| silver_verify(batch, &mut scratch));
        table.row(vec![
            columns.to_string(),
            (columns * blob_count).to_string(),
            format!("{:.2}ms", ms(theirs)),
            format!("{:.2}ms", ms(ours)),
            format!("{:.2}x", theirs.as_secs_f64() / ours.as_secs_f64()),
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

    let mut ckzg_cells = CkzgCells::default();
    let mut cell_scratch = CellScratch::default();
    for (b, blob) in all_blobs.iter().enumerate() {
        let expected = ckzg_cells.compute(blob).expect("c-kzg accepts a captured blob");
        let cells = cell_scratch.compute(blob).expect("crypto_simd accepts a captured blob");
        for (k, cell) in cells.iter().enumerate() {
            assert!(*cell == expected[k].to_bytes(), "blob {b}, cell {k}");
        }
    }
    let ckzg = best_of(|| {
        for blob in &all_blobs {
            black_box(ckzg_cells.compute(blob).unwrap());
        }
    });
    let ours = best_of(|| {
        for blob in &all_blobs {
            black_box(cell_scratch.compute(blob).unwrap());
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
