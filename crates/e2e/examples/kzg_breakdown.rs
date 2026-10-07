//! Where one `verify_cell_kzg_proof_batch` call spends its time, per batch
//! size, on the captured sidecars of the slot with the most blobs.
//!
//!   cargo run --release -p silver_e2e --example kzg_breakdown
//!
//! The total is the real c-kzg call through `kzg_verify_batch_multi`. Each
//! phase is the same arithmetic re-run through blst on the same inputs, so the
//! rows are independent measurements and `residual` is what the phases fail to
//! explain (c-kzg's IFFTs, scalar powers, dedup, allocations).

use std::{
    hint::black_box,
    ptr,
    time::{Duration, Instant},
};

use blst::{
    blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_fr, blst_fr_add,
    blst_fr_from_scalar, blst_fr_from_uint64, blst_fr_mul, blst_miller_loop, blst_p1,
    blst_p1_affine, blst_p1_affine_in_g1, blst_p1_uncompress, blst_p1s_mult_pippenger,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_p2_affine_generator, blst_scalar,
    blst_scalar_fr_check, blst_scalar_from_bendian, blst_scalar_from_fr, blst_sha256,
};
use silver_common::{
    column_util::{KzgBatchEntry, KzgScratch, kzg_verify_batch_multi, warm_kzg_settings},
    ssz_view::{
        BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, DataColumnSidecarFuluView,
    },
};
use silver_e2e::da_capture::ColumnFixtures;
use silver_metrics::table::{Column, Table};

const FIELD_ELEMENTS_PER_CELL: usize = BYTES_PER_CELL / 32;
const CELLS_PER_EXT_BLOB: usize = 128;
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

struct Batch<'a> {
    sidecars: Vec<&'a [u8]>,
    blobs: usize,
}

impl<'a> Batch<'a> {
    fn entries(&self) -> impl Iterator<Item = KzgBatchEntry<'a>> + '_ {
        self.sidecars.iter().map(|s| KzgBatchEntry {
            column: DataColumnSidecarFuluView::column(s),
            commitments: DataColumnSidecarFuluView::kzg_commitments(s),
            proofs: DataColumnSidecarFuluView::kzg_proofs(s),
            index: DataColumnSidecarFuluView::index(s),
        })
    }

    fn proof_bytes(&self) -> Vec<&'a [u8]> {
        self.sidecars
            .iter()
            .flat_map(|s| {
                DataColumnSidecarFuluView::kzg_proofs(s).chunks_exact(BYTES_PER_KZG_PROOF)
            })
            .collect()
    }

    fn cell_bytes(&self) -> Vec<(&'a [u8], usize)> {
        self.sidecars
            .iter()
            .flat_map(|s| {
                let index = DataColumnSidecarFuluView::index(s) as usize;
                DataColumnSidecarFuluView::column(s)
                    .chunks_exact(BYTES_PER_CELL)
                    .map(move |c| (c, index))
            })
            .collect()
    }

    fn commitment_bytes(&self) -> Vec<&'a [u8]> {
        DataColumnSidecarFuluView::kzg_commitments(self.sidecars[0])
            .chunks_exact(BYTES_PER_KZG_COMMITMENT)
            .collect()
    }
}

fn uncompress_all(points: &[&[u8]]) -> Vec<blst_p1_affine> {
    points
        .iter()
        .map(|p| {
            let mut out = blst_p1_affine::default();
            unsafe { blst_p1_uncompress(&mut out, p.as_ptr()) };
            out
        })
        .collect()
}

fn in_g1_all(points: &[blst_p1_affine]) -> bool {
    points.iter().all(|p| unsafe { blst_p1_affine_in_g1(p) })
}

/// c-kzg's challenge transcript: domain, sizes, commitments, indices, cells,
/// proofs — one buffer, one hash.
fn challenge_hash(batch: &Batch, cells: &[(&[u8], usize)], proofs: &[&[u8]]) -> [u8; 32] {
    let mut buf =
        Vec::with_capacity(64 + batch.blobs * 48 + cells.len() * (16 + BYTES_PER_CELL + 48));
    buf.extend_from_slice(b"RCKZGCBATCH__V1_");
    buf.extend_from_slice(&4096u64.to_be_bytes());
    buf.extend_from_slice(&(batch.blobs as u64).to_be_bytes());
    buf.extend_from_slice(&(cells.len() as u64).to_be_bytes());
    for c in batch.commitment_bytes() {
        buf.extend_from_slice(c);
    }
    for (i, (cell, index)) in cells.iter().enumerate() {
        buf.extend_from_slice(&((i % batch.blobs) as u64).to_be_bytes());
        buf.extend_from_slice(&(*index as u64).to_be_bytes());
        buf.extend_from_slice(cell);
        buf.extend_from_slice(proofs[i]);
    }
    let mut out = [0u8; 32];
    unsafe { blst_sha256(out.as_mut_ptr(), buf.as_ptr(), buf.len()) };
    out
}

fn powers(r: &blst_fr, n: usize) -> Vec<blst_fr> {
    let mut out = Vec::with_capacity(n);
    let mut acc = blst_fr::default();
    unsafe { blst_fr_from_uint64(&mut acc, [1u64, 0, 0, 0].as_ptr()) };
    for _ in 0..n {
        out.push(acc);
        let prev = acc;
        unsafe { blst_fr_mul(&mut acc, &prev, r) };
    }
    out
}

/// The vertical collapse: every field element of every cell scaled by its
/// power of r and summed into its column slot.
fn aggregate_cells(cells: &[(&[u8], usize)], r_powers: &[blst_fr]) -> Vec<blst_fr> {
    let mut agg = vec![blst_fr::default(); CELLS_PER_EXT_BLOB * FIELD_ELEMENTS_PER_CELL];
    for (k, (cell, column)) in cells.iter().enumerate() {
        for (j, fe) in cell.chunks_exact(32).enumerate() {
            let mut s = blst_scalar::default();
            let mut f = blst_fr::default();
            let mut scaled = blst_fr::default();
            let slot = &mut agg[column * FIELD_ELEMENTS_PER_CELL + j];
            unsafe {
                blst_scalar_from_bendian(&mut s, fe.as_ptr());
                assert!(blst_scalar_fr_check(&s));
                blst_fr_from_scalar(&mut f, &s);
                blst_fr_mul(&mut scaled, &f, &r_powers[k]);
                let prev = *slot;
                blst_fr_add(slot, &prev, &scaled);
            }
        }
    }
    agg
}

fn msm(points: &[blst_p1_affine], scalars: &[blst_fr]) -> blst_p1 {
    let scalars: Vec<blst_scalar> = scalars
        .iter()
        .map(|f| {
            let mut s = blst_scalar::default();
            unsafe { blst_scalar_from_fr(&mut s, f) };
            s
        })
        .collect();
    let mut scratch =
        vec![0u64; unsafe { blst_p1s_mult_pippenger_scratch_sizeof(points.len()) } / 8];
    let point_ptrs = [points.as_ptr(), ptr::null()];
    let scalar_ptrs = [scalars.as_ptr() as *const u8, ptr::null()];
    let mut out = blst_p1::default();
    unsafe {
        blst_p1s_mult_pippenger(
            &mut out,
            point_ptrs.as_ptr(),
            points.len(),
            scalar_ptrs.as_ptr(),
            255,
            scratch.as_mut_ptr(),
        )
    };
    out
}

fn pairing_check(a: &blst_p1_affine, b: &blst_p1_affine) -> bool {
    let mut l0 = blst_fp12::default();
    let mut l1 = blst_fp12::default();
    let mut gt = blst_fp12::default();
    unsafe {
        let q = blst_p2_affine_generator();
        blst_miller_loop(&mut l0, q, a);
        blst_miller_loop(&mut l1, q, b);
        blst_fp12_mul(&mut gt, &l0, &l1);
        let f = gt;
        blst_final_exp(&mut gt, &f);
        blst_fp12_is_one(&gt)
    }
}

struct Row {
    columns: usize,
    total: Duration,
    phases: Vec<(&'static str, Duration)>,
}

fn measure(batch: &Batch, scratch: &mut KzgScratch) -> Row {
    let total = best_of(|| assert!(kzg_verify_batch_multi(batch.entries(), scratch)));

    let proofs = batch.proof_bytes();
    let cells = batch.cell_bytes();
    let commitments = batch.commitment_bytes();

    let proof_uncompress = best_of(|| uncompress_all(&proofs));
    let proof_points = uncompress_all(&proofs);
    let proof_in_g1 = best_of(|| assert!(in_g1_all(&proof_points)));
    let commit_deser = best_of(|| assert!(in_g1_all(&uncompress_all(&commitments))));
    let hash = best_of(|| challenge_hash(batch, &cells, &proofs));

    let mut r = blst_fr::default();
    let digest = challenge_hash(batch, &cells, &proofs);
    unsafe {
        let mut s = blst_scalar::default();
        blst_scalar_from_bendian(&mut s, digest.as_ptr());
        blst_fr_from_scalar(&mut r, &s);
    }
    let r_powers = powers(&r, cells.len());
    let aggregate = best_of(|| aggregate_cells(&cells, &r_powers));
    let msm_proofs = best_of(|| msm(&proof_points, &r_powers));
    let n64 = 64.min(proof_points.len());
    let msm_64 = best_of(|| msm(&proof_points[..n64], &r_powers[..n64]));
    let commit_points = uncompress_all(&commitments);
    let msm_commits = best_of(|| msm(&commit_points, &r_powers[..commit_points.len()]));
    let pairing =
        best_of(|| pairing_check(&proof_points[0], &proof_points[1 % proof_points.len()]));
    let alloc = best_of(|| {
        vec![0u8; CELLS_PER_EXT_BLOB * BYTES_PER_CELL + cells.len() * (48 * 3 + 32 + 8 * 2)]
    });

    Row {
        columns: batch.sidecars.len(),
        total,
        phases: vec![
            ("proof uncompress", proof_uncompress),
            ("proof in_g1", proof_in_g1),
            ("commitment deser", commit_deser),
            ("challenge hash", hash),
            ("fe aggregate", aggregate),
            ("msm proofs x2", msm_proofs * 2),
            ("msm interp (64)", msm_64),
            ("msm commitments", msm_commits),
            ("pairing", pairing),
            ("alloc+zero", alloc),
        ],
    }
}

fn main() {
    warm_kzg_settings();
    let cap = ColumnFixtures::da().load();
    let (slot, capture) = cap
        .slots
        .iter()
        .max_by_key(|(_, c)| {
            let first = c.sidecars.values().next().unwrap();
            DataColumnSidecarFuluView::kzg_commitments(first).len()
        })
        .unwrap();
    let by_arrival: Vec<&[u8]> =
        capture.arrivals.iter().map(|a| capture.sidecars[&a.index].as_slice()).collect();
    let blobs =
        DataColumnSidecarFuluView::kzg_commitments(by_arrival[0]).len() / BYTES_PER_KZG_COMMITMENT;
    println!("slot {slot}: {blobs} blobs, {} columns, best of {REPS}", by_arrival.len());

    let mut scratch = KzgScratch::default();
    let sizes = [1usize, 2, 4, 8, 16, 32, 64, 128];
    let rows: Vec<Row> = sizes
        .iter()
        .map(|&k| measure(&Batch { sidecars: by_arrival[..k].to_vec(), blobs }, &mut scratch))
        .collect();

    let mut columns = vec![Column::left("phase")];
    columns.extend(rows.iter().map(|r| Column::right(format!("{} col", r.columns))));
    let mut table = Table::new(columns);
    let mut row = vec!["cells".to_string()];
    row.extend(rows.iter().map(|r| (r.columns * blobs).to_string()));
    table.row(row);
    let mut row = vec!["c-kzg total".to_string()];
    row.extend(rows.iter().map(|r| format!("{:.2}ms", ms(r.total))));
    table.row(row);
    for (i, (name, _)) in rows[0].phases.iter().enumerate() {
        let mut row = vec![format!("  {name}")];
        row.extend(rows.iter().map(|r| {
            let d = r.phases[i].1;
            format!("{:.2}ms {:>3.0}%", ms(d), 100.0 * ms(d) / ms(r.total))
        }));
        table.row(row);
    }
    let mut row = vec!["  residual".to_string()];
    row.extend(rows.iter().map(|r| {
        let explained: Duration = r.phases.iter().map(|p| p.1).sum();
        format!("{:.2}ms", ms(r.total) - ms(explained))
    }));
    table.row(row);
    let mut row = vec!["per column".to_string()];
    row.extend(rows.iter().map(|r| format!("{:.3}ms", ms(r.total) / r.columns as f64)));
    table.row(row);
    print!("{}", table.render());

    let (a, b) = (&rows[0], &rows[rows.len() - 1]);
    let marginal = (ms(b.total) - ms(a.total)) / (b.columns - a.columns) as f64;
    let fixed = ms(a.total) - marginal;
    println!(
        "linear fit: {fixed:.2}ms per call + {marginal:.3}ms per column ({:.1}us per cell)",
        marginal * 1e3 / blobs as f64
    );
    for flushes in [1usize, 2, 4, 8, 16, 64] {
        let per = 64 / flushes;
        println!(
            "64 columns as {flushes:>2} x {per:>2}: {:.1}ms",
            flushes as f64 * (fixed + marginal * per as f64)
        );
    }
}
