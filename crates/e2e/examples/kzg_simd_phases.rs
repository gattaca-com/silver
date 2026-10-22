//! Cycle budget of the AVX-512 IFMA G1 and G2 paths, one phase at a time:
//! field multiply and square, square-root exponentiation, Scott membership
//! test, and the whole decompression. G1 runs on eight genuine proofs from the
//! capture, G2 on eight hashed points.
//!
//!   cargo run --release -p silver_e2e --example kzg_simd_phases

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use blst::{
    BLST_ERROR, blst_fp, blst_hash_to_g2, blst_p1_affine_in_g1, blst_p1_uncompress, blst_p2,
    blst_p2_compress, blst_uint64_from_fp,
};
use silver_common::ssz_view::DataColumnSidecarFuluView;
use silver_crypto_simd::{
    bls::{
        COMPRESSED_LEN, G2_COMPRESSED_LEN, blst_p1_affine,
        constants::FOUR_MONT,
        decompress::decompress,
        decompress_g2,
        fp2x8::Fp2x8,
        fp8::Fp8,
        g1x8::G1x8,
        g2x8::G2x8,
        limbs::{LANES, Limbs, unpack52},
        uncompress_in_g2_blst,
    },
    ifma_available,
};
use silver_e2e::da_capture::ColumnFixtures;

const REPS: usize = 7;

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

#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_chain(a: &Fp8, b: &Fp8, n: usize) -> Fp8 {
    let mut r = *a;
    for _ in 0..n {
        r = r.mul(b);
    }
    r
}

/// Two independent chains in the same loop: what the out-of-order core can
/// overlap when it is given the parallelism.
#[target_feature(enable = "avx512f,avx512ifma")]
fn mul_chain_x2(a: &Fp8, b: &Fp8, n: usize) -> (Fp8, Fp8) {
    let mut r = *a;
    let mut s = *b;
    for _ in 0..n {
        r = r.mul(b);
        s = s.mul(a);
    }
    (r, s)
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn square_chain(a: &Fp8, n: usize) -> Fp8 {
    let mut r = *a;
    for _ in 0..n {
        r = r.square();
    }
    r
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn sqrt(a: &Fp8) -> Fp8 {
    a.sqrt_candidate()
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn scott(x: &Fp8, y: &Fp8) -> u8 {
    G1x8::scott_membership(x, y).members
}

/// The square root `decompress_g2` takes of x³ + 4(1 + i).
#[target_feature(enable = "avx512f,avx512ifma")]
fn sqrt_g2(x: &Fp2x8) -> u8 {
    let four = Fp8::splat_limbs(&FOUR_MONT);
    x.square().mul(x).add(&Fp2x8 { c0: four, c1: four }).sqrt().1
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn scott_g2(x: &Fp2x8, y: &Fp2x8) -> u8 {
    G2x8::scott_membership(x, y).members
}

/// blst's plain-integer export as 52-bit limbs.
fn plain_limbs(fp: &blst_fp) -> Limbs {
    let mut plain = [0u64; 6];
    // SAFETY: `plain` has the six limbs blst writes.
    unsafe { blst_uint64_from_fp(plain.as_mut_ptr(), fp) };
    unpack52(&plain)
}

/// The eight points' affine coordinates as lanes.
#[target_feature(enable = "avx512f,avx512ifma")]
fn affine_lanes(points: &[[u8; COMPRESSED_LEN]; LANES]) -> (Fp8, Fp8) {
    let mut xs = [[0u64; 8]; LANES];
    let mut ys = [[0u64; 8]; LANES];
    for (lane, bytes) in points.iter().enumerate() {
        let p = uncompress_in_g1_blst(bytes).expect("genuine proof");
        xs[lane] = plain_limbs(&p.x);
        ys[lane] = plain_limbs(&p.y);
    }
    (Fp8::from_plain(&xs), Fp8::from_plain(&ys))
}

/// Eight members of G2, hashed from distinct messages.
fn g2_batch() -> [[u8; G2_COMPRESSED_LEN]; LANES] {
    let mut batch = [[0u8; G2_COMPRESSED_LEN]; LANES];
    for (lane, bytes) in batch.iter_mut().enumerate() {
        let msg = [lane as u8; 32];
        let mut p = blst_p2::default();
        // SAFETY: the pointers are to live values of the lengths blst reads and
        // writes.
        unsafe {
            blst_hash_to_g2(
                &mut p,
                msg.as_ptr(),
                msg.len(),
                b"G2".as_ptr(),
                2,
                std::ptr::null(),
                0,
            );
            blst_p2_compress(bytes.as_mut_ptr(), &p);
        }
    }
    batch
}

/// The eight G2 points' affine coordinates as lanes.
#[target_feature(enable = "avx512f,avx512ifma")]
fn affine_lanes_g2(points: &[[u8; G2_COMPRESSED_LEN]; LANES]) -> (Fp2x8, Fp2x8) {
    let mut coordinates = [[[0u64; 8]; LANES]; 4];
    for (lane, bytes) in points.iter().enumerate() {
        let p = uncompress_in_g2_blst(bytes).expect("member of G2");
        for (k, fp) in [p.x.fp[0], p.x.fp[1], p.y.fp[0], p.y.fp[1]].iter().enumerate() {
            coordinates[k][lane] = plain_limbs(fp);
        }
    }
    let [x0, x1, y0, y1] = coordinates;
    let x = Fp2x8 { c0: Fp8::from_plain(&x0), c1: Fp8::from_plain(&x1) };
    let y = Fp2x8 { c0: Fp8::from_plain(&y0), c1: Fp8::from_plain(&y1) };
    (x, y)
}

fn main() {
    assert!(ifma_available(), "this CPU has no avx512ifma");
    let cap = ColumnFixtures::da().load();
    let slot = cap.slots.values().next().unwrap();
    let mut batch = [[0u8; COMPRESSED_LEN]; LANES];
    let proofs = slot
        .sidecars
        .values()
        .flat_map(|s| DataColumnSidecarFuluView::kzg_proofs(s).chunks_exact(COMPRESSED_LEN));
    for (lane, chunk) in proofs.take(LANES).enumerate() {
        batch[lane].copy_from_slice(chunk);
    }
    // SAFETY: `ifma_available` confirmed the target features.
    let (x, y) = unsafe { affine_lanes(&batch) };

    let batch_g2 = g2_batch();
    // SAFETY: as above.
    let (x2, y2) = unsafe { affine_lanes_g2(&batch_g2) };
    // SAFETY: as above.
    assert!(unsafe { decompress_g2::decompress(&batch_g2) }.valid == 0xff, "members of G2");

    let n = 10_000;
    // An idle core runs the first few hundred milliseconds below full clock.
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(500) {
        black_box(unsafe { mul_chain(&x, &y, n) });
    }
    let chain = best_of(|| unsafe { mul_chain(&x, &y, n) });
    let chain2 = best_of(|| unsafe { mul_chain_x2(&x, &y, n) });
    let squares = best_of(|| unsafe { square_chain(&x, n) });
    let root = best_of(|| unsafe { sqrt(&x) });
    let member = best_of(|| unsafe { scott(&x, &y) });
    let whole = best_of(|| unsafe { decompress(&batch) });
    let scalar = best_of(|| batch.iter().map(uncompress_in_g1_blst).collect::<Vec<_>>());
    let root_g2 = best_of(|| unsafe { sqrt_g2(&x2) });
    let member_g2 = best_of(|| unsafe { scott_g2(&x2, &y2) });
    let whole_g2 = best_of(|| unsafe { decompress_g2::decompress(&batch_g2) });
    let scalar_g2 = best_of(|| batch_g2.iter().map(uncompress_in_g2_blst).collect::<Vec<_>>());

    let ns = |d: Duration, per: f64| d.as_secs_f64() * 1e9 / per;
    println!("eight lanes; per lane-element unless noted");
    println!(
        "  fp mul, dependent chain           {:7.1} ns/mul  ({:.0} ns per 8-wide op)",
        ns(chain, n as f64 * 8.0),
        ns(chain, n as f64)
    );
    println!(
        "  fp mul, two chains interleaved    {:7.1} ns/mul  ({:.0} ns per 8-wide op)",
        ns(chain2, n as f64 * 16.0),
        ns(chain2, 2.0 * n as f64)
    );
    println!(
        "  fp square, dependent chain        {:7.1} ns/sqr  ({:.0} ns per 8-wide op)",
        ns(squares, n as f64 * 8.0),
        ns(squares, n as f64)
    );
    println!("  sqrt exponentiation               {:7.2} us/pt", ns(root, 8.0) / 1e3);
    println!("  scott membership                  {:7.2} us/pt", ns(member, 8.0) / 1e3);
    println!("  decompress + membership, 8-wide   {:7.2} us/pt", ns(whole, 8.0) / 1e3);
    println!("  blst uncompress + in_g1           {:7.2} us/pt", ns(scalar, 8.0) / 1e3);
    println!("  g2 sqrt, x^3 + 4(1 + i)           {:7.2} us/pt", ns(root_g2, 8.0) / 1e3);
    println!("  g2 scott membership               {:7.2} us/pt", ns(member_g2, 8.0) / 1e3);
    println!("  g2 decompress + membership        {:7.2} us/pt", ns(whole_g2, 8.0) / 1e3);
    println!("  blst g2 uncompress + in_g2        {:7.2} us/pt", ns(scalar_g2, 8.0) / 1e3);
}
