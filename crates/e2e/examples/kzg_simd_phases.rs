//! Cycle budget of the AVX-512 IFMA G1 path, one phase at a time, on eight
//! genuine proofs from the capture: field multiply, square-root exponentiation,
//! Scott membership test, and the whole decompression.
//!
//!   cargo run --release -p silver_e2e --example kzg_simd_phases

use std::{
    hint::black_box,
    time::{Duration, Instant},
};

use blst::blst_uint64_from_fp;
use silver_common::ssz_view::DataColumnSidecarFuluView;
use silver_crypto_simd::{
    bls::{
        COMPRESSED_LEN,
        decompress::decompress,
        fp8::{Fp8, LANES, unpack52},
        g1x8::G1x8,
        uncompress_in_g1_blst,
    },
    simd_available,
};
use silver_e2e::da_capture::ColumnFixtures;

const REPS: usize = 7;

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
fn sqrt(a: &Fp8) -> Fp8 {
    a.sqrt_candidate()
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn scott(x: &Fp8, y: &Fp8) -> u8 {
    G1x8::scott_membership(x, y).members
}

/// The eight points' affine coordinates as lanes, via blst's plain-integer
/// export.
#[target_feature(enable = "avx512f,avx512ifma")]
fn affine_lanes(points: &[[u8; COMPRESSED_LEN]; LANES]) -> (Fp8, Fp8) {
    let mut xs = [[0u64; 8]; LANES];
    let mut ys = [[0u64; 8]; LANES];
    for (lane, bytes) in points.iter().enumerate() {
        let p = uncompress_in_g1_blst(bytes).expect("genuine proof");
        let mut plain = [0u64; 6];
        // SAFETY: `plain` has the six limbs blst writes.
        unsafe { blst_uint64_from_fp(plain.as_mut_ptr(), &p.x) };
        xs[lane] = unpack52(&plain);
        unsafe { blst_uint64_from_fp(plain.as_mut_ptr(), &p.y) };
        ys[lane] = unpack52(&plain);
    }
    (Fp8::from_plain(&xs), Fp8::from_plain(&ys))
}

fn main() {
    assert!(simd_available(), "this CPU has no avx512ifma");
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
    // SAFETY: `simd_available` confirmed the target features.
    let (x, y) = unsafe { affine_lanes(&batch) };

    let n = 10_000;
    let chain = best_of(|| unsafe { mul_chain(&x, &y, n) });
    let chain2 = best_of(|| unsafe { mul_chain_x2(&x, &y, n) });
    let root = best_of(|| unsafe { sqrt(&x) });
    let member = best_of(|| unsafe { scott(&x, &y) });
    let whole = best_of(|| unsafe { decompress(&batch) });
    let scalar = best_of(|| batch.iter().map(uncompress_in_g1_blst).collect::<Vec<_>>());

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
    println!("  sqrt exponentiation               {:7.2} us/pt", ns(root, 8.0) / 1e3);
    println!("  scott membership                  {:7.2} us/pt", ns(member, 8.0) / 1e3);
    println!("  decompress + membership, 8-wide   {:7.2} us/pt", ns(whole, 8.0) / 1e3);
    println!("  blst uncompress + in_g1           {:7.2} us/pt", ns(scalar, 8.0) / 1e3);
}
