use std::{hint::black_box, time::Instant};

use blst::blst_fr;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    kernels_run,
    kzg::{
        BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB, CellExtender,
        blst_ops::{fr_from_bytes, fr_from_u64, fr_inverse, fr_sub, fr_to_bytes, hash_to_fr},
        domain::{inverse_roots, reverse_bits, roots_of_unity},
        fft::{fft, inverse_fft},
        fft8::Fft8,
        fr8::{Fr8, LANES},
    },
    simd_available,
};

const SEED: u64 = 0x6666_7438_6b65_726e;
const MAX_LOG: u32 = 12;

fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
    hash_to_fr(&rng.r#gen::<[u8; 32]>())
}

/// Zeros, ones, r − 1 everywhere, r − 1 among random values, and random
/// values.
fn edge_inputs(rng: &mut ChaCha8Rng, n: usize) -> Vec<Vec<blst_fr>> {
    let largest = fr_sub(&fr_from_u64(0), &fr_from_u64(1));
    let mut mixed: Vec<_> = (0..n).map(|_| random_fr(rng)).collect();
    for _ in 0..n / 4 {
        mixed[rng.gen_range(0..n)] = largest;
    }
    vec![
        vec![fr_from_u64(0); n],
        vec![fr_from_u64(1); n],
        vec![largest; n],
        mixed,
        (0..n).map(|_| random_fr(rng)).collect(),
    ]
}

fn to_bytes(values: &[blst_fr]) -> Vec<u8> {
    values.iter().flat_map(fr_to_bytes).collect()
}

/// SAFETY: the caller checked `simd_available`.
unsafe fn load(input: &[blst_fr]) -> Vec<Fr8> {
    let bytes = to_bytes(input);
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    (0..input.len() / LANES)
        .map(|v| {
            // SAFETY: the caller checked `simd_available`.
            let (vector, below_r) = unsafe { Fr8::from_bytes(&bytes, v * vector_bytes) };
            assert!(below_r == 0xff, "inputs below r");
            vector
        })
        .collect()
}

/// SAFETY: the caller checked `simd_available`.
unsafe fn store(data: &[Fr8]) -> Vec<blst_fr> {
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    let mut bytes = vec![0u8; data.len() * vector_bytes];
    for (v, vector) in data.iter().enumerate() {
        // SAFETY: the caller checked `simd_available`.
        unsafe { vector.to_bytes(&mut bytes, v * vector_bytes) };
    }
    bytes
        .chunks_exact(BYTES_PER_FIELD_ELEMENT)
        .map(|element| fr_from_bytes(element.try_into().unwrap()).expect("canonical"))
        .collect()
}

/// SAFETY: the caller checked `simd_available`.
unsafe fn transform(kernel: &Fft8, input: &[blst_fr], dif: bool) -> Vec<blst_fr> {
    // SAFETY: the caller checked `simd_available`.
    unsafe {
        let mut data = load(input);
        if dif {
            kernel.dif(&mut data);
        } else {
            kernel.dit(&mut data);
        }
        store(&data)
    }
}

/// At every supported length, with roots of exactly that order and strided
/// roots of order 2^12, in both directions.
#[test]
fn kernel_transforms_match_scalar_fft() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let strided = roots_of_unity(MAX_LOG);
    let strided_inverse = inverse_roots(&strided);
    for log_n in 6..=MAX_LOG {
        let n = 1 << log_n;
        let exact = roots_of_unity(log_n);
        let exact_inverse = inverse_roots(&exact);
        for roots in [&exact, &exact_inverse, &strided, &strided_inverse] {
            // SAFETY: `kernels_run` checked `simd_available`.
            let kernel = unsafe { Fft8::new(roots, n) };
            for (case, input) in edge_inputs(&mut rng, n).iter().enumerate() {
                let mut expected = vec![blst_fr::default(); n];
                fft(&mut expected, input, roots);

                // SAFETY: as above.
                let dif = unsafe { transform(&kernel, input, true) };
                for p in 0..n {
                    assert!(
                        dif[p] == expected[reverse_bits(p, log_n)],
                        "dif n {n} case {case} at {p}"
                    );
                }

                let reversed: Vec<_> = (0..n).map(|p| input[reverse_bits(p, log_n)]).collect();
                // SAFETY: as above.
                let dit = unsafe { transform(&kernel, &reversed, false) };
                assert!(dit == expected, "dit n {n} case {case}");
            }
        }
    }
}

fn blob_of(elements: impl Fn(usize) -> [u8; 32]) -> Box<[u8; BYTES_PER_BLOB]> {
    let mut blob = Box::new([0u8; BYTES_PER_BLOB]);
    for (i, element) in blob.chunks_exact_mut(32).enumerate() {
        element.copy_from_slice(&elements(i));
    }
    blob
}

#[test]
fn kernel_cells_match_scalar_cells() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    let largest = fr_to_bytes(&fr_sub(&fr_from_u64(0), &fr_from_u64(1)));
    let random: Vec<[u8; 32]> = (0..4096).map(|_| fr_to_bytes(&random_fr(&mut rng))).collect();
    let blobs = [
        blob_of(|_| [0; 32]),
        blob_of(|i| {
            let mut one = [0; 32];
            one[31] = (i == 0) as u8;
            one
        }),
        blob_of(|_| largest),
        blob_of(|i| if i % 3 == 0 { largest } else { random[i] }),
        blob_of(|i| random[i]),
    ];
    let mut kernel = CellExtender::new();
    let mut scalar = CellExtender::without_kernel();
    let mut ours = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
    let mut expected = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
    for (b, blob) in blobs.iter().enumerate() {
        assert!(scalar.compute(blob, &mut expected), "scalar, blob {b}");
        assert!(kernel.compute(blob, &mut ours), "kernel, blob {b}");
        for k in 0..CELLS_PER_EXT_BLOB {
            assert!(ours[k] == expected[k], "blob {b}, cell {k}");
        }
    }
}

fn best_micros(reps: usize, mut f: impl FnMut()) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..reps {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed().as_secs_f64() * 1e6);
    }
    best
}

/// Not a check: times the transforms, scalar against the kernel.
///
///   cargo test --release -p silver_crypto_simd --lib -- --ignored --nocapture
/// fft_timing
#[test]
#[ignore]
fn fft_timing() {
    assert!(simd_available(), "this CPU has no avx512ifma");
    let reps = 50;
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    // An idle core runs the first few hundred milliseconds below full clock.
    let mut warm_up = CellExtender::without_kernel();
    let mut cells = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
    let zeros = blob_of(|_| [0; 32]);
    let started = Instant::now();
    while started.elapsed().as_millis() < 500 {
        assert!(warm_up.compute(&zeros, black_box(&mut cells)));
    }
    println!("{:<40} {:>10}", "best of 50", "µs");
    for log_n in [6, MAX_LOG] {
        let n = 1 << log_n;
        let roots = roots_of_unity(log_n);
        let inverse = inverse_roots(&roots);
        let inverse_n = fr_inverse(&fr_from_u64(n as u64));
        let input: Vec<_> = (0..n).map(|_| random_fr(&mut rng)).collect();
        let mut out = vec![blst_fr::default(); n];
        // SAFETY: asserted `simd_available` above.
        let kernel = unsafe { Fft8::new(&roots, n) };
        // SAFETY: as above.
        let mut data = unsafe { load(&input) };
        let bytes = to_bytes(&input);
        let mut out_bytes = bytes.clone();
        let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;

        let scalar = best_micros(reps, || fft(black_box(&mut out), &input, &roots));
        let scalar_inverse =
            best_micros(reps, || inverse_fft(black_box(&mut out), &input, &inverse, &inverse_n));
        // SAFETY: as above.
        let kernel_only = best_micros(reps, || unsafe { kernel.dit(black_box(&mut data)) });
        // SAFETY: as above.
        let kernel_dif = best_micros(reps, || unsafe { kernel.dif(black_box(&mut data)) });
        let converted = best_micros(reps, || {
            // SAFETY: as above.
            unsafe {
                for v in 0..n / LANES {
                    data[v] = Fr8::from_bytes(&bytes, v * vector_bytes).0;
                }
                kernel.dit(&mut data);
                for v in 0..n / LANES {
                    data[v].to_bytes(black_box(&mut out_bytes), v * vector_bytes);
                }
            }
        });
        println!("{:<40} {scalar:>10.1}", format!("scalar fft, n = {n}"));
        println!("{:<40} {scalar_inverse:>10.1}", format!("scalar inverse_fft, n = {n}"));
        println!("{:<40} {kernel_only:>10.1}", format!("kernel dit, n = {n}"));
        println!("{:<40} {kernel_dif:>10.1}", format!("kernel dif, n = {n}"));
        println!("{:<40} {converted:>10.1}", format!("kernel from_bytes+dit+to_bytes, n = {n}"));
    }

    let random: Vec<_> = (0..4096).map(|_| fr_to_bytes(&random_fr(&mut rng))).collect();
    let blob = blob_of(|i| random[i]);
    let mut kernel = CellExtender::new();
    let mut scalar = CellExtender::without_kernel();
    let with_kernel = best_micros(reps, || assert!(kernel.compute(&blob, black_box(&mut cells))));
    let without = best_micros(reps, || assert!(scalar.compute(&blob, black_box(&mut cells))));
    println!("{:<40} {without:>10.1}", "CellExtender::compute, scalar");
    println!("{:<40} {with_kernel:>10.1}", "CellExtender::compute, kernel");
}
