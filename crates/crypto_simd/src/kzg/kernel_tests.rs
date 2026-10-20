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
        fr8::{Fr8, LANES, multiplier},
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

/// Five 52-bit limbs, little-endian, as `Fr8` lanes hold them.
type Limbs = [u64; 5];

fn limbs_from_bytes(bytes: &[u8; 32]) -> Limbs {
    let mut x = [0u64; 5];
    for bit in 0..256 {
        x[bit / 52] |= u64::from(bytes[31 - bit / 8] >> (bit % 8) & 1) << (bit % 52);
    }
    x
}

fn bytes_from_limbs(x: &Limbs) -> [u8; 32] {
    assert!(x[4] >> (256 - 4 * 52) == 0, "below 2^256");
    let mut bytes = [0u8; 32];
    for bit in 0..256 {
        bytes[31 - bit / 8] |= ((x[bit / 52] >> (bit % 52) & 1) as u8) << (bit % 8);
    }
    bytes
}

/// The value of limbs read as signed 64-bit integers, which must lie in
/// [0, 2^260), in normalised limbs.
fn carried(limbs: &Limbs) -> Limbs {
    let mut x = [0u64; 5];
    let mut carry = 0i128;
    for j in 0..5 {
        let limb = limbs[j] as i64 as i128 + carry;
        x[j] = (limb & ((1 << 52) - 1)) as u64;
        carry = limb >> 52;
    }
    assert!(carry == 0, "value in [0, 2^260)");
    x
}

/// a + k·b in normalised limbs, for k ≥ 0 or a ≥ |k|·b.
fn plus_multiple(a: &Limbs, k: i128, b: &Limbs) -> Limbs {
    let mut x = [0u64; 5];
    let mut carry = 0i128;
    for j in 0..5 {
        let limb = a[j] as i128 + k * b[j] as i128 + carry;
        x[j] = (limb & ((1 << 52) - 1)) as u64;
        carry = limb >> 52;
    }
    assert!(carry == 0, "result in [0, 2^260)");
    x
}

fn is_below(a: &Limbs, b: &Limbs) -> bool {
    a.iter().rev().lt(b.iter().rev())
}

fn r_limbs() -> Limbs {
    let largest = fr_to_bytes(&fr_sub(&fr_from_u64(0), &fr_from_u64(1)));
    plus_multiple(&limbs_from_bytes(&largest), 1, &[1, 0, 0, 0, 0])
}

/// `input`, with the elements at the positions `raised` picks raised by r:
/// reduced, but not canonical.
///
/// SAFETY: the caller checked `simd_available`.
unsafe fn load_raised(input: &[blst_fr], raised: &dyn Fn(usize) -> bool) -> Vec<Fr8> {
    let r = r_limbs();
    let mut bytes = Vec::with_capacity(input.len() * BYTES_PER_FIELD_ELEMENT);
    for (p, x) in input.iter().enumerate() {
        let lift = if raised(p) { 1 } else { 0 };
        bytes.extend(bytes_from_limbs(&plus_multiple(
            &limbs_from_bytes(&fr_to_bytes(x)),
            lift,
            &r,
        )));
    }
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    (0..input.len() / LANES)
        .map(|v| {
            // SAFETY: the caller checked `simd_available`.
            let (vector, below_r) = unsafe { Fr8::from_bytes(&bytes, v * vector_bytes) };
            for lane in 0..LANES {
                assert!(below_r >> lane & 1 != u8::from(raised(LANES * v + lane)), "raised");
            }
            vector
        })
        .collect()
}

/// `dit`'s outputs, checked against its bound lazy(16 + 2w, 73 + 33w) for w
/// wide stages, then reduced below r by subtracting r.
///
/// SAFETY: the caller checked `simd_available`.
unsafe fn store_lazy(data: &[Fr8], wide_stages: u32) -> Vec<blst_fr> {
    let r = r_limbs();
    let (k, m) = (16 + 2 * wide_stages, 73 + 33 * wide_stages);
    let bound = plus_multiple(&[0; 5], k.into(), &r);
    let mut out = Vec::with_capacity(data.len() * LANES);
    for vector in data {
        // SAFETY: the caller checked `simd_available`.
        for lane in unsafe { vector.lane_limbs() } {
            let limit = u64::from(m) << 52;
            assert!(lane.iter().all(|&limb| (limb as i64).unsigned_abs() < limit), "limbs");
            let mut x = carried(&lane);
            assert!(is_below(&x, &bound), "value below {k}r");
            while !is_below(&x, &r) {
                x = plus_multiple(&x, -1, &r);
            }
            out.push(fr_from_bytes(&bytes_from_limbs(&x)).expect("canonical"));
        }
    }
    out
}

/// Both transforms of x against the scalar FFT, each loaded with the
/// positions `raised` picks raised by r. `dif` takes x in natural order, also
/// as uncarried products by 1, and `dit` in bit-reversed order.
///
/// SAFETY: the caller checked `simd_available`.
unsafe fn check_transforms(
    kernel: &Fft8,
    roots: &[blst_fr],
    x: &[blst_fr],
    raised: &dyn Fn(usize) -> bool,
    case: &str,
) {
    let n = x.len();
    let log_n = n.trailing_zeros();
    let mut expected = vec![blst_fr::default(); n];
    fft(&mut expected, x, roots);
    // SAFETY: the caller checked `simd_available`.
    unsafe {
        let one = Fr8::load(&[multiplier(&fr_from_u64(1)); LANES], 0);
        for as_products in [false, true] {
            let mut data = load_raised(x, raised);
            if as_products {
                for v in 0..data.len() {
                    data[v] = data[v].mul(&one);
                }
            }
            kernel.dif(&mut data);
            let dif = store(&data);
            for p in 0..n {
                let at = reverse_bits(p, log_n);
                assert!(dif[p] == expected[at], "dif {case} products {as_products} at {p}");
            }
        }

        let reversed: Vec<_> = (0..n).map(|p| x[reverse_bits(p, log_n)]).collect();
        let mut data = load_raised(&reversed, raised);
        kernel.dit(&mut data);
        assert!(store_lazy(&data, log_n - 3) == expected, "dit {case}");
    }
}

/// At every supported length, with roots of exactly that order and strided
/// roots of order 2^12, in both directions. The inputs are canonical, raised
/// by r, and, for each stage, zeros paired with values raised by r: then a
/// difference meets its widest gap, from 0 down to a large subtrahend.
#[test]
fn kernel_transforms_match_scalar_fft() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let strided = roots_of_unity(MAX_LOG);
    let strided_inverse = inverse_roots(&strided);
    let largest = fr_sub(&fr_from_u64(0), &fr_from_u64(1));
    for log_n in 6..=MAX_LOG {
        let n = 1 << log_n;
        let exact = roots_of_unity(log_n);
        let exact_inverse = inverse_roots(&exact);
        for roots in [&exact, &exact_inverse, &strided, &strided_inverse] {
            // SAFETY: `kernels_run` checked `simd_available`.
            let kernel = unsafe { Fft8::new(roots, n) };
            for (case, x) in edge_inputs(&mut rng, n).iter().enumerate() {
                for raised in [false, true] {
                    let case = format!("n {n} case {case} raised {raised}");
                    // SAFETY: as above.
                    unsafe { check_transforms(&kernel, roots, x, &|_| raised, &case) };
                }
            }
            for log_h in 0..log_n {
                let second_of_pair = |p: usize| p >> log_h & 1 == 1;
                for trial in 0..4 {
                    let x: Vec<_> = (0..n)
                        .map(|j| match (second_of_pair(reverse_bits(j, log_n)), trial) {
                            (false, _) => fr_from_u64(0),
                            (true, 0) => largest,
                            (true, _) => random_fr(&mut rng),
                        })
                        .collect();
                    let case = format!("n {n} gap at stage {} trial {trial}", 1 << log_h);
                    // SAFETY: as above.
                    unsafe { check_transforms(&kernel, roots, &x, &second_of_pair, &case) };
                }
            }
        }
    }
}

/// Elements start this far into their buffers, so no lane is 8-byte aligned.
const ODD_OFFSET: usize = 5;

fn single_bit(bit: usize) -> Limbs {
    let mut x = [0; 5];
    x[bit / 52] = 1 << (bit % 52);
    x
}

/// r − 1, r and r + 1, and r ± 2^b at each limb and word boundary b.
fn around_r() -> Vec<Limbs> {
    let r = r_limbs();
    let mut out: Vec<_> =
        [-1, 0, 1].iter().map(|&d| plus_multiple(&r, d, &single_bit(0))).collect();
    for bit in [52, 104, 156, 208, 64, 128, 192] {
        out.push(plus_multiple(&r, -1, &single_bit(bit)));
        out.push(plus_multiple(&r, 1, &single_bit(bit)));
    }
    out
}

/// Every value of `values` in every lane, eight to a vector.
fn in_every_lane(values: &[Limbs]) -> Vec<Limbs> {
    (0..values.len())
        .flat_map(|v| (0..LANES).map(move |lane| values[(v + lane) % values.len()]))
        .collect()
}

/// The blst element whose 64-bit limbs, which `Fr8::load` takes as they are,
/// hold x.
fn raw_fr(x: &Limbs) -> blst_fr {
    let bytes = bytes_from_limbs(x);
    let mut l = [0; 4];
    for k in 0..4 {
        l[k] = u64::from_be_bytes(bytes[24 - 8 * k..32 - 8 * k].try_into().unwrap());
    }
    blst_fr { l }
}

/// Lane l of `from_bytes` holds the 32 big-endian bytes at `at + 32·l` as
/// normalised limbs, whatever their value, and the mask flags exactly the
/// lanes below r. Single bits tell every bit's place apart.
#[test]
fn from_bytes_decodes_every_lane_and_flags_values_below_r() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let r = r_limbs();
    let mut edges: Vec<_> = (0..256).map(single_bit).collect();
    edges.extend([[0; 5], limbs_from_bytes(&[0xff; 32])]);
    edges.extend(around_r());
    let mut values = in_every_lane(&edges);
    for _ in 0..64 * LANES {
        values.push(limbs_from_bytes(&rng.r#gen()));
        values.push(limbs_from_bytes(&fr_to_bytes(&random_fr(&mut rng))));
    }
    let mut bytes = vec![0x5a; ODD_OFFSET + values.len() * BYTES_PER_FIELD_ELEMENT];
    for (i, x) in values.iter().enumerate() {
        let at = ODD_OFFSET + i * BYTES_PER_FIELD_ELEMENT;
        bytes[at..at + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&bytes_from_limbs(x));
    }
    for v in 0..values.len() / LANES {
        let at = ODD_OFFSET + v * LANES * BYTES_PER_FIELD_ELEMENT;
        // SAFETY: `kernels_run` checked `simd_available`.
        let (vector, below_r) = unsafe { Fr8::from_bytes(&bytes, at) };
        // SAFETY: as above.
        let limbs = unsafe { vector.lane_limbs() };
        for lane in 0..LANES {
            let x = &values[v * LANES + lane];
            assert!(limbs[lane] == *x, "vector {v} lane {lane}");
            assert!((below_r >> lane & 1 == 1) == is_below(x, &r), "vector {v} lane {lane} mask");
        }
    }
}

/// `to_bytes` writes lane l, for values below 2r, as the 32 big-endian bytes
/// of its value mod r at `at + 32·l`, and changes no other byte.
#[test]
fn to_bytes_writes_canonical_lanes_and_nothing_else() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 4);
    let r = r_limbs();
    let two_r = plus_multiple(&r, 1, &r);
    let mut edges: Vec<_> = (0..256).map(single_bit).collect();
    edges.push([0; 5]);
    edges.extend([-2, -1].iter().map(|&d| plus_multiple(&two_r, d, &single_bit(0))));
    edges.extend(around_r());
    let mut values = in_every_lane(&edges);
    let count = values.len() + 64 * LANES;
    while values.len() < count {
        let x = limbs_from_bytes(&rng.r#gen());
        if is_below(&x, &two_r) {
            values.push(x);
        }
    }
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    let mut bytes = vec![0; ODD_OFFSET + vector_bytes + ODD_OFFSET];
    for v in 0..values.len() / LANES {
        let raw: Vec<_> = values[v * LANES..(v + 1) * LANES].iter().map(raw_fr).collect();
        bytes.fill(0x5a);
        // SAFETY: `kernels_run` checked `simd_available`.
        unsafe { Fr8::load(&raw, 0).to_bytes(&mut bytes, ODD_OFFSET) };
        for lane in 0..LANES {
            let x = &values[v * LANES + lane];
            let canonical = if is_below(x, &r) { *x } else { plus_multiple(x, -1, &r) };
            let at = ODD_OFFSET + lane * BYTES_PER_FIELD_ELEMENT;
            assert!(bytes[at..at + 32] == bytes_from_limbs(&canonical), "vector {v} lane {lane}");
        }
        let mut outside = bytes[..ODD_OFFSET].iter().chain(&bytes[ODD_OFFSET + vector_bytes..]);
        assert!(outside.all(|&byte| byte == 0x5a), "vector {v}: bytes outside the lanes");
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
                kernel.dif(&mut data);
                for v in 0..n / LANES {
                    data[v].to_bytes(black_box(&mut out_bytes), v * vector_bytes);
                }
            }
        });
        let decoded = best_micros(reps, || {
            for v in 0..n / LANES {
                // SAFETY: as above.
                data[v] = unsafe { Fr8::from_bytes(black_box(&bytes), v * vector_bytes).0 };
            }
        });
        let encoded = best_micros(reps, || {
            for v in 0..n / LANES {
                // SAFETY: as above.
                unsafe { data[v].to_bytes(black_box(&mut out_bytes), v * vector_bytes) };
            }
        });
        println!("{:<40} {scalar:>10.1}", format!("scalar fft, n = {n}"));
        println!("{:<40} {scalar_inverse:>10.1}", format!("scalar inverse_fft, n = {n}"));
        println!("{:<40} {kernel_only:>10.1}", format!("kernel dit, n = {n}"));
        println!("{:<40} {kernel_dif:>10.1}", format!("kernel dif, n = {n}"));
        println!("{:<40} {converted:>10.1}", format!("kernel from_bytes+dif+to_bytes, n = {n}"));
        println!("{:<40} {decoded:>10.1}", format!("kernel from_bytes, n = {n}"));
        println!("{:<40} {encoded:>10.1}", format!("kernel to_bytes, n = {n}"));
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
