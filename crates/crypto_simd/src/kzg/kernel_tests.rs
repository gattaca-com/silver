use std::{hint::black_box, panic::catch_unwind, time::Instant};

use blst::blst_fr;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    ifma_available, kernels_run,
    kzg::{
        BYTES_PER_BLOB, BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB, CellExtender,
        FIELD_ELEMENTS_PER_CELL,
        blst_ops::{
            fr_add, fr_from_bytes, fr_from_u64, fr_inverse, fr_mul, fr_sub, fr_to_bytes, hash_to_fr,
        },
        cosets::Cosets,
        domain::{inverse_roots, reverse_bits, roots_of_unity},
        fft::{fft, inverse_fft},
        fft8::Fft8,
        fr8::{Fr8, LANES, limbs::Limbs, multiplier},
        interpolation_kernel::InterpolationKernel,
    },
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

/// SAFETY: the caller checked `ifma_available`.
unsafe fn load(input: &[blst_fr]) -> Vec<Fr8> {
    let bytes = to_bytes(input);
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    (0..input.len() / LANES)
        .map(|v| {
            // SAFETY: the caller checked `ifma_available`.
            let (vector, below_r) = unsafe { Fr8::from_bytes(&bytes, v * vector_bytes) };
            assert!(below_r == 0xff, "inputs below r");
            vector
        })
        .collect()
}

/// SAFETY: the caller checked `ifma_available`.
unsafe fn store(data: &[Fr8]) -> Vec<blst_fr> {
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    let mut bytes = vec![0u8; data.len() * vector_bytes];
    for (v, vector) in data.iter().enumerate() {
        // SAFETY: the caller checked `ifma_available`.
        unsafe { vector.to_bytes(&mut bytes, v * vector_bytes) };
    }
    bytes
        .chunks_exact(BYTES_PER_FIELD_ELEMENT)
        .map(|element| fr_from_bytes(element.try_into().unwrap()).expect("canonical"))
        .collect()
}

/// `input`, with the elements at the positions `raised` picks raised by r:
/// reduced, but not canonical.
///
/// SAFETY: the caller checked `ifma_available`.
unsafe fn load_raised(input: &[blst_fr], raised: &dyn Fn(usize) -> bool) -> Vec<Fr8> {
    let r = Limbs::r();
    let mut bytes = Vec::with_capacity(input.len() * BYTES_PER_FIELD_ELEMENT);
    for (p, x) in input.iter().enumerate() {
        let lift = if raised(p) { 1 } else { 0 };
        bytes.extend(Limbs::from_bytes(&fr_to_bytes(x)).plus_multiple(lift, &r).to_bytes());
    }
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    (0..input.len() / LANES)
        .map(|v| {
            // SAFETY: the caller checked `ifma_available`.
            let (vector, below_r) = unsafe { Fr8::from_bytes(&bytes, v * vector_bytes) };
            for lane in 0..LANES {
                assert!(below_r >> lane & 1 != u8::from(raised(LANES * v + lane)), "raised");
            }
            vector
        })
        .collect()
}

/// `dit`'s outputs, checked against its bound lazy(16 + 2w, 73 + 33w) for w
/// wide stages, then reduced below r by subtracting r. The check is coarse,
/// as no input drives the products to their bound; the proof establishes the
/// exact bound.
///
/// SAFETY: the caller checked `ifma_available`.
unsafe fn store_lazy(data: &[Fr8], wide_stages: u32) -> Vec<blst_fr> {
    let r = Limbs::r();
    let (k, m) = (16 + 2 * wide_stages, 73 + 33 * wide_stages);
    let bound = Limbs::near_multiple_of_r(k.into(), 0);
    let mut out = Vec::with_capacity(data.len() * LANES);
    for vector in data {
        // SAFETY: the caller checked `ifma_available`.
        for lane in unsafe { vector.lane_limbs() } {
            let limit = u64::from(m) << 52;
            assert!(lane.iter().all(|&limb| (limb as i64).unsigned_abs() < limit), "limbs");
            let mut x = Limbs(lane).carried();
            assert!(x.is_below(&bound), "value below {k}r");
            while !x.is_below(&r) {
                x = x.plus_multiple(-1, &r);
            }
            out.push(fr_from_bytes(&x.to_bytes()).expect("canonical"));
        }
    }
    out
}

/// Both transforms of x against the scalar FFT, each loaded with the
/// positions `raised` picks raised by r. `dif` takes x in natural order, also
/// as uncarried products by 1, and `dit` in bit-reversed order.
///
/// SAFETY: the caller checked `ifma_available`.
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
    // SAFETY: the caller checked `ifma_available`.
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
            // SAFETY: `kernels_run` checked `ifma_available`.
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

/// One stage more than 4096 elements takes `dit`'s output bound to 36r, past
/// 2^260.
#[test]
fn transforms_beyond_4096_elements_are_rejected() {
    if !kernels_run() {
        return;
    }
    let roots = roots_of_unity(MAX_LOG + 1);
    // SAFETY: `kernels_run` checked `ifma_available`.
    let rejected = catch_unwind(|| unsafe { Fft8::new(&roots, roots.len()) }).err();
    let message = rejected.as_ref().and_then(|payload| payload.downcast_ref::<&str>());
    assert!(message.is_some_and(|m| m.contains("4096 elements")), "panic: {message:?}");
}

/// Elements start this far into their buffers, so no lane is 8-byte aligned.
const ODD_OFFSET: usize = 5;

/// r, and r ± 2^b for b = 0 and at each limb and word boundary b.
fn around_r() -> Vec<Limbs> {
    let r = Limbs::r();
    let moved = [0, 52, 104, 156, 208, 64, 128, 192]
        .into_iter()
        .flat_map(|b| [-1, 1].map(|d| r.plus_multiple(d, &Limbs::single_bit(b))));
    [r].into_iter().chain(moved).collect()
}

/// Every value of `values` in every lane, eight to a vector.
fn in_every_lane(values: &[Limbs]) -> Vec<Limbs> {
    (0..values.len())
        .flat_map(|v| (0..LANES).map(move |lane| values[(v + lane) % values.len()]))
        .collect()
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
    let r = Limbs::r();
    let edges: Vec<_> = (0..256)
        .map(Limbs::single_bit)
        .chain([Limbs::ZERO, Limbs::from_bytes(&[0xff; 32])])
        .chain(around_r())
        .collect();
    let mut values = in_every_lane(&edges);
    for _ in 0..64 * LANES {
        values.push(Limbs::from_bytes(&rng.r#gen()));
        values.push(Limbs::from_bytes(&fr_to_bytes(&random_fr(&mut rng))));
    }
    let mut bytes = vec![0x5a; ODD_OFFSET + values.len() * BYTES_PER_FIELD_ELEMENT];
    for (i, x) in values.iter().enumerate() {
        let at = ODD_OFFSET + i * BYTES_PER_FIELD_ELEMENT;
        bytes[at..at + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&x.to_bytes());
    }
    for v in 0..values.len() / LANES {
        let at = ODD_OFFSET + v * LANES * BYTES_PER_FIELD_ELEMENT;
        // SAFETY: `kernels_run` checked `ifma_available`.
        let (vector, below_r) = unsafe { Fr8::from_bytes(&bytes, at) };
        // SAFETY: as above.
        let limbs = unsafe { vector.lane_limbs() };
        for lane in 0..LANES {
            let x = &values[v * LANES + lane];
            assert!(Limbs(limbs[lane]) == *x, "vector {v} lane {lane}");
            assert!((below_r >> lane & 1 == 1) == x.is_below(&r), "vector {v} lane {lane} mask");
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
    let r = Limbs::r();
    let two_r = Limbs::near_multiple_of_r(2, 0);
    let edges: Vec<_> = (0..256)
        .map(Limbs::single_bit)
        .chain([Limbs::ZERO, Limbs::near_multiple_of_r(2, -2), Limbs::near_multiple_of_r(2, -1)])
        .chain(around_r())
        .collect();
    let mut values = in_every_lane(&edges);
    values.extend((0..64 * LANES).map(|_| two_r.random_below(&mut rng)));
    let vector_bytes = LANES * BYTES_PER_FIELD_ELEMENT;
    let mut bytes = vec![0; ODD_OFFSET + vector_bytes + ODD_OFFSET];
    for v in 0..values.len() / LANES {
        let raw: Vec<_> = values[v * LANES..(v + 1) * LANES].iter().map(Limbs::to_raw_fr).collect();
        bytes.fill(0x5a);
        // SAFETY: `kernels_run` checked `ifma_available`.
        unsafe { Fr8::load(&raw, 0).to_bytes(&mut bytes, ODD_OFFSET) };
        for lane in 0..LANES {
            let x = &values[v * LANES + lane];
            let canonical = if x.is_below(&r) { *x } else { x.plus_multiple(-1, &r) };
            let at = ODD_OFFSET + lane * BYTES_PER_FIELD_ELEMENT;
            assert!(bytes[at..at + 32] == canonical.to_bytes(), "vector {v} lane {lane}");
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

fn cell_of(values: &[blst_fr]) -> [u8; BYTES_PER_CELL] {
    let mut cell = [0u8; BYTES_PER_CELL];
    for (j, value) in values.iter().enumerate() {
        cell[j * BYTES_PER_FIELD_ELEMENT..(j + 1) * BYTES_PER_FIELD_ELEMENT]
            .copy_from_slice(&fr_to_bytes(value));
    }
    cell
}

fn random_cell(rng: &mut ChaCha8Rng) -> [u8; BYTES_PER_CELL] {
    cell_of(&(0..FIELD_ELEMENTS_PER_CELL).map(|_| random_fr(rng)).collect::<Vec<_>>())
}

/// Σ_k powers[k]·I_k by the scalar route's steps: each column's weighted
/// cells in natural order, `inverse_fft`, then the shift by h_c^(−i).
fn scalar_interpolation(
    cosets: &Cosets,
    cells: &[[u8; BYTES_PER_CELL]],
    cell_indices: &[u64],
    powers: &[blst_fr],
) -> Vec<blst_fr> {
    let zero = fr_from_u64(0);
    let mut total = vec![zero; FIELD_ELEMENTS_PER_CELL];
    for column in 0..CELLS_PER_EXT_BLOB {
        let members: Vec<_> =
            (0..cells.len()).filter(|&k| cell_indices[k] as usize == column).collect();
        if members.is_empty() {
            continue;
        }
        let mut natural = vec![zero; FIELD_ELEMENTS_PER_CELL];
        for k in members {
            let elements = cells[k].chunks_exact(BYTES_PER_FIELD_ELEMENT);
            for (j, bytes) in elements.enumerate() {
                let element = fr_from_bytes(bytes.try_into().unwrap()).expect("cells below r");
                let i = reverse_bits(j, FIELD_ELEMENTS_PER_CELL.trailing_zeros());
                natural[i] = fr_add(&natural[i], &fr_mul(&powers[k], &element));
            }
        }
        let mut coefficients = vec![zero; FIELD_ELEMENTS_PER_CELL];
        inverse_fft(&mut coefficients, &natural, &cosets.inverse_roots, &cosets.inverse_size);
        let mut factor = fr_from_u64(1);
        for i in 0..FIELD_ELEMENTS_PER_CELL {
            total[i] = fr_add(&total[i], &fr_mul(&coefficients[i], &factor));
            factor = fr_mul(&factor, &cosets.shift_inverse[column]);
        }
    }
    total
}

/// Edge and random cells, powers and column patterns go through one kernel
/// in turn, so no call may see the columns of the call before.
#[test]
fn kernel_interpolation_matches_scalar_interpolation() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 5);
    let cosets = Cosets::new();
    // SAFETY: `kernels_run` checked `ifma_available`.
    let mut kernel = unsafe { InterpolationKernel::new(&cosets) };
    let (zero, one) = (fr_from_u64(0), fr_from_u64(1));
    let largest = fr_sub(&zero, &one);
    let edge_cells: Vec<_> =
        edge_inputs(&mut rng, FIELD_ELEMENTS_PER_CELL).iter().map(|v| cell_of(v)).collect();
    let mut edge_powers = vec![zero, one, largest];
    edge_powers.extend((0..2).map(|_| random_fr(&mut rng)));

    let mut cases: Vec<(Vec<[u8; BYTES_PER_CELL]>, Vec<u64>, Vec<blst_fr>)> = vec![
        (vec![], vec![], vec![]),
        (vec![edge_cells[4]], vec![0], vec![random_fr(&mut rng)]),
        (vec![edge_cells[3]], vec![127], vec![largest]),
        (edge_cells.clone(), vec![3; 5], edge_powers.clone()),
    ];
    let every_column: Vec<_> = (0..CELLS_PER_EXT_BLOB).map(|_| random_cell(&mut rng)).collect();
    let powers: Vec<_> = (0..CELLS_PER_EXT_BLOB).map(|_| random_fr(&mut rng)).collect();
    cases.push((every_column, (0..CELLS_PER_EXT_BLOB as u64).collect(), powers));
    cases.push((vec![edge_cells[2]; 256], vec![42; 256], vec![largest; 256]));
    let mut mixed = (vec![], vec![], vec![]);
    for _ in 0..300 {
        let cell = if rng.gen_bool(0.5) {
            edge_cells[rng.gen_range(0..edge_cells.len())]
        } else {
            random_cell(&mut rng)
        };
        mixed.0.push(cell);
        mixed.1.push(rng.gen_range(0..CELLS_PER_EXT_BLOB as u64));
        mixed.2.push(edge_powers[rng.gen_range(0..edge_powers.len())]);
    }
    cases.push(mixed);

    for (case, (cells, cell_indices, powers)) in cases.iter().enumerate() {
        let mut got = vec![fr_from_u64(7); FIELD_ELEMENTS_PER_CELL];
        // SAFETY: as above.
        unsafe { kernel.interpolate(cells, cell_indices, powers, &mut got) };
        let want = scalar_interpolation(&cosets, cells, cell_indices, powers);
        for i in 0..FIELD_ELEMENTS_PER_CELL {
            assert!(got[i].l == want[i].l, "case {case}, coefficient {i}");
        }
    }
}

/// `check` accepts exactly the cells whose every element is below r: each
/// value around r goes at both ends of the first and last cells and inside
/// the middle one.
#[test]
fn kernel_check_accepts_exactly_cells_below_r() {
    if !kernels_run() {
        return;
    }
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 6);
    // SAFETY: `kernels_run` checked `ifma_available`.
    let kernel = unsafe { InterpolationKernel::new(&Cosets::new()) };
    let valid: Vec<_> = (0..3).map(|_| random_cell(&mut rng)).collect();
    // SAFETY: as above.
    unsafe {
        assert!(kernel.check(&[]), "no cells");
        assert!(kernel.check(&valid), "random cells");
    }
    let r = Limbs::r();
    let values: Vec<_> = around_r().into_iter().chain([Limbs::from_bytes(&[0xff; 32])]).collect();
    for x in &values {
        for (cell, element) in [(0, 0), (0, 63), (1, 37), (2, 0), (2, 63)] {
            let mut cells = valid.clone();
            let at = element * BYTES_PER_FIELD_ELEMENT;
            cells[cell][at..at + BYTES_PER_FIELD_ELEMENT].copy_from_slice(&x.to_bytes());
            // SAFETY: as above.
            let accepted = unsafe { kernel.check(&cells) };
            assert!(accepted == x.is_below(&r), "cell {cell}, element {element}");
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
    assert!(ifma_available(), "this CPU has no avx512ifma");
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
        // SAFETY: asserted `ifma_available` above.
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
