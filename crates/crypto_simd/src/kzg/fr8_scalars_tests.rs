use blst::blst_fr;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::simd_available,
    kzg::{
        BYTES_PER_CELL, BYTES_PER_FIELD_ELEMENT, CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_CELL,
        blst_msm::scalar_bytes,
        blst_ops::{fr_add, fr_from_bytes, fr_from_u64, fr_mul},
        cosets::Cosets,
        domain::reverse_bits,
        fft::inverse_fft,
        fr8_interpolation::Interpolation,
        fr8_scalars::CellScalars,
    },
};

const SEED: u64 = 0x4652_3873_6361_6c61;
const R_MINUS_ONE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
];

struct Fixture {
    cosets: Cosets,
    scalars: CellScalars,
    interpolation: Interpolation,
}

fn fixture() -> Option<Fixture> {
    let available = simd_available();
    assert!(
        available || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    available.then(|| {
        let cosets = Cosets::new();
        Fixture {
            scalars: CellScalars::new(&cosets),
            interpolation: Interpolation::new(&cosets),
            cosets,
        }
    })
}

fn random_fr(rng: &mut ChaCha8Rng) -> blst_fr {
    loop {
        let mut bytes: [u8; 32] = rng.r#gen();
        bytes[0] &= 0x7f;
        if let Some(fr) = fr_from_bytes(&bytes) {
            return fr;
        }
    }
}

/// Cells of elements anywhere in [0, r), with some elements 0 and r − 1.
fn random_cells(rng: &mut ChaCha8Rng, count: usize) -> Vec<[u8; BYTES_PER_CELL]> {
    (0..count)
        .map(|_| {
            let mut cell = [0u8; BYTES_PER_CELL];
            for element in cell.chunks_exact_mut(BYTES_PER_FIELD_ELEMENT) {
                match rng.gen_range(0..16) {
                    0 => element.fill(0),
                    1 => element.copy_from_slice(&R_MINUS_ONE),
                    _ => element.copy_from_slice(&scalar_be(&random_fr(rng))),
                }
            }
            cell
        })
        .collect()
}

fn scalar_be(fr: &blst_fr) -> [u8; 32] {
    let mut bytes = scalar_bytes(fr);
    bytes.reverse();
    bytes
}

/// The blst computation of `CellBatchVerifier`: the powers, the three sets of
/// pairing scalars, and the 64 interpolation scalars.
struct Expected {
    ll: Vec<[u8; 32]>,
    rlp: Vec<[u8; 32]>,
    rlc: Vec<[u8; 32]>,
    rli: Vec<[u8; 32]>,
}

fn expected(
    cosets: &Cosets,
    r: &blst_fr,
    cell_indices: &[u64],
    index_of_cell: &[usize],
    unique: usize,
    cells: &[[u8; BYTES_PER_CELL]],
) -> Expected {
    let n = cell_indices.len();
    let mut powers = Vec::new();
    let mut power = fr_from_u64(1);
    for _ in 0..n {
        powers.push(power);
        power = fr_mul(&power, r);
    }
    let mut rlc = vec![fr_from_u64(0); unique];
    for k in 0..n {
        rlc[index_of_cell[k]] = fr_add(&rlc[index_of_cell[k]], &powers[k]);
    }

    let mut columns = vec![fr_from_u64(0); CELLS_PER_EXT_BLOB * FIELD_ELEMENTS_PER_CELL];
    let mut used = [false; CELLS_PER_EXT_BLOB];
    for k in 0..n {
        let c = cell_indices[k] as usize;
        used[c] = true;
        for j in 0..FIELD_ELEMENTS_PER_CELL {
            let element = fr_from_bytes(
                cells[k][j * BYTES_PER_FIELD_ELEMENT..(j + 1) * BYTES_PER_FIELD_ELEMENT]
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
            let at = c * FIELD_ELEMENTS_PER_CELL + j;
            columns[at] = fr_add(&columns[at], &fr_mul(&powers[k], &element));
        }
    }
    let mut interpolation = vec![fr_from_u64(0); FIELD_ELEMENTS_PER_CELL];
    let mut coefficients = vec![fr_from_u64(0); FIELD_ELEMENTS_PER_CELL];
    for c in (0..CELLS_PER_EXT_BLOB).filter(|&c| used[c]) {
        let column: Vec<_> = (0..FIELD_ELEMENTS_PER_CELL)
            .map(|j| columns[c * FIELD_ELEMENTS_PER_CELL + reverse_bits(j, 6)])
            .collect();
        inverse_fft(&mut coefficients, &column, &cosets.inverse_roots, &cosets.inverse_size);
        let mut factor = fr_from_u64(1);
        for i in 0..FIELD_ELEMENTS_PER_CELL {
            let term = fr_mul(&coefficients[i], &factor);
            interpolation[i] = fr_add(&interpolation[i], &term);
            factor = fr_mul(&factor, &cosets.shift_inverse[c]);
        }
    }

    let bytes = |frs: &[blst_fr]| frs.iter().map(scalar_bytes).collect();
    let rlp: Vec<_> = (0..n)
        .map(|k| fr_mul(&powers[k], &cosets.shift_pow_cell[cell_indices[k] as usize]))
        .collect();
    Expected { ll: bytes(&powers), rlp: bytes(&rlp), rlc: bytes(&rlc), rli: bytes(&interpolation) }
}

struct Batch {
    r: blst_fr,
    cell_indices: Vec<u64>,
    index_of_cell: Vec<usize>,
    unique: usize,
    cells: Vec<[u8; BYTES_PER_CELL]>,
}

/// `commitments` distinct commitments, cells in random columns, repeats
/// allowed.
fn random_batch(rng: &mut ChaCha8Rng, size: usize, commitments: usize) -> Batch {
    Batch {
        r: random_fr(rng),
        cell_indices: (0..size).map(|_| rng.gen_range(0..CELLS_PER_EXT_BLOB as u64)).collect(),
        index_of_cell: (0..size).map(|_| rng.gen_range(0..commitments)).collect(),
        unique: commitments,
        cells: random_cells(rng, size),
    }
}

fn assert_matches_blst(fixture: &mut Fixture, batch: &Batch, name: &str) {
    let Batch { r, cell_indices, index_of_cell, unique, cells } = batch;
    let want = expected(&fixture.cosets, r, cell_indices, index_of_cell, *unique, cells);
    // SAFETY: `fixture` returned Some, so avx512f and avx512ifma are available.
    let rli = unsafe {
        fixture.scalars.fill(r, cell_indices, index_of_cell, *unique);
        fixture.interpolation.scalars(cells, cell_indices, &fixture.scalars)
    };
    assert!(fixture.scalars.ll() == want.ll, "{name}: LL");
    assert!(fixture.scalars.rlp() == want.rlp, "{name}: RLP");
    assert!(fixture.scalars.rlc() == want.rlc, "{name}: RLC");
    let rli = rli.unwrap_or_else(|| panic!("{name}: cells rejected"));
    assert!(rli[..] == want.rli[..], "{name}: RLI");
}

#[test]
fn scalars_match_blst_on_random_batches() {
    let Some(mut fixture) = fixture() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    for (size, commitments) in
        [(0, 0), (1, 1), (2, 1), (7, 3), (8, 8), (9, 2), (18, 18), (144, 18), (300, 20), (2304, 18)]
    {
        let batch = random_batch(&mut rng, size, commitments);
        assert_matches_blst(
            &mut fixture,
            &batch,
            &format!("{size} cells, {commitments} commitments"),
        );
    }
}

#[test]
fn scalars_match_blst_on_repeats_and_every_column() {
    let Some(mut fixture) = fixture() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);

    let mut batch = random_batch(&mut rng, 40, 5);
    batch.cell_indices.fill(77);
    batch.cells[1] = batch.cells[0];
    batch.cells[2] = batch.cells[0];
    assert_matches_blst(&mut fixture, &batch, "one column, repeated cells");

    let blobs = 6;
    let mut batch = random_batch(&mut rng, CELLS_PER_EXT_BLOB * blobs, blobs);
    for k in 0..batch.cell_indices.len() {
        batch.cell_indices[k] = (k / blobs) as u64;
        batch.index_of_cell[k] = k % blobs;
    }
    assert_matches_blst(&mut fixture, &batch, "all 128 columns");
}

#[test]
fn rlc_sums_stay_exact_across_folds() {
    let Some(mut fixture) = fixture() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    let mut batch = random_batch(&mut rng, 5000, 3);
    batch.cells.truncate(5000);
    for cell in &mut batch.cells {
        cell.fill(0);
    }
    assert_matches_blst(&mut fixture, &batch, "5000 cells, three commitments");
}

#[test]
fn an_element_of_r_or_more_is_rejected() {
    let Some(mut fixture) = fixture() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let valid = random_batch(&mut rng, 12, 4);
    let mut modulus = R_MINUS_ONE;
    modulus[31] = 1;
    for (position, bytes) in [
        (0, modulus),
        (63, [0xff; 32]),
        (31, {
            let mut value = [0u8; 32];
            value[0] = 0x80;
            value
        }),
    ] {
        for cell in [0, 5, 11] {
            let mut batch = Batch { cells: valid.cells.clone(), ..valid_clone(&valid) };
            let at = position * BYTES_PER_FIELD_ELEMENT;
            batch.cells[cell][at..at + 32].copy_from_slice(&bytes);
            // SAFETY: `fixture` returned Some, so avx512f and avx512ifma are available.
            let rli = unsafe {
                fixture.scalars.fill(
                    &batch.r,
                    &batch.cell_indices,
                    &batch.index_of_cell,
                    batch.unique,
                );
                fixture.interpolation.scalars(&batch.cells, &batch.cell_indices, &fixture.scalars)
            };
            assert!(rli.is_none(), "element {position} of cell {cell}");
        }
    }
}

fn valid_clone(batch: &Batch) -> Batch {
    Batch {
        r: batch.r,
        cell_indices: batch.cell_indices.clone(),
        index_of_cell: batch.index_of_cell.clone(),
        unique: batch.unique,
        cells: Vec::new(),
    }
}
