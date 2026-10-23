use c_kzg::{Blob, Cell, ethereum_kzg_settings};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::simd_available,
    kzg::{BYTES_PER_BLOB, BYTES_PER_CELL, CELLS_PER_EXT_BLOB, CellExtender, SimdCellExtender},
};

const SEED: u64 = 0x5149_4d44_6365_6c6c;
/// r − 1, big-endian.
const R_MINUS_ONE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
];

type Cells = Box<[[u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]>;

fn extender() -> Option<SimdCellExtender> {
    let extender = SimdCellExtender::new();
    assert!(
        extender.is_some() || std::env::var_os("SILVER_REQUIRE_IFMA").is_none(),
        "SILVER_REQUIRE_IFMA is set, but the IFMA path is off: no avx512ifma, or no simd feature"
    );
    assert_eq!(extender.is_some(), simd_available());
    extender
}

fn cells_filled(byte: u8) -> Cells {
    vec![[byte; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB].into_boxed_slice().try_into().unwrap()
}

fn blob_of(mut element: impl FnMut(usize) -> [u8; 32]) -> Box<[u8; BYTES_PER_BLOB]> {
    let mut blob = Box::new([0u8; BYTES_PER_BLOB]);
    for (i, chunk) in blob.chunks_exact_mut(32).enumerate() {
        chunk.copy_from_slice(&element(i));
    }
    blob
}

/// Elements anywhere in [0, r): a random 255-bit value, redrawn when not below
/// r.
fn random_element_below_r(rng: &mut ChaCha8Rng) -> [u8; 32] {
    loop {
        let mut element: [u8; 32] = rng.r#gen();
        element[0] &= 0x7f;
        if element <= R_MINUS_ONE {
            return element;
        }
    }
}

fn ckzg_cells(blob: &[u8; BYTES_PER_BLOB]) -> Option<Vec<[u8; BYTES_PER_CELL]>> {
    let cells = ethereum_kzg_settings(0).compute_cells(&Blob::new(*blob)).ok()?;
    Some(cells.iter().map(Cell::to_bytes).collect())
}

fn assert_matches_both(
    simd: &mut SimdCellExtender,
    scalar: &mut CellExtender,
    blob: &[u8; BYTES_PER_BLOB],
    name: &str,
) {
    let expected = ckzg_cells(blob).expect("c-kzg accepts the blob");
    let mut scalar_cells = cells_filled(0);
    assert!(scalar.compute(blob, &mut scalar_cells));
    let mut cells = cells_filled(0xa5);
    assert!(simd.compute(blob, &mut cells), "{name}");
    for k in 0..CELLS_PER_EXT_BLOB {
        assert!(cells[k] == expected[k], "{name}: cell {k} differs from c-kzg");
        assert!(cells[k] == scalar_cells[k], "{name}: cell {k} differs from CellExtender");
    }
}

#[test]
fn simd_cells_match_ckzg_and_scalar() {
    let Some(mut simd) = extender() else { return };
    let mut scalar = CellExtender::new();
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);

    let mut blobs: Vec<(&str, Box<[u8; BYTES_PER_BLOB]>)> = vec![
        ("zero", blob_of(|_| [0; 32])),
        ("all r-1", blob_of(|_| R_MINUS_ONE)),
        ("alternating r-1 and 0", blob_of(|i| if i % 2 == 0 { R_MINUS_ONE } else { [0; 32] })),
    ];
    for _ in 0..3 {
        blobs.push((
            "random below 2^248",
            blob_of(|_| {
                let mut element: [u8; 32] = rng.r#gen();
                element[0] = 0;
                element
            }),
        ));
    }
    for _ in 0..3 {
        blobs.push(("full range below r", blob_of(|_| random_element_below_r(&mut rng))));
    }
    for _ in 0..3 {
        let mut blob = blob_of(|_| random_element_below_r(&mut rng));
        for _ in 0..64 {
            let at = 32 * rng.gen_range(0..4096);
            blob[at..at + 32].copy_from_slice(&R_MINUS_ONE);
        }
        blobs.push(("r-1 at random positions", blob));
    }

    for (name, blob) in &blobs {
        assert_matches_both(&mut simd, &mut scalar, blob, name);
    }
}

#[test]
fn repeated_calls_on_one_instance_agree() {
    let Some(mut simd) = extender() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    let blob = blob_of(|_| random_element_below_r(&mut rng));
    let other = blob_of(|_| random_element_below_r(&mut rng));
    let mut first = cells_filled(0);
    let mut second = cells_filled(0);
    let mut between = cells_filled(0);
    assert!(simd.compute(&blob, &mut first));
    assert!(simd.compute(&other, &mut between));
    assert!(simd.compute(&blob, &mut second));
    assert!(first[..] == second[..]);
    assert!(first[..] != between[..]);
}

#[test]
fn simd_rejects_invalid_blobs_and_leaves_cells() {
    let Some(mut simd) = extender() else { return };
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    let valid = blob_of(|_| random_element_below_r(&mut rng));
    let mut cells = cells_filled(0x5a);

    let mut r = R_MINUS_ONE;
    r[31] = 1;
    for position in [0, 1, 2047, 2048, 4095, rng.gen_range(0..4096)] {
        let mut blob = valid.clone();
        let at = 32 * position;
        match position % 3 {
            0 => blob[at..at + 32].copy_from_slice(&r),
            1 => blob[at..at + 32].fill(0xff),
            _ => {
                blob[at..at + 32].fill(0);
                blob[at] = 0x80;
            }
        }
        assert!(ckzg_cells(&blob).is_none(), "c-kzg rejects position {position}");
        assert!(!simd.compute(&blob, &mut cells), "position {position}");
        assert!(
            cells.iter().all(|cell| cell.iter().all(|&byte| byte == 0x5a)),
            "position {position}"
        );
    }
}

#[test]
fn simd_cells_match_ckzg_and_scalar_on_structured_extremes() {
    let Some(mut simd) = extender() else { return };
    let mut scalar = CellExtender::new();
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let one_bit = |i: usize| {
        let mut element = [0; 32];
        element[31 - i / 8 % 31] = 1 << (i % 8);
        element
    };

    let blobs: Vec<(&str, Box<[u8; BYTES_PER_BLOB]>)> = vec![
        ("r-1 first half, zero second", blob_of(|i| if i < 2048 { R_MINUS_ONE } else { [0; 32] })),
        ("zero first half, r-1 second", blob_of(|i| if i < 2048 { [0; 32] } else { R_MINUS_ONE })),
        (
            "r-1 on lane 0 of each vector",
            blob_of(|i| if i % 8 == 0 { R_MINUS_ONE } else { [0; 32] }),
        ),
        (
            "r-1 off lane 7 of each vector",
            blob_of(|i| if i % 8 == 7 { [0; 32] } else { R_MINUS_ONE }),
        ),
        (
            "r-1 in alternating blocks of 64",
            blob_of(|i| if i / 64 % 2 == 0 { R_MINUS_ONE } else { [0; 32] }),
        ),
        ("r-1 with one zero", blob_of(|i| if i == 1234 { [0; 32] } else { R_MINUS_ONE })),
        ("single bits", blob_of(one_bit)),
        (
            "r-1 xor random bit below 2^248",
            blob_of(|_| {
                let mut element = R_MINUS_ONE;
                element[rng.gen_range(1..32)] ^= 1 << rng.gen_range(0..8);
                if element > R_MINUS_ONE { R_MINUS_ONE } else { element }
            }),
        ),
    ];
    for (name, blob) in &blobs {
        assert_matches_both(&mut simd, &mut scalar, blob, name);
    }
}
