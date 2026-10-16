use c_kzg::{Blob, Bytes48, Cell, KzgSettings, ethereum_kzg_settings};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::kzg::{
    BYTES_PER_BLOB, BYTES_PER_CELL, CELLS_PER_EXT_BLOB, CellBatchVerifier, CellExtender,
};

const SEED: u64 = 0x6b7a_6763_656c_6c73;
/// r, big-endian.
const MODULUS: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

/// The same field element, encoded as its value plus r: the spec rejects it.
fn add_modulus(element: &mut [u8]) {
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = element[i] as u16 + MODULUS[i] as u16 + carry;
        element[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "the element is small enough");
}

struct BlobFixture {
    commitment: [u8; 48],
    cells: Vec<[u8; BYTES_PER_CELL]>,
    proofs: Vec<[u8; 48]>,
}

/// Field elements below r: each 32-byte big-endian element has a zero top byte.
fn random_blob(rng: &mut ChaCha8Rng) -> Blob {
    let mut bytes = [0u8; BYTES_PER_BLOB];
    rng.fill(&mut bytes[..]);
    for element in bytes.chunks_exact_mut(32) {
        element[0] = 0;
    }
    Blob::new(bytes)
}

fn fixture(settings: &KzgSettings, blob: &Blob) -> BlobFixture {
    let commitment = settings.blob_to_kzg_commitment(blob).unwrap().to_bytes().into_inner();
    let (cells, proofs) = settings.compute_cells_and_kzg_proofs(blob).unwrap();
    BlobFixture {
        commitment,
        cells: cells.iter().map(Cell::to_bytes).collect(),
        proofs: proofs.iter().map(|p| p.to_bytes().into_inner()).collect(),
    }
}

#[derive(Clone, Default)]
struct Batch {
    commitments: Vec<[u8; 48]>,
    cell_indices: Vec<u64>,
    cells: Vec<[u8; BYTES_PER_CELL]>,
    proofs: Vec<[u8; 48]>,
}

impl Batch {
    fn push(&mut self, blob: &BlobFixture, cell: usize) {
        self.commitments.push(blob.commitment);
        self.cell_indices.push(cell as u64);
        self.cells.push(blob.cells[cell]);
        self.proofs.push(blob.proofs[cell]);
    }

    fn ours(&self, verifier: &mut CellBatchVerifier) -> bool {
        verifier.verify(&self.commitments, &self.cell_indices, &self.cells, &self.proofs)
    }

    /// c-kzg's verdict, with its errors as false, as silver treats them.
    fn ckzg(&self, settings: &KzgSettings) -> bool {
        let commitments: Vec<_> = self.commitments.iter().map(|c| Bytes48::new(*c)).collect();
        let cells: Vec<_> = self.cells.iter().map(|c| Cell::new(*c)).collect();
        let proofs: Vec<_> = self.proofs.iter().map(|p| Bytes48::new(*p)).collect();
        settings
            .verify_cell_kzg_proof_batch(&commitments, &self.cell_indices, &cells, &proofs)
            .unwrap_or(false)
    }
}

fn blobs(rng: &mut ChaCha8Rng, settings: &KzgSettings, count: usize) -> Vec<BlobFixture> {
    (0..count).map(|_| fixture(settings, &random_blob(rng))).collect()
}

/// Random cells of random blobs, in random order, repeats allowed.
fn random_batch(rng: &mut ChaCha8Rng, blobs: &[BlobFixture], size: usize) -> Batch {
    let mut batch = Batch::default();
    for _ in 0..size {
        batch.push(&blobs[rng.gen_range(0..blobs.len())], rng.gen_range(0..CELLS_PER_EXT_BLOB));
    }
    batch
}

#[test]
fn valid_batches_verify_like_ckzg() {
    let settings = ethereum_kzg_settings(0);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED);
    let blobs = blobs(&mut rng, settings, 3);
    let mut verifier = CellBatchVerifier::new();

    let mut sizes: Vec<usize> = (0..=17).collect();
    sizes.extend([64, 129]);
    for size in sizes {
        let batch = random_batch(&mut rng, &blobs, size);
        assert!(batch.ckzg(settings), "c-kzg accepts size {size}");
        assert!(batch.ours(&mut verifier), "size {size}");
    }

    let mut whole = Batch::default();
    for cell in 0..CELLS_PER_EXT_BLOB {
        whole.push(&blobs[0], cell);
    }
    assert!(whole.ours(&mut verifier), "every cell of one blob");
}

/// Each case changes one thing in a valid batch; both verifiers must agree,
/// whatever the verdict.
#[test]
fn corrupted_batches_match_ckzg() {
    let settings = ethereum_kzg_settings(0);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    let blobs = blobs(&mut rng, settings, 2);
    let mut verifier = CellBatchVerifier::new();

    let mut rejected = 0;
    for case in 0..108 {
        let size = rng.gen_range(1..12);
        let mut batch = random_batch(&mut rng, &blobs, size);
        let k = rng.gen_range(0..batch.cells.len());
        match case % 9 {
            0 => batch.cells[k][rng.gen_range(0..BYTES_PER_CELL)] ^= 1 << rng.gen_range(0..8),
            1 => batch.cells[k][32 * rng.gen_range(0..64)] = 0xff,
            2 => batch.proofs[k][rng.gen_range(0..48)] ^= 1 << rng.gen_range(0..8),
            3 => batch.commitments[k][rng.gen_range(0..48)] ^= 1 << rng.gen_range(0..8),
            4 => batch.cell_indices[k] = (batch.cell_indices[k] + 1) % CELLS_PER_EXT_BLOB as u64,
            5 => batch.cell_indices[k] = CELLS_PER_EXT_BLOB as u64 + rng.gen_range(0..1000),
            6 => {
                let other = random_batch(&mut rng, &blobs, 1);
                batch.proofs[k] = other.proofs[0];
            }
            7 => {
                batch.cells.pop();
            }
            _ => {
                let at = 32 * rng.gen_range(0..64);
                add_modulus(&mut batch.cells[k][at..at + 32]);
            }
        }
        let expected = batch.ckzg(settings);
        rejected += !expected as usize;
        assert_eq!(batch.ours(&mut verifier), expected, "case {case}");
    }
    assert!(rejected > 90, "most corruptions are rejected: {rejected}");
}

fn ckzg_cells(
    settings: &KzgSettings,
    blob: &[u8; BYTES_PER_BLOB],
) -> Option<Vec<[u8; BYTES_PER_CELL]>> {
    let cells = settings.compute_cells(&Blob::new(*blob)).ok()?;
    Some(cells.iter().map(Cell::to_bytes).collect())
}

#[test]
fn cells_match_ckzg() {
    let settings = ethereum_kzg_settings(0);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 2);
    let mut extender = CellExtender::new();
    let mut cells = Box::new([[0u8; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);

    let mut blobs: Vec<[u8; BYTES_PER_BLOB]> = vec![[0; BYTES_PER_BLOB]];
    for _ in 0..3 {
        blobs.push(*random_blob(&mut rng));
    }
    // r − 1, the largest element, at random positions.
    let mut largest = *random_blob(&mut rng);
    for _ in 0..64 {
        let at = 32 * rng.gen_range(0..4096);
        largest[at..at + 32].copy_from_slice(&MODULUS);
        largest[at + 31] -= 1;
    }
    blobs.push(largest);

    for (b, blob) in blobs.iter().enumerate() {
        let expected = ckzg_cells(settings, blob).expect("c-kzg accepts the blob");
        assert!(extender.compute(blob, &mut cells), "blob {b}");
        for (k, cell) in cells.iter().enumerate() {
            assert!(*cell == expected[k], "blob {b}, cell {k}");
        }
    }
}

/// An element of r or more anywhere rejects the blob, as in c-kzg, and leaves
/// `cells` as it was.
#[test]
fn invalid_blobs_are_rejected() {
    let settings = ethereum_kzg_settings(0);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 3);
    let mut extender = CellExtender::new();
    let mut cells = Box::new([[0x5a; BYTES_PER_CELL]; CELLS_PER_EXT_BLOB]);
    let valid = *random_blob(&mut rng);

    for position in [0, 1, 2047, 2048, 4095, rng.gen_range(0..4096)] {
        let mut blob = valid;
        let at = 32 * position;
        if position % 2 == 0 {
            add_modulus(&mut blob[at..at + 32]);
        } else {
            blob[at..at + 32].fill(0xff);
        }
        assert!(ckzg_cells(settings, &blob).is_none(), "c-kzg rejects position {position}");
        assert!(!extender.compute(&blob, &mut cells), "position {position}");
        assert!(
            cells.iter().all(|cell| cell.iter().all(|&byte| byte == 0x5a)),
            "position {position}"
        );
    }
}

/// The spec's `pairingCheck` skips a pair when either point is infinity.
#[test]
fn pairing_check_skips_infinity_on_either_side() {
    use blst::{blst_p1, blst_p1_affine_generator, blst_p1_from_affine, blst_p2_affine_generator};

    use crate::{
        bls::{blst_p1_affine, blst_p2_affine},
        kzg::blst_ops::{g1_neg, g1_to_affine, pairing_check},
    };

    // SAFETY: blst returns pointers to its static generators.
    let (g1, g2) = unsafe { (*blst_p1_affine_generator(), *blst_p2_affine_generator()) };
    let mut g1_projective = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_from_affine(&mut g1_projective, &g1) };
    let minus_g1 = g1_to_affine(&g1_neg(&g1_projective));
    let (inf1, inf2) = (blst_p1_affine::default(), blst_p2_affine::default());

    assert!(pairing_check(&g1, &inf2, &inf1, &g2), "both pairs skipped");
    assert!(pairing_check(&g1, &inf2, &g1, &inf2), "G2 infinity in both pairs");
    assert!(pairing_check(&g1, &g2, &minus_g1, &g2), "e(g1, g2)·e(−g1, g2) = 1");
    assert!(!pairing_check(&g1, &g2, &g1, &inf2), "e(g1, g2) alone is not 1");
}
