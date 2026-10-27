#[cfg(target_arch = "x86_64")]
use blst::{blst_fp, blst_fp_mul, blst_fp2, blst_p1_affine_generator};
use c_kzg::{Blob, Bytes48, Cell, KzgSettings, ethereum_kzg_settings};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

use crate::{
    bls::uncompress_in_g2_blst,
    kzg::{
        BYTES_PER_BLOB, BYTES_PER_CELL, CELLS_PER_EXT_BLOB, CellBatchVerifier, CellExtender,
        FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL, FR_ONE, FR_ZERO, INVERSE_BLOB_SIZE,
        INVERSE_CELL_SIZE, PRIMITIVE_ROOT_OF_UNITY,
        blst_ops::{fr_from_u64, fr_inverse, g2_neg},
        cosets::Cosets,
        domain::{reverse_bits, roots_of_unity},
        setup::{G2_NEG_GENERATOR, G2_S_POW_CELL},
        trusted_setup::{G2_MONOMIAL_0, G2_MONOMIAL_64},
    },
};
#[cfg(target_arch = "x86_64")]
use crate::{
    bls::{
        limbs::{Limbs, pack64},
        spec_pairing::{fp, miller_lines, mul, of_g1, of_g2, zero},
    },
    kzg::pairing_lines::PAIRING_LINES,
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
    let mut scalar = CellBatchVerifier::without_kernel();

    let mut sizes: Vec<usize> = (0..=17).collect();
    sizes.extend([64, 129]);
    for size in sizes {
        let batch = random_batch(&mut rng, &blobs, size);
        assert!(batch.ckzg(settings), "c-kzg accepts size {size}");
        assert!(batch.ours(&mut verifier), "size {size}");
        assert!(batch.ours(&mut scalar), "scalar route, size {size}");
    }

    let mut whole = Batch::default();
    for cell in 0..CELLS_PER_EXT_BLOB {
        whole.push(&blobs[0], cell);
    }
    assert!(whole.ours(&mut verifier), "every cell of one blob");
    assert!(whole.ours(&mut scalar), "scalar route, every cell of one blob");
}

/// Each case changes one thing in a valid batch; both verifiers must agree,
/// whatever the verdict.
#[test]
fn corrupted_batches_match_ckzg() {
    let settings = ethereum_kzg_settings(0);
    let mut rng = ChaCha8Rng::seed_from_u64(SEED ^ 1);
    let blobs = blobs(&mut rng, settings, 2);
    let mut verifier = CellBatchVerifier::new();
    let mut scalar = CellBatchVerifier::without_kernel();

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
        assert_eq!(batch.ours(&mut scalar), expected, "scalar route, case {case}");
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
        kzg::blst_ops::{g1_neg, g1_to_affine, pairing_check_affine},
    };

    // SAFETY: blst returns pointers to its static generators.
    let (g1, g2) = unsafe { (*blst_p1_affine_generator(), *blst_p2_affine_generator()) };
    let mut g1_projective = blst_p1::default();
    // SAFETY: valid pointers to single values.
    unsafe { blst_p1_from_affine(&mut g1_projective, &g1) };
    let minus_g1 = g1_to_affine(&g1_neg(&g1_projective));
    let (inf1, inf2) = (blst_p1_affine::default(), blst_p2_affine::default());

    assert!(pairing_check_affine(&g1, &inf2, &inf1, &g2), "both pairs skipped");
    assert!(pairing_check_affine(&g1, &inf2, &g1, &inf2), "G2 infinity in both pairs");
    assert!(pairing_check_affine(&g1, &g2, &minus_g1, &g2), "e(g1, g2)·e(−g1, g2) = 1");
    assert!(!pairing_check_affine(&g1, &g2, &g1, &inf2), "e(g1, g2) alone is not 1");
}

/// The verifier's G2 literals are blst's decoding of the setup's compressed
/// points, with the generator negated by blst, limb for limb.
#[test]
fn setup_g2_literals_match_blst() {
    let cell = uncompress_in_g2_blst(&G2_MONOMIAL_64).expect("setup point 64 decodes");
    assert!(G2_S_POW_CELL.x == cell.x && G2_S_POW_CELL.y == cell.y, "[s^64]");
    let generator = uncompress_in_g2_blst(&G2_MONOMIAL_0).expect("setup point 0 decodes");
    let negated = g2_neg(&generator);
    assert!(G2_NEG_GENERATOR.x == negated.x && G2_NEG_GENERATOR.y == negated.y, "−[1]");
}

/// Each step of `PAIRING_LINES` is the spec's line for its G2 point, which
/// `Embedded.ofG2` untwists, up to a factor c·w⁻³ with c in Fp2. So at P =
/// (x, y), w³ times the spec's line is c·((1, l1·x, 0) + (0, l2·y, 0)·w).
#[cfg(target_arch = "x86_64")]
#[test]
fn pairing_lines_are_the_spec_lines() {
    /// Fp8's form v·2^416, read as blst limbs, is v·2^32; 2^352 as blst
    /// limbs is 2^−32.
    fn blst_of_fp8_form(limbs: &Limbs) -> blst_fp {
        let two_pow_352 = blst_fp { l: [0, 0, 0, 0, 0, 1 << 32] };
        let mut out = blst_fp::default();
        // SAFETY: valid pointers to single values.
        unsafe { blst_fp_mul(&mut out, &blst_fp { l: pack64(limbs) }, &two_pow_352) };
        out
    }
    fn stored(step: usize, lane: usize) -> blst_fp2 {
        let lanes = &PAIRING_LINES.0[step];
        blst_fp2 { fp: [blst_of_fp8_form(&lanes[lane]), blst_of_fp8_form(&lanes[lane + 1])] }
    }
    fn times(a: &blst_fp2, b: &blst_fp) -> blst_fp2 {
        let mut out = blst_fp2::default();
        for c in 0..2 {
            // SAFETY: valid pointers to single values.
            unsafe { blst_fp_mul(&mut out.fp[c], &a.fp[c], b) };
        }
        out
    }

    // The generator's x and y are not 0, so the line's values there fix l1
    // and l2.
    // SAFETY: blst returns a pointer to a static point.
    let p = unsafe { *blst_p1_affine_generator() };
    let mut w_cubed = zero();
    w_cubed.fp6[1].fp2[1].fp[0] = fp(1);
    for (lane, q) in [(0, &G2_S_POW_CELL), (4, &G2_NEG_GENERATOR)] {
        let spec = miller_lines(&of_g2(q), &of_g1(&p));
        assert_eq!(spec.len(), PAIRING_LINES.0.len());
        for (step, line) in spec.iter().enumerate() {
            let scaled = mul(line, &w_cubed);
            let mut c = zero();
            c.fp6[0].fp2[0] = scaled.fp6[0].fp2[0];
            let mut ours = zero();
            ours.fp6[0].fp2[0].fp[0] = fp(1);
            ours.fp6[0].fp2[1] = times(&stored(step, lane), &p.x);
            ours.fp6[1].fp2[1] = times(&stored(step, lane + 2), &p.y);
            assert!(scaled == mul(&c, &ours), "step {step}, lane {lane}");
        }
    }
}

#[test]
fn fr_literals_match_blst() {
    assert!(FR_ZERO == fr_from_u64(0), "0");
    assert!(FR_ONE == fr_from_u64(1), "1");
    assert!(PRIMITIVE_ROOT_OF_UNITY == fr_from_u64(7), "7");
    let cell_size = fr_from_u64(FIELD_ELEMENTS_PER_CELL as u64);
    assert!(INVERSE_CELL_SIZE == fr_inverse(&cell_size), "1/64");
    let blob_size = fr_from_u64(FIELD_ELEMENTS_PER_BLOB as u64);
    assert!(INVERSE_BLOB_SIZE == fr_inverse(&blob_size), "1/4096");
}

/// blst's form of 1/2^k is 2^(256 − k): one bit of the top word, for k ≤ 64.
#[test]
fn inverse_sizes_are_powers_of_two() {
    let form_of_inverse = |n: usize| [0, 0, 0, 1u64 << (256 - n.trailing_zeros() - 192)];
    assert!(INVERSE_CELL_SIZE.l == form_of_inverse(FIELD_ELEMENTS_PER_CELL), "1/64");
    assert!(INVERSE_BLOB_SIZE.l == form_of_inverse(FIELD_ELEMENTS_PER_BLOB), "1/4096");
}

#[test]
fn coset_shift_inverses_match_blst() {
    let log_ext_blob = (FIELD_ELEMENTS_PER_CELL * CELLS_PER_EXT_BLOB).trailing_zeros();
    let ext_roots = roots_of_unity(log_ext_blob);
    let cosets = Cosets::new();
    for k in 0..CELLS_PER_EXT_BLOB {
        let shift = ext_roots[reverse_bits(FIELD_ELEMENTS_PER_CELL * k, log_ext_blob)];
        assert!(cosets.shift_inverse[k] == fr_inverse(&shift), "cell {k}");
    }
}
