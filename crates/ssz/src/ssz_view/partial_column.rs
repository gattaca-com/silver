//! Partial data-column wire types (fulu/partial-columns and
//! gloas/partial-columns p2p specs). Row bitmaps index blobs, not
//! columns, and decode to `u128`: schedules beyond 128 rows are
//! unsupported.

use super::{
    BYTES_PER_CELL, BYTES_PER_KZG_COMMITMENT, BYTES_PER_KZG_PROOF, MAX_BLOB_COMMITMENTS_PER_BLOCK,
    u32_le,
};

pub const PARTIAL_COLUMNS_VERSION_BYTE: u8 = 0x00;
pub const FULU_GROUP_ID_SIZE: usize = 33;
pub const GLOAS_GROUP_ID_SIZE: usize = 41;

// PartialDataColumnHeader:
//   [0..4)     offset to kzg_commitments (== 340)
//   [4..212)   signed_block_header (SignedBeaconBlockHeader, 208B)
//   [212..340) kzg_commitments_inclusion_proof (Vector[Bytes32, 4])
//   [340..)    kzg_commitments (n * 48B)
pub const PARTIAL_HEADER_FIXED: usize = 340;

const PARTIAL_SIDECAR_FIXED_FULU: usize = 16;
const PARTIAL_SIDECAR_FIXED_GLOAS: usize = 12;

/// Spec constant: bounds the Gloas SSZ payload, not the protobuf RPC.
pub const MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE_GLOAS: usize = 8_585_741;
/// Derived from the Fulu SSZ schema bounds (4096-cell lists plus a
/// one-element header list).
pub const MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE_FULU: usize = PARTIAL_SIDECAR_FIXED_FULU +
    bitlist_bytes(MAX_BLOB_COMMITMENTS_PER_BLOCK) +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * (BYTES_PER_CELL + BYTES_PER_KZG_PROOF) +
    4 +
    PARTIAL_HEADER_FIXED +
    MAX_BLOB_COMMITMENTS_PER_BLOCK * BYTES_PER_KZG_COMMITMENT;

pub fn fulu_group_id(block_root: &[u8; 32]) -> [u8; FULU_GROUP_ID_SIZE] {
    let mut id = [PARTIAL_COLUMNS_VERSION_BYTE; FULU_GROUP_ID_SIZE];
    id[1..].copy_from_slice(block_root);
    id
}

pub fn gloas_group_id(block_root: &[u8; 32], slot: u64) -> [u8; GLOAS_GROUP_ID_SIZE] {
    let mut id = [PARTIAL_COLUMNS_VERSION_BYTE; GLOAS_GROUP_ID_SIZE];
    id[1..33].copy_from_slice(block_root);
    id[33..].copy_from_slice(&slot.to_le_bytes());
    id
}

pub const fn bitlist_bytes(n_bits: usize) -> usize {
    n_bits / 8 + 1
}

/// Decode a bitlist into a row mask. Canonical form is enforced: the
/// delimiter bit terminates the last byte, so a trailing zero byte or
/// empty input fails. `max_bits` is the trusted row count; anything
/// longer (or beyond the 128-row `u128` ceiling) fails.
pub fn bitlist_u128(buf: &[u8], max_bits: usize) -> Option<(u128, usize)> {
    let last = *buf.last()?;
    if last == 0 {
        return None;
    }
    let delimiter = 7 - last.leading_zeros() as usize;
    let n = (buf.len() - 1) * 8 + delimiter;
    if n > max_bits || n > 128 {
        return None;
    }
    let mut mask = 0u128;
    for (i, &b) in buf.iter().enumerate() {
        let b = if i == buf.len() - 1 { b ^ (1 << delimiter) } else { b };
        if b == 0 {
            continue;
        }
        mask |= (b as u128) << (i * 8);
    }
    Some((mask, n))
}

/// `mask` must fit in `n_bits`; `out` must be exactly `bitlist_bytes(n_bits)`.
pub fn write_bitlist_u128(mask: u128, n_bits: usize, out: &mut [u8]) {
    debug_assert!(n_bits <= 128 && (n_bits == 128 || mask >> n_bits == 0));
    debug_assert_eq!(out.len(), bitlist_bytes(n_bits));
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = if i * 8 < 128 { (mask >> (i * 8)) as u8 } else { 0 };
    }
    out[n_bits / 8] |= 1 << (n_bits % 8);
}

// PartialDataColumnSidecar (Fulu):
//   [0..4)   offset to cells_present_bitmap (== 16)
//   [4..8)   offset to partial_column
//   [8..12)  offset to kzg_proofs
//   [12..16) offset to header (List[PartialDataColumnHeader, 1])
//   bitmap | cells (k * 2048) | proofs (k * 48) | header list
// A one-element header list is a 4-byte inner offset (== 4) plus the
// header SSZ; an omitted header is an empty list (zero bytes).
pub struct PartialDataColumnSidecarFuluView;

impl PartialDataColumnSidecarFuluView {
    /// Full structural check; returns the row mask. The bitmap must
    /// have exactly the trusted `n_rows` bits, cell/proof region
    /// lengths must match its popcount, and a cell-less sidecar is
    /// only valid when it carries a header.
    pub fn check_size(buf: &[u8], n_rows: usize) -> Option<u128> {
        if buf.len() < PARTIAL_SIDECAR_FIXED_FULU + 1 ||
            buf.len() > MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE_FULU
        {
            return None;
        }
        let o0 = u32_le(buf, 0) as usize;
        let o1 = u32_le(buf, 4) as usize;
        let o2 = u32_le(buf, 8) as usize;
        let o3 = u32_le(buf, 12) as usize;
        if o0 != PARTIAL_SIDECAR_FIXED_FULU || o1 < o0 || o2 < o1 || o3 < o2 || o3 > buf.len() {
            return None;
        }
        let (rows, n) = bitlist_u128(&buf[o0..o1], n_rows)?;
        let k = rows.count_ones() as usize;
        if n != n_rows || o2 - o1 != k * BYTES_PER_CELL || o3 - o2 != k * BYTES_PER_KZG_PROOF {
            return None;
        }
        let header = &buf[o3..];
        if header.is_empty() {
            (k > 0).then_some(rows)
        } else {
            if header.len() < 4 || u32_le(header, 0) != 4 {
                return None;
            }
            PartialDataColumnHeaderView::check_size(&header[4..]).then_some(rows)
        }
    }

    #[inline]
    pub fn cells(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 4) as usize..u32_le(buf, 8) as usize]
    }

    #[inline]
    pub fn proofs(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 8) as usize..u32_le(buf, 12) as usize]
    }

    /// The header SSZ, or empty when omitted.
    #[inline]
    pub fn header(buf: &[u8]) -> &[u8] {
        let list = &buf[u32_le(buf, 12) as usize..];
        if list.is_empty() { list } else { &list[4..] }
    }
}

// PartialDataColumnSidecar (Gloas): three offsets, no header field.
//   [0..4)  offset to cells_present_bitmap (== 12)
//   [4..8)  offset to partial_column
//   [8..12) offset to kzg_proofs
pub struct PartialDataColumnSidecarGloasView;

impl PartialDataColumnSidecarGloasView {
    /// As Fulu, but a partial payload must contain at least one cell.
    pub fn check_size(buf: &[u8], n_rows: usize) -> Option<u128> {
        if buf.len() < PARTIAL_SIDECAR_FIXED_GLOAS + 1 ||
            buf.len() > MAX_PARTIAL_DATA_COLUMN_SIDECAR_SIZE_GLOAS
        {
            return None;
        }
        let o0 = u32_le(buf, 0) as usize;
        let o1 = u32_le(buf, 4) as usize;
        let o2 = u32_le(buf, 8) as usize;
        if o0 != PARTIAL_SIDECAR_FIXED_GLOAS || o1 < o0 || o2 < o1 || o2 > buf.len() {
            return None;
        }
        let (rows, n) = bitlist_u128(&buf[o0..o1], n_rows)?;
        let k = rows.count_ones() as usize;
        if n != n_rows ||
            k == 0 ||
            o2 - o1 != k * BYTES_PER_CELL ||
            buf.len() - o2 != k * BYTES_PER_KZG_PROOF
        {
            return None;
        }
        Some(rows)
    }

    #[inline]
    pub fn cells(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 4) as usize..u32_le(buf, 8) as usize]
    }

    #[inline]
    pub fn proofs(buf: &[u8]) -> &[u8] {
        &buf[u32_le(buf, 8) as usize..]
    }
}

pub struct PartialDataColumnHeaderView;

impl PartialDataColumnHeaderView {
    pub fn check_size(buf: &[u8]) -> bool {
        if buf.len() < PARTIAL_HEADER_FIXED || u32_le(buf, 0) as usize != PARTIAL_HEADER_FIXED {
            return false;
        }
        let commitments = buf.len() - PARTIAL_HEADER_FIXED;
        commitments.is_multiple_of(BYTES_PER_KZG_COMMITMENT) &&
            commitments / BYTES_PER_KZG_COMMITMENT <= MAX_BLOB_COMMITMENTS_PER_BLOCK
    }

    #[inline]
    pub fn signed_block_header(buf: &[u8]) -> &[u8; 208] {
        super::fixed(buf, 4)
    }

    #[inline]
    pub fn inclusion_proof(buf: &[u8]) -> &[u8; 128] {
        super::fixed(buf, 212)
    }

    #[inline]
    pub fn kzg_commitments(buf: &[u8]) -> &[u8] {
        &buf[PARTIAL_HEADER_FIXED..]
    }
}

// PartialDataColumnPartsMetadata: { available, requests }, both
// bitlists of the block's row count.
//   [0..4) offset to available (== 8)
//   [4..8) offset to requests
pub struct PartialDataColumnPartsMetadataView;

impl PartialDataColumnPartsMetadataView {
    /// Returns (available, requests); both bitlists must have exactly
    /// the trusted `n_rows` bits.
    pub fn check_size(buf: &[u8], n_rows: usize) -> Option<(u128, u128)> {
        if buf.len() < 10 {
            return None;
        }
        let o0 = u32_le(buf, 0) as usize;
        let o1 = u32_le(buf, 4) as usize;
        if o0 != 8 || o1 < o0 || o1 > buf.len() {
            return None;
        }
        let (available, n) = bitlist_u128(&buf[o0..o1], n_rows)?;
        let (requests, n_req) = bitlist_u128(&buf[o1..], n_rows)?;
        (n == n_rows && n_req == n_rows).then_some((available, requests))
    }
}

pub const fn parts_metadata_len(n_rows: usize) -> usize {
    8 + 2 * bitlist_bytes(n_rows)
}

pub fn write_parts_metadata(available: u128, requests: u128, n_rows: usize, out: &mut [u8]) {
    debug_assert_eq!(out.len(), parts_metadata_len(n_rows));
    let bits = bitlist_bytes(n_rows);
    out[0..4].copy_from_slice(&8u32.to_le_bytes());
    out[4..8].copy_from_slice(&((8 + bits) as u32).to_le_bytes());
    write_bitlist_u128(available, n_rows, &mut out[8..8 + bits]);
    write_bitlist_u128(requests, n_rows, &mut out[8 + bits..]);
}

/// Layout of one partial sidecar's SSZ: the offsets-plus-bitmap prefix
/// is written locally; cells, proofs, and any header bytes follow as
/// retained ranges and are never gathered. Construction validates the
/// invariants once, so encoding cannot fail.
#[derive(Clone, Copy)]
pub struct PartialSidecarPlan {
    layout: PartialLayout,
    rows: u128,
    n_rows: usize,
}

#[derive(Clone, Copy)]
pub enum PartialLayout {
    /// `header_bytes` is the header SSZ length; 0 encodes the empty list.
    Fulu {
        header_bytes: usize,
    },
    Gloas,
}

impl PartialSidecarPlan {
    /// `rows` must fit the declared count within the 128-row ceiling, a
    /// Fulu header length must be structurally possible, and the fork's
    /// payload rule holds: Gloas needs a cell, Fulu a cell or header.
    pub fn new(layout: PartialLayout, rows: u128, n_rows: usize) -> Option<Self> {
        let header_bytes = match layout {
            PartialLayout::Fulu { header_bytes } => header_bytes,
            PartialLayout::Gloas => 0,
        };
        let header_ok = header_bytes == 0 ||
            (header_bytes >= PARTIAL_HEADER_FIXED &&
                (header_bytes - PARTIAL_HEADER_FIXED)
                    .is_multiple_of(BYTES_PER_KZG_COMMITMENT) &&
                (header_bytes - PARTIAL_HEADER_FIXED) / BYTES_PER_KZG_COMMITMENT <=
                    MAX_BLOB_COMMITMENTS_PER_BLOCK);
        let rows_fit = n_rows <= 128 && (n_rows == 128 || rows >> n_rows == 0);
        (header_ok && rows_fit && (rows != 0 || header_bytes > 0)).then_some(Self {
            layout,
            rows,
            n_rows,
        })
    }

    #[inline]
    pub fn n_rows(&self) -> usize {
        self.n_rows
    }

    #[inline]
    pub fn header_bytes(&self) -> usize {
        match self.layout {
            PartialLayout::Fulu { header_bytes } => header_bytes,
            PartialLayout::Gloas => 0,
        }
    }

    #[inline]
    pub fn cell_count(&self) -> usize {
        self.rows.count_ones() as usize
    }

    pub fn prefix_len(&self) -> usize {
        let fixed = match self.layout {
            PartialLayout::Fulu { .. } => PARTIAL_SIDECAR_FIXED_FULU,
            PartialLayout::Gloas => PARTIAL_SIDECAR_FIXED_GLOAS,
        };
        fixed + bitlist_bytes(self.n_rows)
    }

    pub fn ssz_len(&self) -> usize {
        let payload = self.cell_count() * (BYTES_PER_CELL + BYTES_PER_KZG_PROOF);
        let header = match self.layout {
            PartialLayout::Fulu { header_bytes: 0 } | PartialLayout::Gloas => 0,
            PartialLayout::Fulu { header_bytes } => 4 + header_bytes,
        };
        self.prefix_len() + payload + header
    }

    /// Write offsets and bitmap into `out` (exactly `prefix_len` bytes).
    pub fn write_prefix(&self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.prefix_len());
        let k = self.cell_count();
        let o0 = out.len() - bitlist_bytes(self.n_rows);
        let o1 = self.prefix_len();
        let o2 = o1 + k * BYTES_PER_CELL;
        let o3 = o2 + k * BYTES_PER_KZG_PROOF;
        out[0..4].copy_from_slice(&(o0 as u32).to_le_bytes());
        out[4..8].copy_from_slice(&(o1 as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(o2 as u32).to_le_bytes());
        if matches!(self.layout, PartialLayout::Fulu { .. }) {
            out[12..16].copy_from_slice(&(o3 as u32).to_le_bytes());
        }
        write_bitlist_u128(self.rows, self.n_rows, &mut out[o0..]);
    }

    /// Fulu only: the header list's 4-byte inner offset, appended
    /// between the proofs and the header bytes when a header is present.
    pub const HEADER_LIST_PREFIX: [u8; 4] = 4u32.to_le_bytes();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitlist_round_trips() {
        for (mask, n) in [(0u128, 0usize), (0b1011, 4), (0, 9), (u128::MAX, 128), (1 << 127, 128)] {
            let mut buf = vec![0u8; bitlist_bytes(n)];
            write_bitlist_u128(mask, n, &mut buf);
            assert_eq!(bitlist_u128(&buf, n), Some((mask, n)), "mask {mask:#x} n {n}");
            assert_eq!(bitlist_u128(&buf, 128), Some((mask, n)));
        }
    }

    #[test]
    fn bitlist_rejects_non_canonical_and_oversized() {
        assert!(bitlist_u128(&[], 128).is_none());
        assert!(bitlist_u128(&[0], 128).is_none(), "missing delimiter");
        assert!(bitlist_u128(&[0b11, 0], 128).is_none(), "trailing zero byte");
        let mut full = vec![0u8; bitlist_bytes(9)];
        write_bitlist_u128(0x1ff, 9, &mut full);
        assert!(bitlist_u128(&full, 8).is_none(), "longer than trusted rows");
        let mut over = vec![0u8; bitlist_bytes(129)];
        over[16] = 2;
        assert!(bitlist_u128(&over, 4096).is_none(), "beyond u128 rows");
    }

    #[test]
    fn group_ids_match_spec_layout() {
        let root = [0xab; 32];
        let fulu = fulu_group_id(&root);
        assert_eq!(fulu[0], 0);
        assert_eq!(&fulu[1..], &root);
        let gloas = gloas_group_id(&root, 0x0102_0304);
        assert_eq!(gloas[0], 0);
        assert_eq!(&gloas[1..33], &root);
        assert_eq!(gloas[33..], 0x0102_0304u64.to_le_bytes());
    }

    fn build(plan: &PartialSidecarPlan, header: &[u8]) -> Vec<u8> {
        let k = plan.cell_count();
        let mut buf = vec![0u8; plan.prefix_len()];
        plan.write_prefix(&mut buf);
        buf.extend_from_slice(&vec![0x11; k * BYTES_PER_CELL]);
        buf.extend_from_slice(&vec![0x22; k * BYTES_PER_KZG_PROOF]);
        if !header.is_empty() {
            buf.extend_from_slice(&PartialSidecarPlan::HEADER_LIST_PREFIX);
            buf.extend_from_slice(header);
        }
        assert_eq!(buf.len(), plan.ssz_len());
        buf
    }

    fn test_header(commitments: usize) -> Vec<u8> {
        let mut h = vec![0u8; PARTIAL_HEADER_FIXED + commitments * BYTES_PER_KZG_COMMITMENT];
        h[0..4].copy_from_slice(&(PARTIAL_HEADER_FIXED as u32).to_le_bytes());
        assert!(PartialDataColumnHeaderView::check_size(&h));
        h
    }

    fn fulu_plan(header_bytes: usize, rows: u128, n_rows: usize) -> PartialSidecarPlan {
        PartialSidecarPlan::new(PartialLayout::Fulu { header_bytes }, rows, n_rows).unwrap()
    }

    #[test]
    fn plan_rejects_unencodable_inputs() {
        assert!(PartialSidecarPlan::new(PartialLayout::Gloas, 0b1, 129).is_none());
        assert!(PartialSidecarPlan::new(PartialLayout::Gloas, 0b100, 2).is_none());
        assert!(PartialSidecarPlan::new(PartialLayout::Gloas, 0, 2).is_none());
        assert!(PartialSidecarPlan::new(PartialLayout::Fulu { header_bytes: 0 }, 0, 2).is_none());
        assert!(
            PartialSidecarPlan::new(PartialLayout::Fulu { header_bytes: 12 }, 0b1, 2).is_none()
        );
        assert!(
            PartialSidecarPlan::new(
                PartialLayout::Fulu { header_bytes: PARTIAL_HEADER_FIXED + 1 },
                0b1,
                2
            )
            .is_none()
        );
        assert!(PartialSidecarPlan::new(PartialLayout::Gloas, 1 << 127, 128).is_some());
        assert!(
            PartialSidecarPlan::new(
                PartialLayout::Fulu { header_bytes: PARTIAL_HEADER_FIXED },
                0,
                2
            )
            .is_some()
        );
    }

    #[test]
    fn fulu_sidecar_round_trips_with_and_without_header() {
        let plan = fulu_plan(0, 0b10, 2);
        let buf = build(&plan, &[]);
        assert_eq!(PartialDataColumnSidecarFuluView::check_size(&buf, 2), Some(0b10));
        assert_eq!(PartialDataColumnSidecarFuluView::cells(&buf), &[0x11; BYTES_PER_CELL]);
        assert_eq!(PartialDataColumnSidecarFuluView::proofs(&buf), &[0x22; BYTES_PER_KZG_PROOF]);
        assert!(PartialDataColumnSidecarFuluView::header(&buf).is_empty());

        let header = test_header(2);
        let plan = fulu_plan(header.len(), 0, 2);
        let buf = build(&plan, &header);
        assert_eq!(PartialDataColumnSidecarFuluView::check_size(&buf, 2), Some(0));
        assert!(PartialDataColumnSidecarFuluView::check_size(&buf, 3).is_none());
        assert_eq!(PartialDataColumnSidecarFuluView::header(&buf), &header[..]);
    }

    #[test]
    fn fulu_rejects_cell_less_sidecar_without_header() {
        // Hand-encoded: such a plan is unconstructible by design.
        let mut buf = vec![0u8; 17];
        buf[0..4].copy_from_slice(&16u32.to_le_bytes());
        buf[4..8].copy_from_slice(&17u32.to_le_bytes());
        buf[8..12].copy_from_slice(&17u32.to_le_bytes());
        buf[12..16].copy_from_slice(&17u32.to_le_bytes());
        buf[16] = 0b100; // n = 2, no rows set
        assert!(PartialDataColumnSidecarFuluView::check_size(&buf, 2).is_none());
    }

    #[test]
    fn fulu_rejects_length_and_offset_corruption() {
        let plan = fulu_plan(0, 0b1, 1);
        let good = build(&plan, &[]);
        assert!(PartialDataColumnSidecarFuluView::check_size(&good, 1).is_some());

        let mut short = good.clone();
        short.pop();
        assert!(PartialDataColumnSidecarFuluView::check_size(&short, 1).is_none());

        let mut bad_first = good.clone();
        bad_first[0] = 17;
        assert!(PartialDataColumnSidecarFuluView::check_size(&bad_first, 1).is_none());

        let mut crossed = good;
        crossed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(PartialDataColumnSidecarFuluView::check_size(&crossed, 1).is_none());
    }

    #[test]
    fn gloas_sidecar_round_trips_and_requires_a_cell() {
        let plan = PartialSidecarPlan::new(PartialLayout::Gloas, 0b101, 3).unwrap();
        let buf = build(&plan, &[]);
        assert_eq!(PartialDataColumnSidecarGloasView::check_size(&buf, 3), Some(0b101));
        assert!(PartialDataColumnSidecarGloasView::check_size(&buf, 4).is_none());
        assert_eq!(PartialDataColumnSidecarGloasView::cells(&buf).len(), 2 * BYTES_PER_CELL);
        assert_eq!(PartialDataColumnSidecarGloasView::proofs(&buf).len(), 2 * BYTES_PER_KZG_PROOF);

        // Hand-encoded cell-less payload: unconstructible as a plan.
        let mut empty = vec![0u8; 13];
        empty[0..4].copy_from_slice(&12u32.to_le_bytes());
        empty[4..8].copy_from_slice(&13u32.to_le_bytes());
        empty[8..12].copy_from_slice(&13u32.to_le_bytes());
        empty[12] = 0b1000; // n = 3, no rows set
        assert!(PartialDataColumnSidecarGloasView::check_size(&empty, 3).is_none());
    }

    #[test]
    fn parts_metadata_round_trips_and_rejects_length_mismatch() {
        let mut buf = vec![0u8; parts_metadata_len(6)];
        write_parts_metadata(0b110000, 0b1010, 6, &mut buf);
        assert_eq!(
            PartialDataColumnPartsMetadataView::check_size(&buf, 6),
            Some((0b110000, 0b1010))
        );
        assert!(PartialDataColumnPartsMetadataView::check_size(&buf, 5).is_none());
        assert!(PartialDataColumnPartsMetadataView::check_size(&buf, 7).is_none());

        // requests bitlist shorter than available: reject.
        let mut mismatch = vec![0u8; 8 + bitlist_bytes(9) + bitlist_bytes(2)];
        mismatch[0..4].copy_from_slice(&8u32.to_le_bytes());
        mismatch[4..8].copy_from_slice(&((8 + bitlist_bytes(9)) as u32).to_le_bytes());
        write_bitlist_u128(0, 9, &mut mismatch[8..8 + bitlist_bytes(9)]);
        write_bitlist_u128(0, 2, &mut mismatch[8 + bitlist_bytes(9)..]);
        assert!(PartialDataColumnPartsMetadataView::check_size(&mismatch, 16).is_none());
        assert!(PartialDataColumnPartsMetadataView::check_size(&mismatch, 9).is_none());
    }

    /// Byte layouts written out by hand from the partial-columns specs,
    /// independent of the encoders under test.
    #[test]
    fn encoders_match_spec_derived_fixtures() {
        // Fulu: n = 2 rows, row 0 present. Offsets 16/17/2065/2113;
        // bitmap 0b101 = row 0 plus the delimiter at bit 2.
        let mut fulu = vec![
            16, 0, 0, 0, //
            17, 0, 0, 0, //
            0x11, 0x08, 0, 0, //
            0x41, 0x08, 0, 0, //
            0b101,
        ];
        let plan = fulu_plan(0, 0b01, 2);
        let mut prefix = vec![0u8; plan.prefix_len()];
        plan.write_prefix(&mut prefix);
        assert_eq!(prefix, fulu);
        fulu.extend_from_slice(&[0xCC; BYTES_PER_CELL]);
        fulu.extend_from_slice(&[0xDD; BYTES_PER_KZG_PROOF]);
        assert_eq!(PartialDataColumnSidecarFuluView::check_size(&fulu, 2), Some(0b01));
        assert_eq!(PartialDataColumnSidecarFuluView::cells(&fulu), &[0xCC; BYTES_PER_CELL]);
        assert_eq!(PartialDataColumnSidecarFuluView::proofs(&fulu), &[0xDD; BYTES_PER_KZG_PROOF]);

        // Gloas: n = 1 row, present. Offsets 12/13/2061; bitmap 0b11.
        let mut gloas = vec![
            12, 0, 0, 0, //
            13, 0, 0, 0, //
            0x0D, 0x08, 0, 0, //
            0b11,
        ];
        let plan = PartialSidecarPlan::new(PartialLayout::Gloas, 0b1, 1).unwrap();
        let mut prefix = vec![0u8; plan.prefix_len()];
        plan.write_prefix(&mut prefix);
        assert_eq!(prefix, gloas);
        gloas.extend_from_slice(&[0xCC; BYTES_PER_CELL]);
        gloas.extend_from_slice(&[0xDD; BYTES_PER_KZG_PROOF]);
        assert_eq!(PartialDataColumnSidecarGloasView::check_size(&gloas, 1), Some(0b1));

        // Metadata: n = 3, available 0b101, requests 0b010; each
        // bitlist gains the delimiter at bit 3.
        let metadata = [8, 0, 0, 0, 9, 0, 0, 0, 0b1101, 0b1010];
        let mut ours = vec![0u8; parts_metadata_len(3)];
        write_parts_metadata(0b101, 0b010, 3, &mut ours);
        assert_eq!(ours, metadata);
        assert_eq!(
            PartialDataColumnPartsMetadataView::check_size(&metadata, 3),
            Some((0b101, 0b010))
        );
    }
}
