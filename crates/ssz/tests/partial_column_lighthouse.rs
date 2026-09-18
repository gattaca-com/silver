use silver_ssz::ssz_view::{
    BYTES_PER_CELL, BYTES_PER_KZG_PROOF,
    partial_column::{
        PartialDataColumnHeaderView, PartialDataColumnPartsMetadataView,
        PartialDataColumnSidecarFuluView as Sidecar, PartialLayout, PartialSidecarPlan,
        parts_metadata_len, write_parts_metadata,
    },
};

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.split_whitespace()
        .flat_map(|line| {
            (0..line.len())
                .step_by(2)
                .map(|index| u8::from_str_radix(&line[index..index + 2], 16).unwrap())
        })
        .collect()
}

#[test]
fn fulu_views_and_encoder_match_lighthouse() {
    let fixtures = [
        (include_str!("fixtures/partial_columns/fulu_header_only.hex"), 0, true),
        (include_str!("fixtures/partial_columns/fulu_sparse_with_header.hex"), 0x109, true),
        (include_str!("fixtures/partial_columns/fulu_sparse.hex"), 0x109, false),
    ];
    for (hex, rows, has_header) in fixtures {
        let reference = decode_hex(hex);
        assert_eq!(Sidecar::check_size(&reference, 9), Some(rows));
        assert!(Sidecar::check_size(&reference, 8).is_none());
        let header = Sidecar::header(&reference);
        assert_eq!(!header.is_empty(), has_header);
        if has_header {
            assert!(PartialDataColumnHeaderView::check_size(header));
        }
        let cells = Sidecar::cells(&reference);
        let proofs = Sidecar::proofs(&reference);
        if rows == 0 {
            assert!(cells.is_empty() && proofs.is_empty());
        } else {
            for (position, row) in [0, 3, 8].into_iter().enumerate() {
                assert_eq!(
                    &cells[position * BYTES_PER_CELL..(position + 1) * BYTES_PER_CELL],
                    &[0x50 + row; BYTES_PER_CELL]
                );
                assert_eq!(
                    &proofs[position * BYTES_PER_KZG_PROOF..(position + 1) * BYTES_PER_KZG_PROOF],
                    &[0x60 + row; BYTES_PER_KZG_PROOF]
                );
            }
        }
        let plan =
            PartialSidecarPlan::new(PartialLayout::Fulu { header_bytes: header.len() }, rows, 9)
                .unwrap();
        let mut encoded = vec![0; plan.prefix_len()];
        plan.write_prefix(&mut encoded);
        encoded.extend_from_slice(cells);
        encoded.extend_from_slice(proofs);
        if has_header {
            encoded.extend_from_slice(&PartialSidecarPlan::HEADER_LIST_PREFIX);
            encoded.extend_from_slice(header);
        }
        assert_eq!(encoded, reference);
    }
}

#[test]
fn metadata_matches_lighthouse_across_a_byte_boundary() {
    let reference = decode_hex(include_str!("fixtures/partial_columns/metadata.hex"));
    assert_eq!(PartialDataColumnPartsMetadataView::check_size(&reference, 9), Some((0x109, 0xf6)));
    let mut encoded = vec![0; parts_metadata_len(9)];
    write_parts_metadata(0x109, 0xf6, 9, &mut encoded);
    assert_eq!(encoded, reference);
}
