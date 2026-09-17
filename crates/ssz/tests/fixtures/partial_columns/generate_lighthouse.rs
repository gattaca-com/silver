use bls::Signature;
use kzg::{KzgCommitment, KzgProof};
use ssz::Encode;
use types::{
    BeaconBlockHeader, Cell, CellBitmap, EthSpec, Hash256, MainnetEthSpec,
    PartialDataColumnHeader, PartialDataColumnPartsMetadata, PartialDataColumnSidecar,
    SignedBeaconBlockHeader, Slot,
};

type E = MainnetEthSpec;

fn output(name: &str, bytes: &[u8]) {
    print!("{name}=");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}

fn bitmap(indices: &[usize]) -> CellBitmap<E> {
    let mut bitmap = CellBitmap::<E>::with_capacity(9).unwrap();
    for &index in indices {
        bitmap.set(index, true).unwrap();
    }
    bitmap
}

fn main() {
    let header = PartialDataColumnHeader::<E> {
        kzg_commitments: (0..9)
            .map(|row| KzgCommitment([row + 1; 48]))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        signed_block_header: SignedBeaconBlockHeader {
            message: BeaconBlockHeader {
                slot: Slot::new(96),
                proposer_index: 7,
                parent_root: Hash256::repeat_byte(0x11),
                state_root: Hash256::repeat_byte(0x22),
                body_root: Hash256::repeat_byte(0x33),
            },
            signature: Signature::empty(),
        },
        kzg_commitments_inclusion_proof: (0..E::kzg_commitments_inclusion_proof_depth())
            .map(|index| Hash256::repeat_byte(0x40 + index as u8))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    };
    let mut sidecar = PartialDataColumnSidecar::<E> {
        cells_present_bitmap: bitmap(&[]),
        column: Vec::new().try_into().unwrap(),
        kzg_proofs: Vec::new().try_into().unwrap(),
        header: Some(header).into(),
    };
    output("fulu_header_only", &sidecar.as_ssz_bytes());
    sidecar.cells_present_bitmap = bitmap(&[0, 3, 8]);
    sidecar.column = [0, 3, 8]
        .into_iter()
        .map(|row| Cell::<E>::new(vec![0x50 + row; E::bytes_per_cell()]).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    sidecar.kzg_proofs = [0, 3, 8]
        .into_iter()
        .map(|row| KzgProof([0x60 + row; 48]))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    output("fulu_sparse_with_header", &sidecar.as_ssz_bytes());
    sidecar.header = None.into();
    output("fulu_sparse", &sidecar.as_ssz_bytes());
    let metadata = PartialDataColumnPartsMetadata::<E> {
        available: bitmap(&[0, 3, 8]),
        requests: bitmap(&[1, 2, 4, 5, 6, 7]),
    };
    output("metadata", &metadata.as_ssz_bytes());
}
