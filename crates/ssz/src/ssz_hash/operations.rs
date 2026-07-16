//! Block-body operations: proposer slashings, deposits, voluntary exits, and
//! bls-to-execution changes — plus the block-header helpers the slashing hasher
//! builds on.

use flux_profiler::timed;

use crate::{
    merkle::{
        B256, FixedContainer, ZERO_HASH, hash_concat, hash_fixed_bytes, merkleize, merkleize_bytes,
        uint64_chunk,
    },
    ssz_view::{
        DEPOSIT_CONTRACT_TREE_DEPTH, DEPOSIT_DATA_SIZE, DEPOSIT_PROOF_SIZE, DEPOSIT_SIZE,
        DepositView, PROPOSER_SLASHING_SIZE, ProposerSlashingView, SIGNED_BLS_CHANGE_SIZE,
        SIGNED_VOLUNTARY_EXIT_SIZE, SignedBlsToExecutionChangeView, SignedVoluntaryExitView,
    },
};

#[timed]
pub fn hash_signed_beacon_block_header(d: &[u8]) -> B256 {
    let msg = hash_beacon_block_header_bytes(&d[..112]);
    let sig = hash_fixed_bytes(&d[112..208]);
    hash_concat(&msg, &sig)
}

#[timed]
pub fn hash_beacon_block_header_bytes(d: &[u8]) -> B256 {
    let u64c = |off: usize| uint64_chunk(u64::from_le_bytes(d[off..off + 8].try_into().unwrap()));
    let b = |off: usize| -> B256 { d[off..off + 32].try_into().unwrap() };
    merkleize(&[u64c(0), u64c(8), b(16), b(48), b(80)])
}

impl FixedContainer for ProposerSlashingView {
    const SSZ_SIZE: usize = PROPOSER_SLASHING_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        hash_concat(
            &hash_signed_beacon_block_header(&d[..208]),
            &hash_signed_beacon_block_header(&d[208..416]),
        )
    }
}

/// hash_tree_root(DepositData): merkleize 4 chunks
/// [pubkey_root, withdrawal_credentials, amount_chunk, signature_root].
#[timed]
pub fn hash_tree_root_deposit_data(dd: &[u8; 184]) -> B256 {
    merkleize(&[
        hash_fixed_bytes(&dd[..48]),
        <[u8; 32]>::try_from(&dd[48..80]).unwrap(),
        uint64_chunk(u64::from_le_bytes(dd[80..88].try_into().unwrap())),
        hash_fixed_bytes(&dd[88..184]),
    ])
}

impl FixedContainer for DepositView {
    const SSZ_SIZE: usize = DEPOSIT_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        let proof_root = merkleize_bytes(&d[..DEPOSIT_PROOF_SIZE], DEPOSIT_CONTRACT_TREE_DEPTH + 1);

        let dd: &[u8; DEPOSIT_DATA_SIZE] =
            d[DEPOSIT_PROOF_SIZE..DEPOSIT_PROOF_SIZE + DEPOSIT_DATA_SIZE].try_into().unwrap();
        let dd_root = hash_tree_root_deposit_data(dd);
        hash_concat(&proof_root, &dd_root)
    }
}

impl FixedContainer for SignedVoluntaryExitView {
    const SSZ_SIZE: usize = SIGNED_VOLUNTARY_EXIT_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        let msg = hash_concat(
            &uint64_chunk(u64::from_le_bytes(d[0..8].try_into().unwrap())),
            &uint64_chunk(u64::from_le_bytes(d[8..16].try_into().unwrap())),
        );
        hash_concat(&msg, &hash_fixed_bytes(&d[16..112]))
    }
}

impl FixedContainer for SignedBlsToExecutionChangeView {
    const SSZ_SIZE: usize = SIGNED_BLS_CHANGE_SIZE;
    #[timed]
    fn hash_tree_root(d: &[u8]) -> B256 {
        let mut addr = ZERO_HASH;
        addr[..20].copy_from_slice(&d[56..76]);
        let msg = merkleize(&[
            uint64_chunk(u64::from_le_bytes(d[0..8].try_into().unwrap())),
            hash_fixed_bytes(&d[8..56]),
            addr,
        ]);
        hash_concat(&msg, &hash_fixed_bytes(&d[76..172]))
    }
}
