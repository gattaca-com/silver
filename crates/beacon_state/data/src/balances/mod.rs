mod delta;
mod finalized;

#[cfg(test)]
mod tests;

pub use delta::BalancesDelta;
pub use finalized::FinalizedBalances;

use crate::types::B256;

/// SSZ-pack four little-endian `u64`s into one 32-byte chunk leaf — the leaf
/// granularity for `List[uint64]` (4 elements share one merkle leaf).
fn pack_chunk(vals: [u64; 4]) -> B256 {
    let mut leaf = [0u8; 32];
    for (slot, v) in vals.iter().enumerate() {
        leaf[slot * 8..slot * 8 + 8].copy_from_slice(&v.to_le_bytes());
    }
    leaf
}
