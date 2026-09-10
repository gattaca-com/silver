use silver_beacon_state_data::{B256, Epoch, PendingDeposit, Slot};
use silver_ssz::ssz_view::{MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTING_INDICES};

use crate::stf::MAX_PENDING_DEPOSITS_PER_EPOCH;

pub(crate) const MIN_ACTIVATION_BALANCE: u64 = 32_000_000_000;

/// One attester's block-included vote, emitted by `process_attestations` for
/// the tile to fold into the LMD vote tracker.
#[derive(Clone, Copy)]
pub struct AttestationVote {
    pub validator: u32,
    pub block_root: B256,
    pub target_epoch: Epoch,
    // [New in Gloas]
    pub attestation_slot: Slot,
    pub payload_present: bool,
}

/// What a block's transition hands fork choice: its attesters' votes and the
/// validators its attester slashings slashed.
#[derive(Default)]
pub struct BlockVotes {
    pub votes: Vec<AttestationVote>,
    pub slashed: Vec<u32>,
}

impl BlockVotes {
    pub fn with_max_capacity() -> Self {
        Self {
            votes: Vec::with_capacity(MAX_ATTESTATIONS_ELECTRA * MAX_ATTESTING_INDICES),
            slashed: Vec::with_capacity(MAX_ATTESTING_INDICES),
        }
    }

    pub fn clear(&mut self) {
        self.votes.clear();
        self.slashed.clear();
    }
}

/// Free list of `BlockVotes` buffers. A block waiting for its data columns
/// keeps its buffer until it imports, so the pool grows to the peak number of
/// waiting blocks and then stops allocating.
#[derive(Default)]
pub struct VotePool(Vec<BlockVotes>);

impl VotePool {
    pub fn take(&mut self) -> BlockVotes {
        self.0.pop().unwrap_or_else(BlockVotes::with_max_capacity)
    }

    pub fn recycle(&mut self, mut votes: BlockVotes) {
        votes.clear();
        self.0.push(votes);
    }
}

/// Reusable scratch buffers threaded together through the state transition
/// (`apply_block` → `process_slots` → `process_epoch`).
pub struct StfScratch {
    /// Active set / committee participants / participating indices — reused
    /// across the epoch-transition and block-body passes.
    pub active: Vec<u32>,
    pub postponed: Vec<PendingDeposit>,
    /// Sparse-edit rebuild buffers + effective-balance column for the
    /// epoch-transition passes.
    pub replace_u64: Vec<(u32, u64)>,
    pub eff: Vec<u64>,
    pub votes: VotePool,
}

impl StfScratch {
    pub fn new(validator_cap: usize) -> Self {
        Self {
            active: Vec::with_capacity(validator_cap.max(MAX_ATTESTING_INDICES)),
            postponed: Vec::with_capacity(MAX_PENDING_DEPOSITS_PER_EPOCH),
            replace_u64: Vec::with_capacity(validator_cap),
            eff: Vec::with_capacity(validator_cap),
            votes: VotePool::default(),
        }
    }
}

/// Walk an SSZ variable-size list's offset table, calling `f(item)` per
/// element. Empty or unparseable tables yield zero items; an inverted or
/// out-of-bounds offset pair yields `bad_offsets(start, end)`.
pub(crate) fn for_each_ssz_list_item<E>(
    data: &[u8],
    bad_offsets: impl Fn(usize, usize) -> E,
    mut f: impl FnMut(&[u8]) -> std::result::Result<(), E>,
) -> std::result::Result<(), E> {
    if data.is_empty() {
        return Ok(());
    }
    let first_offset = u32::from_le_bytes(data[..4].try_into().unwrap_or([0; 4])) as usize;
    if first_offset == 0 || !first_offset.is_multiple_of(4) || first_offset > data.len() {
        return Ok(());
    }
    let count = first_offset / 4;
    for i in 0..count {
        let start = u32::from_le_bytes(data[i * 4..(i + 1) * 4].try_into().unwrap()) as usize;
        let end = if i + 1 < count {
            u32::from_le_bytes(data[(i + 1) * 4..(i + 2) * 4].try_into().unwrap()) as usize
        } else {
            data.len()
        };
        if start >= end || end > data.len() {
            return Err(bad_offsets(start, end));
        }
        f(&data[start..end])?;
    }
    Ok(())
}
