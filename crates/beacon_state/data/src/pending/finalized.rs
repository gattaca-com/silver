use std::io::{self, Write};

use crate::{
    decompose::u64_le,
    gloas::{BUILDER_PENDING_WITHDRAWALS_LIMIT, BuilderPendingWithdrawal},
    ssz_hash::{hash_concat, hash_fixed_bytes, merkleize, uint64_chunk},
    types::{
        B256, PENDING_CONSOLIDATIONS_LIMIT, PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT, PendingConsolidation, PendingDeposit,
        PendingPartialWithdrawal, Withdrawals,
    },
};

/// One pending-queue element: its SSZ container `leaf` (fixed once enqueued —
/// the queues never mutate in place), the `List[T, N]` capacity for the root
/// pad, and the SSZ wire codec. The whole "ssz constructor" for a queue lives
/// on its element type, beside the data it serialises.
pub trait QueueItem: Copy {
    const SSZ_LIMIT: usize;
    /// Serialised byte size of one element (all three are fixed-size).
    const SSZ_SIZE: usize;
    fn leaf(&self) -> B256;
    fn read_ssz(src: &[u8]) -> Self;
    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()>;
}

impl QueueItem for PendingDeposit {
    const SSZ_LIMIT: usize = PENDING_DEPOSITS_LIMIT;
    const SSZ_SIZE: usize = 192;

    #[inline]
    fn leaf(&self) -> B256 {
        merkleize(&[
            hash_fixed_bytes(&self.pubkey),
            self.withdrawal_credentials.0,
            uint64_chunk(self.amount),
            hash_fixed_bytes(&self.signature),
            uint64_chunk(self.slot),
        ])
    }

    fn read_ssz(src: &[u8]) -> Self {
        let mut pubkey = [0u8; 48];
        pubkey.copy_from_slice(&src[..48]);
        let mut signature = [0u8; 96];
        signature.copy_from_slice(&src[88..184]);
        Self {
            pubkey,
            withdrawal_credentials: Withdrawals(src[48..80].try_into().unwrap()),
            amount: u64_le(src, 80),
            signature,
            slot: u64_le(src, 184),
        }
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; Self::SSZ_SIZE];
        buf[0..48].copy_from_slice(&self.pubkey);
        buf[48..80].copy_from_slice(&self.withdrawal_credentials.0);
        buf[80..88].copy_from_slice(&self.amount.to_le_bytes());
        buf[88..184].copy_from_slice(&self.signature);
        buf[184..192].copy_from_slice(&self.slot.to_le_bytes());
        w.write_all(&buf)
    }
}

impl QueueItem for PendingPartialWithdrawal {
    const SSZ_LIMIT: usize = PENDING_PARTIAL_WITHDRAWALS_LIMIT;
    const SSZ_SIZE: usize = 24;

    #[inline]
    fn leaf(&self) -> B256 {
        merkleize(&[
            uint64_chunk(self.index),
            uint64_chunk(self.amount),
            uint64_chunk(self.withdrawable_epoch),
        ])
    }

    fn read_ssz(src: &[u8]) -> Self {
        Self { index: u64_le(src, 0), amount: u64_le(src, 8), withdrawable_epoch: u64_le(src, 16) }
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.index.to_le_bytes())?;
        w.write_all(&self.amount.to_le_bytes())?;
        w.write_all(&self.withdrawable_epoch.to_le_bytes())
    }
}

impl QueueItem for PendingConsolidation {
    const SSZ_LIMIT: usize = PENDING_CONSOLIDATIONS_LIMIT;
    const SSZ_SIZE: usize = 16;

    #[inline]
    fn leaf(&self) -> B256 {
        hash_concat(&uint64_chunk(self.source_index), &uint64_chunk(self.target_index))
    }

    fn read_ssz(src: &[u8]) -> Self {
        Self { source_index: u64_le(src, 0), target_index: u64_le(src, 8) }
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(&self.source_index.to_le_bytes())?;
        w.write_all(&self.target_index.to_le_bytes())
    }
}

impl QueueItem for BuilderPendingWithdrawal {
    const SSZ_LIMIT: usize = BUILDER_PENDING_WITHDRAWALS_LIMIT;
    const SSZ_SIZE: usize = 36;

    #[inline]
    fn leaf(&self) -> B256 {
        merkleize(&[
            hash_fixed_bytes(&self.fee_recipient),
            uint64_chunk(self.amount),
            uint64_chunk(self.builder_index),
        ])
    }

    fn read_ssz(src: &[u8]) -> Self {
        BuilderPendingWithdrawal::from_ssz(src)
    }

    fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        let mut buf = [0u8; Self::SSZ_SIZE];
        buf[0..20].copy_from_slice(&self.fee_recipient);
        buf[20..28].copy_from_slice(&self.amount.to_le_bytes());
        buf[28..36].copy_from_slice(&self.builder_index.to_le_bytes());
        w.write_all(&buf)
    }
}

/// One queue's finalized base: entries with their cached SSZ leaves
/// (`leaves[i] == entries[i].leaf()`), maintained in lockstep so the root folds
/// cached leaves rather than re-hashing every container — re-hashing the
/// `pending_deposits` queue each slot was the bulk of state-hashing cost.
#[derive(Clone)]
pub(crate) struct Queue<Q> {
    entries: Vec<Q>,
    leaves: Vec<B256>,
}

// Manual impl: the derive would spuriously bind `Q: Default`.
impl<Q> Default for Queue<Q> {
    fn default() -> Self {
        Self { entries: Vec::new(), leaves: Vec::new() }
    }
}

impl<Q: QueueItem> Queue<Q> {
    /// Decode a queue from its SSZ byte range (a flat array of fixed-size
    /// records); `bytes.len()` must be a multiple of [`QueueItem::SSZ_SIZE`].
    pub(super) fn from_ssz(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len().is_multiple_of(Q::SSZ_SIZE));
        let n = bytes.len() / Q::SSZ_SIZE;
        let mut q = Self::default();
        q.entries.reserve_exact(n);
        q.leaves.reserve_exact(n);
        for i in 0..n {
            q.push(Q::read_ssz(&bytes[i * Q::SSZ_SIZE..]));
        }
        q
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entries in order — indexed by the delta's reads, iterated by SSZ encode.
    #[inline]
    pub(super) fn entries(&self) -> &[Q] {
        &self.entries
    }

    /// Cached leaves, parallel to [`entries`](Self::entries) — fed to the
    /// delta's frontier rebuild.
    #[inline]
    pub(super) fn leaves(&self) -> &[B256] {
        &self.leaves
    }

    /// Push onto the tail, returning the cached leaf so the caller can fold it
    /// into a frontier without re-hashing.
    #[inline]
    pub(super) fn push(&mut self, e: Q) -> B256 {
        let leaf = e.leaf();
        self.entries.push(e);
        self.leaves.push(leaf);
        leaf
    }

    /// Pop `n` off the front (drain).
    pub(super) fn drain_front(&mut self, n: usize) {
        self.entries.drain(..n);
        self.leaves.drain(..n);
    }

    /// Empty the queue, keeping the allocations.
    pub(super) fn clear(&mut self) {
        self.entries.clear();
        self.leaves.clear();
    }

    /// Splice `other` onto the tail (finalization folds a delta into the base).
    pub(super) fn extend(&mut self, other: &Self) {
        self.entries.extend_from_slice(&other.entries);
        self.leaves.extend_from_slice(&other.leaves);
    }

    /// SSZ-encode the live entries (checkpoint persist section body); callers
    /// hold the group's promote barrier.
    pub(crate) fn write_ssz<W: Write>(&self, w: &mut W) -> io::Result<()> {
        for e in &self.entries {
            e.write_ssz(w)?;
        }
        Ok(())
    }
}
