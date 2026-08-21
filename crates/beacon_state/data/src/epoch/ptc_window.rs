use crate::{
    gloas::{PTC_SIZE, PTC_WINDOW_LEN, PtcCommittee, zeroed_ptc_window},
    merkle::{B256, MerkleStack, hash_uint64_vector, merkleize},
    types::SLOTS_PER_EPOCH,
};

const SPE: usize = SLOTS_PER_EPOCH as usize;

const EMPTY_COMMITTEE_ROOT: B256 = MerkleStack::empty_root(PTC_SIZE * size_of::<u64>() / 32);

/// `ptc_window: Vector[Vector[ValidatorIndex, PTC_SIZE], PTC_WINDOW_LEN]` with
/// its SSZ roots cached beside the committees. A committee root is 127
/// compressions and only the newest epoch's `SLOTS_PER_EPOCH` change per
/// epoch, so per-committee roots and their field-root fold are refreshed at
/// the writes and `hash_root` is a read.
pub struct PtcWindow {
    committees: Box<[PtcCommittee; PTC_WINDOW_LEN]>,
    roots: Box<[B256; PTC_WINDOW_LEN]>,
    root: B256,
}

// Manual so `clone_from` copies into the existing boxes; the derived default
// would reallocate the 393 KB window on every roll/promote.
impl Clone for PtcWindow {
    fn clone(&self) -> Self {
        Self { committees: self.committees.clone(), roots: self.roots.clone(), root: self.root }
    }

    fn clone_from(&mut self, source: &Self) {
        self.committees.clone_from(&source.committees);
        self.roots.clone_from(&source.roots);
        self.root = source.root;
    }
}

impl Default for PtcWindow {
    fn default() -> Self {
        let roots = Box::new([EMPTY_COMMITTEE_ROOT; PTC_WINDOW_LEN]);
        Self { root: merkleize(&roots[..]), committees: zeroed_ptc_window(), roots }
    }
}

impl PtcWindow {
    pub(crate) fn new(committees: Box<[PtcCommittee; PTC_WINDOW_LEN]>) -> Self {
        let roots: Box<[B256; PTC_WINDOW_LEN]> =
            Box::new(std::array::from_fn(|i| hash_uint64_vector(&committees[i])));
        Self { root: merkleize(&roots[..]), committees, roots }
    }

    #[inline]
    pub fn committees(&self) -> &[PtcCommittee; PTC_WINDOW_LEN] {
        &self.committees
    }

    #[inline]
    pub fn hash_root(&self) -> B256 {
        self.root
    }

    /// Shift the window one epoch forward, hashing only the committees that
    /// entered it.
    pub(super) fn rotate(&mut self, new_last_epoch: &[PtcCommittee]) {
        debug_assert_eq!(new_last_epoch.len(), SPE);
        self.committees.copy_within(SPE.., 0);
        self.committees[PTC_WINDOW_LEN - SPE..].copy_from_slice(new_last_epoch);
        self.roots.copy_within(SPE.., 0);
        for (root, committee) in self.roots[PTC_WINDOW_LEN - SPE..].iter_mut().zip(new_last_epoch) {
            *root = hash_uint64_vector(committee);
        }
        self.root = merkleize(&self.roots[..]);
    }
}
