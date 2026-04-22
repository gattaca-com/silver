use flux::communication::ShmemData;
use silver_common::{TierPool, arena::open_or_create_shm};

use crate::types::{
    EPOCH_POOL_CAP, EpochData, HistoricalLongtail, IMM_POOL_CAP, Immutable, LONGTAIL_POOL_CAP,
    ROOTS_POOL_CAP, SLOT_POOL_CAP, SlotData, SlotRoots, VID_POOL_CAP, ValidatorIdentity,
    box_zeroed,
};

#[repr(C)]
pub struct BeaconArena {
    pub imm: TierPool<Immutable, IMM_POOL_CAP>,
    pub vid: TierPool<ValidatorIdentity, VID_POOL_CAP>,
    pub longtail: TierPool<HistoricalLongtail, LONGTAIL_POOL_CAP>,
    pub epoch: TierPool<EpochData, EPOCH_POOL_CAP>,
    pub roots: TierPool<SlotRoots, ROOTS_POOL_CAP>,
    pub slot: TierPool<SlotData, SLOT_POOL_CAP>,
}

impl BeaconArena {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const ALIGN: usize = core::mem::align_of::<Self>();

    /// # Safety
    /// `ptr` must be non-null, `ALIGN`-aligned, and point to a
    /// zero-initialised `BeaconArena` that outlives `'a`.
    pub unsafe fn from_ptr<'a>(ptr: *mut u8) -> &'a Self {
        debug_assert!(!ptr.is_null());
        debug_assert_eq!(ptr as usize % Self::ALIGN, 0);
        unsafe { &*(ptr as *const Self) }
    }
}

pub enum ArenaBacking {
    Shm(ShmemData<BeaconArena>),
    Heap(Box<BeaconArena>),
}

impl ArenaBacking {
    pub fn open_shm(app_name: &str) -> Self {
        Self::Shm(unsafe { open_or_create_shm::<BeaconArena>(app_name) })
    }

    pub fn heap() -> Self {
        Self::Heap(box_zeroed())
    }
}

impl core::ops::Deref for ArenaBacking {
    type Target = BeaconArena;

    fn deref(&self) -> &BeaconArena {
        match self {
            Self::Shm(s) => s,
            Self::Heap(b) => b,
        }
    }
}
