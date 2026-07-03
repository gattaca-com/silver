use flux::timing::Instant;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Mark {
    // id - pointer to the function name in .rodata
    pub(crate) id: u64,
    pub(crate) ts: u64,
    // High bit flags an open; the low 31 bits carry the name's byte length (opens
    // only), letting a resolver read that many bytes of the name from .rodata.
    len_and_open: u32,
}

const OPEN_BIT: u32 = 1 << 31;

/// Frame id of the synthetic span covering a ring hole. Real ids are `.rodata`
/// pointers, never null.
pub(crate) const MISSED_ID: u64 = 0;

impl Mark {
    pub(crate) const EMPTY: Self = Mark { id: 0, ts: 0, len_and_open: 0 };

    pub(crate) fn open(name: &'static str) -> Self {
        debug_assert!(name.len() < OPEN_BIT as usize, "timed name exceeds 31-bit length");
        Mark {
            id: name.as_ptr() as u64,
            ts: Instant::now().0,
            len_and_open: name.len() as u32 | OPEN_BIT,
        }
    }

    pub(crate) fn close(name: &'static str) -> Self {
        Mark { id: name.as_ptr() as u64, ts: Instant::now().0, len_and_open: 0 }
    }

    pub(crate) fn is_open(&self) -> bool {
        self.len_and_open & OPEN_BIT != 0
    }

    pub(crate) fn name_len(&self) -> u32 {
        self.len_and_open & !OPEN_BIT
    }

    pub(crate) const fn from_parts(id: u64, ts: u64, open: bool) -> Self {
        Mark { id, ts, len_and_open: if open { OPEN_BIT } else { 0 } }
    }
}
