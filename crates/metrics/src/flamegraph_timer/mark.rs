#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) enum Frame {
    // id - pointer to function name in .rodata
    // len - length of the function name in bytes
    Open { id: u64, len: u32 },
    Close { id: u64 },
}

impl Frame {
    pub(crate) fn open(name: &'static str) -> Self {
        Frame::Open { id: name.as_ptr() as u64, len: name.len() as u32 }
    }

    pub(crate) fn close(name: &'static str) -> Self {
        Frame::Close { id: name.as_ptr() as u64 }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Mark {
    pub(crate) frame: Frame,
    pub(crate) ts: u64,
}
