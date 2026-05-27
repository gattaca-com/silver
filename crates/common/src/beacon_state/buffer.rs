pub trait Reset {
    /// Resets to defaults ready for reuse.
    fn reset(&mut self);

    /// Resets with values from another instance.
    fn reset_from(&mut self, other: &Self);
}

pub struct DeltaBuffer<T, const N: usize> {
    head_seq: Option<usize>,
    tail_seq: Option<usize>,
    entries: Box<[T]>,
}

/// Returns the result of a call to `roll` the buffer.
pub enum RollResult {
    /// Previous head value rolled forward
    Rolled(usize),
    /// New head value reset to defaults
    Reset(usize),
}

impl<T: Clone + Default, const N: usize> Default for DeltaBuffer<T, N> {
    fn default() -> Self {
        assert!(N.is_power_of_two());
        Self { head_seq: None, tail_seq: None, entries: vec![T::default(); N].into_boxed_slice() }
    }
}

impl<T: Reset, const N: usize> DeltaBuffer<T, N> {
    /// Roll the delta forward - if there is a previous entry it will be copied
    /// forward, otherwise the new entry will be reset to default.
    pub fn roll(&mut self, previous: Option<usize>) -> RollResult {
        let new_head = self.head_seq.map(|h| h + 1).unwrap_or_default();
        let new_head_pos = new_head & (N - 1);

        if let Some(tail_seq) = self.tail_seq &&
            new_head - tail_seq >= N
        {
            tracing::warn!(new_head, tail_seq, N, "buffer is wrapping!!");
            let tail_pos = tail_seq & (N - 1);
            assert!(new_head_pos != tail_pos, "would trample head");
        }

        let result = if let Some(parent) = previous {
            let parent_pos = parent & (N - 1);
            let parent_ptr = &self.entries[parent_pos] as *const T;
            unsafe {
                // SAFETY: the reference to the old head is local and we are not
                // accessing it mutably.
                let previous = &*parent_ptr;
                self.entries[new_head_pos].reset_from(previous);
            }
            if self.tail_seq.is_none() {
                self.tail_seq.replace(parent);
            }
            RollResult::Rolled(new_head)
        } else {
            self.entries[new_head_pos].reset();
            RollResult::Reset(new_head)
        };

        self.head_seq.replace(new_head);
        result
    }

    /// Advance the tail forward to `to_seq` (the new oldest live seq); entries
    /// older than `to_seq` are reclaimed and the wrap check relaxes
    /// accordingly. No-op if the tail is already at or past `to_seq`.
    pub fn free(&mut self, to_seq: usize) {
        if let Some(tail_seq) = self.tail_seq &&
            to_seq > tail_seq
        {
            self.tail_seq = Some(to_seq);
        }
    }

    pub fn get(&self, seq: usize) -> &T {
        let i = seq & (N - 1);
        &self.entries[i]
    }

    pub fn get_mut(&mut self, seq: usize) -> &mut T {
        let i = seq & (N - 1);
        &mut self.entries[i]
    }

    pub fn head(&self) -> Option<usize> {
        self.head_seq
    }
}
