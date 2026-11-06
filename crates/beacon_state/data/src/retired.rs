use std::mem;

/// Finalized-base columns replaced by a capacity grow. A lock-free reader may
/// have resolved a column before the swap and still be reading it. Its
/// version re-check discards the result, but the memory must stay mapped.
/// So replaced columns live until the base drops, like `Ring`'s retired
/// generations.
#[derive(Default)]
pub(crate) struct RetiredColumns(Vec<Box<dyn Send + Sync>>);

impl RetiredColumns {
    /// Swap `column` for one of `len` entries, keeping its first `keep`
    /// entries and filling the rest with `fill`.
    pub(crate) fn grow<T: Copy + Send + Sync + 'static>(
        &mut self,
        column: &mut Box<[T]>,
        keep: usize,
        len: usize,
        fill: T,
    ) {
        debug_assert!(keep <= column.len() && column.len() <= len);
        let mut grown = vec![fill; len].into_boxed_slice();
        grown[..keep].copy_from_slice(&column[..keep]);
        self.0.push(Box::new(mem::replace(column, grown)));
    }
}
