use std::mem;

/// Replaced allocations remain owned until this collection drops.
/// Retention does not synchronize reads of the live collection or its elements.
#[derive(Default)]
pub struct RetiredColumns(Vec<Box<dyn Send + Sync>>);

impl RetiredColumns {
    pub fn grow<T: Copy + Send + Sync + 'static>(
        &mut self,
        column: &mut Box<[T]>,
        keep: usize,
        len: usize,
        fill: T,
    ) {
        assert!(keep <= column.len() && column.len() <= len);
        let mut grown = vec![fill; len].into_boxed_slice();
        grown[..keep].copy_from_slice(&column[..keep]);
        self.replace(column, grown);
    }

    pub(crate) fn replace<T: Send + Sync + 'static>(&mut self, column: &mut T, replacement: T) {
        self.0.push(Box::new(mem::replace(column, replacement)));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    struct CountDrop(Arc<AtomicUsize>);

    impl Drop for CountDrop {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn replaced_columns_drop_only_with_the_retirement_owner() {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut retired = RetiredColumns::default();
        let mut current = Box::new(CountDrop(drops.clone()));
        for _ in 0..3 {
            retired.replace(&mut current, Box::new(CountDrop(drops.clone())));
        }
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        drop(retired);
        assert_eq!(drops.load(Ordering::Relaxed), 3);
        drop(current);
        assert_eq!(drops.load(Ordering::Relaxed), 4);
    }
}
