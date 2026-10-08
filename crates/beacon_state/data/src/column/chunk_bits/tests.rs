use super::ChunkBits;
use crate::column::subtree::NodeRange;

fn marked(chunks: usize, marks: impl IntoIterator<Item = usize>) -> ChunkBits {
    let mut dirty = ChunkBits::default();
    dirty.resize(chunks);
    for c in marks {
        dirty.mark(c);
    }
    dirty
}

fn drain(dirty: &mut ChunkBits) -> Vec<NodeRange> {
    let mut ranges = Vec::new();
    dirty.drain(&mut ranges);
    ranges
}

fn ranges(dirty: &mut ChunkBits) -> Vec<(u32, u32)> {
    drain(dirty).iter().map(|r| (r.start, r.end)).collect()
}

#[test]
fn drain_emits_sorted_maximal_ranges() {
    let mut dirty = marked(256, [9, 3, 4, 5, 3, 100, 0]);
    assert_eq!(ranges(&mut dirty), vec![(0, 1), (3, 6), (9, 10), (100, 101)]);
}

#[test]
fn drain_merges_ranges_across_word_boundaries() {
    let mut dirty = marked(8192, (60..200).chain(4094..4098));
    assert_eq!(ranges(&mut dirty), vec![(60, 200), (4094, 4098)]);
}

#[test]
fn drain_handles_full_words_and_the_last_bit() {
    let chunks = 64 * 64 * 2;
    let mut dirty = marked(chunks, (0..64).chain([chunks - 1]));
    assert_eq!(ranges(&mut dirty), vec![(0, 64), (chunks as u32 - 1, chunks as u32)]);
}

#[test]
fn drain_clears_and_marks_again() {
    let mut dirty = marked(4096, [7, 8, 1000]);
    assert!(!dirty.is_empty());
    ranges(&mut dirty);
    assert!(dirty.is_empty());
    assert!(drain(&mut dirty).is_empty());

    dirty.mark(8);
    dirty.mark(2000);
    assert_eq!(ranges(&mut dirty), vec![(8, 9), (2000, 2001)]);
}

#[test]
fn drain_matches_a_naive_scan() {
    let chunks = 3 * 4096 + 17;
    let marks: Vec<_> = (0..chunks).filter(|c| (c * 2654435761) % 7 < 3).collect();
    let mut dirty = marked(chunks, marks.iter().copied());

    let mut expected: Vec<NodeRange> = Vec::new();
    for &c in &marks {
        let c = c as u32;
        match expected.last_mut() {
            Some(last) if last.end == c => last.end += 1,
            _ => expected.push(NodeRange { start: c, end: c + 1 }),
        }
    }
    assert_eq!(drain(&mut dirty), expected);
}

#[test]
fn clear_forgets_marks_and_resize_grows() {
    let mut dirty = marked(128, [5, 127]);
    dirty.clear();
    dirty.resize(8192);
    assert!(dirty.is_empty());
    dirty.mark(8191);
    assert_eq!(ranges(&mut dirty), vec![(8191, 8192)]);
}
