use std::ops::{Deref, DerefMut, Range};

use crate::flat_hashing::subtree::NodeRange;

const WORD_BITS: usize = u64::BITS as usize;

#[derive(Default)]
struct Words(Vec<u64>);

impl Words {
    #[inline]
    fn any_in(&self, bits: Range<usize>) -> bool {
        if bits.is_empty() {
            return false;
        }
        let (first, last) = (bits.start / WORD_BITS, (bits.end - 1) / WORD_BITS);
        let head = !0 << (bits.start % WORD_BITS);
        let tail = !0 >> (WORD_BITS - 1 - (bits.end - 1) % WORD_BITS);
        if first == last {
            return self[first] & head & tail != 0;
        }
        self[first] & head != 0 ||
            self[last] & tail != 0 ||
            self[first + 1..last].iter().any(|&w| w != 0)
    }
}

impl Deref for Words {
    type Target = Vec<u64>;

    #[inline]
    fn deref(&self) -> &Vec<u64> {
        &self.0
    }
}

impl DerefMut for Words {
    #[inline]
    fn deref_mut(&mut self) -> &mut Vec<u64> {
        &mut self.0
    }
}

/// A set of leaf chunks in two levels. Draining and clearing visit only the
/// touched words, and `any_in` over a wide range tests whole summary words.
#[derive(Default)]
pub(super) struct ChunkBits {
    words: Words,
    /// Bit `i` is set iff `words[i] != 0`.
    summary: Words,
}

impl ChunkBits {
    #[inline]
    pub(super) fn mark(&mut self, chunk: usize) {
        self.mark_word(chunk / WORD_BITS, 1 << (chunk % WORD_BITS));
    }

    #[inline]
    fn mark_word(&mut self, w: usize, bits: u64) {
        self.words[w] |= bits;
        self.summary[w / WORD_BITS] |= 1 << (w % WORD_BITS);
    }

    #[inline]
    pub(super) fn mark_all(&mut self) {
        self.words.fill(!0);
        self.summary.fill(!0);
        let unused = self.summary.len() * WORD_BITS - self.words.len();
        if let Some(last) = self.summary.last_mut() {
            *last = !0 >> unused;
        }
    }

    #[inline]
    pub(super) fn is_empty(&self) -> bool {
        self.summary.iter().all(|&s| s == 0)
    }

    #[inline]
    pub(super) fn any_in(&self, chunks: Range<usize>) -> bool {
        let whole_words = chunks.start.div_ceil(WORD_BITS)..chunks.end / WORD_BITS;
        if whole_words.is_empty() {
            return self.words.any_in(chunks);
        }
        self.words.any_in(chunks.start..whole_words.start * WORD_BITS) ||
            self.summary.any_in(whole_words.clone()) ||
            self.words.any_in(whole_words.end * WORD_BITS..chunks.end)
    }

    #[inline]
    pub(super) fn resize(&mut self, chunks: usize) {
        let words = chunks.div_ceil(WORD_BITS);
        debug_assert!(words >= self.words.len() || self.is_empty(), "shrinking a marked bitmap");
        self.words.resize(words, 0);
        self.summary.resize(words.div_ceil(WORD_BITS), 0);
    }

    #[inline]
    pub(super) fn clear(&mut self) {
        self.take_words(|_, _| {});
    }

    /// Move the marks into `done`, emitting them as sorted, disjoint,
    /// maximal ranges.
    #[inline]
    pub(super) fn drain_into(&mut self, done: &mut ChunkBits, ranges: &mut Vec<NodeRange>) {
        ranges.clear();
        self.take_words(|w, mut word| {
            done.mark_word(w, word);
            let base = (w * WORD_BITS) as u32;
            while word != 0 {
                // Each pass takes the lowest range of ones:
                //   word          0b0111_0110
                //   lowest        0b0000_0010
                //   word + lowest 0b0111_1000  the carry clears the range
                //   rest          0b0111_0000  & word drops the carried-in bit
                //   range         0b0000_0110  chunks [1, 3); next pass [4, 7)
                let lowest = word & word.wrapping_neg();
                let rest = word & word.wrapping_add(lowest);
                let range = word ^ rest;
                let start = base + range.trailing_zeros();
                let end = base + u64::BITS - range.leading_zeros();
                match ranges.last_mut() {
                    Some(last) if last.end == start => last.end = end,
                    _ => ranges.push(NodeRange { start, end }),
                }
                word = rest;
            }
        });
    }

    /// Zero every marked word, in order, after handing it to `f`.
    #[inline]
    fn take_words(&mut self, mut f: impl FnMut(usize, u64)) {
        for (s, summary) in self.summary.iter_mut().enumerate() {
            let mut touched = *summary;
            *summary = 0;
            while touched != 0 {
                let w = s * WORD_BITS + touched.trailing_zeros() as usize;
                touched &= touched - 1;
                f(w, self.words[w]);
                self.words[w] = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests;
