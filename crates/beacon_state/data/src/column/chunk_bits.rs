use super::subtree::NodeRange;

const WORD_BITS: usize = u64::BITS as usize;

/// A set of leaf chunks. Two levels so draining and clearing scan only the
/// words that were touched.
#[derive(Default)]
pub(super) struct ChunkBits {
    words: Vec<u64>,
    /// Bit `i` is set iff `words[i] != 0`.
    summary: Vec<u64>,
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
    pub(super) fn is_empty(&self) -> bool {
        self.summary.iter().all(|&s| s == 0)
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

    /// Clear the marks, emitting them as sorted, disjoint, maximal ranges.
    #[inline]
    pub(super) fn drain(&mut self, ranges: &mut Vec<NodeRange>) {
        ranges.clear();
        self.take_words(|w, mut word| {
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
