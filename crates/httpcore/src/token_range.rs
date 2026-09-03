use mio::Token;

/// One tenant's share of a shared [`Readiness`](crate::Readiness) token space:
/// a token two tenants could both allocate would deliver one's socket
/// readiness into the other's dispatch, so each takes a disjoint range.
#[derive(Clone, Copy)]
pub struct TokenRange {
    base: usize,
    span: usize,
}

impl TokenRange {
    pub const fn new(base: usize, span: usize) -> Self {
        Self { base, span }
    }

    /// The token space of a loop with a sole tenant, bar `Token(usize::MAX)`
    /// which no span based at zero reaches.
    pub const fn whole() -> Self {
        Self::new(0, usize::MAX)
    }

    /// One of `count` equal shares, for a loop with that many tenants.
    /// Distinct indices cannot alias, at the price of the tokens above the
    /// last share: integer division leaves those owned by nobody.
    pub const fn share(index: usize, count: usize) -> Self {
        assert!(index < count, "share index outside the tenant count");
        let span = usize::MAX / count;
        Self::new(index * span, span)
    }

    pub const fn span(&self) -> usize {
        self.span
    }

    #[cfg(test)]
    const fn overlaps(self, other: Self) -> bool {
        let (lower, upper) = if self.base <= other.base { (self, other) } else { (other, self) };
        upper.base - lower.base < lower.span
    }

    pub fn at(&self, offset: usize) -> Token {
        assert!(offset < self.span, "offset {offset} outside a span of {}", self.span);
        Token(self.base + offset)
    }

    pub fn offset_of(&self, token: Token) -> Option<usize> {
        token.0.checked_sub(self.base).filter(|offset| *offset < self.span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The partition a tile with two tenants hands out: neither half may claim
    /// a token the other allocates.
    const HALF: usize = 1 << (usize::BITS - 1);

    #[test]
    fn offsets_map_to_tokens_above_the_base() {
        let range = TokenRange::new(HALF, HALF);
        assert_eq!(range.at(0), Token(HALF));
        assert_eq!(range.at(7), Token(HALF + 7));
        assert_eq!(range.offset_of(Token(HALF + 7)), Some(7));
    }

    #[test]
    fn a_token_outside_the_range_has_no_offset() {
        let low = TokenRange::new(0, HALF);
        let high = TokenRange::new(HALF, HALF);

        assert_eq!(low.offset_of(Token(HALF)), None, "the high half is not the low half's");
        assert_eq!(high.offset_of(Token(0)), None, "the low half is not the high half's");
        assert_eq!(high.offset_of(Token(HALF - 1)), None);
        assert_eq!(low.offset_of(Token(HALF - 1)), Some(HALF - 1));
    }

    #[test]
    fn every_token_belongs_to_exactly_one_half() {
        let low = TokenRange::new(0, HALF);
        let high = TokenRange::new(HALF, HALF);
        for token in [Token(0), Token(1), Token(HALF - 1), Token(HALF), Token(usize::MAX)] {
            assert!(
                low.offset_of(token).is_some() != high.offset_of(token).is_some(),
                "{token:?} must belong to one half only"
            );
        }
    }

    /// The property the partition rests on, over more tenants than the two a
    /// tile splits the loop between today.
    #[test]
    fn no_two_shares_of_a_count_overlap() {
        for count in 1..=8 {
            let shares = (0..count).map(|i| TokenRange::share(i, count)).collect::<Vec<_>>();
            for (i, share) in shares.iter().enumerate() {
                assert!(share.span() > 0, "share {i} of {count} is empty");
                for other in &shares[i + 1..] {
                    assert!(!share.overlaps(*other), "share {i} of {count} overlaps a later one");
                }
            }
        }
    }

    #[test]
    fn a_share_index_at_or_past_the_count_is_refused() {
        assert!(std::panic::catch_unwind(|| TokenRange::share(2, 2)).is_err());
    }

    #[test]
    fn halves_do_not_overlap_but_anything_sharing_a_base_does() {
        let low = TokenRange::new(0, HALF);
        let high = TokenRange::new(HALF, HALF);

        assert!(!low.overlaps(high));
        assert!(!high.overlaps(low));
        assert!(low.overlaps(low));
        assert!(low.overlaps(TokenRange::new(HALF - 1, 4)), "one shared token is an overlap");
        assert!(TokenRange::whole().overlaps(high));
    }

    #[test]
    fn the_whole_space_claims_every_token_a_sole_tenant_can_allocate() {
        let whole = TokenRange::whole();
        assert_eq!(whole.offset_of(Token(0)), Some(0));
        assert_eq!(whole.offset_of(Token(HALF)), Some(HALF));
        assert_eq!(whole.span(), usize::MAX);
        assert_eq!(whole.offset_of(Token(usize::MAX)), None, "the last token is nobody's");
    }

    #[test]
    #[should_panic(expected = "outside a span")]
    fn allocating_past_the_span_is_a_bug() {
        TokenRange::new(0, 4).at(4);
    }
}
