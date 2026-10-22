use silver_beacon_state_data::BLSPubkey;

/// What a `BuilderEntry` makes of its builder's bid, in Gwei.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderTerms {
    pub min_bid: u64,
    pub builder_boost_factor: u64,
    pub max_execution_payment: u64,
}

impl BuilderTerms {
    /// `value` plus `execution_payment` up to the entry's cap.
    pub fn counted(&self, value: u64, execution_payment: u64) -> u128 {
        u128::from(value) + u128::from(execution_payment.min(self.max_execution_payment))
    }
}

/// A builder-API bid as the boundary tile frames it: a [`Self::HEADER_LEN`]
/// header, the entry's accepted builder pubkeys, then the
/// `SignedExecutionPayloadBid` SSZ. A frame holds any number back to back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuilderBid<'a> {
    /// Index of the `BuilderEntry` the bid answered.
    pub entry: u32,
    pub terms: BuilderTerms,
    /// Concatenated `BLSPubkey`s; empty accepts any builder.
    pub builder_pubkeys: &'a [u8],
    pub signed_bid: &'a [u8],
}

impl<'a> BuilderBid<'a> {
    /// Entry index, the three terms, then the pubkeys and bid lengths.
    pub const HEADER_LEN: usize = 4 + 3 * 8 + 4 + 4;

    pub fn write(&self, out: &mut Vec<u8>) {
        let BuilderTerms { min_bid, builder_boost_factor, max_execution_payment } = self.terms;
        out.extend_from_slice(&self.entry.to_le_bytes());
        out.extend_from_slice(&min_bid.to_le_bytes());
        out.extend_from_slice(&builder_boost_factor.to_le_bytes());
        out.extend_from_slice(&max_execution_payment.to_le_bytes());
        out.extend_from_slice(&(self.builder_pubkeys.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.signed_bid.len() as u32).to_le_bytes());
        out.extend_from_slice(self.builder_pubkeys);
        out.extend_from_slice(self.signed_bid);
    }

    /// Every bid of `frame`, stopping at the first misframed one.
    pub fn iter(frame: &'a [u8]) -> impl Iterator<Item = Self> {
        let mut rest = frame;
        std::iter::from_fn(move || {
            let (bid, tail) = Self::parse(rest)?;
            rest = tail;
            Some(bid)
        })
    }

    pub fn accepts(&self, builder_pubkey: &BLSPubkey) -> bool {
        self.builder_pubkeys.is_empty() ||
            self.builder_pubkeys
                .chunks_exact(size_of::<BLSPubkey>())
                .any(|key| key == builder_pubkey)
    }

    fn parse(frame: &'a [u8]) -> Option<(Self, &'a [u8])> {
        let (header, rest) = frame.split_at_checked(Self::HEADER_LEN)?;
        let u64_at =
            |at: usize| u64::from_le_bytes(header[at..at + 8].try_into().expect("8 bytes"));
        let u32_at =
            |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"));
        let terms = BuilderTerms {
            min_bid: u64_at(4),
            builder_boost_factor: u64_at(12),
            max_execution_payment: u64_at(20),
        };
        let (builder_pubkeys, rest) = rest.split_at_checked(u32_at(28) as usize)?;
        let (signed_bid, rest) = rest.split_at_checked(u32_at(32) as usize)?;
        Some((Self { entry: u32_at(0), terms, builder_pubkeys, signed_bid }, rest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bids_read_back_in_frame_order() {
        let terms =
            BuilderTerms { min_bid: 1, builder_boost_factor: 150, max_execution_payment: 3 };
        let keys = [[7u8; 48], [9u8; 48]].concat();
        let first = BuilderBid { entry: 2, terms, builder_pubkeys: &keys, signed_bid: b"bid" };
        let second = BuilderBid { entry: 5, terms, builder_pubkeys: &[], signed_bid: b"other" };
        let mut frame = Vec::new();
        first.write(&mut frame);
        second.write(&mut frame);

        assert_eq!(BuilderBid::iter(&frame).collect::<Vec<_>>(), [first, second]);
        assert!(first.accepts(&[9; 48]) && !first.accepts(&[8; 48]));
        assert!(second.accepts(&[8; 48]), "no pubkeys accept any builder");
        assert_eq!(BuilderBid::iter(&frame[..frame.len() - 1]).count(), 1, "a cut bid ends it");
    }

    #[test]
    fn execution_payment_counts_up_to_the_cap() {
        let terms =
            BuilderTerms { min_bid: 0, builder_boost_factor: 100, max_execution_payment: 5 };
        assert_eq!(terms.counted(10, 3), 13);
        assert_eq!(terms.counted(10, 9), 15);
        assert_eq!(terms.counted(u64::MAX, 1), u128::from(u64::MAX) + 1);
    }
}
