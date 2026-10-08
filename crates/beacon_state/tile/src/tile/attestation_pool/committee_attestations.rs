use silver_common::Slab;

use super::{
    InsertOutcome,
    committee_bits::{CommitteeBits, bit_positions},
    selection::MAX_AGGREGATES,
};
use crate::bls::{AggregateSignature, BLANK_SIGNATURE, EMPTY_AGGREGATE, Signature};

const NO_SINGLE: u32 = u32::MAX;

/// One committee's aggregates and singles for one vote candidate. The
/// aggregates and singles themselves live in slabs it indexes.
#[derive(Clone, Copy)]
pub(super) struct CommitteeAttestations {
    pub(super) committee_len: usize,
    /// Every committee member seen attesting: more than the aggregates and
    /// singles hold once an aggregate is evicted.
    pub(super) attesters: CommitteeBits,
    pub(super) singles: CommitteeBits,
    pub(super) singles_signature: AggregateSignature,
    first_single: u32,
    /// Slab indices by position; a position keeps its aggregate until it is
    /// removed.
    aggregates: [u32; MAX_AGGREGATES],
    /// Bit `k` is set while position `k` holds an aggregate.
    held: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Aggregate {
    pub(super) bits: CommitteeBits,
    pub(super) signature: Signature,
}

impl Aggregate {
    pub(super) const BLANK: Self = Self { bits: CommitteeBits::EMPTY, signature: BLANK_SIGNATURE };
}

/// A link in its committee's list of singles.
#[derive(Clone, Copy)]
pub(super) struct Single {
    pub(super) member: u16,
    next: u32,
    pub(super) signature: Signature,
}

impl Single {
    pub(super) const BLANK: Self = Self { member: 0, next: NO_SINGLE, signature: BLANK_SIGNATURE };
}

impl CommitteeAttestations {
    pub(super) const EMPTY: Self = Self::new(0);

    pub(super) const fn new(committee_len: usize) -> Self {
        Self {
            committee_len,
            attesters: CommitteeBits::EMPTY,
            singles: CommitteeBits::EMPTY,
            singles_signature: EMPTY_AGGREGATE,
            first_single: NO_SINGLE,
            aggregates: [0; MAX_AGGREGATES],
            held: 0,
        }
    }

    /// Its aggregates' positions, ascending, with their slab indices.
    pub(super) fn aggregates(&self) -> impl Iterator<Item = (usize, u32)> + Clone + '_ {
        bit_positions(self.held.into()).map(|position| (position, self.aggregates[position]))
    }

    pub(super) fn aggregate(&self, position: usize) -> u32 {
        debug_assert!(self.held & 1 << position != 0, "held position");
        self.aggregates[position]
    }

    pub(super) fn singles<'a>(
        &self,
        singles: &'a Slab<Single>,
    ) -> impl Iterator<Item = &'a Single> {
        let mut next = self.first_single;
        std::iter::from_fn(move || {
            (next != NO_SINGLE).then(|| {
                let single = &singles[next];
                next = single.next;
                single
            })
        })
    }

    pub(super) fn add_single(
        &mut self,
        member: usize,
        signature: &Signature,
        singles: &mut Slab<Single>,
    ) -> InsertOutcome {
        if self.singles.contains(member) {
            return InsertOutcome::Duplicate;
        }
        let single =
            Single { member: member as u16, next: self.first_single, signature: *signature };
        let Some(i) = singles.insert(single) else {
            return InsertOutcome::Full;
        };
        self.first_single = i;
        self.singles.insert(member);
        self.attesters.insert(member);
        self.singles_signature
            .add_signature(signature, false)
            .expect("infallible without groupcheck");
        InsertOutcome::Inserted
    }

    /// An aggregate whose committee members outside the singles fit inside a
    /// held one's is dropped as covered. In theory it could still pack beside
    /// an aggregate that overlaps the larger one; that trade keeps the pool
    /// bounded.
    pub(super) fn add_aggregate(
        &mut self,
        bits: CommitteeBits,
        signature: &Signature,
        aggregates: &mut Slab<Aggregate>,
    ) -> InsertOutcome {
        let added = self.outside_singles(&bits);
        if added.is_empty() || self.held_covers(&added, aggregates) {
            return InsertOutcome::Duplicate;
        }

        self.remove_covered_by(&bits, aggregates);
        if self.held == u32::MAX && !self.remove_weakest_below(added.count(), aggregates) {
            return InsertOutcome::Duplicate;
        }
        let Some(i) = aggregates.insert(Aggregate { bits, signature: *signature }) else {
            return InsertOutcome::Full;
        };
        self.hold(i);
        self.attesters.union_with(&bits);
        InsertOutcome::Inserted
    }

    /// Returns its aggregates and singles to their slabs.
    pub(super) fn remove_all(&self, aggregates: &mut Slab<Aggregate>, singles: &mut Slab<Single>) {
        for (_, i) in self.aggregates() {
            aggregates.remove(i);
        }
        let mut next = self.first_single;
        while next != NO_SINGLE {
            let i = next;
            next = singles[i].next;
            singles.remove(i);
        }
    }

    fn outside_singles(&self, bits: &CommitteeBits) -> CommitteeBits {
        bits.difference(&self.singles)
    }

    fn held_covers(&self, bits: &CommitteeBits, aggregates: &Slab<Aggregate>) -> bool {
        self.aggregates().any(|(_, i)| bits.is_subset(&aggregates[i].bits))
    }

    /// Holds slab index `i` at the lowest free position.
    fn hold(&mut self, i: u32) {
        let position = (!self.held).trailing_zeros() as usize;
        self.aggregates[position] = i;
        self.held |= 1 << position;
    }

    /// Drops the held aggregates whose committee members outside the singles
    /// `bits` covers.
    fn remove_covered_by(&mut self, bits: &CommitteeBits, aggregates: &mut Slab<Aggregate>) {
        for position in bit_positions(self.held.into()) {
            let held = &aggregates[self.aggregates[position]].bits;
            if self.outside_singles(held).is_subset(bits) {
                self.remove_aggregate(position, aggregates);
            }
        }
    }

    /// Drops the held aggregate with the fewest committee members outside the
    /// singles, if it has fewer than `added`; `false` when none does.
    fn remove_weakest_below(&mut self, added: u32, aggregates: &mut Slab<Aggregate>) -> bool {
        let counts = self
            .aggregates()
            .map(|(position, i)| (position, self.outside_singles(&aggregates[i].bits).count()));
        let (weakest, count) = counts.min_by_key(|&(_, count)| count).expect("held aggregates");
        if count >= added {
            return false;
        }
        self.remove_aggregate(weakest, aggregates);
        true
    }

    fn remove_aggregate(&mut self, position: usize, aggregates: &mut Slab<Aggregate>) {
        aggregates.remove(self.aggregate(position));
        self.held &= !(1 << position);
    }
}
