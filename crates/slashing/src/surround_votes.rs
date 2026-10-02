use silver_beacon_state_data::{Epoch, Version};
use silver_ssz::ssz_view::{SINGLE_ATT_SIZE, SingleAttestationView};

use crate::{
    Offence,
    signed_vote::{AttesterProof, IndexedVote, SIGNED_VOTE_SIZE, SignedVote},
};

const SEGMENT: usize = 1 << 16;

/// Epochs plus one: zero stays empty even when a vote has source > target.
type Span = [u32; 2];

struct Segment {
    lanes: usize,
    // Validator-major keeps each surround scan contiguous.
    spans: Box<[Span]>,
    // Lane-major confines a target epoch's evidence writes to one lane.
    // Flat bytes request zeroed allocation; residency depends on the allocator.
    votes: Box<[u8]>,
}

impl Segment {
    fn new(lanes: usize) -> Self {
        Self {
            lanes,
            spans: vec![[0; 2]; SEGMENT * lanes].into_boxed_slice(),
            votes: vec![0; SEGMENT * lanes * SIGNED_VOTE_SIZE].into_boxed_slice(),
        }
    }

    fn vote(&self, lane: usize, offset: usize) -> SignedVote {
        SignedVote(self.votes.as_chunks::<SIGNED_VOTE_SIZE>().0[lane * SEGMENT + offset])
    }

    fn surround(&self, offset: usize, [source, target]: Span) -> Option<usize> {
        let row = offset * self.lanes;
        self.spans[row..row + self.lanes]
            .iter()
            .position(|&[s, t]| (s < source && target < t) || (source < s && t < target))
    }

    /// Capture `(surrounding, surrounded)` before reusing the evidence lane.
    fn record(
        &mut self,
        offset: usize,
        [source, target]: Span,
        vote: &SignedVote,
    ) -> Option<(SignedVote, SignedVote)> {
        let row = offset * self.lanes;
        let surround = self.surround(offset, [source, target]).map(|lane| {
            let recorded = self.vote(lane, offset);
            if self.spans[row + lane][0] < source { (recorded, *vote) } else { (*vote, recorded) }
        });
        let (votes, _) = self.votes.as_chunks_mut::<SIGNED_VOTE_SIZE>();

        let lane = target as usize % self.lanes;
        if self.spans[row + lane][1] != target {
            self.spans[row + lane] = [source, target];
            votes[lane * SEGMENT + offset] = vote.0;
        }
        surround
    }
}

/// Target epochs share lanes modulo the lane count; replacing a lane can
/// discard evidence of a surround.
pub(crate) struct SurroundVotes {
    lanes: usize,
    segments: Vec<Segment>,
}

impl SurroundVotes {
    /// Reserves `historical_epochs + 1` lanes, growing by validator segment.
    pub(crate) fn new(historical_epochs: u8, validators: usize) -> Self {
        let lanes = usize::from(historical_epochs) + 1;
        let segments = (0..validators.div_ceil(SEGMENT)).map(|_| Segment::new(lanes));
        Self { lanes, segments: segments.collect() }
    }

    pub(crate) fn record(
        &mut self,
        accepted: &[u8; SINGLE_ATT_SIZE],
        fork_version: Version,
    ) -> Option<AttesterProof> {
        let (validator, span) = located(accepted)?;
        while self.segments.len() <= validator / SEGMENT {
            self.segments.push(Segment::new(self.lanes));
        }
        let vote = SignedVote::of(accepted, fork_version);
        let segment = &mut self.segments[validator / SEGMENT];
        let (surrounding, surrounded) = segment.record(validator % SEGMENT, span, &vote)?;
        let signed_by = |vote| IndexedVote { vote, signers: vec![validator as u32] };
        Some(AttesterProof::new(
            Offence::SurroundVote,
            signed_by(surrounding),
            signed_by(surrounded),
        ))
    }

    /// Compares spans and the recorded fork version; does not verify
    /// signatures.
    pub(crate) fn conflicts(
        &self,
        single: &[u8; SINGLE_ATT_SIZE],
        signing_version: impl Fn(Epoch) -> Version,
    ) -> bool {
        let Some((validator, span)) = located(single) else { return false };
        let Some(segment) = self.segments.get(validator / SEGMENT) else { return false };
        let offset = validator % SEGMENT;
        segment.surround(offset, span).is_some_and(|lane| {
            segment.vote(lane, offset).versioned_data().verifies_under(&signing_version)
        })
    }

    /// History allocation size, excluding allocator overhead.
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.segments.len() * SEGMENT * self.lanes * (size_of::<Span>() + SIGNED_VOTE_SIZE)
    }
}

fn located(single: &[u8; SINGLE_ATT_SIZE]) -> Option<(usize, Span)> {
    let data = SingleAttestationView::data(single);
    let span_epoch = |epoch: u64| epoch.checked_add(1).and_then(|e| u32::try_from(e).ok());
    let validator = u32::try_from(SingleAttestationView::attester_index(single)).ok()? as usize;
    Some((validator, [span_epoch(data.source_epoch())?, span_epoch(data.target_epoch())?]))
}
