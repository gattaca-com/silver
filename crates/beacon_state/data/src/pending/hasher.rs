use crate::{
    merkle::{MerkleStack, mix_in_length},
    progressive::ProgressiveHasher,
    types::B256,
};

#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(super) enum QueueHasher {
    Fulu(MerkleStack),
    Gloas(ProgressiveHasher),
}

impl QueueHasher {
    pub(super) fn empty(gloas: bool, ssz_limit: usize) -> Self {
        if gloas {
            QueueHasher::Gloas(ProgressiveHasher::new())
        } else {
            QueueHasher::Fulu(MerkleStack::new(ssz_limit))
        }
    }

    pub(super) fn is_gloas(&self) -> bool {
        matches!(self, QueueHasher::Gloas(_))
    }

    #[inline]
    pub(super) fn push(&mut self, leaf: B256) {
        match self {
            QueueHasher::Fulu(stack) => stack.push(leaf),
            QueueHasher::Gloas(hasher) => hasher.push_chunk(leaf),
        }
    }

    pub(super) fn root(&self, len: usize) -> B256 {
        match self {
            QueueHasher::Fulu(stack) => mix_in_length(&stack.finalize(), len),
            QueueHasher::Gloas(hasher) => mix_in_length(&hasher.root(), len),
        }
    }
}
