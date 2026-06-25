use super::{BuildersGroup, finalized::FinalizedBuilders};
use crate::{
    buffer::{Reset, Slot},
    gloas::{BUILDER_REGISTRY_LIMIT, Builder},
};

#[derive(Clone, Default)]
pub(super) struct BuildersDelta {
    appended: Vec<Builder>,
}

impl BuildersDelta {
    #[inline]
    pub(super) fn appended(&self) -> &[Builder] {
        &self.appended
    }

    pub(super) fn rebase(&mut self, winner: &Self) {
        self.appended.drain(..winner.appended.len());
    }
}

impl Reset for BuildersDelta {
    fn reset(&mut self) {
        self.appended.clear();
    }

    fn reset_from(&mut self, other: &Self) {
        self.appended.clone_from(&other.appended);
    }
}

#[derive(Clone, Copy)]
pub struct BuildersView<'a> {
    base: &'a FinalizedBuilders,
    delta: &'a BuildersDelta,
}

impl<'a> BuildersView<'a> {
    #[inline]
    pub(super) fn new(base: &'a FinalizedBuilders, delta: &'a BuildersDelta) -> Self {
        Self { base, delta }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.base.len() + self.delta.appended.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&'a Builder> {
        let base = self.base.as_slice();
        if i < base.len() { base.get(i) } else { self.delta.appended.get(i - base.len()) }
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &'a Builder> + use<'a> {
        self.base.as_slice().iter().chain(self.delta.appended.iter())
    }
}

pub struct BuildersWriteView<'a> {
    base: &'a FinalizedBuilders,
    fork: Slot<'a, BuildersGroup, BuildersDelta>,
}

impl<'a> BuildersWriteView<'a> {
    #[inline]
    pub(super) fn new(
        base: &'a FinalizedBuilders,
        fork: Slot<'a, BuildersGroup, BuildersDelta>,
    ) -> Self {
        Self { base, fork }
    }

    #[inline]
    pub fn commit(self) -> super::BuildersId {
        self.fork.commit()
    }

    #[inline]
    pub fn reader(&self) -> BuildersView<'_> {
        BuildersView { base: self.base, delta: &self.fork }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.reader().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.reader().is_empty()
    }

    #[inline]
    pub fn push(&mut self, builder: Builder) {
        assert!(self.len() < BUILDER_REGISTRY_LIMIT, "builders exceeded BUILDER_REGISTRY_LIMIT");
        self.fork.appended.push(builder);
    }

    #[inline]
    pub fn add_balance(&mut self, builder_index: usize, amount: u64) {
        let base = self.base.len();
        let appended = builder_index
            .checked_sub(base)
            .expect("add_balance on a finalized builder; base-edit overlay not implemented");
        self.fork.appended[appended].balance += amount;
    }
}
