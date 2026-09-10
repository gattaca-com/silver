use crate::{
    BeaconState, EpochGroup, EpochId, EpochView, LongtailGroup, LongtailId, StateId, StateReadView,
    StateWriterView,
};

/// An unpublished child fork off `parent`: every slot-tier writer held for
/// one transition, then `commit` assembles the child bundle. Epoch and
/// longtail are not rolled up front; a transition crossing a boundary rolls
/// them and records the committed ids in `epoch_idx` / `longtail_idx`, which
/// start as the parent's.
pub struct ForkWriter<'a> {
    pub view: StateWriterView<'a>,
    pub epoch: &'a mut EpochGroup,
    pub longtail: &'a mut LongtailGroup,
    pub epoch_idx: Option<EpochId>,
    pub longtail_idx: Option<LongtailId>,
}

impl ForkWriter<'_> {
    pub fn epoch_view(&self) -> EpochView<'_> {
        self.epoch.view_opt(self.epoch_idx)
    }

    pub fn read(&mut self) -> StateReadView<'_> {
        let epoch = self.epoch.view_opt(self.epoch_idx);
        let longtail = self.longtail.view_opt(self.longtail_idx);
        self.view.read(epoch, longtail)
    }

    pub fn commit(self) -> StateId {
        self.view.commit(self.epoch_idx, self.longtail_idx)
    }
}

impl BeaconState {
    pub fn fork_writer(&mut self, parent: StateId) -> ForkWriter<'_> {
        let (view, epoch, longtail) = self.roll_from(parent);
        ForkWriter {
            view,
            epoch,
            longtail,
            epoch_idx: parent.epoch_idx,
            longtail_idx: parent.longtail_idx,
        }
    }
}
