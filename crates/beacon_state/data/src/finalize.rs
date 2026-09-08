use crate::{BeaconState, ColumnGroup, ColumnSpec, Id, StateId};

/// A bundle listed twice re-anchors once: every group dedups its survivors.
struct Survivors<'a> {
    winner: StateId,
    live: Vec<&'a mut StateId>,
}

impl<'a> Survivors<'a> {
    fn rebase<I: Copy>(
        &mut self,
        proj: impl Fn(&mut StateId) -> &mut I,
        finalize: impl FnOnce(I, &[I]) -> Vec<I>,
    ) {
        let winner = *proj(&mut self.winner);
        let ids: Vec<I> = self.live.iter_mut().map(|s| *proj(s)).collect();
        let fresh = finalize(winner, &ids);
        for (s, fresh_id) in self.live.iter_mut().zip(fresh) {
            *proj(s) = fresh_id;
        }
    }

    fn rebase_lazy<I: Copy>(
        &mut self,
        proj: impl Fn(&mut StateId) -> &mut Option<I>,
        finalize: impl FnOnce(I, &[I]) -> Vec<I>,
    ) {
        let Some(winner) = *proj(&mut self.winner) else {
            return;
        };
        let ids: Vec<I> = self.live.iter_mut().filter_map(|s| *proj(s)).collect();
        let fresh = finalize(winner, &ids);
        for (id, fresh_id) in self.live.iter_mut().filter_map(|s| proj(s).as_mut()).zip(fresh) {
            *id = fresh_id;
        }
    }

    fn finalize_column<C: ColumnSpec>(
        &self,
        group: &mut ColumnGroup<C>,
        idx: impl Fn(&StateId) -> Id<ColumnGroup<C>>,
    ) {
        group.finalize(idx(&self.winner), &self.live, |s| idx(s));
    }
}

impl BeaconState {
    pub fn finalize<'a>(
        &mut self,
        winner: StateId,
        survivors: impl IntoIterator<Item = &'a mut StateId>,
    ) {
        let mut survivors = Survivors { winner, live: survivors.into_iter().collect() };

        // Each base is untouched until its own group's finalize, so it still
        // holds the old count its rebase bounds read.
        survivors.rebase(|s| &mut s.validators_idx, |w, ids| self.validators.finalize(w, ids));
        survivors.rebase(|s| &mut s.eth1_idx, |w, ids| self.eth1.finalize(w, ids));
        survivors.finalize_column(&mut self.balances, |s| s.balances_idx);
        survivors
            .finalize_column(&mut self.previous_participation, |s| s.previous_participation_idx);
        survivors.finalize_column(&mut self.current_participation, |s| s.current_participation_idx);
        survivors.finalize_column(&mut self.inactivity, |s| s.inactivity_idx);
        survivors.finalize_column(&mut self.slashings, |s| s.slashings_idx);
        survivors.finalize_column(&mut self.block_roots, |s| s.block_roots_idx);
        survivors.finalize_column(&mut self.state_roots, |s| s.state_roots_idx);
        survivors.finalize_column(&mut self.randao_mixes, |s| s.randao_mixes_idx);
        survivors.rebase(|s| &mut s.pending_idx, |w, ids| self.pending.finalize(w, ids));
        survivors.rebase(|s| &mut s.slot_idx, |w, ids| self.slot_states.finalize(w, ids));
        survivors.rebase(|s| &mut s.builders_idx, |w, ids| self.builders.finalize(w, ids));

        survivors.rebase_lazy(|s| &mut s.epoch_idx, |w, ids| self.epoch.finalize(w, ids));
        survivors.rebase_lazy(|s| &mut s.longtail_idx, |w, ids| self.longtail.finalize(w, ids));
    }
}
