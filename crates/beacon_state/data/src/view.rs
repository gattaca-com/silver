use std::{
    cell::UnsafeCell,
    ops::{Deref, DerefMut},
    sync::{self, Arc, atomic::Ordering},
};

use flux::communication::Seqlock;

use crate::{BeaconState, EpochGroup, LongtailGroup, StateId, StateReadView, StateWriterView};

/// The shared `BeaconState` allocation. Lifetime rides the `Arc` (a reader
/// can never dangle, whatever the teardown order); ACCESS rides the seqlock
/// protocol — this cell is the protocol's one irreducible `unsafe`.
struct StateCell(UnsafeCell<BeaconState>);

// SAFETY: single writer — `BeaconStateOwner` is the unique write handle (not
// `Clone`, mutation behind `&mut self`); cross-thread readers are optimistic
// (re-validate the control version after reading, discard torn reads).
unsafe impl Sync for StateCell {}

impl StateCell {
    /// Owner-side shared read (`&self` on the owner excludes its `&mut` uses).
    fn get(&self) -> &BeaconState {
        unsafe { &*self.0.get() }
    }

    /// Owner-side exclusive access; sound only because the owner is the
    /// single writer and takes `&mut self` for every call.
    #[allow(clippy::mut_from_ref)]
    fn get_mut(&self) -> &mut BeaconState {
        unsafe { &mut *self.0.get() }
    }
}

/// Beacon state writer control.
/// Single writer.
pub struct BeaconStateOwner {
    state: Arc<StateCell>,
    inner: Arc<Seqlock<ControlInner>>,
}

impl BeaconStateOwner {
    /// Construct around a real (decomposed or test-built) state. Readers see
    /// nothing until the first `publish_state_id`: the control seqlock starts
    /// never-written (version 0).
    pub fn new(state: BeaconState) -> Self {
        Self {
            state: Arc::new(StateCell(UnsafeCell::new(state))),
            inner: Arc::new(Seqlock::default()),
        }
    }

    /// The syncing-mode owner — exists so reader handles can be wired before
    /// the snapshot arrives; readers observe nothing until the first publish.
    pub fn pre_bootstrap() -> Self {
        Self::new(BeaconState::pre_bootstrap())
    }

    pub fn state(&self) -> &BeaconState {
        self.state.get()
    }

    /// Anchor fresh per-tier forks on the owner's state and hand back the
    /// anchor bundle (bootstrap / pre-bootstrap head). All other owner-side
    /// mutation goes through [`Self::apply_block_view`] (block path) or
    /// [`Self::write`] (finalize window).
    pub fn roll_fresh(&mut self) -> StateId {
        self.state.get_mut().roll_fresh()
    }

    /// Roll an unpublished child off the `parent` bundle, HOLD every tier's
    /// writer, and hand back a `StateWriterView` over the held writers — no
    /// separate publish, no re-open. The STF mutates the view, then `commit`
    /// (which assembles the child bundle from the held writers) +
    /// `publish_state_id` make it visible (publish-last).
    ///
    /// Epoch/longtail are NOT rolled here: their idxs stay inherited from the
    /// parent (the caller carries them as plain data) and the block path only
    /// reads them — `process_epoch` rolls the boundary writers itself. The
    /// groups ride alongside the view for exactly those boundary reads and
    /// rolls.
    pub fn apply_block_view(
        &mut self,
        parent: StateId,
    ) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
        let s = self.state.get_mut();
        // Production state-transition path: finalized base must be populated
        // (decompose from genesis SSZ or a checkpoint). The zero-validator
        // pre-bootstrap stub never reaches the STF.
        assert!(
            s.validators.base().validator_count() > 0,
            "apply_block_view: operating on empty finalized state",
        );
        // Hold the always-written tiers' writers (rolled from the parent's
        // idx); their ids surface only at `commit`.
        let view = StateWriterView::new(
            &s.immutable,
            s.balances.roll_from(parent.balances_idx),
            s.pending.roll_from(parent.pending_idx),
            s.previous_participation.roll_from(parent.previous_participation_idx),
            s.current_participation.roll_from(parent.current_participation_idx),
            s.inactivity.roll_from(parent.inactivity_idx),
            s.slot_states.roll_from(parent.slot_idx),
            s.validators.roll_from(parent.validators_idx),
        );
        (view, &mut s.epoch, &mut s.longtail)
    }

    /// Read-only view over the fork named by `state_id` for the writer
    /// thread's own reads (gossip validation, head recompute). Resolves shared
    /// refs from the bundle — `&self`, no mutation, no re-open. See
    /// [`StateReadView`].
    pub fn read_view(&self, state_id: StateId) -> StateReadView<'_> {
        self.state.get().read_view(state_id)
    }

    /// Publish the head's index bundle for cross-thread readers — call only
    /// once the per-tier slots it names will no longer be mutated. The first
    /// publish is what makes the state observable at all.
    pub fn publish_state_id(&mut self, state_id: StateId) {
        debug_assert!(self.inner.version() & 1 == 0, "publish inside a write window");
        // Single producer; `write` also handles the never-written 0→2 case.
        self.inner.write(&ControlInner { state_id: Some(state_id) });
    }

    /// Open the finalize write window: the seqlock's version goes (and stays)
    /// odd, so optimistic readers spin inside `read_copy` until the
    /// [`WriteGuard`] drops. The guard's drop writes the staged control word
    /// and closes the window in one seqlock write.
    pub fn write(&mut self) -> WriteGuard<'_> {
        // Stage from the current control; pre-publish (never-written) windows
        // stage the default — its `None` still reads as "no state yet" if the
        // window closes before the first publish.
        let value = match self.inner.read_copy() {
            Ok((value, _)) => value,
            Err(_) => ControlInner::default(),
        };
        let version = self.inner.version();
        debug_assert!(version & 1 == 0, "nested finalize write window");
        // Crossbeam-style writer begin: odd store, then a Release fence so the
        // state mutations behind the guard can't hoist above it.
        self.inner.set_version_unsafe(version + 1);
        sync::atomic::fence(Ordering::Release);

        WriteGuard { beacon_state: self.state.get_mut(), value, inner: &self.inner }
    }

    pub fn reader(&self) -> BeaconStateReader {
        BeaconStateReader { state: self.state.clone(), inner: self.inner.clone() }
    }
}

/// Cross-thread optimistic reader handle. `Send`/`Sync` fall out of
/// `StateCell: Sync` — the `Arc` keeps the allocation alive for as long as
/// any reader exists, so no teardown-order invariant remains.
pub struct BeaconStateReader {
    state: Arc<StateCell>,
    inner: Arc<Seqlock<ControlInner>>,
}

impl BeaconStateReader {
    /// Performs optimistic reads from the beacon state, this will loop if the
    /// finalized state is updated during a read. Returns `None` until the
    /// writer publishes its first real snapshot.
    ///
    /// Lock-free path: only the fixed-size bases (epoch/slot scalars,
    /// validators columns, balances/participation/inactivity boxes) are safe
    /// to read optimistically. The pending / longtail / slot `eth1_votes`
    /// bases are realloc-prone `Vec`s — reading their CONTENT here can race a
    /// finalize realloc; those reads need the planned lock-guarded path.
    pub fn read<F, R>(&self, reader: &F) -> Option<R>
    where
        F: Fn(StateReadView<'_>) -> R,
    {
        loop {
            // `read_copy` spins through odd versions (an open finalize
            // window) and returns the version it validated against.
            // `Err(Empty)` = never written; `state_id: None` = a pre-publish
            // finalize window closed — both mean no snapshot yet.
            let Ok((control, version)) = self.inner.read_copy() else { return None };
            let state_id = control.state_id?;
            sync::atomic::fence(Ordering::Acquire);
            let result = reader(self.state.get().read_view(state_id));

            // Validate: no finalize ran while we were reading the state.
            sync::atomic::fence(Ordering::Acquire);
            if self.inner.version() == version {
                return Some(result);
            }
        }
    }
}

pub struct WriteGuard<'a> {
    beacon_state: &'a mut BeaconState,
    value: ControlInner,
    inner: &'a Seqlock<ControlInner>,
}

impl<'a> Deref for WriteGuard<'a> {
    type Target = BeaconState;

    fn deref(&self) -> &Self::Target {
        self.beacon_state
    }
}

impl<'a> DerefMut for WriteGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.beacon_state
    }
}

impl<'a> WriteGuard<'a> {
    /// Stage a new published head bundle; lands atomically when the guard
    /// drops. Finalization rewrites survivor bundles' per-tier ids, so the
    /// head's refreshed bundle must publish in the same seqlock window —
    /// readers must never observe a bundle whose ids were already re-anchored.
    pub fn set_state_id(&mut self, state_id: StateId) {
        self.value.state_id = Some(state_id);
    }
}

impl<'a> Drop for WriteGuard<'a> {
    fn drop(&mut self) {
        debug_assert!(self.inner.version() & 1 == 1, "write window already closed");
        // Order the window's state mutations before the closing version store.
        sync::atomic::fence(Ordering::Release);
        // Writes the staged control word and flips the held-odd version back
        // to even — readers spinning in `read_copy` resume with the new head.
        self.inner.write_unpoison(&self.value);
    }
}

/// The control word: just the published head's per-tier index bundle.
/// Write-window state lives in the `Seqlock`'s OWN version counter (odd =
/// finalize in progress; `WriteGuard` holds it odd across the window).
/// `Default` exists only because `Seqlock::default()` requires it; readers
/// treat `state_id: None` (only reachable when a finalize window closes
/// before the first publish) as "no state yet" — every publish writes `Some`.
#[derive(Clone, Copy, Default)]
struct ControlInner {
    state_id: Option<StateId>,
}
