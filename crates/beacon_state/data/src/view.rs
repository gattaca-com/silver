use std::{
    cell::UnsafeCell,
    io,
    ops::{Deref, DerefMut},
    sync::{self, Arc, atomic::Ordering},
};

use flux::communication::Seqlock;
use flux_profiler::timed;

use crate::{
    BeaconState, CHECKPOINT_SECTIONS, EpochGroup, LongtailGroup, StateId, StateReadView,
    StateWriterView,
    encode::{Section, VAR_LEN_SECTIONS},
};

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

    /// Owner around the all-empty test state at `slot` — the
    /// `BeaconStateOwner::new(BeaconState::empty_test(slot))` shorthand for
    /// test wiring that needs an owner/reader without a real checkpoint.
    /// Test-only.
    #[doc(hidden)]
    pub fn empty_test(slot: u64) -> Self {
        Self::new(BeaconState::empty_test(slot))
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
    #[timed]
    pub fn apply_block_view(
        &mut self,
        parent: StateId,
    ) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
        let s = self.state.get_mut();
        // Production state-transition path: finalized base must be populated
        // (decompose from genesis SSZ or a checkpoint). The zero-validator
        // pre-bootstrap stub never reaches the STF.
        assert!(
            s.validators.finalized().validator_count() > 0,
            "apply_block_view: operating on empty finalized state",
        );
        // Hold the always-written tiers' writers (rolled from the parent's
        // idx); their ids surface only at `commit`.
        let view = StateWriterView {
            imm: &s.immutable,
            balances: s.balances.roll_from(parent.balances_idx),
            eth1: s.eth1.roll_from(parent.eth1_idx),
            pending: s.pending.roll_from(parent.pending_idx),
            previous_participation: s
                .previous_participation
                .roll_from(parent.previous_participation_idx),
            current_participation: s
                .current_participation
                .roll_from(parent.current_participation_idx),
            inactivity: s.inactivity.roll_from(parent.inactivity_idx),
            slot: s.slot_states.roll_from(parent.slot_idx),
            validators: s.validators.roll_from(parent.validators_idx),
            builders: s.builders.roll_from(parent.builders_idx),
        };
        (view, &mut s.epoch, &mut s.longtail)
    }

    /// Read-only view over the fork named by `state_id` for the writer
    /// thread's own reads (gossip validation, head recompute). Resolves shared
    /// refs from the bundle — `&self`, no mutation, no re-open. See
    /// [`StateReadView`].
    pub fn read_view(&self, state_id: StateId) -> StateReadView<'_> {
        self.state.get().read_view(state_id)
    }

    /// Single writer: the current control word is whatever we last wrote;
    /// pre-publish (never written) it's the default.
    fn current_control(&self) -> ControlInner {
        self.inner.read_copy().map_or_else(|_| ControlInner::default(), |(value, _)| value)
    }

    /// Publish the head's index bundle for cross-thread readers — call only
    /// once the per-tier slots it names will no longer be mutated. The first
    /// publish is what makes the state observable at all. Carries the
    /// finalize counter unchanged: a publish never invalidates an in-flight
    /// read.
    pub fn publish_state_id(&mut self, state_id: StateId) {
        let mut value = self.current_control();
        debug_assert!(value.finalize_version & 1 == 0, "publish inside a write window");
        value.state_id = Some(state_id);
        // Single producer; `write` also handles the never-written 0→2 case.
        self.inner.write(&value);
    }

    /// Open the finalize write window: the published finalize counter goes
    /// (and stays) odd, so optimistic readers spin until the [`WriteGuard`]
    /// drops. The guard's drop writes the staged control word — even counter
    /// plus any bundle staged via [`WriteGuard::set_state_id`] — closing the
    /// window in one seqlock write.
    pub fn write(&mut self) -> WriteGuard<'_> {
        // Stage from the current control; pre-publish (never-written) windows
        // stage the default — its `None` still reads as "no state yet" if the
        // window closes before the first publish.
        let mut value = self.current_control();
        debug_assert!(value.finalize_version & 1 == 0, "nested finalize write window");
        // Crossbeam-style writer begin: publish the odd counter, then a
        // Release fence so the state mutations behind the guard can't hoist
        // above it.
        value.finalize_version += 1;
        self.inner.write(&value);
        sync::atomic::fence(Ordering::Release);

        // Stage the even close; lands at guard drop.
        value.finalize_version += 1;
        WriteGuard { beacon_state: self.state.get_mut(), value, inner: &self.inner }
    }

    pub fn reader(&self) -> BeaconStateReader {
        BeaconStateReader { state: self.state.clone(), inner: self.inner.clone() }
    }
}

/// Cross-thread optimistic reader handle. `Send`/`Sync` fall out of
/// `StateCell: Sync` — the `Arc` keeps the allocation alive for as long as
/// any reader exists, so no teardown-order invariant remains.
#[derive(Clone)]
pub struct BeaconStateReader {
    state: Arc<StateCell>,
    inner: Arc<Seqlock<ControlInner>>,
}

impl BeaconStateReader {
    /// Current published finalize counter; `None` if never written.
    fn finalize_version(&self) -> Option<u64> {
        self.inner.read_copy().ok().map(|(control, _)| control.finalize_version)
    }

    /// Performs optimistic reads from the beacon state, this will loop if the
    /// finalized state is updated during a read — concurrent publishes leave
    /// the read standing (the bundle's data is append-only until the next
    /// finalize). Returns `None` until the writer publishes its first real
    /// snapshot.
    ///
    /// Lock-free path: only the fixed-size bases (epoch/slot scalars, the
    /// inline eth1 vote list, validators columns, balances/participation/
    /// inactivity boxes) are safe to read optimistically. The pending /
    /// longtail bases are realloc-prone `Vec`s — reading their CONTENT here
    /// can race a finalize realloc; those reads need the lock-guarded path.
    pub fn read<F, R>(&self, reader: &F) -> Option<R>
    where
        F: Fn(StateReadView<'_>) -> R,
    {
        loop {
            // `Err(Empty)` = never written; `state_id: None` = a pre-publish
            // finalize window closed — both mean no snapshot yet.
            let Ok((control, _)) = self.inner.read_copy() else { return None };
            if control.finalize_version & 1 == 1 {
                // Finalize window open: wait it out.
                std::hint::spin_loop();
                continue;
            }
            let state_id = control.state_id?;
            sync::atomic::fence(Ordering::Acquire);
            let result = reader(self.state.get().read_view(state_id));

            // Validate: no finalize ran while we were reading the state.
            sync::atomic::fence(Ordering::Acquire);
            if self.finalize_version() == Some(control.finalize_version) {
                return Some(result);
            }
        }
    }

    /// Open a checkpoint cursor over the finalized base. `None` until the
    /// writer publishes its first snapshot (nothing to persist). Feed the
    /// cursor to [`Self::checkpoint_chunk`] to pull the SSZ out part by part.
    pub fn begin_checkpoint(&self) -> Option<CheckpointCursor> {
        let (control, _) = self.inner.read_copy().ok()?;
        control.state_id?;
        let mut cursor = CheckpointCursor::default();
        self.capture_checkpoint(&mut cursor);
        Some(cursor)
    }

    /// Copy the next checkpoint part into `buf` (cleared first) and advance
    /// the cursor. Synchronization is internal: the part is encoded, the
    /// seqlock version is re-checked, and torn bytes are re-encoded — `buf`
    /// only ever holds bytes consistent with the cursor's captured state. A
    /// superseding finalize is waited out and reported as `Restarted` (cursor
    /// back at the first part, on the NEWER finalized state) — the caller
    /// drops what it wrote so far and keeps stepping.
    pub fn checkpoint_chunk(
        &self,
        cursor: &mut CheckpointCursor,
        buf: &mut Vec<u8>,
    ) -> io::Result<CheckpointChunk> {
        loop {
            // A finalize landed (or its window is open): wait it out, restart.
            // Publishes keep the counter — they don't disturb the checkpoint.
            if self.finalize_version() != Some(cursor.version) {
                self.capture_checkpoint(cursor);
                return Ok(CheckpointChunk::Restarted);
            }
            if cursor.done {
                return Ok(CheckpointChunk::Done);
            }

            let state = self.state.get();
            buf.clear();
            let pubkeys_stage = cursor.section >= CHECKPOINT_SECTIONS;
            let complete = if pubkeys_stage {
                state.write_pubkeys_chunk(cursor.chunk, buf)?
            } else {
                state.write_section_chunk(
                    Section::ALL[cursor.section],
                    cursor.chunk,
                    &cursor.offsets,
                    buf,
                )?
            };

            // Validate before handing out: bytes encoded across a finalize
            // are torn — loop (the version mismatch branch restarts).
            sync::atomic::fence(Ordering::Acquire);
            if self.finalize_version() != Some(cursor.version) {
                continue;
            }

            if pubkeys_stage {
                cursor.done = complete;
                cursor.chunk += 1;
                return Ok(CheckpointChunk::Pubkeys);
            }
            if complete {
                cursor.section += 1;
                cursor.chunk = 0;
            } else {
                cursor.chunk += 1;
            }
            return Ok(CheckpointChunk::Ssz);
        }
    }

    /// (Re)capture a consistent `(version, slot, offsets)` snapshot into the
    /// cursor and reset its position, waiting out an open finalize window.
    fn capture_checkpoint(&self, cursor: &mut CheckpointCursor) {
        loop {
            // Post-`begin_checkpoint` the control is always written.
            let Some(version) = self.finalize_version() else { continue };
            if version & 1 == 1 {
                // Finalize window open: wait it out.
                std::hint::spin_loop();
                continue;
            }
            sync::atomic::fence(Ordering::Acquire);
            let state = self.state.get();
            let lens = state.var_len_section_lens();
            let slot = state.slot_states.finalized().state().slot;
            sync::atomic::fence(Ordering::Acquire);
            if self.finalize_version() == Some(version) {
                *cursor = CheckpointCursor {
                    version,
                    slot,
                    offsets: BeaconState::offsets_from_lens(&lens),
                    section: 0,
                    chunk: 0,
                    done: false,
                };
                return;
            }
        }
    }
}

/// Which part [`BeaconStateReader::checkpoint_chunk`] just produced.
pub enum CheckpointChunk {
    /// `buf` holds the next slice of the canonical state SSZ.
    Ssz,
    /// `buf` holds the next slice of the decompressed-pubkeys sidecar.
    Pubkeys,
    /// A finalize superseded the snapshot: `buf` is untouched, the cursor is
    /// back at the first part (of the newer state) — drop the output written
    /// so far and keep stepping.
    Restarted,
    /// Everything has been produced.
    Done,
}

/// Position + consistency token for a chunked checkpoint read: which part
/// comes next, and the finalize counter every produced byte must agree with.
/// Plain data — all the synchronization lives in
/// [`BeaconStateReader::checkpoint_chunk`].
#[derive(Default)]
pub struct CheckpointCursor {
    version: u64,
    slot: u64,
    offsets: [u32; VAR_LEN_SECTIONS],
    // Section index; pubkeys stage once past `CHECKPOINT_SECTIONS`.
    section: usize,
    // Chunk index within `section` — only validators/pubkeys span >1.
    chunk: usize,
    done: bool,
}

impl CheckpointCursor {
    /// The finalized slot being persisted (names the output files). Advances
    /// on `Restarted` — read it again at commit time.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Index of the section the next chunk comes from
    /// (`0..CHECKPOINT_SECTIONS`, canonical SSZ order); `None` once in the
    /// pubkeys stage. Diagnostics only.
    pub fn section_index(&self) -> Option<usize> {
        (self.section < CHECKPOINT_SECTIONS).then_some(self.section)
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
        debug_assert!(self.value.finalize_version & 1 == 0, "staged close must be even");
        // Order the window's state mutations before the closing control write.
        sync::atomic::fence(Ordering::Release);
        // One seqlock write lands the staged bundle and the even counter
        // together — readers never resolve re-anchored tiers through a stale
        // bundle, and spinners resume with the new head.
        self.inner.write(&self.value);
    }
}

/// The control word: the published head's per-tier index bundle plus the
/// finalize counter (odd = finalize window open). Publishes rewrite
/// `state_id` but keep the counter — tiers are append-only between
/// finalizations, so a publish never invalidates an in-flight read; only the
/// finalize window (which rebases and frees tier slots) does. `Default`
/// exists only because `Seqlock::default()` requires it; readers treat
/// `state_id: None` (only reachable when a finalize window closes before the
/// first publish) as "no state yet" — every publish writes `Some`.
#[derive(Clone, Copy, Default)]
struct ControlInner {
    state_id: Option<StateId>,
    finalize_version: u64,
}
