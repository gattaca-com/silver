use blst::min_pk::PublicKey;

use crate::{
    BalancesReader, BalancesWriteView, Current, EpochId, EpochView, InactivityView,
    InactivityWriteView, LongtailId, LongtailView, ParticipationView, ParticipationWriteView,
    PendingView, PendingWriteView, Previous, SlotStateView, SlotStateWriteView, ValidatorsView,
    ValidatorsWriteView, Withdrawals,
    types::{B256, BLSPubkey, Epoch, Immutable, SLOTS_PER_EPOCH, StateId},
};

/// Per-tier read-view bundle over a fork at a published slot id, for the
/// **writer thread's own** reads (gossip validation, head recompute): no
/// `&mut`, no seqlock (synchronous self-read; the cross-thread lock-free path
/// is `BeaconStateReader::read`, which hands out the same type). Pure field
/// holder — consumers read through the tier views directly.
pub struct StateReadView<'a> {
    pub imm: &'a Immutable,
    /// Writer-side reader (carries the SSZ list root for full-state hashing).
    pub balances: BalancesReader<'a>,
    /// Base + the fork's delta when it owns one, else the lazy base view.
    pub epoch: EpochView<'a>,
    /// Same lazy resolution as `epoch`.
    pub longtail: LongtailView<'a>,
    pub pending: PendingView<'a>,
    pub previous_participation: ParticipationView<'a, Previous>,
    pub current_participation: ParticipationView<'a, Current>,
    pub inactivity: InactivityView<'a>,
    pub slot: SlotStateView<'a>,
    pub validators: ValidatorsView<'a>,
}

/// All scalar per-validator columns merged at one index, yielded by
/// [`iter_validator_rows`]. Passes read only the fields they need; the unused
/// ones cost a cursor advance, no allocation.
#[derive(Clone, Copy)]
pub struct ValidatorRow {
    pub effective_balance: u64,
    pub balance: u64,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
    pub slashed: bool,
    pub previous_participation: u8,
    pub current_participation: u8,
    pub inactivity_score: u64,
}

// The base+delta merge for the cross-tier reads (validator rows, the
// circular-buffer rings hashed by `hash_tree_root_state`) lives here as free
// fns over the individual tier read views, so a leaf can call them with the
// subset of views it holds.

/// Merged per-validator row over all scalar columns, in validator-index order.
/// `validators`/`balances` are the tier readers; participation + inactivity are
/// read through their writers (`&self`, no standalone read view). Zero-alloc.
pub fn iter_validator_rows<'v>(
    validators: ValidatorsView<'v>,
    balances: BalancesReader<'v>,
    previous_participation: &'v ParticipationWriteView<'_, Previous>,
    current_participation: &'v ParticipationWriteView<'_, Current>,
    inactivity: &'v InactivityWriteView<'_>,
) -> impl Iterator<Item = ValidatorRow> + 'v {
    let total = validators.count();
    let mut effective_balance = validators.iter_effective_balances();
    let mut balance = balances.iter();
    let mut elig = validators.iter_activation_eligibility_epochs();
    let mut act = validators.iter_activation_epochs();
    let mut exit = validators.iter_exit_epochs();
    let mut withdr = validators.iter_withdrawable_epochs();
    let mut slashed = validators.iter_slashed();
    let mut prev_p = previous_participation.iter();
    let mut curr_p = current_participation.iter();
    let mut inact = inactivity.iter();
    (0..total).map(move |_| ValidatorRow {
        effective_balance: effective_balance.next().unwrap(),
        balance: balance.next().unwrap(),
        activation_eligibility_epoch: elig.next().unwrap(),
        activation_epoch: act.next().unwrap(),
        exit_epoch: exit.next().unwrap(),
        withdrawable_epoch: withdr.next().unwrap(),
        slashed: slashed.next().unwrap(),
        previous_participation: prev_p.next().unwrap(),
        current_participation: curr_p.next().unwrap(),
        inactivity_score: inact.next().unwrap(),
    })
}

/// Merged `randao_mixes` ring. Overlays per-completed-epoch delta entries
/// (written to both `e % EHV` and `(e+1) % EHV`), then substitutes the
/// per-block accumulator at the current epoch's bucket. `epoch`/`slot` are the
/// tier read views.
pub fn effective_randao_mixes_into(
    epoch: &EpochView<'_>,
    slot: &SlotStateView<'_>,
    out: &mut Vec<B256>,
) {
    out.clear();
    out.extend_from_slice(epoch.finalized_randao_mixes());
    let cap = out.len();
    let fin_epoch = (slot.base_state().slot / SLOTS_PER_EPOCH) as usize;
    for (k, m) in epoch.delta_randao_mixes().iter().enumerate() {
        let e = fin_epoch + k;
        out[e % cap] = *m;
        out[(e + 1) % cap] = *m;
    }
    let current_idx = (slot.state().slot / SLOTS_PER_EPOCH) as usize % cap;
    out[current_idx] = slot.state().randao_mix_current;
}

/// Merged `slashings` ring. Overlays per-completed-epoch delta entries
/// (`e % SV` = running total, `(e+1) % SV` = 0 reset), then folds the
/// in-progress epoch's accumulator at the current bucket.
pub fn effective_slashings_into(
    epoch: &EpochView<'_>,
    slot: &SlotStateView<'_>,
    out: &mut Vec<u64>,
) {
    out.clear();
    out.extend_from_slice(epoch.finalized_slashings());
    let cap = out.len();
    let fin_epoch = (slot.base_state().slot / SLOTS_PER_EPOCH) as usize;
    for (k, s) in epoch.delta_slashings().iter().enumerate() {
        let e = fin_epoch + k;
        out[e % cap] = *s;
        out[(e + 1) % cap] = 0;
    }
    // `current_epoch_slashings` caches the *full* current-bucket value, so it
    // replaces the bucket rather than adding to the stale finalized snapshot.
    let current = (slot.state().slot / SLOTS_PER_EPOCH) as usize % cap;
    out[current] = slot.state().current_epoch_slashings;
}

/// `randao_mix(epoch)` with the epoch-delta overlay; the circular-buffer
/// offset comes from the slot tier's finalized base.
pub fn randao_mix_at_epoch(epoch: &EpochView<'_>, slot: &SlotStateView<'_>, e: Epoch) -> B256 {
    let fin_epoch = slot.base_state().slot / SLOTS_PER_EPOCH;
    epoch.randao_mix_at_epoch(e, fin_epoch)
}

/// Append a validator across the lockstep tiers (registry + balances +
/// participation + inactivity all grow together so every column stays the same
/// length). New validator → balance/participation/inactivity 0. Returns the
/// new validator index.
#[inline]
pub fn append_validator(
    view: &mut StateWriterView<'_>,
    pubkey: BLSPubkey,
    pubkey_decompressed: PublicKey,
    credentials: Withdrawals,
) -> u32 {
    let idx = view.validators.append(pubkey, pubkey_decompressed, credentials);
    let bal_idx = view.balances.append(0);
    debug_assert_eq!(idx, bal_idx, "validator/balance append indices must agree");
    let prev_idx = view.previous_participation.append();
    let cur_idx = view.current_participation.append();
    let inact_idx = view.inactivity.append();
    debug_assert!(
        idx == prev_idx && idx == cur_idx && idx == inact_idx,
        "validator/participation/inactivity append indices must agree",
    );
    idx
}

/// Holder of a fork's per-slot tier writers (by value) — what the STF takes.
/// The epoch/longtail tiers are NOT here: they roll only at epoch / rotation
/// boundaries, so they travel as `&mut EpochGroup` / `&mut LongtailGroup`
/// alongside, and their inherited ids ride as plain data next to the holder.
/// [`Self::commit`] finishes the block, assembling the fork's index bundle.
pub struct StateWriterView<'a> {
    pub imm: &'a Immutable,
    pub balances: BalancesWriteView<'a>,
    pub pending: PendingWriteView<'a>,
    pub previous_participation: ParticipationWriteView<'a, Previous>,
    pub current_participation: ParticipationWriteView<'a, Current>,
    pub inactivity: InactivityWriteView<'a>,
    pub slot: SlotStateWriteView<'a>,
    pub validators: ValidatorsWriteView<'a>,
}

impl<'a> StateWriterView<'a> {
    /// Finish the block: consume every held writer and assemble the fork's
    /// index bundle (for `publish_state_id`) — ids exist only from here on,
    /// so publication happens publish-last. The boundary tiers' ids come from
    /// the caller (inherited from the parent or committed at a boundary roll).
    #[inline]
    pub fn commit(self, epoch_idx: Option<EpochId>, longtail_idx: Option<LongtailId>) -> StateId {
        StateId {
            epoch_idx,
            longtail_idx,
            balances_idx: self.balances.commit(),
            validators_idx: self.validators.commit(),
            pending_idx: self.pending.commit(),
            previous_participation_idx: self.previous_participation.commit(),
            current_participation_idx: self.current_participation.commit(),
            inactivity_idx: self.inactivity.commit(),
            slot_idx: self.slot.commit(),
        }
    }

    /// Hand out a read-only [`StateReadView`] over the same fork — mirrors
    /// `BalancesWriteView::reader`. The boundary tiers are the caller's
    /// resolved views (`group.view_opt(idx)`) — resolution stays at
    /// the hub, which knows when a boundary may have re-rolled them.
    #[inline]
    pub fn read<'s>(
        &'s self,
        epoch: EpochView<'s>,
        longtail: LongtailView<'s>,
    ) -> StateReadView<'s> {
        StateReadView {
            imm: self.imm,
            balances: self.balances.reader(),
            epoch,
            longtail,
            pending: self.pending.reader(),
            previous_participation: self.previous_participation.reader(),
            current_participation: self.current_participation.reader(),
            inactivity: self.inactivity.reader(),
            slot: self.slot.reader(),
            validators: self.validators.reader(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BalancesGroup, BeaconState, CurrentParticipationGroup, EpochGroup, EpochStateFinalized,
        InactivityScoresGroup, LongtailGroup, LongtailState, PendingGroup, PendingQueues,
        PreviousParticipationGroup, SlotStateFinalized, SlotStateGroup, ValidatorsGroup,
        types::{PendingDeposit, SLOTS_PER_HISTORICAL_ROOT, SlotState},
        validators::{FinalizedValidators, ValSeed},
    };

    /// Finalized slot the test harness anchors at (lives in the slot group's
    /// base).
    const TEST_FIN_SLOT: u64 = 100;

    /// `BeaconState` + its working bundle for unit tests; `view()` rolls a
    /// fresh fork off the bundle like production `apply_block_view` (which
    /// can't be reused here: it asserts a non-empty validator set, which
    /// doesn't fit these hand-crafted, often zero-validator cases). Mutations
    /// persist only through `commit` + `state_id` writeback ([`Self::mutate`]).
    struct TestState {
        bs: BeaconState,
        state_id: StateId,
    }

    impl TestState {
        /// Anchored state with no validators and empty balances.
        fn new() -> Self {
            Self::seeded(&[], &[])
        }

        /// Anchored state whose validator registry is seeded from `seeds` and
        /// balances are empty.
        fn with_validators(seeds: &[ValSeed]) -> Self {
            Self::seeded(seeds, &[])
        }

        /// Anchored state with the validator registry seeded from `seeds` and
        /// balances seeded to `balances` (sized to the validator capacity).
        fn seeded(seeds: &[ValSeed], balances: &[u64]) -> Self {
            let validators = ValidatorsGroup::new(FinalizedValidators::with_validators(seeds));
            let cap = validators.base().capacity();
            let n = seeds.len();
            // The sibling lists stay lockstep with the validator registry, so
            // seed their finalized counts to `n` too (balances default to zero
            // when no explicit seed is given).
            let seed_balances = if balances.is_empty() { vec![0u64; n] } else { balances.to_vec() };
            let balance_bytes: Vec<u8> =
                seed_balances.iter().flat_map(|v| v.to_le_bytes()).collect();
            let zero_flags = vec![0u8; n];
            let zero_scores = vec![0u8; n * 8];
            let zero_roots = || vec![[0u8; 32]; SLOTS_PER_HISTORICAL_ROOT].into_boxed_slice();
            let mut bs = BeaconState {
                immutable: Immutable::default(),
                validators,
                balances: BalancesGroup::new(cap, n, &balance_bytes).unwrap(),
                pending: PendingGroup::new(PendingQueues::default()),
                previous_participation: PreviousParticipationGroup::new(cap, n, &zero_flags)
                    .unwrap(),
                current_participation: CurrentParticipationGroup::new(cap, n, &zero_flags).unwrap(),
                inactivity: InactivityScoresGroup::new(cap, n, &zero_scores).unwrap(),
                slot_states: SlotStateGroup::new(SlotStateFinalized::from_parts(
                    SlotState { slot: TEST_FIN_SLOT, ..Default::default() },
                    zero_roots(),
                    zero_roots(),
                )),
                epoch: EpochGroup::new(EpochStateFinalized::default()),
                longtail: LongtailGroup::new(LongtailState::default()),
            };
            let state_id = bs.roll_fresh();
            Self { bs, state_id }
        }

        fn view(&mut self) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
            let sid = self.state_id;
            let bs = &mut self.bs;
            let view = StateWriterView {
                imm: &bs.immutable,
                balances: bs.balances.roll_from(sid.balances_idx),
                pending: bs.pending.roll_from(sid.pending_idx),
                previous_participation: bs
                    .previous_participation
                    .roll_from(sid.previous_participation_idx),
                current_participation: bs
                    .current_participation
                    .roll_from(sid.current_participation_idx),
                inactivity: bs.inactivity.roll_from(sid.inactivity_idx),
                slot: bs.slot_states.roll_from(sid.slot_idx),
                validators: bs.validators.roll_from(sid.validators_idx),
            };
            (view, &mut bs.epoch, &mut bs.longtail)
        }

        /// Roll → mutate → commit → write the new bundle back: the production
        /// apply-block cycle.
        fn mutate(&mut self, f: impl FnOnce(&mut StateWriterView<'_>)) {
            let sid = self.state_id;
            let (mut v, _, _) = self.view();
            f(&mut v);
            self.state_id = v.commit(sid.epoch_idx, sid.longtail_idx);
        }

        fn set_balances(&mut self, changes: &[(u32, u64)]) {
            self.mutate(|v| v.balances.set_many(changes));
        }

        /// Cross-tier lockstep append via the free-fn helper, as production
        /// does.
        fn append(&mut self, pubkey: BLSPubkey, credentials: Withdrawals) -> u32 {
            let sid = self.state_id;
            let (mut v, _, _) = self.view();
            let idx = append_validator(&mut v, pubkey, Default::default(), credentials);
            self.state_id = v.commit(sid.epoch_idx, sid.longtail_idx);
            idx
        }
    }

    #[test]
    fn balance_edit_overrides_base() {
        let seeds = [ValSeed { balance: 1_000, ..ValSeed::default() }];
        let mut state = TestState::seeded(&seeds, &[1_000]);
        {
            let (v, _, _) = state.view();
            assert_eq!(v.balances.get(0), 1_000);
        }

        state.set_balances(&[(0, 2_500)]);
        let (v, _, _) = state.view();
        assert_eq!(v.balances.get(0), 2_500);
    }

    // Spec defaults for a freshly-registered validator
    // (pre-deposit-processing, i.e. after `append_validator` but before
    // STF set_* follow-ups). Per consensus-spec `get_validator_from_deposit`:
    //   - balance / effective_balance / inactivity_score / participation: 0
    //   - {activation, exit, activation_eligibility, withdrawable}_epoch:
    //     FAR_FUTURE_EPOCH
    //   - slashed: false
    //   - pubkey / withdrawal_credentials come from the appended record.
    #[test]
    fn appended_validator_uses_delta_pubkey_and_defaults() {
        let pk = [7u8; 48];
        let creds = Withdrawals([0x42; 32]);
        let mut state = TestState::new();
        state.append(pk, creds);

        let (v, _, _) = state.view();

        // identity (from the appended record)
        assert_eq!(*v.validators.pubkey(0), pk);
        assert_eq!(*v.validators.credentials(0), creds);

        // numeric defaults: 0
        assert_eq!(v.balances.get(0), 0);
        assert_eq!(v.validators.effective_balance(0), 0);
        assert_eq!(v.inactivity.get(0), 0);
        assert_eq!(v.current_participation.get(0), 0);
        assert_eq!(v.previous_participation.get(0), 0);

        // epoch sentinels: FAR_FUTURE_EPOCH = u64::MAX
        assert_eq!(v.validators.activation_epoch(0), u64::MAX);
        assert_eq!(v.validators.exit_epoch(0), u64::MAX);
        assert_eq!(v.validators.activation_eligibility_epoch(0), u64::MAX);
        assert_eq!(v.validators.withdrawable_epoch(0), u64::MAX);

        // boolean defaults
        assert!(!v.validators.is_slashed(0));
    }

    #[test]
    fn iter_balances_merges_in_order() {
        let seeds: Vec<ValSeed> =
            (0..5u64).map(|i| ValSeed { balance: i * 100, ..ValSeed::default() }).collect();
        let bals: Vec<u64> = seeds.iter().map(|s| s.balance).collect();
        let mut state = TestState::seeded(&seeds, &bals);
        state.set_balances(&[(1, 999), (3, 333)]);
        let (v, _, _) = state.view();
        let got: Vec<u64> = v.balances.iter().collect();
        assert_eq!(got, vec![0, 999, 200, 333, 400]);
    }

    #[test]
    fn pending_deposits_drain_then_appended() {
        let deposit = |amount| PendingDeposit {
            pubkey: [0; 48],
            withdrawal_credentials: Default::default(),
            amount,
            signature: [0; 96],
            slot: 0,
        };
        let mut base = PendingQueues::default();
        for i in 0..3u64 {
            base.pending_deposits.push(deposit(i));
        }
        let mut group = PendingGroup::new(base);
        let mut wv = group.roll_fresh();
        wv.drain_pending_deposits(1);
        wv.push_pending_deposit(deposit(99));

        assert_eq!(wv.pending_deposits_len(), 3);
        assert_eq!(wv.pending_deposit(0).amount, 1);
        assert_eq!(wv.pending_deposit(1).amount, 2);
        assert_eq!(wv.pending_deposit(2).amount, 99);
    }

    #[test]
    fn find_by_pubkey_hits_base_index_then_appended() {
        let pk_a = [0xA; 48];
        let pk_b = [0xB; 48];
        let seeds = [ValSeed { pubkey: pk_a, ..ValSeed::default() }];
        let mut state = TestState::with_validators(&seeds);
        state.append(pk_b, Default::default());

        let (v, _, _) = state.view();
        assert_eq!(v.validators.find_by_pubkey(&pk_a), Some(0));
        assert_eq!(v.validators.find_by_pubkey(&pk_b), Some(1));
        assert_eq!(v.validators.find_by_pubkey(&[0xC; 48]), None);
    }

    #[test]
    fn set_slashed_round_trips() {
        let mut state = TestState::with_validators(&[ValSeed::default()]);

        {
            let (v, _, _) = state.view();
            assert!(!v.validators.is_slashed(0));
        }
        state.mutate(|v| v.validators.set_slashed(0, true));
        {
            let (v, _, _) = state.view();
            assert!(v.validators.is_slashed(0));
        }

        state.mutate(|v| v.validators.set_slashed(0, false));
        let (v, _, _) = state.view();
        assert!(!v.validators.is_slashed(0));
    }

    #[test]
    fn append_validator_returns_idx_and_grows_count() {
        let seeds = [ValSeed::default(), ValSeed::default()];
        let mut state = TestState::with_validators(&seeds);

        {
            let sid = state.state_id;
            let (view, epoch, longtail) = state.view();
            assert_eq!(
                view.read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx))
                    .validators
                    .count(),
                2
            );
        }
        let pk = [0xFA; 48];
        let new_idx = state.append(pk, Default::default());
        assert_eq!(new_idx, 2);
        state.mutate(|v| v.validators.set_activation_epoch(2, 7));

        let (v, _, _) = state.view();
        assert_eq!(v.validators.count(), 3);
        assert_eq!(*v.validators.pubkey(2), pk);
        assert_eq!(v.validators.activation_epoch(2), 7);
    }

    /// Regression test for the `iter_*` slicing fix. The four epoch iterators
    /// must return `FAR_FUTURE_EPOCH` (u64::MAX) for an appended-no-edit
    /// validator, not the zero-init slot from the base `Box<[T]>`.
    /// Earlier impl passed the full Box to `sweep`, so the `i < base.len()`
    /// branch always fired and read 0 instead of the `appended_default`.
    /// `balances().iter()` etc. happen to coincide (0 == default) but
    /// the four epoch iterators have `FAR_FUTURE_EPOCH` default; if the
    /// slicing breaks, those return 0.
    #[test]
    fn iter_epoch_fields_yield_far_future_for_appended_no_edit() {
        let seeds = [ValSeed::default(), ValSeed::default()];
        let mut state = TestState::with_validators(&seeds);

        // Append two validators with no follow-up set_*. They should appear
        // in the iterators with FAR_FUTURE_EPOCH for all four epoch fields.
        state.append([0x11; 48], Default::default());
        state.append([0x22; 48], Default::default());

        let sid = state.state_id;
        let (view, epoch, longtail) = state.view();
        let validators = view
            .read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx))
            .validators;
        assert_eq!(validators.count(), 4);

        let acts: Vec<u64> = validators.iter_activation_epochs().collect();
        let exits: Vec<u64> = validators.iter_exit_epochs().collect();
        let withdrs: Vec<u64> = validators.iter_withdrawable_epochs().collect();
        let eligs: Vec<u64> = validators.iter_activation_eligibility_epochs().collect();

        assert_eq!(acts[..2], [u64::MAX, u64::MAX]);
        assert_eq!(exits[..2], [u64::MAX, u64::MAX]);
        assert_eq!(withdrs[..2], [u64::MAX, u64::MAX]);
        assert_eq!(eligs[..2], [u64::MAX, u64::MAX]);

        // Appended validators — these are what the fix matters for. Without
        // base slicing they'd read 0 from the zero-init Box slot.
        assert_eq!(acts[2..], [u64::MAX, u64::MAX]);
        assert_eq!(exits[2..], [u64::MAX, u64::MAX]);
        assert_eq!(withdrs[2..], [u64::MAX, u64::MAX]);
        assert_eq!(eligs[2..], [u64::MAX, u64::MAX]);
    }

    // ---- iter_validator_credentials ----

    /// `iter_validator_credentials` has a unique impl (not via `sweep`)
    /// because appended validators' credentials live on the validators delta's
    /// appended records, not at a constant default. Verify the four cases:
    ///   - base validator, no edit → fin's `val_withdrawal_credentials`
    ///   - base validator, with edit → the edit value
    ///   - appended validator, no edit → the appended record's credentials
    ///   - appended validator, with edit → the edit value
    #[test]
    fn iter_validator_credentials_covers_all_cases() {
        let base_creds_0 = Withdrawals([0xA1; 32]);
        let base_creds_1 = Withdrawals([0xA2; 32]);
        let seeds =
            [ValSeed { withdrawal_credentials: base_creds_0, ..ValSeed::default() }, ValSeed {
                withdrawal_credentials: base_creds_1,
                ..ValSeed::default()
            }];
        let mut state = TestState::with_validators(&seeds);

        // Append two with distinct credentials at construction.
        let appended_creds_0 = Withdrawals([0xB1; 32]);
        let appended_creds_1 = Withdrawals([0xB2; 32]);
        state.append([0x11; 48], appended_creds_0);
        state.append([0x22; 48], appended_creds_1);

        // Edit base[1] and appended[3] (absolute idx 3).
        let edited_base = Withdrawals([0xCC; 32]);
        let edited_appended = Withdrawals([0xDD; 32]);
        state.mutate(|v| v.validators.set_credentials(1, edited_base));
        state.mutate(|v| v.validators.set_credentials(3, edited_appended));

        let sid = state.state_id;
        let (view, epoch, longtail) = state.view();
        let got: Vec<Withdrawals> = view
            .read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx))
            .validators
            .iter_credentials()
            .collect();
        assert_eq!(got, vec![base_creds_0, edited_base, appended_creds_0, edited_appended]);
    }
}
