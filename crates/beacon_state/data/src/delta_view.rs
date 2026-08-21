use blst::min_pk::PublicKey;

use crate::{
    BalancesReader, BalancesWriteView, BlockRoots, BuildersView, BuildersWriteView, Current,
    EpochId, EpochView, Eth1View, Eth1WriteView, InactivityView, InactivityWriteView, LongtailId,
    LongtailView, ParticipationView, ParticipationWriteView, PendingView, PendingWriteView,
    Previous, RandaoMixesView, RandaoMixesWriteView, RootsView, RootsWriteView, SlashingsView,
    SlashingsWriteView, SlotStateView, SlotStateWriteView, StateRoots, ValidatorsView,
    ValidatorsWriteView, Withdrawals,
    types::{BLSPubkey, Immutable, StateId},
};

/// Per-tier read-view bundle over a fork at a published slot id, for the
/// **writer thread's own** reads (gossip validation, head recompute): no
/// `&mut`, no seqlock (synchronous self-read; the cross-thread lock-free path
/// is `BeaconStateReader::read`, which hands out the same type). Pure field
/// holder — consumers read through the tier views directly.
pub struct StateReadView<'a> {
    pub imm: &'a Immutable,
    /// Writer-side column readers (carry the SSZ list root for full-state
    /// hashing) — balances, participation and inactivity alike.
    pub balances: BalancesReader<'a>,
    pub eth1: Eth1View<'a>,
    /// Base + the fork's delta when it owns one, else the lazy base view.
    pub epoch: EpochView<'a>,
    /// Same lazy resolution as `epoch`.
    pub longtail: LongtailView<'a>,
    pub pending: PendingView<'a>,
    pub previous_participation: ParticipationView<'a, Previous>,
    pub current_participation: ParticipationView<'a, Current>,
    pub inactivity: InactivityView<'a>,
    pub slashings: SlashingsView<'a>,
    pub block_roots: RootsView<'a, BlockRoots>,
    pub state_roots: RootsView<'a, StateRoots>,
    pub randao_mixes: RandaoMixesView<'a>,
    pub slot: SlotStateView<'a>,
    pub validators: ValidatorsView<'a>,
    pub builders: BuildersView<'a>,
}

/// Holder of a fork's per-slot tier writers (by value) — what the STF takes.
/// The epoch/longtail tiers are NOT here: they roll only at epoch / rotation
/// boundaries, so they travel as `&mut EpochGroup` / `&mut LongtailGroup`
/// alongside, and their inherited ids ride as plain data next to the holder.
/// [`Self::commit`] finishes the block, assembling the fork's index bundle.
pub struct StateWriterView<'a> {
    pub imm: &'a Immutable,
    pub balances: BalancesWriteView<'a>,
    pub eth1: Eth1WriteView<'a>,
    pub pending: PendingWriteView<'a>,
    pub previous_participation: ParticipationWriteView<'a, Previous>,
    pub current_participation: ParticipationWriteView<'a, Current>,
    pub inactivity: InactivityWriteView<'a>,
    pub slashings: SlashingsWriteView<'a>,
    pub block_roots: RootsWriteView<'a, BlockRoots>,
    pub state_roots: RootsWriteView<'a, StateRoots>,
    pub randao_mixes: RandaoMixesWriteView<'a>,
    pub slot: SlotStateWriteView<'a>,
    pub validators: ValidatorsWriteView<'a>,
    pub builders: BuildersWriteView<'a>,
}

impl<'a> StateReadView<'a> {
    #[inline]
    pub fn is_gloas(&self) -> bool {
        self.epoch.is_gloas(self.imm.gloas_fork_version)
    }
}

impl<'a> StateWriterView<'a> {
    /// Append a validator across the lockstep tiers (registry + balances +
    /// participation + inactivity all grow together so every column stays the
    /// same length). New validator → balance/participation/inactivity 0.
    /// Returns the new validator index.
    #[inline]
    pub fn append_validator(
        &mut self,
        pubkey: BLSPubkey,
        pubkey_decompressed: PublicKey,
        credentials: Withdrawals,
    ) -> u32 {
        let idx = self.validators.append(pubkey, pubkey_decompressed, credentials);
        let bal_idx = self.balances.append_empty();
        debug_assert_eq!(idx, bal_idx, "validator/balance append indices must agree");
        let prev_idx = self.previous_participation.append_empty();
        let cur_idx = self.current_participation.append_empty();
        let inact_idx = self.inactivity.append_empty();
        debug_assert!(
            idx == prev_idx && idx == cur_idx && idx == inact_idx,
            "validator/participation/inactivity append indices must agree",
        );
        idx
    }

    pub fn adopt_gloas(&mut self) {
        self.balances.migrate_to_progressive();
        self.inactivity.migrate_to_progressive();
        self.previous_participation.migrate_to_progressive();
        self.current_participation.migrate_to_progressive();
        self.validators.adopt_gloas();
        self.pending.adopt_gloas();
    }

    #[inline]
    pub fn commit(self, epoch_idx: Option<EpochId>, longtail_idx: Option<LongtailId>) -> StateId {
        StateId {
            epoch_idx,
            longtail_idx,
            balances_idx: self.balances.commit(),
            eth1_idx: self.eth1.commit(),
            validators_idx: self.validators.commit(),
            pending_idx: self.pending.commit(),
            previous_participation_idx: self.previous_participation.commit(),
            current_participation_idx: self.current_participation.commit(),
            inactivity_idx: self.inactivity.commit(),
            slashings_idx: self.slashings.commit(),
            block_roots_idx: self.block_roots.commit(),
            state_roots_idx: self.state_roots.commit(),
            randao_mixes_idx: self.randao_mixes.commit(),
            slot_idx: self.slot.commit(),
            builders_idx: self.builders.commit(),
        }
    }

    #[inline]
    pub fn read<'s>(
        &'s mut self,
        epoch: EpochView<'s>,
        longtail: LongtailView<'s>,
    ) -> StateReadView<'s> {
        StateReadView {
            imm: self.imm,
            balances: self.balances.reader(),
            eth1: self.eth1.reader(),
            epoch,
            longtail,
            pending: self.pending.reader(),
            previous_participation: self.previous_participation.reader(),
            current_participation: self.current_participation.reader(),
            inactivity: self.inactivity.reader(),
            slashings: self.slashings.reader(),
            block_roots: self.block_roots.reader(),
            state_roots: self.state_roots.reader(),
            randao_mixes: self.randao_mixes.reader(),
            slot: self.slot.reader(),
            validators: self.validators.hashed_reader(),
            builders: self.builders.hashed_reader(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BeaconState, EpochGroup, EpochStateFinalized, LongtailGroup, PendingGroup, QueueItem,
        types::PendingDeposit, validators::ValSeed,
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
        /// Anchored state with no validators.
        fn new() -> Self {
            Self::with_validators(&[])
        }

        /// Anchored state whose registry and balances column are seeded from
        /// `seeds` (the balances column takes each seed's `balance`), anchored
        /// at `TEST_FIN_SLOT`.
        fn with_validators(seeds: &[ValSeed]) -> Self {
            let mut bs =
                BeaconState::for_test(EpochStateFinalized::default(), seeds, TEST_FIN_SLOT);
            let state_id = bs.roll_fresh();
            Self { bs, state_id }
        }

        fn view(&mut self) -> (StateWriterView<'_>, &mut EpochGroup, &mut LongtailGroup) {
            self.bs.roll_from(self.state_id)
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
            let idx = v.append_validator(pubkey, Default::default(), credentials);
            self.state_id = v.commit(sid.epoch_idx, sid.longtail_idx);
            idx
        }
    }

    #[test]
    fn balance_edit_overrides_base() {
        let seeds = [ValSeed { balance: 1_000, ..ValSeed::default() }];
        let mut state = TestState::with_validators(&seeds);
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
        let mut state = TestState::with_validators(&seeds);
        state.set_balances(&[(1, 999), (3, 333)]);
        let (v, _, _) = state.view();
        let got: Vec<u64> = (0..5).map(|i| v.balances.get(i)).collect();
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
        // Seed the finalized base with three deposits via the SSZ codec.
        let mut bytes = Vec::new();
        for i in 0..3u64 {
            deposit(i).write_ssz(&mut bytes).unwrap();
        }
        let mut group = PendingGroup::from_ssz(&bytes, &[], &[], &[]);
        let mut wv = group.roll_fresh();
        wv.deposits.drain(1);
        wv.deposits.push(deposit(99));

        let r = wv.reader();
        assert_eq!(r.deposits.len(), 3);
        assert_eq!(r.deposits.get(0).amount, 1);
        assert_eq!(r.deposits.get(1).amount, 2);
        assert_eq!(r.deposits.get(2).amount, 99);
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
            let (mut view, epoch, longtail) = state.view();
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
        let (mut view, epoch, longtail) = state.view();
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
        let (mut view, epoch, longtail) = state.view();
        let got: Vec<Withdrawals> = view
            .read(epoch.view_opt(sid.epoch_idx), longtail.view_opt(sid.longtail_idx))
            .validators
            .iter_credentials()
            .collect();
        assert_eq!(got, vec![base_creds_0, edited_base, appended_creds_0, edited_appended]);
    }
}
