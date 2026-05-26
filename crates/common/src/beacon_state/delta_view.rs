use blst::min_pk::PublicKey;

use crate::{
    Withdrawals,
    beacon_state::{
        buffer::{DeltaBuffer, RollResult},
        types::{
            B256, BLSPubkey, BalancesDelta, BeaconBlockHeader, CurrentParticipationDelta,
            EPOCHS_RING_N, Epoch, EpochState, EpochStateDelta, EpochStateFinalised, Eth1Data,
            ExecutionPayloadHeader, FAR_FUTURE_EPOCH, Finalised, FinalisedBalances,
            FinalisedCurrentParticipation, FinalisedInactivityScores,
            FinalisedPreviousParticipation, HistoricalSummary, InactivityScoresDelta,
            LONGTAILS_RING_N, LongtailState, PendingConsolidation, PendingDeposit,
            PendingPartialWithdrawal, PreviousParticipationDelta, SLOTS_PER_EPOCH, Slot,
            StateDelta,
        },
    },
};

impl StateDelta {
    #[inline]
    pub fn epoch_delta<'a>(
        &self,
        epochs: &'a DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
    ) -> Option<&'a EpochStateDelta> {
        self.epoch_idx.map(|seq| epochs.get(seq))
    }

    #[inline]
    pub fn longtail_delta<'a>(
        &self,
        longtails: &'a DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
    ) -> Option<&'a LongtailState> {
        self.longtail_idx.map(|seq| longtails.get(seq))
    }
}

/// Merged read + write handle on a per-fork delta against the finalised
/// base. Read methods take `&self`; write methods take `&mut self`. Field
/// disjointness lets the borrow checker thread reads through &mut borrows
/// without an intermediate `view()` reborrow.
pub struct StateDeltaView<'a> {
    delta: &'a mut StateDelta,
    fin: &'a Finalised,

    epochs: &'a mut DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
    longtails: &'a mut DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
}

impl<'a> StateDeltaView<'a> {
    #[inline]
    pub fn new(
        fin: &'a Finalised,
        delta: &'a mut StateDelta,
        epochs: &'a mut DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
        longtails: &'a mut DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
    ) -> Self {
        debug_assert_eq!(
            delta.validators.base_cnt,
            fin.validators.validator_cnt(),
            "delta.base_cnt must mirror fin.validator_cnt",
        );
        Self { fin, delta, epochs, longtails }
    }

    #[inline]
    pub fn slot(&self) -> Slot {
        self.delta.slot.slot.slot
    }

    #[inline]
    pub fn current_epoch(&self) -> Epoch {
        self.delta.slot.slot.slot / SLOTS_PER_EPOCH
    }

    #[inline]
    pub fn finalised_slot(&self) -> Slot {
        self.fin.slot.slot.slot
    }

    #[inline]
    pub fn finalised_epoch(&self) -> Epoch {
        self.fin.slot.slot.slot / SLOTS_PER_EPOCH
    }

    #[inline]
    pub fn epoch_state(&self) -> &EpochState {
        self.delta_epoch().map(|d| &d.state).unwrap_or(&self.fin.epoch.state)
    }

    #[inline]
    pub fn randao_mix_current(&self) -> B256 {
        self.delta.slot.slot.randao_mix_current
    }

    #[inline]
    pub fn current_epoch_slashings(&self) -> u64 {
        self.delta.slot.slot.current_epoch_slashings
    }

    #[inline]
    pub fn eth1_data(&self) -> Eth1Data {
        self.delta.slot.slot.eth1_data
    }

    #[inline]
    pub fn eth1_votes(&self) -> &[Eth1Data] {
        self.delta.slot.slot.eth1_votes.as_slice()
    }

    #[inline]
    pub fn eth1_deposit_index(&self) -> u64 {
        self.delta.slot.slot.eth1_deposit_index
    }

    #[inline]
    pub fn latest_block_header(&self) -> BeaconBlockHeader {
        self.delta.slot.slot.latest_block_header
    }

    #[inline]
    pub fn latest_execution_payload_header(&self) -> &ExecutionPayloadHeader {
        &self.delta.slot.slot.latest_execution_payload_header
    }

    #[inline]
    pub fn next_withdrawal_index(&self) -> u64 {
        self.delta.slot.slot.next_withdrawal_index
    }

    #[inline]
    pub fn next_withdrawal_validator_index(&self) -> u64 {
        self.delta.slot.slot.next_withdrawal_validator_index
    }

    #[inline]
    pub fn deposit_requests_start_index(&self) -> u64 {
        self.delta.slot.slot.deposit_requests_start_index
    }

    #[inline]
    pub fn exit_balance_to_consume(&self) -> u64 {
        self.delta.slot.slot.exit_balance_to_consume
    }

    #[inline]
    pub fn earliest_exit_epoch(&self) -> Epoch {
        self.delta.slot.slot.earliest_exit_epoch
    }

    #[inline]
    pub fn consolidation_balance_to_consume(&self) -> u64 {
        self.delta.slot.slot.consolidation_balance_to_consume
    }

    #[inline]
    pub fn earliest_consolidation_epoch(&self) -> Epoch {
        self.delta.slot.slot.earliest_consolidation_epoch
    }

    /// Bundled because BLS sig verification needs
    /// all four together.
    #[inline]
    pub fn fork_descriptor(&self) -> (Epoch, [u8; 4], [u8; 4], B256) {
        let f = &self.fin.immutable.fork;
        (f.epoch, f.previous_version, f.current_version, self.fin.immutable.genesis_validators_root)
    }

    #[inline]
    pub fn genesis_time(&self) -> u64 {
        self.fin.immutable.genesis_time
    }

    #[inline]
    pub fn genesis_validators_root(&self) -> B256 {
        self.fin.immutable.genesis_validators_root
    }

    #[inline]
    pub fn genesis_fork_version(&self) -> [u8; 4] {
        self.fin.immutable.genesis_fork_version
    }

    #[inline]
    pub fn capella_fork_version(&self) -> [u8; 4] {
        self.fin.immutable.capella_fork_version
    }

    #[inline]
    pub fn historical_roots_hash(&self) -> B256 {
        self.fin.immutable.historical_roots_hash
    }

    /// Look up a validator index in the *finalised* pubkey index only,
    /// ignoring `delta.appended`. Used by sync-committee rebuild: the
    /// committee's pubkeys were committed at a prior boundary so the
    /// lookup is intentionally scoped to the finalised registry.
    #[inline]
    pub fn validator_by_finalised_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        self.fin.validators.find_by_pubkey(pk).map(|i| i as u32)
    }

    #[inline]
    pub fn block_root_at_slot(&self, slot: Slot) -> B256 {
        let slot_delta = &self.delta.slot;
        let slot_finalised = &self.fin.slot;

        let fin_slot = slot_finalised.slot.slot;
        if slot >= fin_slot {
            let i = (slot - fin_slot) as usize;
            if i < slot_delta.block_roots.len() {
                return slot_delta.block_roots[i];
            }
        }
        slot_finalised.block_roots[slot as usize % slot_finalised.block_roots.len()]
    }

    #[inline]
    pub fn state_root_at_slot(&self, slot: Slot) -> B256 {
        let slot_delta = &self.delta.slot;
        let slot_finalised = &self.fin.slot;

        let fin_slot = slot_finalised.slot.slot;
        if slot >= fin_slot {
            let i = (slot - fin_slot) as usize;
            if i < slot_delta.state_roots.len() {
                return slot_delta.state_roots[i];
            }
        }
        slot_finalised.state_roots[slot as usize % slot_finalised.state_roots.len()]
    }

    /// `randao_mix(epoch)` with delta overlay. Convention: delta entry `k` is
    /// the final mix for epoch `fin_epoch + k`, stored at circular-buffer
    /// position `(fin_epoch + k) % EHV`. Lookup walks overlay in reverse so
    /// queries for past epochs that *wrap to* a position the overlay touched
    /// (e.g. seed_lookup for future epoch wraps to small index) hit the most
    /// recent overlay entry instead of falling through to the stale base.
    pub fn randao_mix_at_epoch(&self, epoch: Epoch) -> B256 {
        let cap = self.fin.epoch.randao_mixes.len();

        if let Some(delta_epoch) = self.delta_epoch() {
            let target_pos = epoch as usize % cap;
            for (k, m) in delta_epoch.randao_mixes.iter().enumerate().rev() {
                let pos = (self.fin.epoch() as usize + k) % cap;
                if pos == target_pos {
                    return *m;
                }
            }
        }

        self.fin.epoch.randao_mixes[epoch as usize % cap]
    }

    /// Per-completed-epoch slashings sum. For the *current* (in-progress)
    /// epoch the accumulator lives in `SlotState.current_epoch_slashings`;
    /// this helper covers completed epochs only.
    pub fn slashings_at(&self, epoch: Epoch) -> u64 {
        let cap = self.fin.epoch.slashings.len();

        if let Some(delta_epoch) = self.delta_epoch() {
            let target_pos = epoch as usize % cap;
            for (k, s) in delta_epoch.slashings.iter().enumerate().rev() {
                let pos = (self.fin.epoch() as usize + k) % cap;
                if pos == target_pos {
                    return *s;
                }
            }
        }

        self.fin.epoch.slashings[epoch as usize % cap]
    }

    #[inline]
    pub fn historical_summary(&self, ix: usize) -> Option<HistoricalSummary> {
        let fin_summaries = &self.fin.longtail.historical_summaries;
        if ix < fin_summaries.len() {
            return Some(fin_summaries[ix]);
        }

        let j = ix - fin_summaries.len();

        self.delta_longtail().and_then(|d| d.historical_summaries.get(j).copied())
    }

    #[inline]
    pub fn historical_summaries_len(&self) -> usize {
        let fin = &self.fin.longtail;
        let delta = self.delta.longtail_idx;
        fin.historical_summaries.len() +
            delta.map_or(0, |seq| self.longtails.get(seq).historical_summaries.len())
    }

    #[inline]
    pub fn validators_count(&self) -> usize {
        let delta = &self.delta.validators;
        delta.base_cnt + delta.appended.len()
    }

    #[inline]
    pub fn validator_by_pubkey(&self, pk: &BLSPubkey) -> Option<u32> {
        if let Some(i) = self.fin.validators.find_by_pubkey(pk) {
            return Some(i as u32);
        }
        // Linear scan: `appended` only holds validators added since
        // finalisation (≤ MAX_DEPOSITS_PER_BLOCK × delta-span slots).
        self.delta.validators.find_by_pubkey(pk).map(|i| i as u32)
    }

    #[inline]
    pub fn validator_pubkey(&self, ix: usize) -> BLSPubkey {
        *self.delta.validators.effective_pubkey(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_pubkey_decompressed(&self, ix: usize) -> &PublicKey {
        self.delta.validators.effective_pubkey_decompressed(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_credentials(&self, ix: usize) -> Withdrawals {
        *self.delta.validators.effective_credentials(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_effective_balance(&self, ix: usize) -> u64 {
        self.delta.validators.effective_balance(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_activation_epoch(&self, ix: usize) -> Epoch {
        self.delta.validators.activation_epoch(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_exit_epoch(&self, ix: usize) -> Epoch {
        self.delta.validators.exit_epoch(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_activation_eligibility_epoch(&self, ix: usize) -> Epoch {
        self.delta.validators.activation_eligibility_epoch(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_withdrawable_epoch(&self, ix: usize) -> Epoch {
        self.delta.validators.withdrawable_epoch(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn is_validator_slashed(&self, ix: usize) -> bool {
        self.delta.validators.is_slashed(&self.fin.validators, ix as u32)
    }

    #[inline]
    pub fn validator_balance(&self, ix: usize) -> u64 {
        let base_cnt = self.delta.validators.base_cnt;
        let bd = &self.delta.balances;
        if let Some(v) = lookup_sparse(&bd.edits, ix as u32) {
            return v;
        }
        if ix < base_cnt { self.fin.balances.get(ix) } else { 0 }
    }

    #[inline]
    pub fn current_epoch_participation(&self, ix: usize) -> u8 {
        let base_cnt = self.delta.validators.base_cnt;
        let pd = &self.delta.current_participation;
        if let Some(v) = lookup_sparse(&pd.edits, ix as u32) {
            return v;
        }
        if ix < base_cnt { self.fin.current_participation.get(ix) } else { 0 }
    }

    #[inline]
    pub fn previous_epoch_participation(&self, ix: usize) -> u8 {
        let base_cnt = self.delta.validators.base_cnt;
        let pd = &self.delta.previous_participation;
        if let Some(v) = lookup_sparse(&pd.edits, ix as u32) {
            return v;
        }
        if ix < base_cnt { self.fin.previous_participation.get(ix) } else { 0 }
    }

    #[inline]
    pub fn validator_inactivity_score(&self, ix: usize) -> u64 {
        let base_cnt = self.delta.validators.base_cnt;
        let id = &self.delta.inactivity_scores;
        if let Some(v) = lookup_sparse(&id.edits, ix as u32) {
            return v;
        }
        if ix < base_cnt { self.fin.inactivity_scores.get(ix) } else { 0 }
    }

    #[inline]
    pub fn pending_deposit(&self, ix: usize) -> &PendingDeposit {
        let delta = &self.delta.pending;
        let fin = &self.fin.pending;

        let drain = delta.deposits_drain_offset as usize;
        let remaining = fin.pending_deposits.len().saturating_sub(drain);
        if ix < remaining {
            &fin.pending_deposits[drain + ix]
        } else {
            &delta.deposits_appended[ix - remaining]
        }
    }

    #[inline]
    pub fn pending_deposits_len(&self) -> usize {
        let delta = &self.delta.pending;
        let fin = &self.fin.pending;
        let drain = delta.deposits_drain_offset as usize;
        fin.pending_deposits.len().saturating_sub(drain) + delta.deposits_appended.len()
    }

    #[inline]
    pub fn pending_partial_withdrawal(&self, ix: usize) -> &PendingPartialWithdrawal {
        let delta = &self.delta.pending;
        let fin = &self.fin.pending;

        let drain = delta.partial_withdrawals_drain_offset as usize;
        let remaining = fin.pending_partial_withdrawals.len().saturating_sub(drain);
        if ix < remaining {
            &fin.pending_partial_withdrawals[drain + ix]
        } else {
            &delta.partial_withdrawals_appended[ix - remaining]
        }
    }

    #[inline]
    pub fn pending_partial_withdrawals_len(&self) -> usize {
        let delta = &self.delta.pending;
        let fin = &self.fin.pending;
        let drain = delta.partial_withdrawals_drain_offset as usize;
        fin.pending_partial_withdrawals.len().saturating_sub(drain) +
            delta.partial_withdrawals_appended.len()
    }

    #[inline]
    pub fn pending_consolidation(&self, ix: usize) -> &PendingConsolidation {
        let delta = &self.delta.pending;
        let fin = &self.fin.pending;

        let drain = delta.consolidations_drain_offset as usize;
        let remaining = fin.pending_consolidations.len().saturating_sub(drain);
        if ix < remaining {
            &fin.pending_consolidations[drain + ix]
        } else {
            &delta.consolidations_appended[ix - remaining]
        }
    }

    #[inline]
    pub fn pending_consolidations_len(&self) -> usize {
        let delta = &self.delta.pending;
        let fin = &self.fin.pending;
        let drain = delta.consolidations_drain_offset as usize;
        fin.pending_consolidations.len().saturating_sub(drain) + delta.consolidations_appended.len()
    }

    pub fn iter_validator_balances(&self) -> impl Iterator<Item = u64> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.balances.edits,
            &self.fin.balances.data[..base_cnt],
            0,
            self.validators_count(),
        )
    }

    pub fn iter_validator_effective_balances(&self) -> impl Iterator<Item = u64> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.validators.effective_balance_edits,
            &self.fin.validators.effective_balance_slice()[..base_cnt],
            0,
            self.validators_count(),
        )
    }

    pub fn iter_current_epoch_participants(&self) -> impl Iterator<Item = u8> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.current_participation.edits,
            &self.fin.current_participation.data[..base_cnt],
            0,
            self.validators_count(),
        )
    }

    pub fn iter_previous_epoch_participants(&self) -> impl Iterator<Item = u8> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.previous_participation.edits,
            &self.fin.previous_participation.data[..base_cnt],
            0,
            self.validators_count(),
        )
    }

    pub fn iter_inactivity_scores(&self) -> impl Iterator<Item = u64> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.inactivity_scores.edits,
            &self.fin.inactivity_scores.data[..base_cnt],
            0,
            self.validators_count(),
        )
    }

    pub fn iter_activation_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.validators.activation_epoch_edits,
            &self.fin.validators.activation_epoch_slice()[..base_cnt],
            FAR_FUTURE_EPOCH,
            self.validators_count(),
        )
    }

    pub fn iter_exit_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.validators.exit_epoch_edits,
            &self.fin.validators.exit_epoch_slice()[..base_cnt],
            FAR_FUTURE_EPOCH,
            self.validators_count(),
        )
    }

    /// Slashed iterator — the finalised base stores `slashed` as a packed
    /// bitset (1 bit/validator), so this can't share `sweep`'s slice-indexed
    /// path. Edits + bitset + appended-record values are walked explicitly.
    pub fn iter_slashed(&self) -> impl Iterator<Item = bool> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        let total = self.validators_count();
        let edits = &self.delta.validators.slashed_edits;
        let bitset = self.fin.validators.slashed_bitset();
        let appended = &self.delta.validators.appended;
        let mut cursor = 0usize;
        (0..total).map(move |i| {
            if cursor < edits.len() && (edits[cursor].0 as usize) == i {
                let v = edits[cursor].1;
                cursor += 1;
                v
            } else if i < base_cnt {
                bitset[i / 8] & (1u8 << (i % 8)) != 0
            } else {
                appended[i - base_cnt].slashed
            }
        })
    }

    pub fn iter_withdrawable_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.validators.withdrawable_epoch_edits,
            &self.fin.validators.withdrawable_epoch_slice()[..base_cnt],
            FAR_FUTURE_EPOCH,
            self.validators_count(),
        )
    }

    pub fn iter_activation_eligibility_epochs(&self) -> impl Iterator<Item = Epoch> + '_ {
        let base_cnt = self.delta.validators.base_cnt;
        Self::sweep(
            &self.delta.validators.activation_eligibility_epoch_edits,
            &self.fin.validators.activation_eligibility_epoch_slice()[..base_cnt],
            FAR_FUTURE_EPOCH,
            self.validators_count(),
        )
    }

    /// Appended validators' credentials live in
    /// `delta.appended[i].credentials` rather than at a constant default,
    /// so this can't reuse `sweep`.
    pub fn iter_validator_credentials(&self) -> impl Iterator<Item = Withdrawals> + '_ {
        let delta = &self.delta.validators;
        let edits = &delta.credentials_edits;
        let base = self.fin.validators.withdrawal_credentials_slice();
        let appended = &delta.appended;
        let base_cnt = delta.base_cnt;
        let total = base_cnt + appended.len();
        let mut cursor = 0usize;
        (0..total).map(move |i| {
            if cursor < edits.len() && (edits[cursor].0 as usize) == i {
                let v = edits[cursor].1;
                cursor += 1;
                v
            } else if i < base_cnt {
                base[i]
            } else {
                appended[i - base_cnt].credentials
            }
        })
    }

    fn sweep<'b, T>(
        edits: &'b [(u32, T)],
        base: &'b [T],
        appended_default: T,
        total: usize,
    ) -> impl Iterator<Item = T> + 'b
    where
        T: Copy,
    {
        let mut cursor = 0usize;
        (0..total).map(move |i| {
            if cursor < edits.len() && (edits[cursor].0 as usize) == i {
                let v = edits[cursor].1;
                cursor += 1;
                v
            } else if i < base.len() {
                base[i]
            } else {
                appended_default
            }
        })
    }

    fn delta_longtail(&self) -> Option<&LongtailState> {
        self.delta.longtail_idx.map(|seq| self.longtails.get(seq))
    }

    fn delta_epoch(&self) -> Option<&EpochStateDelta> {
        self.delta.epoch_idx.map(|seq| self.epochs.get(seq))
    }
}

impl<'a> StateDeltaView<'a> {
    #[inline]
    pub fn set_slot(&mut self, s: Slot) {
        self.delta.slot.slot.slot = s;
    }

    #[inline]
    pub fn advance_slot(&mut self) {
        self.delta.slot.slot.slot += 1;
    }

    #[inline]
    pub fn set_randao_mix_current(&mut self, m: B256) {
        self.delta.slot.slot.randao_mix_current = m;
    }

    /// XOR `reveal_hash` into the per-block randao accumulator.
    #[inline]
    pub fn xor_into_randao_mix(&mut self, reveal_hash: &[u8; 32]) {
        for (b, &r) in self.delta.slot.slot.randao_mix_current.iter_mut().zip(reveal_hash.iter()) {
            *b ^= r;
        }
    }

    #[inline]
    pub fn add_current_epoch_slashings(&mut self, amount: u64) {
        self.delta.slot.slot.current_epoch_slashings =
            self.delta.slot.slot.current_epoch_slashings.saturating_add(amount);
    }

    #[inline]
    pub fn reset_current_epoch_slashings(&mut self) {
        self.delta.slot.slot.current_epoch_slashings = 0;
    }

    #[inline]
    pub fn set_eth1_data(&mut self, d: Eth1Data) {
        self.delta.slot.slot.eth1_data = d;
    }

    #[inline]
    pub fn push_eth1_vote(&mut self, vote: Eth1Data) {
        self.delta.slot.slot.eth1_votes.push(vote);
    }

    #[inline]
    pub fn clear_eth1_votes(&mut self) {
        self.delta.slot.slot.eth1_votes.clear();
    }

    #[inline]
    pub fn advance_eth1_deposit_index(&mut self) {
        self.delta.slot.slot.eth1_deposit_index += 1;
    }

    #[inline]
    pub fn set_latest_block_header(&mut self, h: BeaconBlockHeader) {
        self.delta.slot.slot.latest_block_header = h;
    }

    /// Fill in `state_root` on the latest block header iff it's currently
    /// zero. Called from `process_slot` before computing the block root.
    #[inline]
    pub fn fill_latest_block_header_state_root(&mut self, state_root: B256) {
        if self.delta.slot.slot.latest_block_header.state_root == [0u8; 32] {
            self.delta.slot.slot.latest_block_header.state_root = state_root;
        }
    }

    #[inline]
    pub fn set_latest_execution_payload_header(&mut self, h: ExecutionPayloadHeader) {
        self.delta.slot.slot.latest_execution_payload_header = h;
    }

    #[inline]
    pub fn set_next_withdrawal_index(&mut self, x: u64) {
        self.delta.slot.slot.next_withdrawal_index = x;
    }

    #[inline]
    pub fn set_next_withdrawal_validator_index(&mut self, x: u64) {
        self.delta.slot.slot.next_withdrawal_validator_index = x;
    }

    #[inline]
    pub fn set_deposit_requests_start_index(&mut self, x: u64) {
        self.delta.slot.slot.deposit_requests_start_index = x;
    }

    #[inline]
    pub fn set_exit_balance_to_consume(&mut self, x: u64) {
        self.delta.slot.slot.exit_balance_to_consume = x;
    }

    #[inline]
    pub fn set_earliest_exit_epoch(&mut self, e: Epoch) {
        self.delta.slot.slot.earliest_exit_epoch = e;
    }

    #[inline]
    pub fn set_consolidation_balance_to_consume(&mut self, x: u64) {
        self.delta.slot.slot.consolidation_balance_to_consume = x;
    }

    #[inline]
    pub fn set_earliest_consolidation_epoch(&mut self, e: Epoch) {
        self.delta.slot.slot.earliest_consolidation_epoch = e;
    }

    #[inline]
    pub fn push_block_root(&mut self, r: B256) {
        self.delta.slot.block_roots.push(r);
    }

    #[inline]
    pub fn push_state_root(&mut self, r: B256) {
        self.delta.slot.state_roots.push(r);
    }

    #[inline]
    pub fn push_pending_deposit(&mut self, d: PendingDeposit) {
        self.delta.pending.deposits_appended.push(d);
    }

    #[inline]
    pub fn push_pending_partial_withdrawal(&mut self, w: PendingPartialWithdrawal) {
        self.delta.pending.partial_withdrawals_appended.push(w);
    }

    #[inline]
    pub fn push_pending_consolidation(&mut self, c: PendingConsolidation) {
        self.delta.pending.consolidations_appended.push(c);
    }

    /// Drop the first `n` items from the effective `pending_deposits`
    /// queue: bump drain_offset against the base, then trim appended.
    #[inline]
    pub fn drain_pending_deposits(&mut self, n: usize) {
        let base_len = self.fin.pending.pending_deposits.len();
        let already = self.delta.pending.deposits_drain_offset as usize;
        let base_remaining = base_len.saturating_sub(already);
        let from_base = n.min(base_remaining);
        self.delta.pending.deposits_drain_offset += from_base as u32;
        let from_appended = n - from_base;
        if from_appended > 0 {
            self.delta.pending.deposits_appended.drain(..from_appended);
        }
    }

    #[inline]
    pub fn drain_pending_partial_withdrawals(&mut self, n: usize) {
        let base_len = self.fin.pending.pending_partial_withdrawals.len();
        let already = self.delta.pending.partial_withdrawals_drain_offset as usize;
        let base_remaining = base_len.saturating_sub(already);
        let from_base = n.min(base_remaining);
        self.delta.pending.partial_withdrawals_drain_offset += from_base as u32;
        let from_appended = n - from_base;
        if from_appended > 0 {
            self.delta.pending.partial_withdrawals_appended.drain(..from_appended);
        }
    }

    #[inline]
    pub fn drain_pending_consolidations(&mut self, n: usize) {
        let base_len = self.fin.pending.pending_consolidations.len();
        let already = self.delta.pending.consolidations_drain_offset as usize;
        let base_remaining = base_len.saturating_sub(already);
        let from_base = n.min(base_remaining);
        self.delta.pending.consolidations_drain_offset += from_base as u32;
        let from_appended = n - from_base;
        if from_appended > 0 {
            self.delta.pending.consolidations_appended.drain(..from_appended);
        }
    }

    /// Move postponed deposits back onto the queue (called by
    /// `process_pending_deposits` to re-queue exited validators' deposits).
    #[inline]
    pub fn append_pending_deposits(&mut self, src: &mut Vec<PendingDeposit>) {
        self.delta.pending.deposits_appended.append(src);
    }

    #[inline]
    pub fn ensure_epoch_delta(&mut self) -> usize {
        self.delta.ensure_epoch_delta(self.epochs, &self.fin.epoch)
    }

    /// Mutable handle to the per-fork epoch tier scalars. Panics if
    /// `ensure_epoch_delta` hasn't been called yet on this fork.
    #[inline]
    pub fn epoch_state_mut(&mut self) -> &mut EpochState {
        let seq = self.delta.epoch_idx.expect("ensure_epoch_delta first");
        &mut self.epochs.get_mut(seq).state
    }

    /// Append a per-epoch entry to the epoch-tier `randao_mixes` log. Used
    /// by `process_randao_mixes_reset`.
    #[inline]
    pub fn push_epoch_randao_mix(&mut self, m: B256) {
        let seq = self.delta.epoch_idx.expect("ensure_epoch_delta first");
        self.epochs.get_mut(seq).randao_mixes.push(m);
    }

    /// Append a per-epoch entry to the epoch-tier `slashings` log. Used by
    /// `process_slashings_reset`.
    #[inline]
    pub fn push_epoch_slashings(&mut self, s: u64) {
        let seq = self.delta.epoch_idx.expect("ensure_epoch_delta first");
        self.epochs.get_mut(seq).slashings.push(s);
    }

    #[inline]
    pub fn ensure_longtail_delta(&mut self) -> usize {
        self.delta.ensure_longtail_delta(self.longtails, &self.fin.longtail)
    }

    #[inline]
    pub fn push_historical_summary(&mut self, h: HistoricalSummary) {
        let seq = self.delta.longtail_idx.expect("ensure_longtail_delta first");
        self.longtails.get_mut(seq).historical_summaries.push(h);
    }

    #[inline]
    pub fn set_credentials(&mut self, idx: u32, v: Withdrawals) {
        self.delta.validators.set_credentials(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn set_effective_balance(&mut self, idx: u32, v: u64) {
        self.delta.validators.set_effective_balance(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn set_activation_epoch(&mut self, idx: u32, v: Epoch) {
        self.delta.validators.set_activation_epoch(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn set_exit_epoch(&mut self, idx: u32, v: Epoch) {
        self.delta.validators.set_exit_epoch(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn set_activation_eligibility_epoch(&mut self, idx: u32, v: Epoch) {
        self.delta.validators.set_activation_eligibility_epoch(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn set_withdrawable_epoch(&mut self, idx: u32, v: Epoch) {
        self.delta.validators.set_withdrawable_epoch(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn set_slashed(&mut self, idx: u32, v: bool) {
        self.delta.validators.set_slashed(&self.fin.validators, idx, v);
    }

    #[inline]
    pub fn append_validator(
        &mut self,
        pubkey: BLSPubkey,
        pubkey_decompressed: PublicKey,
        credentials: Withdrawals,
    ) -> u32 {
        self.delta.validators.append(&self.fin.validators, pubkey, pubkey_decompressed, credentials)
    }

    #[inline]
    pub fn set_balance(&mut self, idx: u32, v: u64) {
        let base_cnt = self.delta.validators.base_cnt;
        set_balance(&mut self.delta.balances, &self.fin.balances, base_cnt, idx, v);
    }

    #[inline]
    pub fn set_current_participation(&mut self, idx: u32, v: u8) {
        let base_cnt = self.delta.validators.base_cnt;
        set_current_participation(
            &mut self.delta.current_participation,
            &self.fin.current_participation,
            base_cnt,
            idx,
            v,
        );
    }

    #[inline]
    pub fn set_previous_participation(&mut self, idx: u32, v: u8) {
        let base_cnt = self.delta.validators.base_cnt;
        set_previous_participation(
            &mut self.delta.previous_participation,
            &self.fin.previous_participation,
            base_cnt,
            idx,
            v,
        );
    }

    #[inline]
    pub fn set_inactivity_score(&mut self, idx: u32, v: u64) {
        let base_cnt = self.delta.validators.base_cnt;
        set_inactivity_score(
            &mut self.delta.inactivity_scores,
            &self.fin.inactivity_scores,
            base_cnt,
            idx,
            v,
        );
    }

    // ── Bulk replace (sibling layers only — dense epoch-boundary passes)

    #[inline]
    pub fn replace_balances<F: FnMut(usize, u64) -> u64>(
        &mut self,
        scratch: &mut Vec<(u32, u64)>,
        f: F,
    ) {
        let base_cnt = self.delta.validators.base_cnt;
        let total = base_cnt + self.delta.validators.appended.len();
        replace_balances(&mut self.delta.balances, &self.fin.balances, base_cnt, total, scratch, f);
    }

    #[inline]
    pub fn replace_inactivity_scores<F: FnMut(usize, u64) -> u64>(
        &mut self,
        scratch: &mut Vec<(u32, u64)>,
        f: F,
    ) {
        let base_cnt = self.delta.validators.base_cnt;
        let total = base_cnt + self.delta.validators.appended.len();
        replace_inactivity_scores(
            &mut self.delta.inactivity_scores,
            &self.fin.inactivity_scores,
            base_cnt,
            total,
            scratch,
            f,
        );
    }

    #[inline]
    pub fn replace_current_participation<F: FnMut(usize, u8) -> u8>(
        &mut self,
        scratch: &mut Vec<(u32, u8)>,
        f: F,
    ) {
        let base_cnt = self.delta.validators.base_cnt;
        let total = base_cnt + self.delta.validators.appended.len();
        replace_current_participation(
            &mut self.delta.current_participation,
            &self.fin.current_participation,
            base_cnt,
            total,
            scratch,
            f,
        );
    }

    #[inline]
    pub fn replace_previous_participation<F: FnMut(usize, u8) -> u8>(
        &mut self,
        scratch: &mut Vec<(u32, u8)>,
        f: F,
    ) {
        let base_cnt = self.delta.validators.base_cnt;
        let total = base_cnt + self.delta.validators.appended.len();
        replace_previous_participation(
            &mut self.delta.previous_participation,
            &self.fin.previous_participation,
            base_cnt,
            total,
            scratch,
            f,
        );
    }
}

#[inline]
fn lookup_sparse<T: Copy>(edits: &[(u32, T)], idx: u32) -> Option<T> {
    edits.binary_search_by_key(&idx, |(k, _)| *k).ok().map(|p| edits[p].1)
}

impl StateDelta {
    /// Allocate a fresh epoch ring slot for this fork iff one isn't already
    /// owned. `epoch_idx` becomes the new seq. The fresh entry has empty
    /// `randao_mixes`/`slashings` logs and inherits the scalar state from
    /// the finalised epoch.
    ///
    /// Caller is responsible for ensuring this fork's `epoch_idx` does not
    /// alias a parent fork's entry that the parent still needs.
    pub fn ensure_epoch_delta(
        &mut self,
        epochs: &mut DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
        finalised_epoch: &EpochStateFinalised,
    ) -> usize {
        if let Some(seq) = self.epoch_idx {
            return seq;
        }
        let seq = match epochs.roll(None) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        // `roll(None)` already invoked `EpochStateDelta::reset()` which clears
        // both Vec logs and resets scalars to default. Overwrite the scalar
        // tier from the finalised base; logs stay empty.
        let e = epochs.get_mut(seq);
        e.state = finalised_epoch.state;
        self.epoch_idx = Some(seq);
        seq
    }

    pub fn ensure_longtail_delta(
        &mut self,
        longtails: &mut DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
        finalised_longtail: &LongtailState,
    ) -> usize {
        if let Some(seq) = self.longtail_idx {
            return seq;
        }
        let seq = match longtails.roll(None) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        let lt = longtails.get_mut(seq);
        lt.current_sync_committee = finalised_longtail.current_sync_committee;
        lt.next_sync_committee = finalised_longtail.next_sync_committee;
        lt.sync_committee_indices = finalised_longtail.sync_committee_indices;
        // historical_summaries cleared by reset().
        self.longtail_idx = Some(seq);
        seq
    }
}

/// Sparse-vec setter — maintains the sorted-by-idx invariant. Elides
/// entries that match the base (and removes any stale edit at that idx),
/// so `sparse_set(i, base_val, base_val)` removes any prior edit at i.
#[inline]
fn sparse_set<T>(edits: &mut Vec<(u32, T)>, idx: u32, v: T, base_val: T)
where
    T: Copy + PartialEq,
{
    match edits.binary_search_by_key(&idx, |(k, _)| *k) {
        Ok(p) => {
            if v == base_val {
                edits.remove(p);
            } else {
                edits[p].1 = v;
            }
        }
        Err(p) => {
            if v != base_val {
                edits.insert(p, (idx, v));
            }
        }
    }
}

/// Bulk overwrite — single forward sweep that rebuilds a sparse edit vec
/// using a caller-supplied scratch (reused across calls; no allocation
/// after warmup). For dense epoch-boundary passes
/// (process_rewards_and_penalties, process_inactivity_updates,
/// process_participation_flag_updates). Naive per-i `sparse_set` would
/// be O(N log N) due to binary-search inserts; the sweep is
/// O(N + |edits_old|).
fn sparse_replace_with_scratch<T, F>(
    edits: &mut Vec<(u32, T)>,
    scratch: &mut Vec<(u32, T)>,
    base_slice: &[T],
    appended_default: T,
    total: usize,
    mut f: F,
) where
    T: Copy + PartialEq,
    F: FnMut(usize, T) -> T,
{
    scratch.clear();
    let mut cursor = 0usize;

    for i in 0..total {
        let cur = if cursor < edits.len() && (edits[cursor].0 as usize) == i {
            let v = edits[cursor].1;
            cursor += 1;
            v
        } else if i < base_slice.len() {
            base_slice[i]
        } else {
            appended_default
        };

        let new = f(i, cur);
        let base_val = if i < base_slice.len() { base_slice[i] } else { appended_default };
        if new != base_val {
            scratch.push((i as u32, new));
        }
    }
    std::mem::swap(edits, scratch);
}

#[inline]
pub fn set_balance(
    delta: &mut BalancesDelta,
    base: &FinalisedBalances,
    base_cnt: usize,
    idx: u32,
    v: u64,
) {
    let base_val = if (idx as usize) < base_cnt { base.get(idx as usize) } else { 0 };
    sparse_set(&mut delta.edits, idx, v, base_val);
}

#[inline]
pub fn set_previous_participation(
    delta: &mut PreviousParticipationDelta,
    base: &FinalisedPreviousParticipation,
    base_cnt: usize,
    idx: u32,
    v: u8,
) {
    let base_val = if (idx as usize) < base_cnt { base.get(idx as usize) } else { 0 };
    sparse_set(&mut delta.edits, idx, v, base_val);
}

#[inline]
pub fn set_current_participation(
    delta: &mut CurrentParticipationDelta,
    base: &FinalisedCurrentParticipation,
    base_cnt: usize,
    idx: u32,
    v: u8,
) {
    let base_val = if (idx as usize) < base_cnt { base.get(idx as usize) } else { 0 };
    sparse_set(&mut delta.edits, idx, v, base_val);
}

#[inline]
pub fn set_inactivity_score(
    delta: &mut InactivityScoresDelta,
    base: &FinalisedInactivityScores,
    base_cnt: usize,
    idx: u32,
    v: u64,
) {
    let base_val = if (idx as usize) < base_cnt { base.get(idx as usize) } else { 0 };
    sparse_set(&mut delta.edits, idx, v, base_val);
}

#[inline]
pub fn replace_balances<F>(
    delta: &mut BalancesDelta,
    base: &FinalisedBalances,
    base_cnt: usize,
    total: usize,
    scratch: &mut Vec<(u32, u64)>,
    f: F,
) where
    F: FnMut(usize, u64) -> u64,
{
    sparse_replace_with_scratch(&mut delta.edits, scratch, &base.data[..base_cnt], 0, total, f);
}

#[inline]
pub fn replace_previous_participation<F>(
    delta: &mut PreviousParticipationDelta,
    base: &FinalisedPreviousParticipation,
    base_cnt: usize,
    total: usize,
    scratch: &mut Vec<(u32, u8)>,
    f: F,
) where
    F: FnMut(usize, u8) -> u8,
{
    sparse_replace_with_scratch(&mut delta.edits, scratch, &base.data[..base_cnt], 0, total, f);
}

#[inline]
pub fn replace_current_participation<F>(
    delta: &mut CurrentParticipationDelta,
    base: &FinalisedCurrentParticipation,
    base_cnt: usize,
    total: usize,
    scratch: &mut Vec<(u32, u8)>,
    f: F,
) where
    F: FnMut(usize, u8) -> u8,
{
    sparse_replace_with_scratch(&mut delta.edits, scratch, &base.data[..base_cnt], 0, total, f);
}

#[inline]
pub fn replace_inactivity_scores<F>(
    delta: &mut InactivityScoresDelta,
    base: &FinalisedInactivityScores,
    base_cnt: usize,
    total: usize,
    scratch: &mut Vec<(u32, u64)>,
    f: F,
) where
    F: FnMut(usize, u64) -> u64,
{
    sparse_replace_with_scratch(&mut delta.edits, scratch, &base.data[..base_cnt], 0, total, f);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon_state::{
        types::{HistoricalSummary, PendingDeposit, SlotState, SlotStateDelta},
        validator_identity::ValidatorsDelta,
    };

    fn fresh_finalised() -> Box<Finalised> {
        let mut f = Box::new(Finalised::default());
        f.slot.slot.slot = 100; // arbitrary post-genesis fin slot
        f
    }

    fn anchored_delta(f: &Finalised) -> StateDelta {
        StateDelta {
            validators: ValidatorsDelta::new_at(f.validators.validator_cnt()),
            slot: SlotStateDelta {
                slot: SlotState { slot: f.slot.slot.slot, ..SlotState::default() },
                ..Default::default()
            },
            ..StateDelta::default()
        }
    }

    /// Stack-allocate two fresh DeltaBuffer rings as `let mut` bindings.
    /// Merged `StateDeltaView` takes `&mut` on rings so the OnceLock-based
    /// shared static no longer works — each test needs its own.
    macro_rules! fresh_rings {
        ($e:ident, $l:ident) => {
            let mut $e: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N> = DeltaBuffer::default();
            let mut $l: DeltaBuffer<LongtailState, LONGTAILS_RING_N> = DeltaBuffer::default();
        };
    }

    /// Roll a fresh epoch ring slot and overwrite it with `entry`.
    /// Returns the seq.
    fn populate_one_epoch(
        buf: &mut DeltaBuffer<EpochStateDelta, EPOCHS_RING_N>,
        entry: EpochStateDelta,
    ) -> usize {
        let seq = match buf.roll(None) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        *buf.get_mut(seq) = entry;
        seq
    }

    fn populate_one_longtail(
        buf: &mut DeltaBuffer<LongtailState, LONGTAILS_RING_N>,
        entry: LongtailState,
    ) -> usize {
        let seq = match buf.roll(None) {
            RollResult::Reset(s) | RollResult::Rolled(s) => s,
        };
        *buf.get_mut(seq) = entry;
        seq
    }

    fn push_default_validator(f: &mut Finalised, balance_v: u64) {
        let i = f.validators.validator_cnt();
        // Identity layer columns. `FinalisedValidators::default()` already
        // seeds `[FAR_FUTURE_EPOCH; MAX]` for the four epochs and zeros
        // elsewhere, so we only need to set the slot and bump the count.
        f.validators.pubkey_slice_mut()[i] = [0; 48];
        f.validators.pubkey_decompressed_slice_mut()[i] = Default::default();
        f.validators.withdrawal_credentials_slice_mut()[i] = Default::default();
        f.validators.set_validator_cnt(i + 1);
        // Sibling layers — only balance needs an explicit value.
        f.balances.slice_mut()[i] = balance_v;
    }

    #[test]
    fn randao_anchored_reads_base() {
        let mut f = fresh_finalised();
        let target_epoch = 4;
        let idx = target_epoch as usize % f.epoch.randao_mixes.len();
        f.epoch.randao_mixes[idx] = [0xAB; 32];

        let mut delta = anchored_delta(&f);
        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut delta, &mut epochs, &mut longtails);
        assert_eq!(view.randao_mix_at_epoch(target_epoch), [0xAB; 32]);
    }

    #[test]
    fn randao_diverged_hits_delta_then_base() {
        let mut f = fresh_finalised();
        let base_epoch = f.epoch();

        // Base value for base_epoch+1; would normally have wrapped via finalisation.
        let post_idx = (base_epoch + 1) as usize % f.epoch.randao_mixes.len();
        f.epoch.randao_mixes[post_idx] = [0x11; 32];

        // Diverged ring entry with one log entry covering base_epoch.
        let mut tile_epochs: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N> = DeltaBuffer::default();
        let mut tile_longtails: DeltaBuffer<LongtailState, LONGTAILS_RING_N> =
            DeltaBuffer::default();
        let seq = populate_one_epoch(&mut tile_epochs, EpochStateDelta {
            randao_mixes: vec![[0xCC; 32]],
            slashings: Vec::new(),
            state: f.epoch.state,
        });
        let mut delta = anchored_delta(&f);
        delta.epoch_idx = Some(seq);

        let view = StateDeltaView::new(&f, &mut delta, &mut tile_epochs, &mut tile_longtails);
        // base_epoch → delta hit
        assert_eq!(view.randao_mix_at_epoch(base_epoch), [0xCC; 32]);
        // base_epoch+1 → falls through to base
        assert_eq!(view.randao_mix_at_epoch(base_epoch + 1), [0x11; 32]);
    }

    #[test]
    fn block_root_anchored_reads_base() {
        let mut f = fresh_finalised();
        let target_slot = 50;
        let idx = target_slot as usize % f.slot.block_roots.len();
        f.slot.block_roots[idx] = [0xEE; 32];

        let mut delta = anchored_delta(&f);
        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut delta, &mut epochs, &mut longtails);
        assert_eq!(view.block_root_at_slot(target_slot), [0xEE; 32]);
    }

    #[test]
    fn block_root_diverged_hits_delta_then_base() {
        let mut f = fresh_finalised();
        let fin_slot = f.slot.slot.slot;

        let post_idx = (fin_slot + 1) as usize % f.slot.block_roots.len();
        f.slot.block_roots[post_idx] = [0x22; 32];

        let mut delta = anchored_delta(&f);
        delta.slot.block_roots.push([0xDD; 32]); // entry 0 = slot fin_slot

        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut delta, &mut epochs, &mut longtails);
        assert_eq!(view.block_root_at_slot(fin_slot), [0xDD; 32]);
        assert_eq!(view.block_root_at_slot(fin_slot + 1), [0x22; 32]);
    }

    #[test]
    fn historical_summary_base_then_delta() {
        let mut f = fresh_finalised();
        f.longtail
            .historical_summaries
            .push(HistoricalSummary { block_summary_root: [1; 32], state_summary_root: [1; 32] });
        f.longtail
            .historical_summaries
            .push(HistoricalSummary { block_summary_root: [2; 32], state_summary_root: [2; 32] });

        let mut delta = anchored_delta(&f);
        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut delta, &mut epochs, &mut longtails);
        assert_eq!(view.historical_summary(0).unwrap().block_summary_root, [1; 32]);
        assert_eq!(view.historical_summary(1).unwrap().block_summary_root, [2; 32]);
        assert!(view.historical_summary(2).is_none());
        assert_eq!(view.historical_summaries_len(), 2);
    }

    #[test]
    fn historical_summary_diverged_extends_past_base() {
        let mut f = fresh_finalised();
        f.longtail
            .historical_summaries
            .push(HistoricalSummary { block_summary_root: [1; 32], state_summary_root: [1; 32] });

        let mut tile_longtails: DeltaBuffer<LongtailState, LONGTAILS_RING_N> =
            DeltaBuffer::default();
        let mut tile_epochs: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N> = DeltaBuffer::default();
        let seq = populate_one_longtail(&mut tile_longtails, LongtailState {
            current_sync_committee: f.longtail.current_sync_committee,
            next_sync_committee: f.longtail.next_sync_committee,
            sync_committee_indices: f.longtail.sync_committee_indices,
            historical_summaries: vec![HistoricalSummary {
                block_summary_root: [3; 32],
                state_summary_root: [3; 32],
            }],
        });
        let mut delta = anchored_delta(&f);
        delta.longtail_idx = Some(seq);

        let view = StateDeltaView::new(&f, &mut delta, &mut tile_epochs, &mut tile_longtails);
        assert_eq!(view.historical_summaries_len(), 2);
        assert_eq!(view.historical_summary(0).unwrap().block_summary_root, [1; 32]);
        assert_eq!(view.historical_summary(1).unwrap().block_summary_root, [3; 32]);
    }

    #[test]
    fn balance_edit_overrides_base() {
        let mut f = fresh_finalised();
        push_default_validator(&mut f, 1_000);

        let mut d = anchored_delta(&f);
        fresh_rings!(epochs, longtails);
        {
            let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
            assert_eq!(view.validator_balance(0), 1_000);
        }

        d.balances.edits.push((0, 2_500));
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
        assert_eq!(view.validator_balance(0), 2_500);
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
        let f = fresh_finalised();
        let mut d = anchored_delta(&f);
        let pk = [7u8; 48];
        let creds = Withdrawals([0x42; 32]);
        d.validators.append(&f.validators, pk, Default::default(), creds);

        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);

        // identity (from the appended record)
        assert_eq!(view.validator_pubkey(0), pk);
        assert_eq!(view.validator_credentials(0), creds);

        // numeric defaults: 0
        assert_eq!(view.validator_balance(0), 0);
        assert_eq!(view.validator_effective_balance(0), 0);
        assert_eq!(view.validator_inactivity_score(0), 0);
        assert_eq!(view.current_epoch_participation(0), 0);
        assert_eq!(view.previous_epoch_participation(0), 0);

        // epoch sentinels: FAR_FUTURE_EPOCH = u64::MAX
        assert_eq!(view.validator_activation_epoch(0), u64::MAX);
        assert_eq!(view.validator_exit_epoch(0), u64::MAX);
        assert_eq!(view.validator_activation_eligibility_epoch(0), u64::MAX);
        assert_eq!(view.validator_withdrawable_epoch(0), u64::MAX);

        // boolean defaults
        assert!(!view.is_validator_slashed(0));
    }

    #[test]
    fn iter_balances_merges_in_order() {
        let mut f = fresh_finalised();
        for i in 0..5u64 {
            push_default_validator(&mut f, i * 100);
        }

        let mut d = anchored_delta(&f);
        d.balances.edits.push((1, 999));
        d.balances.edits.push((3, 333));
        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
        let got: Vec<u64> = view.iter_validator_balances().collect();
        assert_eq!(got, vec![0, 999, 200, 333, 400]);
    }

    #[test]
    fn pending_deposits_drain_then_appended() {
        let mut f = fresh_finalised();
        for i in 0..3u64 {
            f.pending.pending_deposits.push(PendingDeposit {
                pubkey: [0; 48],
                withdrawal_credentials: Default::default(),
                amount: i,
                signature: [0; 96],
                slot: 0,
            });
        }
        let mut d = anchored_delta(&f);
        d.pending.deposits_drain_offset = 1;
        d.pending.deposits_appended.push(PendingDeposit {
            pubkey: [0; 48],
            withdrawal_credentials: Default::default(),
            amount: 99,
            signature: [0; 96],
            slot: 0,
        });

        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
        assert_eq!(view.pending_deposits_len(), 3);
        assert_eq!(view.pending_deposit(0).amount, 1);
        assert_eq!(view.pending_deposit(1).amount, 2);
        assert_eq!(view.pending_deposit(2).amount, 99);
    }

    #[test]
    fn find_by_pubkey_hits_base_index_then_appended() {
        let mut f = fresh_finalised();
        let pk_a = [0xA; 48];
        let pk_b = [0xB; 48];
        // Insert pk_a into the finalised base directly via append.
        f.validators.append(
            &pk_a,
            &Default::default(),
            &Default::default(),
            0,
            false,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            u64::MAX,
        );

        let mut d = anchored_delta(&f);
        d.validators.append(&f.validators, pk_b, Default::default(), Default::default());

        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
        assert_eq!(view.validator_by_pubkey(&pk_a), Some(0));
        assert_eq!(view.validator_by_pubkey(&pk_b), Some(1));
        assert_eq!(view.validator_by_pubkey(&[0xC; 48]), None);
    }

    #[test]
    fn ensure_epoch_delta_is_idempotent() {
        let f = fresh_finalised();
        let mut tile_epochs: DeltaBuffer<EpochStateDelta, EPOCHS_RING_N> = DeltaBuffer::default();
        let mut d = anchored_delta(&f);

        let i1 = d.ensure_epoch_delta(&mut tile_epochs, &f.epoch);
        assert_eq!(i1, 0);
        assert_eq!(d.epoch_idx, Some(0));
        assert_eq!(tile_epochs.head(), Some(0));

        let i2 = d.ensure_epoch_delta(&mut tile_epochs, &f.epoch);
        assert_eq!(i2, 0);
        // No second roll; head still at 0.
        assert_eq!(tile_epochs.head(), Some(0));
    }

    #[test]
    fn replace_balances_elides_same_as_base() {
        let mut f = fresh_finalised();
        for i in 0..4u64 {
            push_default_validator(&mut f, i * 10);
        }

        let mut d = anchored_delta(&f);
        let mut scratch: Vec<(u32, u64)> = Vec::new();
        let base_cnt = f.validators.validator_cnt();
        let total = base_cnt; // no appended in this test
        // Even idx → base value (elided); odd idx → +1000 (kept).
        replace_balances(&mut d.balances, &f.balances, base_cnt, total, &mut scratch, |i, cur| {
            if i % 2 == 0 { cur } else { cur + 1000 }
        });
        assert_eq!(d.balances.edits, vec![(1, 1010), (3, 1030)]);
    }

    #[test]
    fn apply_delta_advances_finalised_slot() {
        let mut f = fresh_finalised();
        let mut d = anchored_delta(&f);
        d.slot.slot.slot = 105;
        d.slot.block_roots.push([0x55; 32]);

        f.apply_delta(&d, None, None);
        assert_eq!(f.slot.slot.slot, 105);
        // Entry 0 maps to slot 100 (old fin_slot).
        assert_eq!(f.slot.block_roots[100 % f.slot.block_roots.len()], [0x55; 32]);
    }

    #[test]
    fn apply_delta_appends_validator_to_base() {
        let mut f = fresh_finalised();
        let mut d = anchored_delta(&f);
        let pk = [0xFE; 48];
        d.validators.append(&f.validators, pk, Default::default(), Default::default());
        d.balances.edits.push((0, 32_000_000_000));

        f.apply_delta(&d, None, None);
        assert_eq!(f.validators.validator_cnt(), 1);
        assert_eq!(f.balances.get(0), 32_000_000_000);
        assert_eq!(f.validators.activation_epoch(0), u64::MAX);
        assert_eq!(f.validators.find_by_pubkey(&pk), Some(0));
    }

    #[test]
    fn set_balance_inserts_then_updates_then_elides() {
        let mut f = fresh_finalised();
        for _ in 0..3 {
            push_default_validator(&mut f, 1_000);
        }
        let mut d = anchored_delta(&f);

        let base_cnt = f.validators.validator_cnt();

        // Insert at idx 2.
        set_balance(&mut d.balances, &f.balances, base_cnt, 2, 2_500);
        assert_eq!(d.balances.edits, vec![(2, 2_500)]);

        // Insert at idx 0 — must land before idx 2 to keep sorted.
        set_balance(&mut d.balances, &f.balances, base_cnt, 0, 4_000);
        assert_eq!(d.balances.edits, vec![(0, 4_000), (2, 2_500)]);

        // Update in place.
        set_balance(&mut d.balances, &f.balances, base_cnt, 0, 5_000);
        assert_eq!(d.balances.edits, vec![(0, 5_000), (2, 2_500)]);

        // Setting back to base value elides the edit.
        set_balance(&mut d.balances, &f.balances, base_cnt, 0, 1_000);
        assert_eq!(d.balances.edits, vec![(2, 2_500)]);
    }

    #[test]
    fn set_slashed_round_trips() {
        let mut f = fresh_finalised();
        push_default_validator(&mut f, 0);
        let mut d = anchored_delta(&f);
        fresh_rings!(epochs, longtails);

        {
            let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
            assert!(!view.is_validator_slashed(0));
        }
        d.validators.set_slashed(&f.validators, 0, true);
        {
            let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
            assert!(view.is_validator_slashed(0));
        }
        assert_eq!(d.validators.slashed_edits, vec![(0, true)]);

        d.validators.set_slashed(&f.validators, 0, false);
        assert!(d.validators.slashed_edits.is_empty());
    }

    #[test]
    fn append_validator_returns_idx_and_grows_count() {
        let mut f = fresh_finalised();
        push_default_validator(&mut f, 0);
        push_default_validator(&mut f, 0);
        let mut d = anchored_delta(&f);
        fresh_rings!(epochs, longtails);

        {
            let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
            assert_eq!(view.validators_count(), 2);
        }
        let pk = [0xFA; 48];
        let new_idx =
            d.validators.append(&f.validators, pk, Default::default(), Default::default());
        assert_eq!(new_idx, 2);
        {
            let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
            assert_eq!(view.validators_count(), 3);
            assert_eq!(view.validator_pubkey(2), pk);
        }

        d.validators.set_activation_epoch(&f.validators, 2, 7);
        f.apply_delta(&d, None, None);
        assert_eq!(f.validators.validator_cnt(), 3);
        assert_eq!(f.validators.activation_epoch(2), 7);
    }

    /// Regression test for the `iter_*` slicing fix. The four epoch iterators
    /// must return `FAR_FUTURE_EPOCH` (u64::MAX) for an appended-no-edit
    /// validator, not the zero-init slot from the `Box<[T; MAX_VALIDATORS]>`.
    /// Earlier impl passed the full Box to `sweep`, so the `i < base.len()`
    /// branch always fired and read 0 instead of the `appended_default`.
    /// `iter_validator_balances` etc. happen to coincide (0 == default) but
    /// the four epoch iterators have `FAR_FUTURE_EPOCH` default; if the
    /// slicing breaks, those return 0.
    #[test]
    fn iter_epoch_fields_yield_far_future_for_appended_no_edit() {
        let mut f = fresh_finalised();
        push_default_validator(&mut f, 0);
        push_default_validator(&mut f, 0);
        let mut d = anchored_delta(&f);

        // Append two validators with no follow-up set_*. They should appear
        // in the iterators with FAR_FUTURE_EPOCH for all four epoch fields.
        d.validators.append(&f.validators, [0x11; 48], Default::default(), Default::default());
        d.validators.append(&f.validators, [0x22; 48], Default::default(), Default::default());

        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
        assert_eq!(view.validators_count(), 4);

        let acts: Vec<u64> = view.iter_activation_epochs().collect();
        let exits: Vec<u64> = view.iter_exit_epochs().collect();
        let withdrs: Vec<u64> = view.iter_withdrawable_epochs().collect();
        let eligs: Vec<u64> = view.iter_activation_eligibility_epochs().collect();

        // Base validators (pushed via push_default_validator with u64::MAX).
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
    /// because appended validators' credentials live in
    /// `delta.appended[i].credentials`, not at a constant default. Verify
    /// the four cases:
    ///   - base validator, no edit → fin's `val_withdrawal_credentials`
    ///   - base validator, with edit → the edit value
    ///   - appended validator, no edit → the appended record's credentials
    ///   - appended validator, with edit → the edit value
    #[test]
    fn iter_validator_credentials_covers_all_cases() {
        let mut f = fresh_finalised();
        // Two base validators with distinct credentials.
        let base_creds_0 = Withdrawals([0xA1; 32]);
        let base_creds_1 = Withdrawals([0xA2; 32]);
        push_default_validator(&mut f, 0);
        f.validators.withdrawal_credentials_slice_mut()[0] = base_creds_0;
        push_default_validator(&mut f, 0);
        f.validators.withdrawal_credentials_slice_mut()[1] = base_creds_1;

        let mut d = anchored_delta(&f);

        // Append two with distinct credentials at construction.
        let appended_creds_0 = Withdrawals([0xB1; 32]);
        let appended_creds_1 = Withdrawals([0xB2; 32]);
        d.validators.append(&f.validators, [0x11; 48], Default::default(), appended_creds_0);
        d.validators.append(&f.validators, [0x22; 48], Default::default(), appended_creds_1);

        // Edit base[1] and appended[3] (absolute idx 3).
        let edited_base = Withdrawals([0xCC; 32]);
        let edited_appended = Withdrawals([0xDD; 32]);
        d.validators.set_credentials(&f.validators, 1, edited_base);
        d.validators.set_credentials(&f.validators, 3, edited_appended);

        fresh_rings!(epochs, longtails);
        let view = StateDeltaView::new(&f, &mut d, &mut epochs, &mut longtails);
        let got: Vec<Withdrawals> = view.iter_validator_credentials().collect();
        assert_eq!(got, vec![base_creds_0, edited_base, appended_creds_0, edited_appended]);
    }

    /// `apply_delta` with an epoch_entry must:
    ///   - overlay `randao_mixes[k]` into the finalised ring at `(old_fin_epoch
    ///     + k) % EPOCHS_PER_HISTORICAL_VECTOR`
    ///   - overlay `slashings[k]` into the finalised slashings ring at
    ///     `(old_fin_epoch + k) % EPOCHS_PER_SLASHINGS_VECTOR`
    ///   - replace `epoch.state` with the entry's `state` scalar block
    #[test]
    fn apply_delta_overlays_epoch_tier() {
        let mut f = fresh_finalised();
        let old_fin_slot = f.slot.slot.slot;
        let old_fin_epoch = old_fin_slot / SLOTS_PER_EPOCH;
        let hv = f.epoch.randao_mixes.len();
        let sv = f.epoch.slashings.len();

        // Plant baseline values to confirm they get overwritten where
        // delta entries land.
        f.epoch.randao_mixes[old_fin_epoch as usize % hv] = [0x01; 32];
        f.epoch.randao_mixes[(old_fin_epoch as usize + 1) % hv] = [0x02; 32];
        f.epoch.slashings[old_fin_epoch as usize % sv] = 100;
        f.epoch.slashings[(old_fin_epoch as usize + 1) % sv] = 200;

        let mut d = anchored_delta(&f);
        d.slot.slot.slot = old_fin_slot + 2 * SLOTS_PER_EPOCH; // crossed 2 epoch boundaries
        // apply_delta asserts epoch_entry.is_some() ↔ delta.epoch_idx.is_some();
        // value isn't read further so any seq works for the test.
        d.epoch_idx = Some(0);

        // Build an epoch delta entry with two completed-epoch log entries
        // and a new scalar state.
        let mut new_state = f.epoch.state;
        new_state.justification_bits = 0x0F;
        new_state.deposit_balance_to_consume = 999;
        let entry = EpochStateDelta {
            randao_mixes: vec![[0xAA; 32], [0xBB; 32]],
            slashings: vec![123, 456],
            state: new_state,
        };

        f.apply_delta(&d, Some(&entry), None);

        // Ring overlay landed.
        assert_eq!(f.epoch.randao_mixes[old_fin_epoch as usize % hv], [0xAA; 32]);
        assert_eq!(f.epoch.randao_mixes[(old_fin_epoch as usize + 1) % hv], [0xBB; 32]);
        assert_eq!(f.epoch.slashings[old_fin_epoch as usize % sv], 123);
        assert_eq!(f.epoch.slashings[(old_fin_epoch as usize + 1) % sv], 456);

        // Scalar state replaced.
        assert_eq!(f.epoch.state.justification_bits, 0x0F);
        assert_eq!(f.epoch.state.deposit_balance_to_consume, 999);
    }

    /// `apply_delta` with a longtail_entry must rotate sync committees and
    /// **extend** historical_summaries (not replace — the entry holds only
    /// the post-finalisation appends).
    #[test]
    fn apply_delta_overlays_longtail_tier() {
        let mut f = fresh_finalised();
        // Pre-existing historical summary on the finalised base.
        f.longtail
            .historical_summaries
            .push(HistoricalSummary { block_summary_root: [1; 32], state_summary_root: [1; 32] });

        let mut d = anchored_delta(&f);
        // apply_delta asserts longtail_entry.is_some() ↔ delta.longtail_idx.is_some().
        d.longtail_idx = Some(0);

        // Longtail delta entry: new sync committees + one new historical summary.
        let mut new_current = f.longtail.current_sync_committee;
        new_current.pubkeys[0] = [0x77; 48];
        let mut new_next = f.longtail.next_sync_committee;
        new_next.pubkeys[0] = [0x88; 48];
        let mut indices = f.longtail.sync_committee_indices;
        indices[0] = 42;

        let entry = LongtailState {
            current_sync_committee: new_current,
            next_sync_committee: new_next,
            sync_committee_indices: indices,
            historical_summaries: vec![HistoricalSummary {
                block_summary_root: [2; 32],
                state_summary_root: [2; 32],
            }],
        };

        f.apply_delta(&d, None, Some(&entry));

        // Sync committees rotated.
        assert_eq!(f.longtail.current_sync_committee.pubkeys[0], [0x77; 48]);
        assert_eq!(f.longtail.next_sync_committee.pubkeys[0], [0x88; 48]);
        assert_eq!(f.longtail.sync_committee_indices[0], 42);

        // Historical summaries extended (base entry kept, delta entry appended).
        assert_eq!(f.longtail.historical_summaries.len(), 2);
        assert_eq!(f.longtail.historical_summaries[0].block_summary_root, [1; 32]);
        assert_eq!(f.longtail.historical_summaries[1].block_summary_root, [2; 32]);
    }
}
