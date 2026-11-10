use crate::{
    BalancesReader, BlockRoots, BuildersView, Current, EpochReadView, InactivityView,
    LongtailReadView, ParticipationView, Previous, RandaoMixesView, RootsView, SlashingsView,
    SlotStateView, StateRoots, ValidatorsView,
    tree::{BuildersHash, TreeView, ValidatorsHash},
    types::Immutable,
};

/// The optimistic reader surface excludes collections whose allocations can be
/// freed during a read. Owner-side reads use [`StateView`](crate::StateView) to
/// access those collections.
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn eth1(reader: &BeaconStateReader) {
///     reader.read(|view| view.eth1.iter().count());
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn pending(reader: &BeaconStateReader) {
///     reader.read_pinned(reader.pin().unwrap(), |view| view.pending.deposits.len());
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn increments(reader: &BeaconStateReader) {
///     reader.read(|view| view.epoch.increments().get(0));
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn historical_summary(reader: &BeaconStateReader) {
///     reader.read(|view| view.longtail.historical_summary(0));
/// }
/// ```
///
/// ```compile_fail
/// # use silver_beacon_state_data::BeaconStateReader;
/// fn longtail_state(reader: &BeaconStateReader) {
///     reader.read(|view| view.longtail.state().clone());
/// }
/// ```
///
/// Helpers that inspect pending queues also require the owner-side view.
///
/// ```compile_fail
/// # use silver_beacon_state_data::{BeaconStateReader, BuilderRegistry};
/// fn builder_withdrawals(reader: &BeaconStateReader) {
///     reader.read(|view| BuilderRegistry::of_reader(&view).pending_balance_to_withdraw(0));
/// }
/// ```
pub struct StateReadView<'a> {
    pub imm: &'a Immutable,
    pub balances: BalancesReader<'a>,
    pub epoch: EpochReadView<'a>,
    pub longtail: LongtailReadView<'a>,
    pub previous_participation: ParticipationView<'a, Previous>,
    pub current_participation: ParticipationView<'a, Current>,
    pub inactivity: InactivityView<'a>,
    pub slashings: SlashingsView<'a>,
    pub block_roots: RootsView<'a, BlockRoots>,
    pub state_roots: RootsView<'a, StateRoots>,
    pub randao_mixes: RandaoMixesView<'a>,
    pub slot: SlotStateView<'a>,
    pub validators: ValidatorsView<'a>,
    pub validators_hash: TreeView<'a, ValidatorsHash>,
    pub builders: BuildersView<'a>,
    pub builders_hash: TreeView<'a, BuildersHash>,
}

impl StateReadView<'_> {
    #[inline]
    pub fn is_gloas(&self) -> bool {
        self.epoch.is_gloas(self.imm.gloas_fork_version)
    }
}
