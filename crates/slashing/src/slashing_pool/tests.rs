use silver_beacon_state_data::{
    BeaconState, EpochStateFinalized, Fork, SLOTS_PER_EPOCH, StateId, StateReadView,
    StateWriterView, ValSeed, Withdrawals,
};

use super::*;

const EPOCH: Epoch = 10;
const GWEI_PER_ETH: u64 = 1_000_000_000;

struct Chain {
    bs: BeaconState,
    base: StateId,
}

impl Chain {
    fn new(eth: &[u64]) -> Self {
        let seeds: Vec<_> = eth
            .iter()
            .map(|&e| ValSeed {
                effective_balance: e * GWEI_PER_ETH,
                activation_epoch: 0,
                ..Default::default()
            })
            .collect();
        let mut bs =
            BeaconState::for_test(EpochStateFinalized::default(), &seeds, EPOCH * SLOTS_PER_EPOCH);
        let base = bs.roll_fresh();
        Self { bs, base }
    }

    fn fork(&mut self, edit: impl FnOnce(&mut StateWriterView)) -> StateId {
        let (mut view, _, _) = self.bs.roll_from(self.base);
        edit(&mut view);
        view.commit(self.base.epoch_idx, self.base.longtail_idx)
    }

    fn only_slashable(&mut self, kept: u32) -> StateId {
        let count = self.view(self.base).validators.count() as u32;
        self.fork(|v| {
            for vi in (0..count).filter(|&vi| vi != kept) {
                v.validators.set_slashed(vi, true);
            }
        })
    }

    fn retiring_0_and_1_activating_2(&mut self) -> StateId {
        self.fork(|v| {
            v.validators.set_slashed(0, true);
            v.validators.set_withdrawable_epoch(1, EPOCH);
            v.validators.set_activation_epoch(2, EPOCH + 1);
        })
    }

    fn with_fork(&mut self, fork: Fork) -> StateId {
        let mut epoch = self.bs.epoch.roll_fresh();
        epoch.state_mut().fork = fork;
        StateId { epoch_idx: Some(epoch.commit()), ..self.base }
    }

    fn before_and_after_upgrade(&mut self) -> (StateId, StateId) {
        let before = Fork { previous_version: [1; 4], current_version: [2; 4], epoch: 5 };
        let after = Fork { previous_version: [2; 4], current_version: [3; 4], epoch: 9 };
        (self.with_fork(before), self.with_fork(after))
    }

    fn view(&self, id: StateId) -> StateReadView<'_> {
        self.bs.read_view(id)
    }
}

fn proposer_proof(offender: u64) -> [u8; PROPOSER_SLASHING_SIZE] {
    proposer_proof_at(offender, EPOCH)
}

fn proposer_proof_at(offender: u64, epoch: Epoch) -> [u8; PROPOSER_SLASHING_SIZE] {
    let mut ssz = [0u8; PROPOSER_SLASHING_SIZE];
    ssz[0..8].copy_from_slice(&(epoch * SLOTS_PER_EPOCH).to_le_bytes());
    ssz[8..16].copy_from_slice(&offender.to_le_bytes());
    ssz
}

/// Structurally valid SSZ; signatures and slashing conditions are not checked
/// here.
fn attester_proof(signers: [&[u32]; 2], target_epochs: [Epoch; 2]) -> Vec<u8> {
    let indexed = |signers: &[u32], target_epoch: Epoch| {
        let mut ia = vec![0u8; 228];
        ia[0..4].copy_from_slice(&228u32.to_le_bytes());
        ia[92..100].copy_from_slice(&target_epoch.to_le_bytes());
        for &vi in signers {
            ia.extend_from_slice(&(vi as u64).to_le_bytes());
        }
        ia
    };
    let first = indexed(signers[0], target_epochs[0]);
    let second = indexed(signers[1], target_epochs[1]);
    let mut ssz = Vec::new();
    ssz.extend_from_slice(&8u32.to_le_bytes());
    ssz.extend_from_slice(&(8 + first.len() as u32).to_le_bytes());
    ssz.extend(first);
    ssz.extend(second);
    assert!(AttesterSlashingView::check_size(&ssz));
    ssz
}

fn double_vote(offenders: &[u32]) -> Vec<u8> {
    attester_proof([offenders, offenders], [EPOCH; 2])
}

impl Selection {
    fn proposer_offenders(&self) -> Vec<u64> {
        let mut offenders: Vec<_> = self
            .proposer_slashings
            .as_chunks()
            .0
            .iter()
            .map(ProposerSlashingView::h1_proposer_index)
            .collect();
        offenders.sort_unstable();
        offenders
    }

    fn attester_slashing(&self) -> Option<&[u8]> {
        self.attester_slashings.get(size_of::<u32>()..)
    }
}

fn selected(pool: &SlashingPool, pre_state: &StateReadView) -> Selection {
    let mut selection = Selection::default();
    pool.select(pre_state, &mut selection);
    selection
}

#[test]
fn select_ranks_proposer_slashings_by_slashable_balance() {
    let eth: Vec<_> = (1..=MAX_PROPOSER_SLASHINGS as u64 + 4).collect();
    let chain = Chain::new(&eth);
    let head = chain.view(chain.base);
    let mut pool = SlashingPool::default();
    for vi in 0..eth.len() as u64 {
        pool.insert_proposer_slashing(&proposer_proof(vi), &head);
    }

    let selection = selected(&pool, &head);

    let richest: Vec<_> = (4..eth.len() as u64).collect();
    assert_eq!(selection.proposer_offenders(), richest);
}

#[test]
fn select_skips_offenders_the_fork_cannot_slash() {
    let mut chain = Chain::new(&[32; 4]);
    let fork = chain.retiring_0_and_1_activating_2();
    let head = chain.view(chain.base);
    let mut proposers = SlashingPool::default();
    for vi in 0..4 {
        proposers.insert_proposer_slashing(&proposer_proof(vi), &head);
    }
    let mut attesters = SlashingPool::default();
    let unslashable = double_vote(&[0, 1, 2]);
    attesters.insert_attester_slashing(&unslashable, &[0, 1, 2], &head);

    assert_eq!(selected(&proposers, &head).proposer_offenders(), [0, 1, 2, 3]);
    assert_eq!(selected(&attesters, &head).attester_slashing(), Some(&unslashable[..]));

    let fork = chain.view(fork);
    assert_eq!(selected(&proposers, &fork).proposer_offenders(), [3]);
    assert_eq!(selected(&attesters, &fork).attester_slashing(), None);
}

#[test]
fn attester_slashing_is_valued_without_proposer_slashed_offenders() {
    let chain = Chain::new(&[2048, 32, 64]);
    let head = chain.view(chain.base);
    let mut pool = SlashingPool::default();
    let with_the_whale = double_vote(&[0, 1]);
    let without = double_vote(&[2]);
    pool.insert_attester_slashing(&with_the_whale, &[0, 1], &head);
    pool.insert_attester_slashing(&without, &[2], &head);
    assert_eq!(selected(&pool, &head).attester_slashing(), Some(&with_the_whale[..]));

    pool.insert_proposer_slashing(&proposer_proof(0), &head);

    let selection = selected(&pool, &head);
    assert_eq!(selection.proposer_offenders(), [0]);
    assert_eq!(selection.attester_slashing(), Some(&without[..]));
}

#[test]
fn attester_slashing_left_slashing_nobody_is_not_selected() {
    let chain = Chain::new(&[32]);
    let head = chain.view(chain.base);
    let mut pool = SlashingPool::default();
    pool.insert_attester_slashing(&double_vote(&[0]), &[0], &head);
    assert!(selected(&pool, &head).attester_slashing().is_some());

    pool.insert_proposer_slashing(&proposer_proof(0), &head);

    assert_eq!(selected(&pool, &head).attester_slashing(), None);
}

#[test]
fn select_includes_one_proof_per_proposer() {
    let chain = Chain::new(&[32]);
    let head = chain.view(chain.base);
    let mut pool = SlashingPool::default();
    let first = proposer_proof(0);
    let mut second = first;
    second[PROPOSER_SLASHING_SIZE - 1] = 1;
    pool.insert_proposer_slashing(&first, &head);
    pool.insert_proposer_slashing(&second, &head);

    assert_eq!(selected(&pool, &head).proposer_offenders().len(), 1);
}

#[test]
fn attester_slashing_with_an_unfinalized_signer_is_refused() {
    let mut chain = Chain::new(&[32; 2]);
    let appended = chain.fork(|v| {
        v.append_validator([0xAA; 48], Default::default(), Withdrawals::default());
    });
    let head = chain.view(appended);
    let mut pool = SlashingPool::default();

    for signers in [[&[0, 2][..], &[0]], [&[0], &[0, 2]]] {
        let admission =
            pool.insert_attester_slashing(&attester_proof(signers, [EPOCH; 2]), &[0], &head);
        assert_eq!(admission, Admission::UnfinalizedSigner);
    }
    assert_eq!(selected(&pool, &head).attester_slashing(), None);

    let finalized_signers = attester_proof([&[0, 1], &[0]], [EPOCH; 2]);
    assert_eq!(pool.insert_attester_slashing(&finalized_signers, &[0], &head), Admission::Stored);
}

#[test]
fn select_skips_proofs_whose_signing_version_the_fork_changed() {
    let mut chain = Chain::new(&[64, 48, 32]);
    let (head, upgraded) = chain.before_and_after_upgrade();
    let (head, upgraded) = (chain.view(head), chain.view(upgraded));
    let mut proposers = SlashingPool::default();
    proposers.insert_proposer_slashing(&proposer_proof_at(0, 3), &head);
    proposers.insert_proposer_slashing(&proposer_proof_at(1, 7), &head);
    let mut attesters = SlashingPool::default();
    let second_stale = attester_proof([&[0], &[0]], [7, 3]);
    let first_stale = attester_proof([&[1], &[1]], [EPOCH, 7]);
    let fresh = attester_proof([&[2], &[2]], [7, 7]);
    attesters.insert_attester_slashing(&second_stale, &[0], &head);
    attesters.insert_attester_slashing(&first_stale, &[1], &head);
    attesters.insert_attester_slashing(&fresh, &[2], &head);

    assert_eq!(selected(&proposers, &head).proposer_offenders(), [0, 1]);
    assert_eq!(selected(&attesters, &head).attester_slashing(), Some(&second_stale[..]));

    assert_eq!(selected(&proposers, &upgraded).proposer_offenders(), [1]);
    assert_eq!(selected(&attesters, &upgraded).attester_slashing(), Some(&fresh[..]));
}

#[test]
fn full_proposer_pool_replaces_its_least_valuable_proof() {
    let eth: Vec<_> = (1..=PROPOSER_SLASHINGS_CAPACITY as u64 + 2).collect();
    let richest = eth.len() as u64 - 1;
    let mut chain = Chain::new(&eth);
    let only_1_slashable = chain.only_slashable(1);
    let only_richest_slashable = chain.only_slashable(richest as u32);
    let mut pool = SlashingPool::default();
    let head = chain.view(chain.base);
    for vi in 1..=PROPOSER_SLASHINGS_CAPACITY as u64 {
        assert_eq!(pool.insert_proposer_slashing(&proposer_proof(vi), &head), Admission::Stored);
    }
    assert_eq!(selected(&pool, &chain.view(only_1_slashable)).proposer_offenders(), [1]);

    let cheaper = proposer_proof(0);
    let as_cheap = proposer_proof(1);
    let richer = proposer_proof(richest);
    assert_eq!(pool.insert_proposer_slashing(&cheaper, &head), Admission::Dropped);
    assert_eq!(pool.insert_proposer_slashing(&as_cheap, &head), Admission::Dropped);
    assert_eq!(pool.insert_proposer_slashing(&richer, &head), Admission::Replaced);

    assert!(selected(&pool, &chain.view(only_1_slashable)).proposer_slashings.is_empty());
    let survivors = selected(&pool, &chain.view(only_richest_slashable));
    assert_eq!(survivors.proposer_offenders(), [richest]);
}

#[test]
fn full_attester_pool_replaces_its_least_valuable_proof() {
    let eth: Vec<_> = (1..=ATTESTER_SLASHINGS_CAPACITY as u64 + 2).collect();
    let richest = eth.len() as u32 - 1;
    let mut chain = Chain::new(&eth);
    let only_1_slashable = chain.only_slashable(1);
    let only_richest_slashable = chain.only_slashable(richest);
    let mut pool = SlashingPool::default();
    let head = chain.view(chain.base);
    for vi in 1..=ATTESTER_SLASHINGS_CAPACITY as u32 {
        let admission = pool.insert_attester_slashing(&double_vote(&[vi]), &[vi], &head);
        assert_eq!(admission, Admission::Stored);
    }
    let least = double_vote(&[1]);
    assert_eq!(
        selected(&pool, &chain.view(only_1_slashable)).attester_slashing(),
        Some(&least[..])
    );

    let richer = double_vote(&[richest]);
    assert_eq!(pool.insert_attester_slashing(&double_vote(&[0]), &[0], &head), Admission::Dropped);
    assert_eq!(pool.insert_attester_slashing(&least, &[1], &head), Admission::Dropped);
    assert_eq!(pool.insert_attester_slashing(&richer, &[richest], &head), Admission::Replaced);

    assert_eq!(selected(&pool, &chain.view(only_1_slashable)).attester_slashing(), None);
    let survivor = selected(&pool, &chain.view(only_richest_slashable));
    assert_eq!(survivor.attester_slashing(), Some(&richer[..]));
}

#[test]
fn prune_drops_proposer_slashings_no_descendant_can_include() {
    let mut chain = Chain::new(&[32; 4]);
    let finalized = chain.retiring_0_and_1_activating_2();
    let mut pool = SlashingPool::default();
    let head = chain.view(chain.base);
    for vi in 0..4 {
        pool.insert_proposer_slashing(&proposer_proof(vi), &head);
    }

    pool.prune(&head);
    assert_eq!(selected(&pool, &head).proposer_offenders(), [0, 1, 2, 3]);

    pool.prune(&chain.view(finalized));
    assert_eq!(selected(&pool, &head).proposer_offenders(), [2, 3]);
}

#[test]
fn prune_drops_attester_slashings_whose_offenders_all_retired() {
    let mut chain = Chain::new(&[32, 64, 32, 32]);
    let finalized = chain.retiring_0_and_1_activating_2();
    let mut pool = SlashingPool::default();
    let head = chain.view(chain.base);
    let retired = double_vote(&[0, 1]);
    let pending_activation = double_vote(&[0, 2]);
    pool.insert_attester_slashing(&retired, &[0, 1], &head);
    pool.insert_attester_slashing(&pending_activation, &[0, 2], &head);

    pool.prune(&head);
    assert_eq!(selected(&pool, &head).attester_slashing(), Some(&retired[..]));

    pool.prune(&chain.view(finalized));
    assert_eq!(selected(&pool, &head).attester_slashing(), Some(&pending_activation[..]));
}

#[test]
fn prune_keeps_proofs_signed_after_the_finalized_state_upgrades() {
    let mut chain = Chain::new(&[32, 32]);
    let (finalized, head) = chain.before_and_after_upgrade();
    let (finalized, head) = (chain.view(finalized), chain.view(head));
    let mut proposers = SlashingPool::default();
    proposers.insert_proposer_slashing(&proposer_proof_at(0, EPOCH), &head);
    let mut attesters = SlashingPool::default();
    let upgraded = attester_proof([&[1], &[1]], [EPOCH; 2]);
    attesters.insert_attester_slashing(&upgraded, &[1], &head);

    proposers.prune(&finalized);
    attesters.prune(&finalized);

    assert_eq!(selected(&proposers, &head).proposer_offenders(), [0]);
    assert_eq!(selected(&attesters, &head).attester_slashing(), Some(&upgraded[..]));
}
