use silver_beacon_state_data::{SLOTS_PER_EPOCH, StateReadView};

use crate::shuffling;

// Constants are deliberately the *pre-MaxEB* ones: the period's derivation
// assumes a 32-ETH per-validator cap and count-based churn, and has not been
// re-derived for EIP-7251. `MAX_EB_ETH` is therefore 32 — not the runtime
// 2048-ETH `MAX_EFFECTIVE_BALANCE` — matching the spec-as-written and other
// clients. A known approximation under MaxEB.
const SAFETY_DECAY: u64 = 10;
const MIN_WITHDRAWABILITY_DELAY: u64 = 256;
const MAX_EB_ETH: u64 = 32;
const ETH_TO_GWEI: u64 = 1_000_000_000;
const MAX_DEPOSITS: u64 = 16;
const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 4;
const CHURN_LIMIT_QUOTIENT: u64 = 1 << 16;

pub(crate) fn weak_subjectivity_period(view: &StateReadView, scratch: &mut Vec<u32>) -> u64 {
    let epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    scratch.clear();
    shuffling::get_active_validator_indices_into(&view.validators, epoch, scratch);
    let n = scratch.len() as u64;
    if n == 0 {
        return MIN_WITHDRAWABILITY_DELAY;
    }

    // get_total_active_balance, floored at one increment, averaged to whole ETH.
    let total = scratch
        .iter()
        .map(|&i| view.validators.effective_balance(i as usize))
        .sum::<u64>()
        .max(ETH_TO_GWEI);
    let d = SAFETY_DECAY;
    let t = total / n / ETH_TO_GWEI;
    let cap = MAX_EB_ETH;
    let delta = (n / CHURN_LIMIT_QUOTIENT).max(MIN_PER_EPOCH_CHURN_LIMIT);
    let big_delta = MAX_DEPOSITS * SLOTS_PER_EPOCH;

    let mut ws = MIN_WITHDRAWABILITY_DELAY;
    // On the else side the branch guarantees `t <= cap*(200+3d)/(200+12d) < cap`,
    // so `cap - t > 0` (no div-by-zero) and the subtraction above never wraps.
    if cap * (200 + 3 * d) < t * (200 + 12 * d) {
        let churn = n * (t * (200 + 12 * d) - cap * (200 + 3 * d)) / (600 * delta * (2 * t + cap));
        let top_ups = n * (200 + 3 * d) / (600 * big_delta);
        ws += churn.max(top_ups);
    } else {
        ws += 3 * n * d * t / (200 * big_delta * (cap - t));
    }
    ws
}
