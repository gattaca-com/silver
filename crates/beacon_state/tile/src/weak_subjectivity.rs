use silver_beacon_state_data::{SLOTS_PER_EPOCH, SpecConfig, StateReadView};

use crate::{shuffling, stf::EFFECTIVE_BALANCE_INCREMENT};

const SAFETY_DECAY: u64 = 10;
const MIN_WITHDRAWABILITY_DELAY: u64 = 256;

// Pre-Gloas constants are deliberately the *pre-MaxEB* ones: the period's
// derivation assumes a 32-ETH per-validator cap and count-based churn, and has
// not been re-derived for EIP-7251. `MAX_EB_ETH` is therefore 32 — not the
// runtime 2048-ETH `MAX_EFFECTIVE_BALANCE` — matching the spec-as-written and
// other clients. A known approximation under MaxEB.
const MAX_EB_ETH: u64 = 32;
const ETH_TO_GWEI: u64 = 1_000_000_000;
const MAX_DEPOSITS: u64 = 16;
const MIN_PER_EPOCH_CHURN_LIMIT: u64 = 4;
const CHURN_LIMIT_QUOTIENT: u64 = 1 << 16;

pub(crate) fn weak_subjectivity_period_fulu(view: &StateReadView, scratch: &mut Vec<u32>) -> u64 {
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

/// EIP-8061
pub(crate) fn weak_subjectivity_period_gloas(
    cfg: &SpecConfig,
    view: &StateReadView,
    scratch: &mut Vec<u32>,
) -> u64 {
    let epoch = view.slot.state().slot / SLOTS_PER_EPOCH;
    scratch.clear();
    shuffling::get_active_validator_indices_into(&view.validators, epoch, scratch);
    if scratch.is_empty() {
        return MIN_WITHDRAWABILITY_DELAY;
    }

    let total = scratch
        .iter()
        .map(|&i| view.validators.effective_balance(i as usize))
        .sum::<u64>()
        .max(EFFECTIVE_BALANCE_INCREMENT);

    ws_period_gloas_impl(cfg, total)
}

/// EIP-8061 weak-subjectivity period from the total active balance (Gwei).
/// Pure arithmetic, split out so it can be unit-tested without a materialised
/// state.
fn ws_period_gloas_impl(cfg: &SpecConfig, total_active_balance: u64) -> u64 {
    let floor_to_increment = |gwei: u64| gwei - gwei % EFFECTIVE_BALANCE_INCREMENT;

    // Base balance churn (spec `get_balance_churn_limit`, Gloas quotient).
    let base = floor_to_increment(
        cfg.min_per_epoch_churn_limit.max(total_active_balance / cfg.churn_limit_quotient_gloas),
    );
    // EIP-8061: exit churn is uncapped, activation shares the base but keeps its
    // cap, consolidation has its own quotient.
    let exit = base;
    let activation = base.min(cfg.max_per_epoch_activation_churn_limit_gloas);
    let consolidation =
        floor_to_increment(total_active_balance / cfg.consolidation_churn_limit_quotient);

    // Weighted churn: exit ×4/3, activation ×2/3, consolidation ×2 — the shared
    // ÷2 is folded into the denominator below, matching the spec expression.
    let delta = 2 * exit / 3 + activation / 3 + consolidation;
    // `base >= min_per_epoch_churn_limit > 0`, so `delta > 0` (no div-by-zero).
    // u128 numerator is defensive; u64 doesn't overflow at realistic stake.
    let churn_epochs =
        (SAFETY_DECAY as u128 * total_active_balance as u128) / (2 * delta as u128 * 100);
    MIN_WITHDRAWABILITY_DELAY + churn_epochs as u64
}

#[cfg(test)]
mod tests {
    use silver_beacon_state_data::SpecConfig;

    use super::*;

    /// EIP-8061: 1M validators × 32 ETH → ~1563 epochs (~7 days).
    #[test]
    fn gloas_ws_period_roughly_seven_days() {
        let total = 1_000_000u64 * 32 * EFFECTIVE_BALANCE_INCREMENT;
        assert_eq!(ws_period_gloas_impl(&SpecConfig::mainnet(), total), 1563);
    }

    /// A degenerate near-empty active set clamps to the withdrawability floor.
    #[test]
    fn gloas_ws_period_min_floor() {
        assert_eq!(
            ws_period_gloas_impl(&SpecConfig::mainnet(), EFFECTIVE_BALANCE_INCREMENT),
            MIN_WITHDRAWABILITY_DELAY
        );
    }
}
