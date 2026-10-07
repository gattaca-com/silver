use flux_profiler::timed;

use crate::types::{EFFECTIVE_BALANCE_INCREMENT, MAX_EFFECTIVE_BALANCE_COMPOUNDING};

const _: () = assert!(
    MAX_EFFECTIVE_BALANCE_COMPOUNDING / EFFECTIVE_BALANCE_INCREMENT <= u16::MAX as u64,
    "the largest effective balance must fit a u16 increment count",
);

/// Each validator's effective balance in increments. A quarter of the `u64`
/// column, so the attester loop's scattered reads mostly hit cache; effective
/// balances only move in the epoch transition, so the epoch tier holds them.
#[derive(Default)]
pub struct EffectiveIncrements(Vec<u16>);

impl Clone for EffectiveIncrements {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }

    /// Reuses the buffer: forks and finalization copy this every epoch.
    fn clone_from(&mut self, source: &Self) {
        self.0.clone_from(&source.0);
    }
}

impl EffectiveIncrements {
    #[timed]
    pub(crate) fn refill(&mut self, effective_balances: impl Iterator<Item = u64>) {
        self.0.clear();
        self.0.extend(effective_balances.map(|eb| (eb / EFFECTIVE_BALANCE_INCREMENT) as u16));
    }

    #[inline]
    pub fn get(&self, validator: u32) -> u64 {
        self.0[validator as usize] as u64
    }
}
