use std::time::{Duration, Instant};

use fxhash::FxHashMap;

/// A backstop against spam, not a rate limit: honest peers stay far below it.
const PUBLISH_ENTRIES_PER_SLOT: u128 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Admission {
    Admitted,
    Dropped { first: bool },
}

/// Credit is held in entries × slot nanos so sub-entry refills accumulate
/// exactly.
struct Credit {
    credit: u128,
    refilled_at: Instant,
    exhausted: bool,
}

/// Publish entries per peer. Keys are connection-slab indices, so the map is
/// bounded by the connection limit; a reused index inherits the credit.
pub(crate) struct PublishBudget {
    slot_nanos: u128,
    peers: FxHashMap<usize, Credit>,
}

impl PublishBudget {
    pub(crate) fn new(slot_duration: Duration) -> Self {
        assert!(!slot_duration.is_zero(), "slot duration must be positive");
        Self { slot_nanos: slot_duration.as_nanos(), peers: FxHashMap::default() }
    }

    pub(crate) fn admit(&mut self, peer: usize, entries: usize, now: Instant) -> Admission {
        let capacity = PUBLISH_ENTRIES_PER_SLOT * self.slot_nanos;
        let c = self.peers.entry(peer).or_insert(Credit {
            credit: capacity,
            refilled_at: now,
            exhausted: false,
        });
        if now > c.refilled_at {
            let elapsed = now.duration_since(c.refilled_at).as_nanos();
            let refill = elapsed.saturating_mul(PUBLISH_ENTRIES_PER_SLOT);
            c.credit = c.credit.saturating_add(refill).min(capacity);
            c.refilled_at = now;
        }

        let cost = entries as u128 * self.slot_nanos;
        if cost > c.credit {
            let first = !c.exhausted;
            c.exhausted = true;
            return Admission::Dropped { first };
        }
        c.credit -= cost;
        c.exhausted = false;
        Admission::Admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SLOT: Duration = Duration::from_secs(12);
    const BUDGET: usize = PUBLISH_ENTRIES_PER_SLOT as usize;

    #[test]
    fn one_slot_of_entries_is_admitted_then_dropped() {
        let now = Instant::now();
        let mut budget = PublishBudget::new(SLOT);
        assert_eq!(budget.admit(1, BUDGET, now), Admission::Admitted);
        assert_eq!(budget.admit(1, 1, now), Admission::Dropped { first: true });
        assert_eq!(budget.admit(1, 1, now), Admission::Dropped { first: false });
        assert_eq!(budget.admit(2, 1, now), Admission::Admitted, "budgets are per peer");
    }

    #[test]
    fn credit_refills_with_time_up_to_one_slot() {
        let now = Instant::now();
        let mut budget = PublishBudget::new(SLOT);
        assert_eq!(budget.admit(1, BUDGET, now), Admission::Admitted);

        let half = now + SLOT / 2;
        assert_eq!(budget.admit(1, BUDGET / 2, half), Admission::Admitted);
        assert_eq!(budget.admit(1, 1, half), Admission::Dropped { first: true });

        let idle = half + 10 * SLOT;
        assert_eq!(budget.admit(1, BUDGET, idle), Admission::Admitted);
        assert_eq!(
            budget.admit(1, 1, idle),
            Admission::Dropped { first: true },
            "capped at a slot"
        );
    }
}
