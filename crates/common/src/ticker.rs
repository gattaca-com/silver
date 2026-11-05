use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use silver_chain_spec::SpecConfig;

type Slot = u64;

/// Consensus-spec clock-skew allowance for slot-scoped gossip validation.
pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY: Duration = Duration::from_millis(500);

pub const BASIS_POINTS: u64 = 10_000;
pub const ATTESTATION_DUE_BPS: u64 = 3333;
pub const ATTESTATION_DUE_BPS_GLOAS: u64 = 2500;
pub const PAYLOAD_ATTESTATION_DUE_BPS: u64 = 7500;

pub fn attestation_due_bps(is_gloas: bool) -> u64 {
    if is_gloas { ATTESTATION_DUE_BPS_GLOAS } else { ATTESTATION_DUE_BPS }
}

// slot/24 before next slot = 500ms on mainnet.
const FORK_CHOICE_LOOKAHEAD_DIVISOR: u64 = 24;
// slot/4 before next slot = 3s on mainnet, state advance fires at 3/4.
const STATE_ADVANCE_DIVISOR: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickEvent {
    /// Slot boundary. Fork choice, cache pruning.
    SlotStart(Slot),
    /// Announce the next slot on the current head, so builders learn of
    /// a missed slot in time.
    AnnouncePayload(Slot),
    /// slot - prepare_payload_lookahead. Notify EL to start building.
    PreparePayload(Slot),
    /// 3/4 slot. Advance head state one slot.
    StateAdvance(Slot),
    /// 23/24 slot. Pre-emptive fork choice for next slot.
    ForkChoiceLookahead(Slot),
    None,
}

#[derive(Debug, Clone, Copy)]
enum Phase {
    SlotStart,
    AnnouncePayload,
    PreparePayload,
    StateAdvance,
    ForkChoiceLookahead,
}

/// The phases of a slot, in firing order.
const PHASES: [Phase; 5] = [
    Phase::SlotStart,
    Phase::AnnouncePayload,
    Phase::PreparePayload,
    Phase::StateAdvance,
    Phase::ForkChoiceLookahead,
];

impl Phase {
    fn event(self, slot: Slot) -> TickEvent {
        match self {
            Self::SlotStart => TickEvent::SlotStart(slot),
            Self::AnnouncePayload => TickEvent::AnnouncePayload(slot),
            Self::PreparePayload => TickEvent::PreparePayload(slot),
            Self::StateAdvance => TickEvent::StateAdvance(slot),
            Self::ForkChoiceLookahead => TickEvent::ForkChoiceLookahead(slot),
        }
    }
}

#[derive(Clone)]
pub struct SlotTicker {
    anchor: Instant,
    anchor_genesis_ms: u64,
    frozen: bool,
    slot_ms: u64,
    payload_off: u64,
    gloas_fork_slot: Slot,
    /// Last emitted: (slot, index into `PHASES`). None = nothing emitted yet.
    last: Option<(Slot, usize)>,
}

impl SlotTicker {
    pub fn new(
        genesis_unix_secs: u64,
        spec: &SpecConfig,
        prepare_payload_lookahead: Duration,
    ) -> Self {
        let slot_ms = spec.slot_duration_ms();
        assert!(slot_ms > 0);

        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_millis() as u64;
        let genesis_ms = genesis_unix_secs * 1000;
        assert!(
            now_unix_ms >= genesis_ms,
            "pre-genesis not supported: {} >= {}",
            now_unix_ms,
            genesis_ms
        );

        let ticker = Self {
            anchor: Instant::now(),
            anchor_genesis_ms: now_unix_ms.saturating_sub(genesis_ms),
            frozen: false,
            slot_ms,
            payload_off: slot_ms.saturating_sub(prepare_payload_lookahead.as_millis() as u64),
            gloas_fork_slot: spec.gloas_fork_slot(),
            last: None,
        };
        // Pre-Gloas has the later attestation deadline, so it bounds both forks.
        assert!(
            PHASES.windows(2).all(|w| ticker.offset(w[0], 0) <= ticker.offset(w[1], 0)),
            "prepare_payload_lookahead must prepare between the attestation deadline and the \
             state advance"
        );
        ticker
    }

    /// Milliseconds into `slot` at which `phase` fires. Only the announcement
    /// moves with the fork: it follows the attestation deadline.
    fn offset(&self, phase: Phase, slot: Slot) -> u64 {
        let slot_ms = self.slot_ms;
        match phase {
            Phase::SlotStart => 0,
            Phase::AnnouncePayload => {
                slot_ms * attestation_due_bps(slot >= self.gloas_fork_slot) / BASIS_POINTS
            }
            Phase::PreparePayload => self.payload_off,
            Phase::StateAdvance => slot_ms - slot_ms / STATE_ADVANCE_DIVISOR,
            Phase::ForkChoiceLookahead => slot_ms - slot_ms / FORK_CHOICE_LOOKAHEAD_DIVISOR,
        }
    }

    pub fn slot_duration(&self) -> Duration {
        Duration::from_millis(self.slot_ms)
    }

    pub fn millis_since_genesis(&self) -> u64 {
        if self.frozen {
            return self.anchor_genesis_ms;
        }
        self.anchor_genesis_ms + self.anchor.elapsed().as_millis() as u64
    }

    pub fn slot_time_elapsed(&self) -> Duration {
        Duration::from_millis(self.millis_since_genesis() % self.slot_ms)
    }

    pub fn current_slot(&self) -> u64 {
        self.millis_since_genesis() / self.slot_ms
    }

    pub fn current_slot_start(&self) -> (u64, Instant) {
        let now = Instant::now();
        let since_genesis =
            Duration::from_millis(self.anchor_genesis_ms) + now.duration_since(self.anchor);
        let slot = (since_genesis.as_millis() / self.slot_ms as u128) as u64;
        let into_slot = since_genesis - Duration::from_millis(slot * self.slot_ms);
        (slot, now - into_slot)
    }

    /// Whether `slot` is current after extending both ends of its wall-clock
    /// interval by `disparity`. Consensus gossip validation uses this for its
    /// permitted clock skew around slot boundaries.
    pub fn is_current_slot_with_disparity(&self, slot: Slot, disparity: Duration) -> bool {
        let now = self.millis_since_genesis();
        let disparity_ms = u64::try_from(disparity.as_millis()).unwrap_or(u64::MAX);
        let start = slot.saturating_mul(self.slot_ms);
        let end = slot.saturating_add(1).saturating_mul(self.slot_ms);
        now.saturating_add(disparity_ms) >= start && now <= end.saturating_add(disparity_ms)
    }

    /// Spec `is_future_slot`: `slot` starts more than `disparity` from now.
    pub fn is_future_slot(&self, slot: Slot, disparity: Duration) -> bool {
        let disparity_ms = u64::try_from(disparity.as_millis()).unwrap_or(u64::MAX);
        self.millis_since_genesis().saturating_add(disparity_ms) < slot.saturating_mul(self.slot_ms)
    }

    /// Spec `is_past_slot`: `slot` started more than `disparity` ago.
    pub fn is_past_slot(&self, slot: Slot, disparity: Duration) -> bool {
        let disparity_ms = u64::try_from(disparity.as_millis()).unwrap_or(u64::MAX);
        self.millis_since_genesis() > slot.saturating_mul(self.slot_ms).saturating_add(disparity_ms)
    }

    /// Spec `is_within_slot_range`: now lies in `[slot, slot + range]`, each
    /// end stretched by `disparity`.
    pub fn is_within_slot_range(&self, slot: Slot, range: u64, disparity: Duration) -> bool {
        let now = self.millis_since_genesis();
        let disparity_ms = u64::try_from(disparity.as_millis()).unwrap_or(u64::MAX);
        let start = slot.saturating_mul(self.slot_ms);
        let end = slot.saturating_add(range + 1).saturating_mul(self.slot_ms);
        now.saturating_add(disparity_ms) >= start && end.saturating_add(disparity_ms) >= now
    }

    /// The newest slot admitted by [`Self::is_current_slot_with_disparity`].
    /// A two-slot seen-cache can rotate to this value and retain every slot
    /// that is valid at the current instant, including across the boundary.
    pub fn latest_slot_with_disparity(&self, disparity: Duration) -> Slot {
        let wall = self.current_slot();
        let next = wall.saturating_add(1);
        if self.is_current_slot_with_disparity(next, disparity) { next } else { wall }
    }

    pub fn is_before_attesting_interval(&self, is_gloas: bool) -> bool {
        let due_ms = self.slot_ms * attestation_due_bps(is_gloas) / BASIS_POINTS;
        self.millis_since_genesis() % self.slot_ms < due_ms
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn set_current_slot(&mut self, slot: u64) {
        self.set_since_genesis_ms(slot * self.slot_ms);
    }

    /// Pin `millis_since_genesis()` to `ms` and hold it there. EF vectors put
    /// messages exactly on the 1 ms edge of a disparity window, so a clock that
    /// kept running between the tick and the check would drift across it.
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_since_genesis_ms(&mut self, ms: u64) {
        self.anchor_genesis_ms = ms;
        self.frozen = true;
        self.last = None;
    }

    pub fn tick(&mut self) -> TickEvent {
        let ms = self.millis_since_genesis();
        let slot = ms / self.slot_ms;
        let into = ms % self.slot_ms;

        // First tick of a new slot (or ever): jump to current wall-clock slot,
        // emit SlotStart, and consume any in-slot phases whose offset has
        // already passed.
        let crossed = match self.last {
            Some((s, _)) if s < slot => true,
            None => true,
            Some((s, _)) if s == slot => false,
            _ => return TickEvent::None,
        };

        if crossed {
            // Advance past any non-SlotStart phases whose offset <= into so
            // they won't fire later in this slot. PHASES[0] is SlotStart at
            // offset 0 and is always the emitted event here.
            let consumed =
                PHASES[1..].iter().take_while(|&&phase| self.offset(phase, slot) <= into).count();
            self.last = Some((slot, consumed));
            return TickEvent::SlotStart(slot);
        }

        // Same slot, advance to the next phase if its offset has been reached.
        let last_idx = self.last.unwrap().1;
        let next = last_idx + 1;
        if let Some(&phase) = PHASES.get(next) &&
            self.offset(phase, slot) <= into
        {
            self.last = Some((slot, next));
            return phase.event(slot);
        }
        TickEvent::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(slot_ms: u64, gloas_fork_epoch: u64) -> SpecConfig {
        SpecConfig { slot_duration_ms: Some(slot_ms), gloas_fork_epoch, ..SpecConfig::mainnet() }
    }

    fn genesis_secs_ago(secs: u64) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - secs
    }

    #[test]
    fn fires_slot_start_at_boundary() {
        let genesis = genesis_secs_ago(12);
        let mut t = SlotTicker::new(genesis, &SpecConfig::mainnet(), Duration::from_secs(4));

        // 12s since genesis = slot 1, ~0ms into slot. SlotStart should fire.
        assert!(matches!(t.tick(), TickEvent::SlotStart(1)));
        // Next phase (AnnouncePayload at 4s) is in the future.
        assert!(t.tick() == TickEvent::None);
    }

    #[test]
    fn slot_start_uses_the_same_anchor_as_the_wall_slot() {
        let mut ticker = SlotTicker::new(
            genesis_secs_ago(20),
            &spec(1250, u64::MAX),
            Duration::from_millis(500),
        );
        ticker.set_since_genesis_ms(10 * 1250 + 750);
        let (slot, start) = ticker.current_slot_start();
        assert_eq!(slot, 10);
        assert_eq!(start, ticker.anchor - Duration::from_millis(750));
    }

    #[test]
    fn skips_stale_phases_on_catchup() {
        // 22s since genesis → slot 1, ~10s in.
        // Overdue offsets: Announce(4s), Payload(8s), StateAdv(9s).
        // FCLookahead(11.5s) not yet reached.
        // Expect: only SlotStart(1) emitted; stale phases dropped.
        let genesis = genesis_secs_ago(22);
        let mut t = SlotTicker::new(genesis, &SpecConfig::mainnet(), Duration::from_secs(4));

        assert!(matches!(t.tick(), TickEvent::SlotStart(1)));
        assert_eq!(t.tick(), TickEvent::None);
    }

    #[test]
    fn skips_fully_passed_slots() {
        // 36s since genesis → slot 3, ~0ms in.
        let genesis = genesis_secs_ago(36);
        let mut t = SlotTicker::new(genesis, &SpecConfig::mainnet(), Duration::from_secs(4));

        // Should fire events for slot 3, not replay slots 0-2.
        let ev = t.tick();
        assert!(matches!(ev, TickEvent::SlotStart(3)));
    }

    #[test]
    fn announces_at_the_attestation_deadline_of_each_fork() {
        // Gloas from slot 32: the deadline moves from 1/3 to 1/4 of the slot.
        let mut t = SlotTicker::new(0, &spec(12_000, 1), Duration::from_secs(4));
        t.set_since_genesis_ms(31 * 12_000);
        let mut at = |ms| {
            t.anchor_genesis_ms = ms;
            t.tick()
        };
        assert_eq!(at(31 * 12_000), TickEvent::SlotStart(31));
        assert_eq!(at(31 * 12_000 + 3_998), TickEvent::None);
        assert_eq!(at(31 * 12_000 + 3_999), TickEvent::AnnouncePayload(31));
        assert_eq!(at(31 * 12_000 + 8_000), TickEvent::PreparePayload(31));

        assert_eq!(at(32 * 12_000), TickEvent::SlotStart(32));
        assert_eq!(at(32 * 12_000 + 2_999), TickEvent::None);
        assert_eq!(at(32 * 12_000 + 3_000), TickEvent::AnnouncePayload(32));
        assert_eq!(at(32 * 12_000 + 8_000), TickEvent::PreparePayload(32));
    }

    #[test]
    #[should_panic(expected = "prepare_payload_lookahead")]
    fn rejects_preparing_before_the_announcement() {
        SlotTicker::new(0, &SpecConfig::mainnet(), Duration::from_secs(10));
    }

    #[test]
    fn current_slot_disparity_covers_both_boundary_sides() {
        let mut t = SlotTicker::new(0, &SpecConfig::mainnet(), Duration::from_secs(4));
        let disparity = Duration::from_millis(500);

        t.set_since_genesis_ms(12_000 + 499);
        assert!(t.is_current_slot_with_disparity(0, disparity));
        assert!(t.is_current_slot_with_disparity(1, disparity));
        assert!(!t.is_current_slot_with_disparity(2, disparity));
        assert_eq!(t.latest_slot_with_disparity(disparity), 1);

        t.set_since_genesis_ms(24_000 - 500);
        assert!(t.is_current_slot_with_disparity(1, disparity));
        assert!(t.is_current_slot_with_disparity(2, disparity));
        assert_eq!(t.latest_slot_with_disparity(disparity), 2);

        t.set_since_genesis_ms(24_000 - 501);
        assert!(!t.is_current_slot_with_disparity(2, disparity));
        assert_eq!(t.latest_slot_with_disparity(disparity), 1);
    }
}
