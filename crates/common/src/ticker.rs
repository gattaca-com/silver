use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

type Slot = u64;

// slot/24 before next slot = 500ms on mainnet.
const FORK_CHOICE_LOOKAHEAD_DIVISOR: u64 = 24;
// slot/4 before next slot = 3s on mainnet, state advance fires at 3/4.
const STATE_ADVANCE_DIVISOR: u64 = 4;

const NUM_PHASES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickEvent {
    /// Slot boundary. Fork choice, cache pruning.
    SlotStart(Slot),
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
    PreparePayload,
    StateAdvance,
    ForkChoiceLookahead,
}

impl Phase {
    fn event(self, slot: Slot) -> TickEvent {
        match self {
            Self::SlotStart => TickEvent::SlotStart(slot),
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
    slot_ms: u64,
    /// (offset_ms_from_slot_start, phase), sorted by offset.
    phases: [(u64, Phase); NUM_PHASES],
    /// Last emitted: (slot, index into phases). None = nothing emitted yet.
    last: Option<(Slot, usize)>,
}

impl SlotTicker {
    pub fn new(
        genesis_unix_secs: u64,
        slot_duration: Duration,
        prepare_payload_lookahead: Duration,
    ) -> Self {
        assert!(slot_duration.as_millis() > 0);

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

        let slot_ms = slot_duration.as_millis() as u64;
        let payload_off = slot_ms.saturating_sub(prepare_payload_lookahead.as_millis() as u64);

        let state_advance_off = slot_ms - slot_ms / STATE_ADVANCE_DIVISOR;
        let fc_lookahead_off = slot_ms - slot_ms / FORK_CHOICE_LOOKAHEAD_DIVISOR;

        debug_assert!(payload_off <= state_advance_off);
        debug_assert!(state_advance_off <= fc_lookahead_off);

        let phases = [
            (0, Phase::SlotStart),
            (payload_off, Phase::PreparePayload),
            (state_advance_off, Phase::StateAdvance),
            (fc_lookahead_off, Phase::ForkChoiceLookahead),
        ];

        Self {
            anchor: Instant::now(),
            anchor_genesis_ms: now_unix_ms.saturating_sub(genesis_ms),
            slot_ms,
            phases,
            last: None,
        }
    }

    pub fn millis_since_genesis(&self) -> u64 {
        self.anchor_genesis_ms + self.anchor.elapsed().as_millis() as u64
    }

    pub fn slot_time_elapsed(&self) -> Duration {
        Duration::from_millis(self.since_genesis_ms() % self.slot_ms)
    }

    pub fn current_slot(&self) -> u64 {
        self.millis_since_genesis() / self.slot_ms
    }

    pub fn is_before_attesting_interval(&self, is_gloas: bool) -> bool {
        let fraction = if is_gloas { 4 } else { 3 };
        self.millis_since_genesis() % self.slot_ms < self.slot_ms / fraction
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn set_current_slot(&mut self, slot: u64) {
        self.anchor = Instant::now();
        self.anchor_genesis_ms = slot * self.slot_ms;
        self.last = None;
    }

    /// Force `since_genesis_ms()` to `ms` at this moment, fixing both the slot
    /// and the sub-slot offset (so `is_before_attesting_interval` reflects a
    /// precise within-slot time). For EF fork-choice vectors that pin proposer
    /// boost to a `tick`. Reads drift by the elapsed call latency (negligible
    /// vs the 12s slot / 4s deadline).
    #[cfg(any(test, feature = "test-util"))]
    pub fn set_since_genesis_ms(&mut self, ms: u64) {
        self.anchor = Instant::now();
        self.anchor_genesis_ms = ms;
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
            // they won't fire later in this slot. phases[0] is SlotStart at
            // offset 0 and is always the emitted event here.
            let mut consumed = 0;
            for i in 1..NUM_PHASES {
                if self.phases[i].0 <= into {
                    consumed = i;
                } else {
                    break;
                }
            }
            self.last = Some((slot, consumed));
            return TickEvent::SlotStart(slot);
        }

        // Same slot, advance to the next phase if its offset has been reached.
        let last_idx = self.last.unwrap().1;
        let next = last_idx + 1;
        if let Some(&(offset, phase)) = self.phases.get(next) &&
            offset <= into
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

    fn genesis_secs_ago(secs: u64) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - secs
    }

    #[test]
    fn fires_slot_start_at_boundary() {
        let slot_dur = Duration::from_secs(12);
        let genesis = genesis_secs_ago(12);
        let mut t = SlotTicker::new(genesis, slot_dur, Duration::from_secs(4));

        // 12s since genesis = slot 1, ~0ms into slot. SlotStart should fire.
        assert!(matches!(t.tick(), TickEvent::SlotStart(1)));
        // Next phase (PreparePayload at 8s) is in the future.
        assert!(t.tick() == TickEvent::None);
    }

    #[test]
    fn skips_stale_phases_on_catchup() {
        let slot_dur = Duration::from_secs(12);
        // 22s since genesis → slot 1, ~10s in.
        // Overdue offsets: Payload(8s), StateAdv(9s).
        // FCLookahead(11.5s) not yet reached.
        // Expect: only SlotStart(1) emitted; stale phases dropped.
        let genesis = genesis_secs_ago(22);
        let mut t = SlotTicker::new(genesis, slot_dur, Duration::from_secs(4));

        assert!(matches!(t.tick(), TickEvent::SlotStart(1)));
        assert_eq!(t.tick(), TickEvent::None);
    }

    #[test]
    fn skips_fully_passed_slots() {
        let slot_dur = Duration::from_secs(12);
        // 36s since genesis → slot 3, ~0ms in.
        let genesis = genesis_secs_ago(36);
        let mut t = SlotTicker::new(genesis, slot_dur, Duration::from_secs(4));

        // Should fire events for slot 3, not replay slots 0-2.
        let ev = t.tick();
        assert!(matches!(ev, TickEvent::SlotStart(3)));
    }
}
