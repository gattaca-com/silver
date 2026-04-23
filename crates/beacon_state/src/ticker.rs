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
        assert!(now_unix_ms >= genesis_ms, "pre-genesis not supported");

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

    fn since_genesis_ms(&self) -> u64 {
        self.anchor_genesis_ms + self.anchor.elapsed().as_millis() as u64
    }

    /// Current wall-clock slot.
    pub fn current_slot(&self) -> u64 {
        self.since_genesis_ms() / self.slot_ms
    }

    pub fn tick(&mut self) -> TickEvent {
        let ms = self.since_genesis_ms();
        let slot = ms / self.slot_ms;
        let into = ms % self.slot_ms;

        let start = match self.last {
            Some((s, i)) if s == slot => i + 1,
            Some((s, _)) if s < slot => 0,
            None => 0,
            _ => return TickEvent::None, /* defensive: last slot > current (can't happen with
                                          * monotonic clock) */
        };

        // Phases are sorted by offset — if the next one is in the future, all
        // subsequent ones are too.
        if let Some(&(offset, phase)) = self.phases.get(start) &&
            offset <= into
        {
            self.last = Some((slot, start));
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
    fn catches_up_within_current_slot() {
        let slot_dur = Duration::from_secs(12);
        // 22s since genesis → slot 1, ~10s in.
        // Overdue: SlotStart(0), Payload(8s), StateAdv(9s).
        // ForkChoiceLookahead(11.5s) not yet.
        let genesis = genesis_secs_ago(22);
        let mut t = SlotTicker::new(genesis, slot_dur, Duration::from_secs(4));

        let mut events = Vec::new();
        loop {
            let ev = t.tick();
            if ev == TickEvent::None {
                break;
            }
            events.push(ev);
        }
        assert_eq!(events.len(), 3);
        assert!(matches!(events[0], TickEvent::SlotStart(1)));
        assert!(matches!(events[2], TickEvent::StateAdvance(1)));
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
