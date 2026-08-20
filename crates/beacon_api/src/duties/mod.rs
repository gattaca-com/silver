mod proposer;
mod sync;
#[cfg(test)]
mod tests;

use silver_beacon_state_data::{
    EPOCHS_PER_SYNC_COMMITTEE_PERIOD, Epoch, PROPOSER_LOOKAHEAD_SIZE, SLOTS_PER_EPOCH,
};

pub(crate) use self::{
    proposer::{ProposerDuty, get_proposer_duties, get_proposer_duties_v2},
    sync::{SyncDuty, post_sync_duties},
};
use crate::{ids::parse_uint64, response::Response, router::Request, routes::ApiCtx};

/// The phrase `CurrentlySyncing` carries in `types/http.yaml`; every duties
/// schema declares that response and none declares a 404.
const CURRENTLY_SYNCING: &str =
    "Beacon node is currently syncing and not serving request on that endpoint";

/// `proposer_lookahead` is anchored to the state's own epoch and holds this
/// many epochs of slots from that epoch's first.
const LOOKAHEAD_EPOCHS: u64 = PROPOSER_LOOKAHEAD_SIZE as u64 / SLOTS_PER_EPOCH;

/// `LongtailState` seats the committee serving the head's own period and the
/// one after it.
const SEATED_PERIODS: u64 = 2;

/// The epoch a request named, beside the epoch the wall clock is in. Duties
/// are read from the head state's window, and an epoch outside it is either
/// one this node will answer once its head arrives or one no node would
/// answer at all — which the wall clock alone separates.
#[derive(Clone, Copy)]
struct RequestedEpoch {
    epoch: Epoch,
    /// `None` until the first status: nothing to judge an early request by.
    wall_epoch: Option<Epoch>,
}

impl RequestedEpoch {
    /// Every duties schema answers 400 "Invalid epoch" for a path parameter
    /// that names no epoch at all.
    fn parse(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) -> Option<Self> {
        let named = req.params.get("epoch").expect("{epoch} in the route pattern");
        let Some(epoch) = parse_uint64(named) else {
            resp.error(400, "invalid epoch");
            return None;
        };
        Some(Self { epoch, wall_epoch: ctx.node_status.wall_epoch() })
    }
}

/// The unit a duties endpoint schedules by, and the span of them one state
/// answers for.
#[derive(Clone, Copy)]
enum DutyWindow {
    ProposerLookahead,
    SeatedSyncCommittees,
}

/// Why the epoch is outside the window the head state answers for.
enum OutOfWindow {
    /// The wall clock has not reached it either, so this node answers it once
    /// its head does — which is what `CurrentlySyncing` says, where a 400
    /// would blame a request the schemas call valid.
    NotYet,
    /// No node at the head would answer it: below the window silver keeps no
    /// state the duties could come from, and above the wall clock's own
    /// window no chain has scheduled them.
    Never,
}

impl DutyWindow {
    /// How many units past the head's own the request falls, while the head
    /// state answers for it.
    fn units_ahead(self, requested: RequestedEpoch, head_epoch: Epoch) -> Result<u64, OutOfWindow> {
        let Some(ahead) = self.unit_of(requested.epoch).checked_sub(self.unit_of(head_epoch))
        else {
            return Err(OutOfWindow::Never);
        };
        if ahead < self.width() {
            return Ok(ahead);
        }
        if requested.wall_epoch.is_none_or(|wall| self.within_reach(requested.epoch, wall)) {
            Err(OutOfWindow::NotYet)
        } else {
            Err(OutOfWindow::Never)
        }
    }

    fn respond(self, out: OutOfWindow, resp: &mut Response<'_>) {
        match out {
            OutOfWindow::NotYet => resp.error(503, CURRENTLY_SYNCING),
            OutOfWindow::Never => resp.error(400, self.out_of_range()),
        }
    }

    fn unit_of(self, epoch: Epoch) -> u64 {
        match self {
            Self::ProposerLookahead => epoch,
            Self::SeatedSyncCommittees => epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD,
        }
    }

    fn width(self) -> u64 {
        match self {
            Self::ProposerLookahead => LOOKAHEAD_EPOCHS,
            Self::SeatedSyncCommittees => SEATED_PERIODS,
        }
    }

    /// Whether the wall clock leaves the epoch within reach: it names a unit
    /// this node's head has still to pass, or the one after it — the window a
    /// head caught up to the wall clock would answer for.
    fn within_reach(self, epoch: Epoch, wall_epoch: Epoch) -> bool {
        self.unit_of(epoch) < self.unit_of(wall_epoch).saturating_add(self.width())
    }

    const fn out_of_range(self) -> &'static str {
        match self {
            Self::ProposerLookahead => "epoch is outside the proposer lookahead",
            Self::SeatedSyncCommittees => {
                "epoch is outside the current and next sync committee periods"
            }
        }
    }
}
