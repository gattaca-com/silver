use silver_beacon_state_data::{B256, SLOTS_PER_EPOCH};
use silver_common::{ELSyncStatus, PayloadResolution, SyncUpdate};

use crate::{
    ctx::ApiCtx,
    http::{json::SyncingData, response::Response, router::Request},
};

/// The status a syncing node reports when the request names no other one.
const DEFAULT_SYNCING_STATUS: u16 = 206;

#[derive(Clone, Copy, Debug)]
pub struct NodeStatus {
    pub head: HeadStatus,
    pub head_root: B256,
    pub head_payload: PayloadResolution,
    pub wall_slot: u64,
    pub finalized_epoch: u64,
    /// `None` until the control tile publishes its first target.
    pub target: Option<SyncUpdate>,
    pub el: ELSyncStatus,
}

/// What `getHealth` answers with: 200, or the syncing code (206 unless the
/// request names another).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Health {
    Ready,
    Syncing,
}

impl NodeStatus {
    pub fn at_anchor(head_slot: u64, head_root: B256, anchor_epoch: u64) -> Self {
        Self {
            head: HeadStatus { slot: head_slot, optimistic: false },
            head_root,
            head_payload: PayloadResolution::Empty,
            wall_slot: 0,
            finalized_epoch: anchor_epoch,
            target: None,
            el: ELSyncStatus::default(),
        }
    }

    pub(crate) fn is_finalized(&self, block_slot: u64) -> bool {
        block_slot <= self.finalized_epoch * SLOTS_PER_EPOCH
    }

    pub(crate) fn execution_optimistic(&self) -> bool {
        self.head.optimistic
    }

    pub(crate) fn health(&self) -> Health {
        if !self.is_following() || self.el != ELSyncStatus::Synced {
            Health::Syncing
        } else {
            Health::Ready
        }
    }

    pub(crate) fn syncing_data(&self) -> SyncingData {
        SyncingData {
            head_slot: self.head.slot,
            sync_distance: self.sync_distance(),
            is_syncing: !self.is_following(),
            is_optimistic: self.head.optimistic,
            el_offline: self.el_offline(),
        }
    }

    pub(crate) fn is_following(&self) -> bool {
        self.target.is_some_and(SyncUpdate::is_following)
    }

    /// Distance from the imported head to the sync target, or to the wall slot
    /// while stalled.
    fn sync_distance(&self) -> u64 {
        match self.target {
            None => u64::MAX,
            Some(SyncUpdate::Stalled) => self.wall_slot.saturating_sub(self.head.slot),
            Some(target) => {
                target.target_slot().map_or(0, |slot| slot.saturating_sub(self.head.slot))
            }
        }
    }

    fn el_offline(&self) -> bool {
        matches!(self.el, ELSyncStatus::Unknown | ELSyncStatus::Offline)
    }
}

/// `slot` is the highest imported block's slot, excluding empty slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeadStatus {
    pub slot: u64,
    pub optimistic: bool,
}

pub(crate) fn syncing(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let syncing = ctx.node_status.syncing_data();
    resp.json_body(|json| json.data_envelope(|json| json.syncing(&syncing)));
}

pub(crate) fn version(_req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    resp.json(&ctx.statics.version);
}

/// Health is the status code and nothing else — the schema gives this
/// endpoint no response body at any code.
pub(crate) fn health(req: &Request<'_>, ctx: &ApiCtx, resp: &mut Response<'_>) {
    let Some(syncing_status) = syncing_status(req) else {
        resp.error(400, "invalid syncing_status");
        return;
    };
    let code = match ctx.node_status.health() {
        Health::Ready => 200,
        Health::Syncing => syncing_status,
    };
    resp.status_only(code);
}

/// The optional `syncing_status` query parameter, which replaces the code a
/// syncing node reports. `None` for a value outside the 100..=599 the schema
/// allows, which the spec answers with a 400.
fn syncing_status(req: &Request<'_>) -> Option<u16> {
    match req.query_value("syncing_status") {
        Some(value) => value.parse().ok().filter(|code| (100..=599).contains(code)),
        None => Some(DEFAULT_SYNCING_STATUS),
    }
}

#[cfg(test)]
pub(crate) mod tests;
