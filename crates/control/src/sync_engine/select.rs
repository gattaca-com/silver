use silver_common::SyncUpdate;

use super::{Ctx, SLOTS_PER_EPOCH};

pub(super) fn select_target(ctx: &Ctx, current: SyncUpdate, force_resync: bool) -> SyncUpdate {
    let local = &ctx.local;
    if !local.have_status {
        return SyncUpdate::Following;
    }
    let local_head_slot = local.head_imported_slot;
    let wall_slot = local.wall_slot;

    if let SyncUpdate::SyncingFinalized { target_epoch, target_root } = current {
        let target_slot = target_epoch.saturating_mul(SLOTS_PER_EPOCH);
        let reached = (local.finalized_epoch >= target_epoch &&
            local.finalized_root == target_root) ||
            local_head_slot >= target_slot;
        if !reached &&
            !ctx.peers.is_rejected(&target_root) &&
            ctx.peers.backs_finalized(target_epoch, &target_root)
        {
            return SyncUpdate::SyncingFinalized { target_epoch, target_root };
        }
    }

    if let SyncUpdate::SyncingHead { head_root, head_slot } = current {
        let reached = local_head_slot >= head_slot;
        if !reached && !ctx.peers.is_rejected(&head_root) && ctx.peers.backs_head(&head_root) {
            return SyncUpdate::SyncingHead { head_root, head_slot };
        }
    }

    if let Some((epoch, root)) = ctx.peers.best_finalized_target(
        local.finalized_epoch,
        local_head_slot,
        wall_slot,
        &ctx.cfg,
        force_resync,
    ) {
        return SyncUpdate::SyncingFinalized { target_epoch: epoch, target_root: root };
    }

    if let Some((head_root, head_slot)) =
        ctx.peers.best_head_target(local_head_slot, wall_slot, &ctx.cfg, force_resync)
    {
        return SyncUpdate::SyncingHead { head_root, head_slot };
    }

    // No viable peer target. If meaningfully behind wall, hold the current pin
    // (a backer is momentarily unavailable).
    if ctx.behind_wall() {
        return current;
    }

    SyncUpdate::Following
}
