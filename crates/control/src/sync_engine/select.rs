use silver_common::SyncUpdate;

use super::{Ctx, SLOTS_PER_EPOCH};

pub(super) fn select_target(
    ctx: &Ctx,
    block_gap: bool,
    current: Option<SyncUpdate>,
) -> Option<SyncUpdate> {
    let local = &ctx.local;
    if !local.have_status {
        return None;
    }

    let local_head_slot = local.head_imported_slot;
    let wall_slot = local.wall_slot;

    if let Some(SyncUpdate::SyncingFinalized { target_epoch, target_root }) = current {
        let target_slot = target_epoch.saturating_mul(SLOTS_PER_EPOCH);
        let reached = (local.finalized_epoch >= target_epoch &&
            local.finalized_root == target_root) ||
            local_head_slot >= target_slot;
        if !reached &&
            !ctx.peers.is_excluded(&target_root) &&
            ctx.peers.backs_finalized(target_epoch, &target_root)
        {
            return Some(SyncUpdate::SyncingFinalized { target_epoch, target_root });
        }
    }

    if let Some(SyncUpdate::SyncingHead { head_root, head_slot }) = current {
        let reached = local_head_slot >= head_slot;
        if !reached && !ctx.peers.is_excluded(&head_root) && ctx.peers.backs_head(&head_root) {
            return Some(SyncUpdate::SyncingHead { head_root, head_slot });
        }
    }

    if let Some((epoch, root)) = ctx.peers.best_finalized_target(
        local.finalized_epoch,
        local_head_slot,
        wall_slot,
        &ctx.cfg,
        block_gap,
    ) {
        return Some(SyncUpdate::SyncingFinalized { target_epoch: epoch, target_root: root });
    }

    if let Some((head_root, head_slot)) =
        ctx.peers.best_head_target(local_head_slot, wall_slot, &ctx.cfg, block_gap)
    {
        return Some(SyncUpdate::SyncingHead { head_root, head_slot });
    }

    if current.is_none() && !ctx.peers.received_statuses() {
        return None;
    }

    // No usable sync target was found above, so if we are behind, we are stalled.
    let peers_ahead = ctx.peers.any_peer_ahead_of(local_head_slot, &ctx.cfg);
    let stalled = block_gap && !ctx.peers.any_peer_level_with(local_head_slot, &ctx.cfg);
    if peers_ahead || stalled { Some(SyncUpdate::Stalled) } else { Some(SyncUpdate::Following) }
}
