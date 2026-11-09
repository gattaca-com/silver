# Slashing-protection cluster

Nodes in a cluster agree through Raft on one signed attestation per validator
and epoch, and one block per proposer and slot, before anything is published.
This page covers the rules an operator has to follow today.

## Membership is static

- The `cluster.nodes` map in the config is the full voter set. Every node must
  list the same ids.
- A cluster has at most 7 nodes. Use an odd count: 4 nodes tolerate one
  failure, like 3, but need more votes for every commit.
- Each node's journal (`data_storage_dir/attestation-cluster.wal`) records its
  own id and the voter set. A node whose config disagrees with its journal
  refuses to start, and names both identities.
- There is no live way to add, remove or replace a node yet.

## Bootstrap exactly once

- Start every node of a new cluster with `bootstrap = true`, then set it to
  `false` for every later start.
- `bootstrap = true` refuses an existing journal, and `bootstrap = false`
  refuses a missing one.
- Never bootstrap a single node over a lost journal. A node without its
  journal has forgotten its Raft term and vote. It can vote twice in one term,
  which can elect two leaders and select conflicting signed messages.

## Replacing a node

Until live membership changes exist, a node whose journal is lost can only
return through a planned reset of the whole cluster:

1. Stop every node.
2. Delete every node's journal.
3. Start every node with `bootstrap = true`.

This discards the cluster's lock history. Slashing safety then rests on the
validator clients' own slashing-protection databases, and on each node's
startup floor, which refuses every slot up to the moment it synced.

A cluster of three keeps serving on two nodes, so the reset can wait for a
planned window. Each further loss before it is an outage.

## Upgrades

The lock snapshot format is `SLVLOCK` v4. New binaries read v3 journals, but
older binaries cannot read v4 snapshots. Upgrade every node of a cluster
together: stop all, upgrade, start.

## When Raft processing stops

A node stops serving duties when `Failed` is 1. `FailureKind` says why, and the
log line `slashing protection spin failed` carries the detail.

| `FailureKind` | Cause | Action |
|---|---|---|
| 1 storage | Journal I/O failed. | Fix the disk, then restart. Recovery replays the journal. |
| 2 bad entry | A committed entry this binary cannot apply. The log names its index and term. | Every restart fails on the same entry. Run a binary that can apply it, usually by finishing an upgrade. |
| 3 snapshot | An installed or recovered snapshot is invalid. | Treat as corruption. Restore the journal, or reset the cluster as above. |
| 4 raft | raft-rs returned an error. | Restart, and report it. |

Alert queries for these counters are in `telemetry-counters.md`.
