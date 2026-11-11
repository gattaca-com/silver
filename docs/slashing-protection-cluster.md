# Slashing-protection cluster

Nodes in a cluster agree through Raft on one signed attestation per validator
and epoch, and one block per proposer and slot, before anything is published.
This page covers the rules an operator has to follow today.

## Availability

Every lock needs a majority of the voters, so the cluster fails closed.

| Nodes | Tolerated failures | Without a majority |
|---|---|---|
| 3 | 1 | Every local attestation and block is refused until a majority returns. |
| 5 | 2 | As above. |
| 7 | 3 | As above. |

- A refused duty is a missed duty, never a slashing.
- After the leader fails, an election starts within 2 to 4 s (a randomised 20
  to 40 ticks of 100 ms). Duties submitted meanwhile are answered
  `LockPending` and published if they commit later.
- The `Role`, `LeaderId` and per-peer stats counters show which node leads and
  which peers it hears from.

## Standalone mode

Without a `cluster` config, a node locks its own attestations and blocks in
memory only.

- A restart forgets every lock. The startup floor then refuses every slot up
  to the moment the node synced, so it cannot re-sign a slot it signed before.
- Older conflicting or surrounding votes are only caught by the validator
  client's own slashing-protection database.
- Turning clustering off on a node that has a cluster journal logs a warning:
  the node no longer checks the cluster's lock history.

## Membership is static

- The `cluster.nodes` map in the config is the full voter set. Every node must
  list the same ids.
- A cluster has at most 7 nodes. Use an odd count: 4 nodes tolerate one
  failure, like 3, but need more votes for every commit.
- Each node's journal (`data_storage_dir/attestation-cluster.wal`) records its
  own id and the voter set it started with. A node whose config gives another
  id refuses to start, and names both ids.
- On restart, the voter set comes from the journal, not from the config.
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

## When a lock is not agreed in time

A local attestation or block waits up to 500 ms for the cluster to agree on
its lock. Past that, the API answers `the slashing protection cluster has not
agreed on it yet; it is published if it agrees later`.

- If the lock still commits, the node publishes the message anyway, up to two
  slots after its slot. `ProposalsCommittedLate` counts every lock that
  commits after its request was answered, published or not.
- A blinded block is the exception: the API reveals it through its original
  request, so a late lock for one is not published.
- Retrying the same signed message is safe. The cluster treats it as the same
  vote or block, never as a conflict.

## Clock skew

Each node checks the cluster's entries against its own clock, with one slot of
slack. Only a node whose own clock is skewed ever trips this check.

- A follower whose clock runs fast proposes slots the leader refuses. Its
  duties fail; the rest of the cluster is unaffected.
- A leader whose clock runs fast appends locks or a floor its followers refuse.
  They ignore it until their own clocks reach the refused entry, so it loses
  its quorum. A new leader is elected within 2 to 4 s, and the skewed entries
  never commit. `LeadersBoycotted` counts this on each follower.
- While ignored, the skewed node cannot be elected again, even though its log
  is longer. Once its clock is fixed, it can lead again after the other
  nodes' clocks pass the slot it refused.
- A follower whose clock runs slow refuses the correct leader, so it drops out
  of the cluster. The rest of the cluster is unaffected while a majority
  remains.
- A leader whose clock runs slow refuses its followers' proposals for the
  current slot. Duties fail until another node leads.

Keep every node on NTP. Admission uses each node's own wall clock.

## When Raft processing stops

A node stops serving duties when `Failed` is 1. `FailureKind` says why, and the
log line `slashing protection spin failed` carries the detail.

| `FailureKind` | Cause | Action |
|---|---|---|
| 1 storage | Journal I/O failed. | Fix the disk, then restart. Recovery replays the journal. |
| 2 bad entry | A committed entry this binary cannot apply. The log names its index and term. | Every restart fails on the same entry. Run a binary that can apply it, usually by finishing an upgrade. |
| 3 snapshot | An installed or recovered snapshot is invalid. | Treat as corruption. Restore the journal, or reset the cluster as above. |
| 4 raft | raft-rs returned an error. | Restart, and report it. |

A node replays its journal before it starts. A journal that is missing or
cannot be replayed stops the start, with the cause in the error.

Alert queries for these counters are in `telemetry-counters.md`.
