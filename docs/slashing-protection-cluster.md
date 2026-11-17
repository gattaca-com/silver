# Slashing-protection cluster

Cluster nodes agree through Raft on one attestation per validator and epoch,
and one block per proposer and slot, before anything is published.

## Availability

- Every lock needs a majority of voters; without one, every local duty is
  refused. A refused duty is a missed duty, never a slashing.
- Use 3, 5 or 7 voters (7 is the maximum). An even count adds votes per commit
  without tolerating more failures.
- A new leader is elected within 2 to 4 s. Meanwhile duties get `LockPending`
  and are published if they commit later.

Without a `cluster` config, a node locks in memory only. A restart forgets the
locks, so the startup floor refuses every slot up to the moment it synced.
Older conflicting votes are then caught only by the validator client.

## Bootstrap and the journal

- The journal is `data_storage_dir/attestation-cluster.wal`. It records the
  node's id; a config with another id refuses to start.
- Start every node of a new cluster with `bootstrap = true`, then `false`
  forever after. `bootstrap = true` refuses an existing journal; `false`
  refuses a missing one.
- Never bootstrap one node over a lost journal. It forgot its term and vote,
  so it can vote twice and elect two leaders.
- `cluster.nodes` is only the initial voter set. Afterwards membership and
  addresses live in the journal. A node that moves updates only its own ENR.

## Changing members

Run these on the leader's host, as the node's user. A follower names the
leader. A change prints `proposed`; check it applied with `silver members`.

| Command | Effect |
|---|---|
| `silver members` | Members, roles, next free id, and (on the leader) progress. |
| `silver add <node_id> <enr>` | Adds a learner: it gets every lock but does not vote. |
| `silver promote <node_id>` | Makes a caught-up learner a voter. |
| `silver replace <old> <new>` | Swaps voter `old` for caught-up learner `new` in one joint change. |
| `silver remove <node_id>` | Removes a voter or learner. |
| `silver transfer-leader <node_id>` | Hands leadership to another voter. |

The leader refuses:

- a second change before the first applied;
- `add` with any id but the next free one (ids are never reused), an ENR
  without a QUIC address, or a key already in use;
- `add` once the locks no longer fit one snapshot (about 150k validators);
- `promote`/`replace` until every member has caught up, except one `replace`
  removes;
- removing itself: `transfer-leader` first.

A removed node refuses every duty, also after restart (`Removed` = 1). Reuse
its host only with a new id and journal.

**Add a node:** find the next id with `silver members`. Configure the node
with `join = true` and a `nodes` map of itself plus the current members. Run
`silver add <id> <enr>`, then start the node; it refuses duties until it
restores the snapshot. Set `join = false` afterwards, and `silver promote <id>`
once it has caught up.

**Replace a lost voter:** add the new node as above without promoting it, then
`silver replace <old> <new>`. A cluster of three keeps signing throughout.

**Lost majority:** changes need a quorum, so stop every node, delete every
journal and bootstrap again. This drops the lock history; safety then rests on
the validator clients and each node's startup floor.

## Late locks

A duty waits up to 500 ms for its lock, then the API answers `the slashing
protection cluster has not agreed on it yet; it is published if it agrees
later`.

- A lock that still commits is published up to two slots late, except for a
  blinded block. `ProposalsCommittedLate` counts these.
- Retrying the same signed message is safe; it is never a conflict.

## Clock skew

Nodes check entries against their own clock with one slot of slack, so only a
skewed node is affected. Keep every node on NTP.

- A fast follower's duties fail. A fast leader loses its quorum
  (`LeadersBoycotted` on followers), and its entries never commit.
- A slow follower drops out. A slow leader fails duties until another leads.

## When Raft stops

`Failed` = 1 means the node serves no duties. The log line `slashing
protection spin failed` has the detail.

| `FailureKind` | Cause | Action |
|---|---|---|
| 1 storage | Journal I/O failed. | Fix the disk, restart; the journal replays. |
| 2 bad entry | Committed entry this binary cannot apply. | Run a binary that can, usually by finishing an upgrade. |
| 3 snapshot | Invalid snapshot. | Corruption: restore the journal or reset the cluster. |
| 4 raft | raft-rs error. | Restart and report it. |
| 5 other | Invalid config or refused member message. | Read the log line, then restart. |

Alert queries are in `telemetry-counters.md`.
