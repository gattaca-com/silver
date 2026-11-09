# Telemetry counters

`silver_telemetry` exports two kinds of counts to ClickHouse, one row per slot
for each count that moved:

| Table | Source | Row key |
|---|---|---|
| `log_counts` | every `silver_log::warn!` / `error!` call site | `level`, `file`, `line`, `template` |
| `counters` | the `declare_counters!` groups listed in `EXPORTED` (`crates/telemetry/src/counters.rs`) | `component`, `name` |

The log messages themselves stay only in the node's log file.

## How log counts work

1. Each `silver_log::warn!`/`error!` expands to a `static` `LogSite` holding its
   level, `file!()`, `line!()` and format string. The linker gathers all of them
   into one slice, `LOG_SITES`. A site's position in that slice is its counter
   index.
2. At startup, the node writes one `log-names` line per site. It then recreates
   `counters-log` with one zeroed counter per site. Both files sit next to the
   other `counters-*` files.
3. Every event is one atomic add on its site's counter. No subscriber and no
   lookup are involved.
4. Once per slot, the daemon reads `counters-log` and inserts the deltas,
   labelled by the matching `log-names` line. When the node restarts, the daemon
   rereads both files and counts from zero.

A new log line becomes a new row type with no registration. A message with no
format string, such as `warn!(%e)`, is labelled with its whole argument list.

Only `silver_log` callsites are counted. Flux and dependencies logging through
`tracing` or the `log` crate (rustls, mio, raft) have no rows. Their messages
are in the log file.

## How counters work

`counters` rows come from the existing `counters-{component}` files that surfer
also reads. `value` is the reading at the end of the slot. `delta` is the change
during it, negative for a falling gauge. To export another group, add its name
to `EXPORTED`; its names come from `silver_stages::counter_names`.

## Finding the data

`silver_telemetry` reads its ClickHouse address from the node config it gets
with `--config`. On a node:

```sh
ps -o args= -C silver_telemetry          # shows --config <path>
grep clickhouse_addr <path>              # host:port of the native protocol
```

The telemetry log also prints it at startup: `clickhouse inserts open ... addr=`.
Query the same host, e.g. over its HTTP interface (port 8123 by default).

## Investigating an error

1. Find the noisy or new types:

   ```sql
   SELECT level, template, file, line, sum(count) AS events,
          min(slot_start_date_time) AS first, max(slot_start_date_time) AS last
   FROM log_counts
   WHERE meta_client_name = '<node>'
     AND slot_start_date_time > now() - INTERVAL 1 DAY
   GROUP BY level, template, file, line
   ORDER BY events DESC
   LIMIT 20
   ```

   New types are those whose `first` falls inside the window.
2. Read the code at `file:line` for the row's `version` commit.
3. Pull the real messages from the node's log. `LOG_PATH` is in the node's
   environment, and files are named `silver.<date>`:

   ```sh
   sed 's/\x1b\[[0-9;]*m//g' "$LOG_PATH/silver.<date>" | grep '<template words>' | grep '<HH:MM>'
   ```

4. Correlate with `counters` and `block_events` for the same slots.

## Cluster alerts

These queries watch the `cluster` component. Nothing in this repository runs
them; wire them into whatever alerting the deployment uses. Each returns one
row per node that should alert, so an empty result means healthy.

A `counters` row exists only for a slot where the value moved. The current
value of a gauge is therefore its newest row, `argMax(value, slot)`. Event
counters are summed from `delta`.

Proposals timed out in at least 3 of the last 25 slots (about 5 minutes):

```sql
SELECT meta_client_name, count() AS slots, sum(delta) AS timeouts
FROM counters
WHERE component = 'cluster' AND name = 'ProposalsTimedOut' AND delta > 0
  AND slot_start_date_time > now() - INTERVAL 5 MINUTE
GROUP BY meta_client_name
HAVING slots >= 3
```

Raft processing has stopped (`Failed` is 1). It resets to 0 on restart.
`FailureKind` gives the cause; `slashing-protection-cluster.md` maps each kind
to its action:

```sql
SELECT meta_client_name,
       argMaxIf(value, slot, name = 'Failed') AS failed,
       argMaxIf(value, slot, name = 'FailureKind') AS kind
FROM counters
WHERE component = 'cluster' AND name IN ('Failed', 'FailureKind')
GROUP BY meta_client_name
HAVING failed = 1
```

More than 3 leader changes in the last hour. Each node counts the changes it
sees, so a cluster-wide election shows on every node:

```sql
SELECT meta_client_name, sum(delta) AS changes
FROM counters
WHERE component = 'cluster' AND name = 'LeaderChanges'
  AND slot_start_date_time > now() - INTERVAL 1 HOUR
GROUP BY meta_client_name
HAVING changes > 3
```

Any conflicting or surrounding lock, for attestations or blocks. Any of them
means two signers exist for one validator:

```sql
SELECT meta_client_name, name, sum(delta) AS locks, min(slot) AS first_slot
FROM counters
WHERE component = 'cluster'
  AND name IN ('AttestationLockConflicting', 'AttestationLockSurrounding', 'BlockLockConflicting')
  AND delta > 0 AND slot_start_date_time > now() - INTERVAL 15 MINUTE
GROUP BY meta_client_name, name
```

The lock snapshot no longer fits one cluster message, so compaction is
skipped and the journal grows. The cap holds about 150k validators signing
through the cluster:

```sql
SELECT meta_client_name, sum(delta) AS skipped
FROM counters
WHERE component = 'cluster' AND name = 'CompactionsSkipped'
  AND delta > 0 AND slot_start_date_time > now() - INTERVAL 1 HOUR
GROUP BY meta_client_name
```

The lock snapshot is past 12 MiB of its 16 MiB cap, an early warning for the
alert above:

```sql
SELECT meta_client_name, argMax(value, slot) AS bytes
FROM counters
WHERE component = 'cluster' AND name = 'SnapshotBytes'
GROUP BY meta_client_name
HAVING bytes > 12 * 1024 * 1024
```

The wall clock runs over an epoch ahead of the head. Slashing protection then
admits and floors against the head-capped slot instead:

```sql
SELECT meta_client_name, argMax(value, slot) AS ahead
FROM counters
WHERE component = 'cluster' AND name = 'ClockAheadSlots'
GROUP BY meta_client_name
HAVING ahead > 0
```

The startup floor has been unlatched for more than 5 minutes on a live node.
The node refuses all duties until it latches. A node that has never latched has
no `FloorLatched` row at all, so liveness comes from `CommitIndex`, which moves
every slot:

```sql
SELECT meta_client_name,
       argMaxIf(value, slot, name = 'FloorLatched') AS latched,
       maxIf(slot_start_date_time, name = 'FloorLatched') AS latched_changed,
       maxIf(slot_start_date_time, name = 'CommitIndex') AS last_commit
FROM counters
WHERE component = 'cluster' AND name IN ('FloorLatched', 'CommitIndex')
  AND slot_start_date_time > now() - INTERVAL 1 DAY
GROUP BY meta_client_name
HAVING last_commit > now() - INTERVAL 2 MINUTE
   AND latched = 0 AND latched_changed < now() - INTERVAL 5 MINUTE
```
