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

## Shuffling cache misses

The `beacon_state` component counts epoch shufflings built during request handling:

| Counter | Request path |
|---|---|
| `AttestationShufflingCacheMiss` | Single attestations and aggregates |
| `BlockShufflingCacheMiss` | Block verification |
| `BlockProductionShufflingCacheMiss` | Block production |

A cold block request can build two epoch shufflings and increment its counter twice.
Cache hits, precomputation, slot-tick warming and API publication do not increment these counters.
Requests later rejected by validation can still contribute misses. These are counts,
not miss rates or elapsed time; there is no corresponding hit counter.

`BlockShufflingUncached` counts block requests that compute both shufflings without
resolved cache identities. This fallback leaves keyed entries untouched. It is
reported separately because increasing cache capacity cannot resolve a missing identity.

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
