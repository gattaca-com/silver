---
status: accepted
---

# Synchronous handlers, materialized responses, and SSE subscriptions

Consolidated 2026-09-16. This document describes the accepted design;
Git history retains the earlier decisions and amendments.

## Request handling and shared I/O

Beacon API handlers run synchronously after a request has fully arrived.
They perform no I/O. Immediate responses are materialized in the connection's
write buffer, which the transport drains incrementally. Block-by-root
requests instead wait for a storage response before materialization.

The application boundary hosts the beacon API server and engine API client
on one thread. Both register sockets with a shared `Poll`, using disjoint
token ranges. Non-blocking transport lets the tile interleave their I/O.
Slow socket consumers do not require blocking writes, but synchronous
handler computation still delays other work on the tile.

The tile uses `poll(Duration::ZERO)`. Supporting parked API tiles requires
socket readiness to wake the tile, rather than relying only on spine
publications. A shared readiness loop remains necessary so waiting for
one API's sockets does not starve the other.

## Storage-backed block requests

`/eth/v2/beacon/blocks/{block_id}` serves blocks by root as SSZ. The handler
queues a storage request and leaves the connection waiting with a request ID.
Storage replies through `beacon_api_responses`; the API then frames the
response into that connection. Requests travel through `beacon_api_requests`.
Only one request waits per connection. A connection without a storage reply
closes on the idle timeout. Block-root and header routes remain 501 stubs.

## Materialization limits

Materializing a response does not by itself bound its size or rendering
cost. The 2026-08-20 investigation measured approximately 1 GiB and 0.9 seconds
for an unfiltered mainnet validator registry response. These are historical
measurements, not bounds on supported responses. Such rendering would delay
engine traffic on the shared thread.

The validator registry, duties, liveness, and configured per-block read
routes remain 501 stubs. Serving them requires the missing data or a design
that addresses rendering cost. The route table defines the exact surface.

Peer listing and peer counts are served. Their inventory tracks established
connections through connection and disconnection events. Other connection
state counts are zero, and peer ENRs are returned as `null`.

## SSE transport and ownership

`/eth/v1/events` serves `block`, `head`, `head_v2`, `block_gossip`, and
`data_column_sidecar`. Unsupported topics reject the subscription with 400.
Subscriptions receive future events without an initial snapshot or replay.

`beacon_api` owns event selection, JSON rendering, SSE framing, and delivery.
The application boundary forwards spine events and sync updates; it holds
no head-observation state. The API reuses a frame buffer across publications.

`ChunkedResponse` in `silver_httpcore` owns HTTP chunk framing and pending
subscription output. After queuing the response head, the connection
replaces its `ServerConnection` with this machine. Each SSE frame occupies
one HTTP chunk. Closing the connection ends the stream without a terminal
chunk.

### Backpressure and timeouts

Delivery first drains existing output, then checks whether the new chunk
fits within the 512 KiB pending-output cap. The cap includes HTTP framing
and the pending response head. If the chunk fits, delivery queues it and
tries to drain again; otherwise, the connection closes.

Each drain writes until the buffer is empty or the socket returns
`WouldBlock`. Unrecoverable write errors close the connection. Successful
writes reset the send deadline while output remains pending; draining it
clears the deadline. Progress means kernel acceptance, not peer consumption.

Subscriptions are exempt from the request idle timeout. The expiry sweep
closes a connection after pending output makes no write progress for over
30 seconds. The pump queues keep-alive comments every 15 seconds, including
when no events are published.

Each subscription reserves its output buffer at construction and retains
it until closing. At 64 subscriptions, the pending-output allowance totals
32 MiB. A full drain reuses the buffer from its beginning; partial drains
can advance through the allocation. Bursts across several subscribed topics
share the same cap and can exhaust it.

## Head observations and notifications

`BeaconStateEvent::Status` carries the selected block's declared state root,
duty-dependent roots, execution optimism, and empty/full payload resolution.
An end-of-loop check publishes changes in the selected root, optimism, or
payload resolution since the last Status. The publication marker is separate
from the reorg marker, so an earlier Status cannot hide a reorg notification.
Replay can publish intermediate observations; completion still requires
`ReplayComplete`.

Beacon-state classifies each Status against its last published head.
With complete head roots and a prior observation, `head_change` is `Head`
when the root or optimism differs. It is `Payload` when only the payload
resolution differs, and `None` otherwise. The first Status and any Status
with incomplete head roots carry `None`. Every published Status becomes
the baseline, including incomplete observations. Overwritten checkpoint
history can make dependent roots unavailable.

`epoch_transition` compares the head block's epoch with its parent's epoch.
It is true when the head's epoch is later, and false when no parent is
available. A reorg between heads in the same epoch can therefore carry
`true` when the new head's parent belongs to an earlier epoch.

The beacon API publishes `head` for `Head`, and `head_v2` for `Head` and
`Payload`, only while its latest sync update reports following.
Payload changes include both empty-to-full and full-to-empty transitions.
The v2 `version` names the configured fork at the head block's slot;
selected pre-Gloas blocks report `full`.

Control waits for disk replay to finish or be skipped before reporting
following. The API suppresses head notifications while its latest sync
update indicates restoration or network catch-up. Following is a sync mode;
it does not guarantee execution validation or a block at the current slot.

Status and sync updates travel on separate queues. The boundary drains
beacon events before sync updates, so observations drained alongside a mode
change use the earlier mode. An observation queued between those drains
uses the updated mode in the next iteration. This introduces one iteration
of imprecision around mode changes. Node-status updates and block
notifications remain independent of the mode.

## Block and sidecar notifications

The `block` topic follows `BlockReceived` receipts at stage `Applied`.
These notifications can precede payload validation, so events are marked
optimistic. Repeated notifications are not deduplicated.

`block_gossip` follows `SendGossip` requests on the beacon-block topic after
Silver's gossip checks. Requests precede payload notification, state
transition, and import. RPC imports remain silent because they do not
request relay. This deliberately narrows the Beacon API's validation
contract to Silver's publication policy.

`data_column_sidecar` follows `DataColumnsEvent::Persist`. The API uses the
receipt's slot, block root, and column index directly. It does not read
sidecar bytes or require a separate gossip publication request. `Available`
does not trigger a sidecar event.

Block gossip events acknowledge publication requests; they do not guarantee
delivery to peers. Sidecar events acknowledge persistence requests, not
completed disk writes. Repeated notifications are not deduplicated. The
beacon, peer, and data-column event queues establish no shared ordering.

### Reading block publication data

Block publication requests carry handles to decompressed SSZ bytes in the
gossip cache. The API computes block roots, including body hashes, even
when no clients subscribe to `block_gossip`. If the cache has overwritten
a block's bytes, the API logs a warning and emits no event for that request.
This does not cancel the publication request.

## Node status

API construction requires a published anchor and seeds node status from it.
The health endpoint has no separate uninitialized response: before the first
sync update, it returns the syncing code, which defaults to 206.
The anchor is reported as not optimistic, matching fork choice's trusted
anchor. `is_syncing` is true until a sync update arrives, then reflects
whether the latest update reports following.

`sync_distance` measures slots from the imported head to Control's sync
target. While stalled, it measures slots from the imported head to the wall
slot in the latest `Status`. Both distances saturate at zero. It is zero
while following and `u64::MAX` before the first sync update.

The `finalized` envelope flag compares the served state's latest block slot
with the cached finalized epoch's first slot. It is true when the block is
at or before that slot.

### Loss of synced status

Control determines whether the node is synced. When it cannot follow and
has no selectable sync target, it enters `Phase::Stalled` and publishes
`SyncUpdate::Stalled`. This applies after following or syncing, and when
the first peer observations establish that the node cannot follow.
Repeated evaluations of the same stall publish no further update.

Without a selectable target, a block gap prevents following when no peer
claims a head within the configured lag behind ours or ahead. The gap is a
consecutive run of unknown block slots after the sync window's covered
tail, bounded by the wall slot. It must reach `head_lag_threshold_slots`.
A known block or proven-empty slot ends the run. Peers claiming heads more
than the configured lag ahead also prevent following, even when their
chains cannot be selected.

`Stalled` reports that the node is not synced while preserving live
processing. Beacon state continues slot ticks, status publication, and
gossip imports. Columns remain eligible for relay, and storage processes
history as it does while following. These consumers distinguish a selected
sync target through `is_syncing()`.

The API uses `is_following()` to determine whether the node is synced and
to gate head-event publication.
While stalled, it reports `is_syncing: true`, returns the syncing health
code, and suppresses `head` and `head_v2` events. Slot updates keep Control's
wall slot and the API's distance current. The API applies no independent
lag threshold.

Control continues requesting peer statuses while stalled with a block gap.
A peer claim within the lag or restored block coverage can restore
`Following`. A selectable target ahead starts syncing. Target selection
reevaluates both paths while stalled. Abandoning the last usable sync target
enters `Stalled` when following is not possible, allowing gossip imports
and slot ticks to resume.

Control starts idle until local status and a peer comparison are available.
Transitions to following or stalled wait for disk replay to finish or be
skipped. Until then, an already selected sync target remains visible.
Publication reflects the resulting phase; the previous update is retained
only to suppress duplicate publications.

The peer comparison uses cached head slots, without expiring claims or
requiring matching block roots. An equally stale peer can therefore
preserve synced status indefinitely. This policy permits following through a
quiet chain but does not distinguish it from peers that stall together.
