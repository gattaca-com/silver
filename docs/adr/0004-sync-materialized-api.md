---
status: accepted
---

# Synchronous handlers, materialized responses, no streaming

Beacon-api handlers are synchronous compute — no I/O, no blocking — invoked
only once a request has fully arrived; responses are materialized in the
connection's write buffer and drained incrementally. All transport pumps are
non-blocking (`poll(Duration::ZERO)`), so serving and engine traffic
interleave per readiness event: a slow API consumer never stalls engine
calls, and vice versa.

This holds for every request/response endpoint in the targeted surface:
verified against the beacon-APIs spec and five validator clients (Teku,
Lighthouse, Nimbus, Prysm, Vouch), nothing a validator client
requires streams or long-polls except the `/eth/v1/events` SSE stream.

Amended 2026-08-18: SSE is in scope — validator clients will not be asked
to poll. It will be served in-process as an explicit subscription-mode
carve-out on the server connection machine (a long-lived, mostly idle
connection with small appended writes — deliberately outside this ADR's
bounded-buffer model), fed from a spine events queue produced by the
beacon-state tile. Implementation is scheduled after the initial endpoint
surface; the 404 served for `/eth/v1/events` today is interim behavior,
not the decision, and the previously-floated out-of-process serving option
is no longer the plan of record. Everything else stays materialized in a
bounded buffer by construction — the SSE carve-out is the single
sanctioned exception, and its design round amends this ADR with the
concrete mechanism.

Amended 2026-08-20: the bounded-buffer claim is not universal. A validator
registry response is bounded only by the registry — ~1GiB at mainnet scale —
because the beacon-APIs schema requires an empty filter to return every
validator, and refusing that answer is a compatibility wall: validator
clients submit their whole key set in one request, and go-eth2-client
deactivates a beacon node that answers 5xx. Serving it costs ~0.9s of
synchronous render on the tile, so the interleaving guarantee above holds
for I/O but not for compute: a handler that materializes a large body does
delay engine traffic, however non-blocking the transport beneath it. Both
follow from serving a request/response API on the thread that drives the
execution client, not from any one endpoint, and neither is bounded by the
connection write buffer, which releases its capacity after each response.

Amended 2026-08-21: `poll(Duration::ZERO)` is the busy-spin build's mechanism, not
the decision. Under `flux/park` a tile that reports no work parks unless it has
registered an `mio::Waker` with the flux work signal, and that signal fires on
spine publishes alone, so a parked tile would sleep through an inbound request. A
park build therefore needs the waker and a non-zero timeout, and both need one
readiness loop, since blocking in either of two would starve the other. The tile
serves the beacon-api server and the engine-api client from a single `Poll`, each
registering through its own share of the token space, so the interleaving above
follows from that loop rather than from the timeout being zero. The waker and the
timeout are what remain.

Amended 2026-08-24: the endpoints the 2026-08-20 amendment measured are not
served for now. The validator registry, duties, liveness, per-block reads and
peer counts answer 501: each needs data the node does not yet keep, or a
render that outruns the synchronous model above, and each is deferred to its
own PR rather than served from the wrong data. The ~1GiB/~0.9s registry
figures stand as the recorded cost a bounded-render design has to answer
before that endpoint returns.

Amended 2026-09-07: `ChunkedResponse` in `silver_httpcore` owns the HTTP chunk
framing and pending output for a subscription. The handler queues the response
head, then the connection replaces its `ServerConnection` with this machine.
Each SSE frame occupies one HTTP chunk. Closing the connection ends the stream
without a terminal chunk.

Subscriptions are exempt from the request idle timeout. After attempting to drain
existing output, a push that would take pending output past 512 KiB closes the
connection. The expiry sweep also closes connections whose pending output has
made no socket write progress for over 30 seconds. This measures writes accepted
by the socket, not reads by the peer.
The pump queues keep-alive comments every 15 seconds, including when no events
are published.

`beacon_api` owns SSE framing, topic selection, and delivery to subscribers.
The tile calls `publish_block` without accessing connections. `/eth/v1/events`
serves `block` and rejects other topics with 400. Further topics and
silver-specific SSE routes can use the same subscription mechanism.

Amended 2026-09-08: `/eth/v1/events` also serves the legacy `head` topic.
`BeaconStateEvent::Status` carries the selected block's declared state root
and both duty-dependent roots from its fork's history.

Status describes an observation. Each consumer decides which fields require
action. Existing publications remain, and an end-of-loop check covers changes
to the selected head or its execution optimism since the last Status.
The publication marker is separate from the reorg marker, so an earlier
Status cannot hide a reorg notification. Replay can emit intermediate
observations; completion still requires `ReplayComplete`.

The application boundary publishes a head event when a complete observation
changes the head root or optimism. The first complete observation establishes
a baseline. Incomplete metadata, including overwritten checkpoint history,
leaves that baseline unchanged. Node-status updates continue independently.

`epoch_transition` compares consecutive complete observations and is true
only when the head epoch advances. Same-block validation updates and backward
reorgs report false. New subscriptions receive future changes without an
initial snapshot.

Amended 2026-09-09: `/eth/v1/events` also serves `head_v2`. Status carries
fork choice's empty/full resolution of the selected block's own payload.
The end-of-loop check publishes an updated Status when this resolution
changes, even if the root and optimism stay the same.

The boundary publishes `head_v2` when the root, optimism or resolution
changes, including both empty-to-full and full-to-empty transitions. Legacy
`head` retains its root-and-optimism filter. Both topics use the same
complete observation. The v2 `version` names the configured fork at the head
block's slot; selected pre-Gloas blocks report `full`.

Amended 2026-09-10: `/eth/v1/events` also serves `block_gossip` for block
publication requests following silver's gossip checks. A request precedes
payload notification, state transition, and import; it does not guarantee
delivery to peers. This deliberately narrows the Beacon API's validation
contract: RPC block imports remain silent because they do not request relay.
The topic follows silver's relay policy, keeping its promise tied to gossip
publication without duplicating an observation on the spine. The boundary
selects `SendGossip` requests on the block topic. It reads the slot and
computes the block root from the relayed block's SSZ bytes. The `block` topic
still follows `Applied` import receipts. These queues establish no shared ordering.
Repeated requests for one root are not deduplicated, and late subscribers
receive no replay. Subscribers to both topics can reach the existing send
cap sooner.

Amended 2026-09-10: `/eth/v1/events` also serves `data_column_sidecar` for
column publication requests following silver's gossip checks, including KZG.
This deliberately narrows the Beacon API's validation contract: validation
without a publication request produces no event. The boundary selects
`SendGossip` requests on column topics and every `PublishDataColumn`. It
derives the slot, block root and column index from Fulu or Gloas sidecar
bytes, without filtering by custody. Control's converted request stays off the
spine, avoiding a second notification. These events acknowledge requests,
including RPC requests that can fail before encoding; they do not guarantee
delivery to peers.
Buffered copies, RPC columns processed while syncing, held copies, and EL
reconstruction remain silent under the existing publication policy.
`Persist` and `Available` retain their existing meaning and selection.
Repeated requests are not deduplicated, and late subscribers receive no
replay. The `beacon_events` and `peer_events` queues establish no shared
ordering. Additional subscriptions can reach the existing send cap sooner.

Amended 2026-09-14: publication requests carry handles to decompressed SSZ
bytes so API consumers can derive event fields without adding API-specific
metadata to those requests. The boundary reads `SendGossip` objects from
the gossip cache and `PublishDataColumn` objects from the RPC cache.
It computes each block root, including the body hash, even when no clients
subscribe to `block_gossip`. For Fulu sidecars, it computes the block root
from the five header fields. Gloas sidecars contain the block root directly.
If the cache has overwritten an object's bytes, the boundary logs a warning
and emits no event for that request. It also skips sidecars whose length
and column offset identify neither supported layout. These failures do not
cancel the publication request.

Amended 2026-09-11: `head` and `head_v2` describe changes observed while
Control reports following. Disk restoration, the wait for a replay strategy
and network catch-up produce no head notifications. Following is a sync
mode, not a guarantee of zero sync distance or execution validation.

The boundary keeps every complete observation as its baseline in every mode
and reports a change only while following. A following period therefore
starts from the head the node already has, and its first change is reported.
Status and sync updates travel on separate queues; the boundary reads the
mode once per iteration after draining beacon events, so an observation
drained in the same iteration as a mode change follows the earlier mode, and
one queued between the two drains is reported in the next iteration. The
imprecision is bounded by one iteration. Node-status updates and block
notifications remain independent of the mode.

Control waits for disk replay to finish or be skipped before reporting
following; previously the gate held only network requests, and disk replay
is chosen exactly when peers look comparable, so following could be announced
during replay. Completion re-evaluates the target. Beacon-state's Status
publications are unchanged.

Amended 2026-09-15: delivery first attempts to drain the subscription's existing
output, then checks whether the new chunk, including its HTTP framing, fits
under the 512 KiB pending-output cap. This lets socket capacity that became
available since the last write attempt free room before rejecting the chunk,
without waiting for the next writable-readiness event. If the chunk still does
not fit, the connection closes. Otherwise, delivery queues it and attempts to
drain again. The pending response head also counts against the cap.

Each drain writes until the buffer is empty or the socket returns `WouldBlock`;
unrecoverable write errors close the connection. Successful writes reset the
send deadline while output remains pending; draining it clears the deadline.
Progress means kernel acceptance, not peer consumption.

Amended 2026-09-14: the send cap is 512 KiB. This accommodates one block's
128 `data_column_sidecar` events with 21 commitments each, estimated at
290 KiB, even when the socket accepts no bytes. Earlier pending events or
repeated publications can still exhaust the allowance.

At 64 subscriptions, the pending-output allowance totals 32 MiB. Each
subscription reserves its buffer at construction and retains the allocation
until it closes. A full drain reuses the buffer from its beginning without
releasing it. Partial drains can advance through the entire allocation.
