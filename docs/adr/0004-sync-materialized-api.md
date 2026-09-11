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

Subscriptions are exempt from the request idle timeout. A push that would take
pending output past 64 KiB closes the connection. The expiry sweep also closes
connections whose pending output has made no socket write progress for over
12 seconds. This measures writes accepted by the socket, not reads by the peer.
The pump queues keep-alive comments every 15 seconds, including when no events
are published.

`beacon_api` owns SSE framing, topic selection, and delivery to subscribers.
The tile calls `publish_block` without accessing connections. `/eth/v1/events`
serves `block` and rejects other topics with 400. Further topics and
silver-specific SSE routes can use the same subscription mechanism.

Amended 2026-09-10: `/eth/v1/events` also serves `block_gossip` for block
publication requests following silver's gossip checks. A request precedes
payload notification, state transition, and import; it does not guarantee
delivery to peers. This deliberately narrows the Beacon API's validation
contract: RPC block imports remain silent because they do not request relay.
The topic follows silver's relay policy, keeping its promise tied to gossip
publication without duplicating an observation on the spine. The boundary
selects block metadata on the existing `SendGossip` request, without reading
its payload; producers own topic consistency. The `block` topic still follows
`Applied` import receipts. These queues establish no shared ordering.
Repeated requests for one root are not deduplicated, and late subscribers
receive no replay. Subscribers to both topics can reach the existing send
cap sooner.

Amended 2026-09-10: `/eth/v1/events` also serves `data_column_sidecar` for
column publication requests following silver's gossip checks, including KZG.
This deliberately narrows the Beacon API's validation contract: validation
without a publication request produces no event. The boundary selects
column metadata on `SendGossip` or `PublishDataColumn`, without reading
payload bytes or filtering by custody. Producers own topic consistency.
Control's converted request stays off the spine, avoiding a second
notification. These events acknowledge requests, including RPC requests
that can fail before encoding; they do not guarantee delivery to peers.
Buffered copies, RPC columns processed while syncing, held copies, and EL
reconstruction remain silent under the existing publication policy.
`Persist` and `Available` retain their existing meaning and selection.
Repeated requests are not deduplicated, and late subscribers receive no
replay. The `beacon_events` and `peer_events` queues establish no shared
ordering. Additional subscriptions can reach the existing send cap sooner.
