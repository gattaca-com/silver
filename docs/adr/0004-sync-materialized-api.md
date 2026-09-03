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
