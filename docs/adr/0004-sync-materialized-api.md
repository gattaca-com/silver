---
status: proposed
---

# Synchronous handlers, materialized responses, no streaming

Beacon-api handlers are synchronous compute — no I/O, no blocking — invoked
only once a request has fully arrived; responses are materialized in the
connection's write buffer and drained incrementally. All transport pumps are
non-blocking (`poll(Duration::ZERO)`), so serving and engine traffic
interleave per readiness event: a slow API consumer never stalls engine
calls, and vice versa.

This holds for every request/response endpoint in the targeted surface:
verified against the beacon-APIs spec and five validator clients (see
`.local/beacon-api-vc-surface.md`, untracked), nothing a validator client
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
