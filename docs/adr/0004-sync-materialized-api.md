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

This holds for the whole surface v1 targets: verified against the
beacon-APIs spec and five validator clients (see
`.local/beacon-api-vc-surface.md`, untracked), nothing a validator client
requires streams or long-polls except the optional `/eth/v1/events` SSE
stream, which every surveyed client can replace with polling. v1 answers it
with a clean 404 and tolerates client reconnect retries. If subscriptions
are ever wanted, they may be served out-of-process (e.g. a circular-buffer
export read by a separate serving process) rather than by adding streaming
here. Endpoints whose response cannot be materialized in a bounded buffer
are out of scope by construction; revisit this ADR before accepting one.
