---
status: accepted
---

# One tile hosts all API access

Every tile is an OS thread pinned to a dedicated CPU core, and API traffic —
serving the beacon API, calling the engine API — is latency-tolerant work
dominated by network round-trips that cannot justify two pinned cores. All API
access is consolidated into a single `application_boundary` tile hosting two
transport-free crates: `beacon_api` (HTTP server) and `engine_api` (HTTP
client, renamed from `engine`). Hosted crates are hardcoded and composed by
plain function calls in the tile's `loop_body` — no plugin registry, no
hosting trait; adding a future hosted crate (e.g. a builder-API client or a
`health`/`log_tail` endpoint family) edits the tile, which is a deliberate,
cheap cost. The spine contract is unchanged: producers and consumers of
`engine_reqs`/`engine_resps`/`engine_health` see no difference.

## Considered options

Separate tiles per API surface (status quo — wastes a core per surface); a
`Hosted` trait + registry (speculative generality for exactly two crates);
per-crate transport ownership behind a port trait (generics leak into every
hosted crate's signatures).
