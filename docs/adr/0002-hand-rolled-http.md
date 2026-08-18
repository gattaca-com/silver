---
status: proposed
---

# Hand-rolled HTTP over mio; no async runtime, no TLS

API I/O uses the same idiom as the rest of the node: non-blocking mio polled
from a busy-poll loop with `httparse` framing — one shared connection state
machine (crate `httpcore`) serving both roles, server and client — rather
than hyper/axum/reqwest and the tokio runtime they drag in. The node has no
async runtime and will not grow one for its coldest path; the machine already
existed twice (engine `http.rs` and the beacon_api prototype, plus a dead
474-line UDS copy) and, once shared, is small and testable at the byte level.

Transports are a closed set we control, so they are an enum
(`Tcp | Uds`), not a trait. Unix sockets are supported on both sides: the
beacon_api server bind and the execution endpoint. TLS is a non-goal — all
API connections run over trusted local LAN or VPN. That transitively rules
out QUIC/HTTP-3 for API surfaces (considered and rejected 2026-08-18): QUIC
mandates TLS 1.3 (RFC 9001), and no validator client speaks HTTP/3, so
there would be no consumers even if the TLS stance changed. Auth is protocol-layer,
not transport-layer: `engine_api` owns the JWT Authorization header; UDS
relies on socket path permissions, and JWT-over-UDS can be added later as an
`engine_api` config flag without touching the transport layer.
