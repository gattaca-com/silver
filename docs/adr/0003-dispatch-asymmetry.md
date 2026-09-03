---
status: accepted
---

# Dispatch: table for server routes, enum match for client methods

Beacon-api request routing is a const data table — (method, parameterised
path pattern) → handler function, compiled to segments at init and linearly
scanned. Engine-api call dispatch stays a Rust `match` on closed enums
(`EngineReq` inbound, `ReqKind` on completion). The asymmetry is deliberate:
the server-side endpoint set is open and keyed by runtime wire strings, so a
table earns its keep; the client-side protocol set is closed and minted by
us, where a match is already a compile-time-exhaustive jump table, and a
runtime table would force type erasure over encoders with genuinely
different shapes (TCache handles, the hand-written newPayload envelope),
trading compile errors for runtime failures.

Do not "fix" this inconsistency by making the client side table-driven: four
independently-produced designs each converged on exactly this split. The
governing principle, which also chose the transport enum in ADR-0002:
**closed set we control → enum; open set from the wire → table.**
