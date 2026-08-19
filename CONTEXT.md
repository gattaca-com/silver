# Silver

A from-scratch Ethereum beacon node, organised as tiles — independent
pinned-thread components communicating over a typed message spine.

## Language

**Tile**:
A component with its own OS thread pinned to a dedicated CPU core,
implementing `loop_body` and attached to the spine.
_Avoid_: service, actor, worker.

**Spine**:
The process-wide typed message fabric connecting tiles.
_Avoid_: bus, broker.

**Spine queue**:
A fixed-size lock-free ring on the spine carrying `Copy` messages, broadcast
to consumers.
_Avoid_: channel.

**TCache**:
The shared-memory bulk store; spine messages carry handles into it instead of
payloads.

**Hosted crate**:
A transport-free library living inside a tile that owns the loop. Hosted
crates are hardcoded into their tile, not plugins.
_Avoid_: plugin, sub-tile, service.
