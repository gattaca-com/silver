# Spine message flow between tiles

Silver's five tiles communicate over **spine queues** — typed SPMC channels declared in
`crates/common/src/spine.rs`. Small typed messages travel on the queues; bulk payloads
live in **tcaches** (shared-memory rings) and queue messages carry `TCacheRead` refs into
them (see [tcaches](#tcaches)).

The tiles: **Network** (QUIC + discv5), **Control** (`PeerManager` + `SyncEngine` +
`GossipHandler` — gossipsub decode/encode runs in-tile, not as its own tile),
**BeaconState** (state transition + fork choice), **Storage** (disk + backfill),
**Engine** (EL / engine API).

```mermaid
flowchart LR
  NET["Network<br/><i>QUIC · discv5</i>"]
  CTL["Control<br/><i>PeerManager + SyncEngine + GossipHandler</i>"]
  BS["BeaconState<br/><i>state · fork choice</i>"]
  ST["Storage<br/><i>disk · backfill</i>"]
  EN["Engine<br/><i>EL / engine API</i>"]

  %% ---- inbound ----
  NET -.->|"incoming_gossip (tcache)"| CTL
  CTL -->|new_gossip : NewGossipMsg| BS
  CTL -->|new_gossip : NewGossipMsg| ST
  NET -->|rpc_inbound : RpcInbound| CTL
  NET -->|rpc_inbound : RpcInbound| BS
  NET -->|rpc_inbound : RpcInbound| ST

  %% ---- outbound ----
  CTL -->|p2p_send : P2pSend| NET
  ST  -->|p2p_send : P2pSend| NET

  %% ---- peer management ----
  NET -->|peer_events : PeerEvent| CTL
  ST  -->|peer_events : PeerEvent| CTL
  BS  -->|peer_events : PeerEvent| CTL
  CTL -->|peer_control : PeerControl| NET
  CTL -->|peer_control : PeerControl| ST

  %% ---- chain state & DA ----
  BS -->|beacon_events : BeaconStateEvent| CTL
  BS -->|beacon_events : BeaconStateEvent| ST
  ST -->|data_columns : DataColumnsAvailable| BS
  ST -->|replay_blocks : ReplayBlock| BS

  %% ---- sync control ----
  CTL -->|sync_target : SyncUpdate| BS
  CTL -->|sync_target : SyncUpdate| ST
  CTL -->|syncing_strategy : SyncingStrategy| ST

  %% ---- engine / EL ----
  BS -->|engine_reqs : EngineReq| EN
  ST -->|"engine_reqs : EngineReq (GetBlobs)"| EN
  EN -->|engine_resps : EngineResp| BS
  EN -->|"engine_resps : EngineResp (GetBlobs)"| ST

  classDef net fill:#fef2f2,stroke:#fca5a5,color:#0f172a;
  classDef ctl fill:#f5f3ff,stroke:#c4b5fd,color:#0f172a;
  classDef bs  fill:#ecfdf5,stroke:#6ee7b7,color:#0f172a;
  classDef st  fill:#fffbeb,stroke:#fcd34d,color:#0f172a;
  classDef en  fill:#fdf4ff,stroke:#f0abfc,color:#0f172a;
  class NET net; class CTL ctl; class BS bs; class ST st; class EN en;
```

Solid arrows are spine queues (`queue : MessageType`), one per consumer since queues are
SPMC. The dashed edge is the exception: `incoming_gossip` is the *tcache* carrying raw
protobuf Network → Control (no spine queue on that hop — the gossip handler's queued
output is `new_gossip`). The gossip handler's other traffic is in-tile, not on the
spine: its `PeerEvent`s (gossipsub scoring/misbehaviour) go straight to the
`PeerManager`, `PeerControl` is forwarded to the handler directly, and its fork digest
is set from the `Status` Control already consumes. `engine_health` is omitted
from the diagram: Engine produces it but no tile currently consumes it. Both
Storage↔Engine edges carry only the `GetBlobs` variants (EL-mempool blob fetch); the
queues are broadcast, so Storage sees every `EngineResp` and ignores the rest.

## Spine queues

| Queue | Message | Producer(s) | Consumer(s) | Carries |
|-------|---------|-------------|-------------|---------|
| `new_gossip` | `NewGossipMsg` | Control _(gossip)_ | BeaconState, Storage | refs → `incoming_gossip`, `ssz_gossip` |
| `p2p_send` | `P2pSend` | Control, Storage | Network | refs → `outgoing_gossip` / `outgoing_rpc` |
| `rpc_inbound` | `RpcInbound` | Network | Control, BeaconState, Storage | ref → `incoming_rpc` |
| `peer_events` | `PeerEvent` | Network, Storage, BeaconState | Control | inline |
| `peer_control` | `PeerControl` | Control | Network, Storage | inline |
| `beacon_events` | `BeaconStateEvent` | BeaconState | Control, Storage | inline |
| `data_columns` | `DataColumnsAvailable` | Storage | BeaconState | inline |
| `sync_target` | `SyncUpdate` | Control | BeaconState, Storage | inline |
| `replay_blocks` | `ReplayBlock` | Storage | BeaconState | ref → `replay_blocks` tcache |
| `syncing_strategy` | `SyncingStrategy` | Control | Storage | inline |
| `engine_reqs` | `EngineReq` | BeaconState, Storage _(GetBlobs)_ | Engine | refs → `ssz_gossip` / `incoming_rpc`; GetBlobs inline |
| `engine_resps` | `EngineResp` | Engine | BeaconState, Storage _(GetBlobs)_ | ref → `incoming_engine_resp` |
| `engine_health` | `EngineHealthEvent` | Engine | _none (currently unconsumed)_ | inline |

## TCaches

Bulk-byte rings that the queue messages reference, so payloads cross tiles without copying.

| TCache | Producer | Consumer(s) | Payload |
|--------|----------|-------------|---------|
| `incoming_gossip` | Network | Control _(gossip)_ | raw gossipsub protobuf from the wire |
| `ssz_gossip` | Control _(gossip)_ | BeaconState, Storage (live + persist), Engine | decompressed gossip SSZ |
| `outgoing_gossip` | Control _(gossip)_ | Network | protobuf to publish / re-broadcast |
| `incoming_rpc` | Network | BeaconState, Storage (live + persist), Engine | RPC response bodies (BeaconBlock / DataColumnSidecar) |
| `outgoing_rpc` _(multi-producer)_ | Control, Storage | Network | RPC request bodies (we ask) + served response bodies (we answer) |
| `replay_blocks` | Storage | BeaconState | persisted block SSZ replayed at startup |
| `incoming_engine_resp` | Engine | BeaconState, Storage (GetBlobs) | EL responses (payloads, blobs, bodies) |

---

Source of truth: `crates/common/src/spine.rs` (queue declarations), `crates/bin/src/main.rs`
(tcache producer/consumer wiring), and each tile's `loop_body`. Regenerate when the spine
changes.
