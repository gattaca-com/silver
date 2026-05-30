# Local kurtosis devnet for peer-connection debugging

A controlled, multi-client ethereum devnet for testing silver's peer behaviour
against real CL clients **whose logs you can read**. The point is two-sided
visibility: every silver `connection lost` / `received goodbye` / eviction can
be matched against the peer's own account of why it dropped silver, same wall
clock.

Containers, not VMs — kurtosis runs the clients as Docker containers; silver
runs as a **bare host process** and joins the enclave over the Docker bridge.

## What this is (and isn't) for

- **Good for:** protocol correctness — handshake, RPC framing, gossip scoring,
  Status/Goodbye semantics, "why did silver drop a healthy peer", multi-client
  behaviour differences.
- **Not for:** the zombie-dial / timeout / peer-supply class. Everything here
  is same-host: near-zero RTT, no loss, no NAT, always enough peers. Those bugs
  only reproduce on the real internet from a clean source IP. Use a public
  Fulu/PeerDAS devnet for that.

Linux only — the host-process-joins-the-bridge model and `external_ip_v4`
detection are Docker-bridge specific.

## Prerequisites

`kurtosis`, `docker`, `curl`, `jq`, and a Fulu-capable silver build.

## Quick start

```bash
# 1. bring up the devnet + harvest config values into silver-devnet.json
kurtosis/setup.sh                       # enclave name defaults to silver-dev

# 2. run silver against it (zero source edits)
RUST_LOG=info,silver_network=info,silver_peer=info \
  cargo run --release --bin silver -- --config kurtosis/silver-devnet.json

# 3. (optional) watch live counters
cargo run -p silver_surfer -- ~/.local/share silver                 # counters-network / counters-peer
```

## Files

| File                 | Purpose                                                        |
|----------------------|---------------------------------------------------------------|
| `net.yaml`           | kurtosis `ethereum-package` args: 4 participants, Fulu-from-genesis, CL at debug. |
| `setup.sh`           | Spins up the enclave, harvests the network values, merges them into the config in place. |
| `silver-devnet.json` | silver `Config` (JSON). `setup.sh` fills the derived fields; you own `secret_key` / ports. |
| `genesis.ssz`        | Genesis state, fetched by `setup.sh` as silver's sync anchor. Generated (gitignored via `*.ssz`); referenced by `chain_config.checkpoint_file`. |

## How `setup.sh` wires silver to the enclave

silver's bin takes a full `Config` from `--config <file>`. The script derives
the four network-specific values and merges them into `silver-devnet.json`,
preserving `secret_key` / ports / `next_fork_*`:

| Field                          | Source                                                          |
|--------------------------------|----------------------------------------------------------------|
| `fork_digest`                  | dominant `/eth2/<digest>/` topic in a CL's debug logs (client ground truth — avoids the Fulu modified-digest computation). |
| `chain_config.genesis_unix_secs` | `/eth/v1/beacon/genesis`                                      |
| `chain_config.bootstrap_enrs`  | `/eth/v1/node/identity` for each CL node                        |
| `external_ip_v4`               | `kt-<enclave>` Docker bridge gateway (so peers can dial silver back; non-fatal). |
| `chain_config.spec`            | `/eth/v1/config/spec` — devnet fork versions + blob schedule. silver derives the fork digest **and** BLS signing domains from these; mainnet defaults mismatch (wrong digest → no peers; wrong domain → blocks fail sig verification). |
| `chain_config.checkpoint_file` | `genesis.ssz` fetched from `/eth/v2/debug/beacon/states/genesis` — silver's sync anchor (bootstraps fork choice so block 1's parent, the genesis block, resolves). |

On Linux the enclave's `172.x` container IPs are routable from the host, so
silver dials them directly (no port-publishing). `next_fork_version` /
`next_fork_epoch` are cosmetic — they decorate silver's own ENR but don't gate
peering. `secret_key` is any 32-byte hex; a fixed value gives silver a stable
peer-id/ENR across restarts.

Re-run `setup.sh` after an enclave restart to re-sync (only the derived fields
change).

## Viewing node logs

```bash
# list services (and their names) in the enclave
kurtosis enclave inspect silver-dev

# follow one node's logs (-f = tail; drop it to dump the full buffer)
kurtosis service logs -f silver-dev cl-1-lighthouse-geth

# the matching execution-layer client
kurtosis service logs -f silver-dev el-1-geth-lighthouse

# all services at once
kurtosis service logs -f silver-dev
```

Service names follow `cl-<n>-<cl>-<el>` (consensus) and `el-<n>-<el>-<cl>`
(execution) — confirm the exact names with `enclave inspect`. With the default
`net.yaml` the CL nodes are `cl-1-lighthouse-geth`, `cl-2-lighthouse-reth`,
`cl-3-lighthouse-nethermind`, `cl-4-prysm-geth`.

## Correlating both sides

```bash
# silver's view: dial/accept outcomes, disconnect reasons, eviction breakdowns
RUST_LOG=...silver_network=info,silver_peer=info cargo run ... --config ...

# the peer's view of the same events
kurtosis service logs -f silver-dev cl-1-lighthouse-geth
```

`dora` (block explorer URL printed by `setup.sh` / `kurtosis enclave inspect`)
confirms the chain is producing and finalizing.

## Compatibility notes

- **QUIC-only:** silver dials a peer only if its ENR advertises a `quic`
  socket. Lighthouse enables QUIC by default — hence the lighthouse-heavy
  participant set in `net.yaml`. A non-QUIC client is skipped (silver logs
  `Peer does not support quic`).
- **`preset: mainnet`** in `net.yaml` matches silver's default
  `SpecConfig::mainnet()`. Minimal preset would desync slot/epoch math.
- **Version-sensitive (upstream, not silver):** the `*_fork_epoch` keys in
  `net.yaml` and the `http` beacon-API port-id used by `setup.sh` track
  `ethereum-package` churn. If `setup.sh` fails resolving a URL or the chain
  won't start, check these against the package version you pulled.

## Teardown

```bash
kurtosis enclave rm -f silver-dev
```
