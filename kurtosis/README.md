# Local kurtosis devnet

A multi-client ethereum devnet for testing silver against real CL clients whose
logs you can read. Every silver disconnect or eviction can be matched against
the peer's own account of it, on the same clock.

Use it for protocol behaviour: handshakes, RPC framing, gossip scoring,
Status/Goodbye, engine-API payload verdicts. Do not use it for timeout or
peer-supply bugs — everything here is same-host, with no loss and no NAT.

Linux only. silver joins the enclave over the Docker bridge, and
`external_ip_v4` detection is bridge-specific.

There are two ways to run silver against it:

- **as a host process**, with its own reth, wired up by `setup.sh`;
- **as a participant**, inside the enclave. See below.

## Prerequisites

`kurtosis`, `docker`, `curl`, `jq`, `reth`, and a Fulu-capable silver build.

## Quick start (host process)

```bash
# 1. start the devnet and write silver-devnet.toml
kurtosis/setup.sh                       # enclave defaults to silver-dev

# 2. start silver's reth (separate terminal, keeps running)
kurtosis/run-reth.sh

# 3. run silver
RUST_LOG=info,silver_network=info,silver_peer=info \
  cargo run --release --bin silver -- --config kurtosis/silver-devnet.toml
```

`cargo run -p silver_surfer -- ~/.local/share silver` shows live counters.

## Files

| File | Purpose |
|------|---------|
| `net.yaml` | ethereum-package args: 4 participants, Fulu from genesis, CL at debug. |
| `net-participant.yaml` | Same devnet, with silver inside it as a `cl_type: silver` participant. |
| `setup.sh` | Starts the enclave, harvests network values, writes the config TOML. |
| `run-reth.sh` | Runs silver's own reth from the harvested `el/` files. |
| `silver-devnet.toml` | silver's config, generated. Gitignored. |
| `genesis.ssz` | Genesis state, silver's sync anchor. Generated. |
| `el/` | EL genesis, enodes, JWT and datadir for the local reth. Generated. |

## What `setup.sh` writes

silver takes a whole `Config` from `--config <file>`. The script harvests these
into `silver-devnet.toml`:

| Field | Source |
|-------|--------|
| `chain_config.spec` | `/eth/v1/config/spec` — fork versions, fork epochs, blob schedule. |
| `chain_config.checkpoint_file` | `genesis.ssz`, or the finalized state with `--finalized-anchor`. |
| `chain_config.bootstrap_enrs` | `/eth/v1/node/identity` on each CL node. |
| `external_ip_v4` | the `kt-<enclave>` bridge gateway, so peers can dial silver back. |
| `engine_config.*` | the local reth's endpoint and `el/jwt.hex`. |

`secret_key` and the ports come from env-overridable vars in the script. A fixed
`secret_key` keeps silver's peer id stable across restarts.

`fork_digest`, `next_fork_version` and `genesis_unix_secs` are **not** written.
silver derives them from `chain_config.spec` and the anchor state, so the config
cannot contradict the network. The spec must therefore be right: a wrong
`FULU_FORK_EPOCH` gives a wrong digest, and silver refuses a spec that reads
earlier than Fulu.

Re-run `setup.sh` after an enclave restart.

## silver as a participant (`net-participant.yaml`)

Here silver runs as a node in the enclave, not on the host. It gets its own
container and its own EL, and appears in `kurtosis enclave inspect`.

Nothing is harvested. The launcher points silver at the enclave's own
`config.yaml` and `genesis.ssz`, and silver reads the rest from them.

The launcher is not upstream yet. It lives on
[`ninaiiad/ethereum-package@ng/silver-cl`](https://github.com/ninaiiad/ethereum-package/tree/ng/silver-cl).

```bash
docker build -t silver:local .            # from the repo root
git clone -b ng/silver-cl https://github.com/ninaiiad/ethereum-package
kurtosis run ./ethereum-package \
  --args-file kurtosis/net-participant.yaml \
  --enclave silver-participant --image-download always
```

Kurtosis 1.15.2 cannot load the package: it fails with `undefined: GpuConfig`.
To run on it, delete the `gpu=GpuConfig(...)` kwarg in
`src/zkboost/zkboost_launcher.star` first.

You can run the branch straight from GitHub instead of cloning it, as
`kurtosis run github.com/ninaiiad/ethereum-package@ng/silver-cl`. That form also
needs the branch's `kurtosis.yml` to name the fork, and gives you nowhere to
apply the `GpuConfig` edit.

Once the launcher is upstream, pin a release that has it:

```bash
kurtosis run github.com/ethpandaops/ethereum-package@<tag> \
  --args-file kurtosis/net-participant.yaml \
  --enclave silver-participant
```

Then drop the `cl_image` and `el_image` pins from `net-participant.yaml`. They
are there because HEAD's genesis needs client builds that track HEAD, and
because silver has no published image yet.

## The execution layer

silver needs an EL to validate payloads, and gets its own reth rather than one
from the enclave. Every enclave EL is already driven by its paired CL, and two
CLs steering one EL fight over its fork choice.

`setup.sh` harvests the EL genesis, the enclave ELs' enodes, and a shared JWT
into `el/`. reth's datadir is `el/datadir`; the script wipes it when the EL
genesis changes.

### Running without an EL

silver's engine tile can run with no EL at all. It answers every engine request
`VALID`, so blocks import without payload execution. Block proposal does not
work. Testing only.

```bash
cargo run --release --bin silver -- \
  --config kurtosis/silver-devnet.toml --unsafe-no-el
```

`UNSAFE_NO_EL=1 kurtosis/setup.sh` bakes it into the config instead. The flag
overrides the file.

## Logs

```bash
kurtosis enclave inspect silver-dev              # list service names
kurtosis service logs -f silver-dev cl-1-lighthouse-geth
kurtosis service logs -f silver-dev              # everything
```

Names are `cl-<n>-<cl>-<el>` and `el-<n>-<el>-<cl>`. `dora`, whose URL
`enclave inspect` prints, shows whether the chain is producing and finalizing.

## Data columns (PeerDAS)

Column sidecars exist only for blocks carrying blob commitments, so `net.yaml`
runs `spamoor` to submit blob transactions continuously. Check they are flowing
with `kurtosis service logs -f silver-dev el-1-geth-lighthouse | grep -i blob`,
or per-block blob counts in dora.

For backfill testing, let the spammer run a while before launching silver.

## Notes

- **QUIC only.** silver dials a peer only if its ENR advertises a `quic`
  socket, and logs `Peer does not support quic` otherwise. Lighthouse enables
  QUIC by default, hence the lighthouse-heavy participant set.
- **`preset: mainnet`** matches silver's `SpecConfig` defaults. The minimal
  preset would break slot and epoch maths.
- **Upstream churn.** The `*_fork_epoch` keys, the `http` and `rpc` port ids,
  and the `el_cl_genesis_data` artifact name all track ethereum-package. Check
  them against the version you pulled when `setup.sh` fails.

## Teardown

```bash
kurtosis enclave rm -f silver-dev
```
