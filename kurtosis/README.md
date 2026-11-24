# Local kurtosis devnet

A multi-client devnet for testing silver against real CL clients with readable logs.
Use it for protocol behaviour: handshakes, RPC framing, gossip scoring, engine-API verdicts.
Do not use it for timeout or peer-supply bugs: everything is same-host, with no loss and no NAT.

There are two ways to run silver against it:

- **Host process**: `setup.sh` starts a Fulu enclave, and silver runs on the host with its own reth.
- **Participant**: silver runs inside the enclave from a Docker image, driven by a validator client.

## Prerequisites

- `kurtosis` (CLI and engine 1.22.2 or later), `docker`, `curl`, `jq`.
- Host process: `reth` on `PATH`, and a silver build.
- Participant: `tar` and `sha256sum`.
  `build-image.sh` downloads a verified Docker Buildx if the plugin is missing.

Linux only. The host process joins the enclave over the Docker bridge.

## Files

| File | Purpose |
|------|---------|
| `net.yaml` | Host-process devnet: 4 CLs, Fulu from genesis, blob spammer. |
| `setup.sh` | Starts the `net.yaml` enclave and writes silver's config. |
| `run-reth.sh` | Runs silver's own reth from the files in `el/`. |
| `net-vc.yaml` | Fulu, two silver nodes, with a Lighthouse VC and a Prysm VC. |
| `net-vc-gloas.yaml` | Silver with a Lighthouse VC, crossing Fulu to Gloas at epoch 4. |
| `gloas-proposals.yaml` | Assertoor test for `net-vc-gloas.yaml`. |
| `prepare-package.sh` | Downloads the pinned ethereum-package and adds the Assertoor test. Prints its path. |
| `build-image.sh` | Builds the Dockerfile's `kurtosis` target, `silver:proposing` by default. It adds the busybox shell that the launcher's `sh -c` needs. |

`setup.sh` generates `silver-devnet.toml`, `silver-devnet-network/` and `el/`.
`prepare-package.sh` and `build-image.sh` write to `.cache/`.
All of these are gitignored.

## Host process

```bash
kurtosis/setup.sh               # enclave silver-dev; --recreate for a fresh chain
kurtosis/run-reth.sh            # separate terminal, keeps running
LOG_STDOUT=1 RUST_LOG=info,silver_network=info,silver_peer=info \
  cargo run --release --bin silver -- --config kurtosis/silver-devnet.toml
```

Without `LOG_STDOUT`, logs go to files under `LOG_PATH` (default `/tmp/logs`).
`cargo run -p silver_surfer` shows live counters.

`setup.sh` writes these into `silver-devnet.toml` and `silver-devnet-network/`:

| Field | Source |
|-------|--------|
| `network` | `silver-devnet-network/`, holding the enclave's `config.yaml`, `genesis.ssz` and `bootstrap_nodes.yaml`. |
| `external_ip_v4` | The `kt-<enclave>` bridge gateway, so peers can dial silver back. |
| `discovery_port`, `quic_port`, `data_column_custody_group_count` | Env vars, defaults 31133, 31123 and 8. |
| `engine_config.*` | `http://127.0.0.1:$ENGINE_PORT` (default 8551) and `el/jwt.hex`. |
| `chain_config.checkpoint_sync_urls` | Only with `--finalized-anchor`: the enclave's CL beacon APIs. |

Silver boots from `genesis.ssz` by default.
`--finalized-anchor` makes it checkpoint-sync from the enclave's CLs instead, once the chain has finalized.
Silver derives the fork digest and genesis time from `config.yaml` and the anchor state.

The data dir is `~/.local/silver/devnet-<first 4 bytes of genesis_validators_root>`.
Silver keeps its peer id in `node.key` there; delete it for a new identity.
Re-run `setup.sh` after an enclave restart; it wipes `el/datadir` when the EL genesis changes.

Silver gets its own reth because two CLs driving one EL fight over its fork choice.
To run without an EL, pass `--unsafe-no-el` or set `UNSAFE_NO_EL=1` for `setup.sh`.
Every payload then counts as valid, and block proposal does not work.

`net.yaml` runs `spamoor`, so blocks carry blobs and data columns.
For backfill testing, let the spammer run before launching silver.

## Participant

The silver launcher is upstream in [`ethpandaops/ethereum-package`](https://github.com/ethpandaops/ethereum-package/tree/main/src/cl/silver).
`prepare-package.sh` pins a `main` commit and checks the archive SHA-256.
It also copies `gloas-proposals.yaml` into the package as an Assertoor test.
Run it again after changing that file.

The launcher points silver at the enclave's metadata with `network`.
It sets `disable_weak_subjectivity_check = true`, since the devnet starts from genesis.
It allows each silver's service name as a beacon API host, so validator clients can reach it.
It gives each silver container 2 GiB of `/dev/shm`; Docker's 64 MiB default causes `SIGBUS`.

### Fulu validator clients

```bash
kurtosis/build-image.sh
SILVER_PACKAGE="$(kurtosis/prepare-package.sh)"
kurtosis run "$SILVER_PACKAGE" --args-file kurtosis/net-vc.yaml \
  --enclave silver-vc --image-download missing
```

### Block production across Gloas

`net-vc-gloas.yaml` runs three Lighthouse/Reth pairs and one silver/Reth pair, each with a Lighthouse VC.
Silver's VC talks only to silver, so its proposals exercise silver's local production path.
Gloas activates at epoch 4 (slot 128), about 26 minutes after genesis.
Images are pinned by digest.

The Assertoor test needs two silver Fulu proposals and three silver Gloas proposals with blobs.
It then waits for finalized epoch 5 and checks CL and EL sync.
Allow about 50 minutes; the test times out at 65.
Use a fresh enclave per run, since a rerun does not repeat the fork.
If you change `gloas_fork_epoch`, update the epoch bounds in `gloas-proposals.yaml`.

```bash
SILVER_ENCLAVE="silver-vc-gloas-$(date +%Y%m%d-%H%M%S)"
kurtosis/build-image.sh
SILVER_PACKAGE="$(kurtosis/prepare-package.sh)"
kurtosis run "$SILVER_PACKAGE" --args-file kurtosis/net-vc-gloas.yaml \
  --enclave "$SILVER_ENCLAVE" --image-download missing
```

Check the Assertoor result:

```bash
ASSERTOOR_API="$(kurtosis port print "$SILVER_ENCLAVE" assertoor http)"
SILVER_RUN_ID="$(curl -fsS "$ASSERTOOR_API/api/v1/test_runs" | jq -er '
  [.data[] | select(.test_id == "silver-gloas-proposals")] | max_by(.run_id) | .run_id')"
curl -fsS "$ASSERTOOR_API/api/v1/test_run/$SILVER_RUN_ID" \
  | jq '.data | {status, tasks: [.tasks[] | {title, status, result}]}'
```

Success needs run status `success`, and result `success` on all eight tasks.

Check one silver Gloas proposal on a reference node:

```bash
REFERENCE_API="$(kurtosis port print "$SILVER_ENCLAVE" cl-1-lighthouse-reth http)"
SILVER_BLOCK_ROOT="$(kurtosis service logs --all "$SILVER_ENCLAVE" vc-4-reth-silver-lighthouse \
  | sed -E 's/\x1b\[[0-9;]*m//g' \
  | awk '/Successfully published signed execution payload envelope/ { root = $NF } END { print root }')"
curl -fsS "$REFERENCE_API/eth/v1/beacon/headers/$SILVER_BLOCK_ROOT" | jq '.data.canonical'
curl -fsS "$REFERENCE_API/eth/v1/beacon/execution_payload_envelopes/$SILVER_BLOCK_ROOT" \
  | jq '{version, execution_optimistic, block_hash: .data.message.payload.block_hash}'
```

Expect `canonical: true`, `version: "gloas"` and `execution_optimistic: false`.
Silver's validator indices are 384–511.

For stateless Gloas production, add `--stateless-block-production` to the silver participant's `vc_extra_params`.
Silver does not emit the `finalized_checkpoint` SSE event yet.
The dashboard can therefore show silver offline while its API checks pass.

## Logs and teardown

```bash
kurtosis enclave inspect <enclave>             # service names
kurtosis service logs -f <enclave> <service>
kurtosis service logs --all <enclave> <service> # full history, not the last 200 lines
kurtosis enclave stop <enclave>                 # keeps data and logs
kurtosis enclave rm -f <enclave>
```

Services are named `cl-<n>-<cl>-<el>`, `el-<n>-<el>-<cl>` and `vc-<n>-<el>-<cl>-<vc>`.

## Notes

- **QUIC only.** Silver dials a peer only if its ENR advertises `quic`, hence the Lighthouse-heavy sets.
- **`preset: mainnet`** only; the minimal preset breaks silver's slot and epoch maths.
- **Upstream churn.** `setup.sh` pins `ethereum-package@6.1.0`.
  Its fork-epoch keys, port ids and the `el_cl_genesis_data` artifact name track that version.
