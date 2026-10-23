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

`kurtosis`, `docker`, `curl`, `jq`, and `patch`.
The prepared package requires Kurtosis CLI and engine 1.22.2 or later.
See the [Kurtosis upgrade instructions](https://docs.kurtosis.com/upgrade/) when updating an older installation.
The host workflow also needs `reth` and a Silver build.
`build-image.sh` uses Docker Buildx, downloading a verified local copy if the plugin is missing on Linux amd64 or arm64.

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
| `net-vc.yaml` | Fulu proposal testing with Lighthouse and Prysm validator clients attached to Silver. |
| `net-vc-gloas.yaml` | Silver with a Lighthouse validator client, crossing Fulu to Gloas at epoch 4. |
| `net-gloas.yaml` | Older Gloas follower setup using devnet-7 images. |
| `prepare-package.sh` | Downloads a pinned package and applies `ethereum-package.patch`. Prints its local path. |
| `build-image.sh` | Builds `silver:proposing`, or the image tag supplied as its first argument. |
| `gloas-proposals.yaml` | Assertoor checks for Silver proposals before and after Gloas, then finality and sync. |
| `setup.sh` | Starts the enclave, harvests network values, writes the config TOML. |
| `run-reth.sh` | Runs silver's own reth from the harvested `el/` files. |
| `silver-devnet.toml` | silver's config, generated. Gitignored. |
| `silver-devnet-network/` | The devnet's metadata directory, laid out like a published devnet's. Generated. Gitignored. |
| `el/` | EL genesis, enodes, JWT and datadir for the local reth. Generated. |

## What `setup.sh` writes

silver takes a whole `Config` from `--config <file>`. The script harvests these
into `silver-devnet.toml` and its `network` directory, `silver-devnet-network/`:

| Field | Source |
|-------|--------|
| `network/config.yaml` | Complete generated config from the `el_cl_genesis_data` artifact. |
| `network/bootstrap_nodes.yaml` | `/eth/v1/node/identity` on each CL node. |
| `network/genesis.ssz` | the genesis state, which silver boots from by default. |
| `chain_config.checkpoint_sync_urls` | only with `--finalized-anchor`: the enclave's CLs, which silver downloads the finalized state from. |
| `external_ip_v4` | the `kt-<enclave>` bridge gateway, so peers can dial silver back. |
| `engine_config.*` | the local reth's endpoint and `el/jwt.hex`. |

The ports come from env-overridable vars in the script. silver keeps its peer id
in `node.key` under `data_storage_dir`; delete that file to get a new one.

`fork_digest`, `next_fork_version` and `genesis_unix_secs` are **not** written.
silver derives them from the spec and the anchor state, so the config
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
`prepare-package.sh` pins commit `19d6bd99ac14c69ff7aa63b53f75fc3701940de1` and verifies the archive's SHA-256.
The prepared package lives under the ignored `kurtosis/.cache/` directory.
The original local checkout is unnecessary.

```bash
kurtosis/build-image.sh silver:local      # from the repo root
SILVER_PACKAGE="$(kurtosis/prepare-package.sh)"
kurtosis run "$SILVER_PACKAGE" \
  --args-file kurtosis/net-participant.yaml \
  --enclave silver-participant --image-download missing
```

The tracked patch selects `network = "/network-configs"`, preserves per-node logging filters, and allows port startup through genesis.
It sets `disable_weak_subjectivity_check = true` in TOML for the local devnet, replacing the removed `--disable-weak-subjectivity` flag.
It gives each Silver service 2 GiB of `/dev/shm` through `GpuConfig(count=0, shm_size=2048)`.
The zero count requests no GPU; Kurtosis exposes shared-memory sizing through this configuration.
Flux queues and profiling exceed Docker's 64 MiB default, causing `SIGBUS` when that mount fills.
The limit applies to Silver containers and requires a fresh enclave; no Silver image rebuild is needed.
Changing the patch or playbook prepares a new package directory, leaving earlier copies intact.
Run `SILVER_PACKAGE="$(kurtosis/prepare-package.sh)"` again after either changes, before launching an enclave.

## Local block production across Gloas

`net-vc-gloas.yaml` gives Silver its own Reth and a Lighthouse validator client.
Three reference Lighthouse/Reth pairs retain 75% of validator stake.
Each participant has 128 keys and full data-column custody.
The Silver VC connects only to Silver; reference nodes cannot fulfill its proposal duties.
EL validation remains enabled, and no external builders are configured.

The chain starts in Fulu and activates Gloas at epoch 4, slot 128.
At 12-second slots, the fork occurs 25 minutes and 36 seconds after genesis.
Assertoor requires two Silver proposals before the fork and three blob-bearing proposals after epoch 5.
It then waits for finalized epoch 5 and checks CL and EL synchronization.
Allow approximately 50 minutes after genesis; the playbook has a 65-minute timeout.

Client, generator, Assertoor, and Spamoor images are pinned by digest.
The pins were resolved on 2026-10-22; a dry-run cannot establish consensus or Engine API interoperability.

Run these commands from the repository root, keeping the variables in the same shell for the checks below.
The timestamp gives each run a fresh enclave and a new fork transition.

```bash
SILVER_ENCLAVE="silver-vc-gloas-$(date +%Y%m%d-%H%M%S)"
kurtosis/build-image.sh silver:proposing
SILVER_PACKAGE="$(kurtosis/prepare-package.sh)"

# Optional: validate the package before starting services.
kurtosis run "$SILVER_PACKAGE" \
  --args-file kurtosis/net-vc-gloas.yaml \
  --enclave "$SILVER_ENCLAVE" --dry-run

kurtosis run "$SILVER_PACKAGE" \
  --args-file kurtosis/net-vc-gloas.yaml \
  --enclave "$SILVER_ENCLAVE" --image-download missing

kurtosis enclave inspect "$SILVER_ENCLAVE"
kurtosis service exec "$SILVER_ENCLAVE" cl-4-silver-reth 'df -h /dev/shm'
```

Expect a 2 GiB `/dev/shm` mount for Silver.
Successful `kurtosis run` means service startup completed; the asynchronous test must also pass.
The dry-run still validates image availability, so build Silver first.
Use a fresh enclave for each transition test; rerunning an existing chain does not repeat its fork.
If changing `gloas_fork_epoch`, update the playbook's epoch bounds and the slot cutoff in the counting command below.

For a Fulu-only VC check, use `net-vc.yaml` with the same prepared package and `silver:proposing` image.
For stateless Gloas production, add `--stateless-block-production` to the Silver participant's Lighthouse `vc_extra_params`.
The default exercises cached-envelope production with `include_payload=false`.

### Check the automated test

For an existing run, set `SILVER_ENCLAVE` to its name from `kurtosis enclave ls`.
Discover the ports for that enclave; they change between runs.

```bash
SILVER_API="$(kurtosis port print "$SILVER_ENCLAVE" cl-4-silver-reth http)"
REFERENCE_API="$(kurtosis port print "$SILVER_ENCLAVE" cl-1-lighthouse-reth http)"
ASSERTOOR_API="$(kurtosis port print "$SILVER_ENCLAVE" assertoor http)"

printf 'Test dashboard: %s\n' "$ASSERTOOR_API"
curl -fsS "$ASSERTOOR_API/api/v1/test_runs" | jq '.data[] | {run_id, name, status}'

SILVER_RUN_ID="$(curl -fsS "$ASSERTOOR_API/api/v1/test_runs" | jq -er '
  [.data[] | select(.test_id == "silver-gloas-proposals")]
  | max_by(.run_id) | .run_id
')"
curl -fsS "$ASSERTOOR_API/api/v1/test_run/$SILVER_RUN_ID" | jq '
  .data | {run_id, status, tasks: [.tasks[] | {title, status, result, result_error}]}
'
```

Success requires run status `success` and result `success` for all eight tasks.
These cover Fulu proposals, Gloas proposals containing blobs and transactions, finalized epoch 5, and consensus/execution synchronization.

### Count published blocks and payload envelopes

Follow Silver and its validator client together; Ctrl-C stops following without stopping the enclave.

```bash
kurtosis service logs --follow "$SILVER_ENCLAVE" \
  cl-4-silver-reth vc-4-reth-silver-lighthouse
```

Capture all validator logs for counts, since `kurtosis service logs` otherwise returns only the last 200 lines.
Rerun the capture command to refresh the snapshot.

```bash
SILVER_LOG_DIR="$(mktemp -d /tmp/silver-proposals.XXXXXX)"
kurtosis service logs --all "$SILVER_ENCLAVE" vc-4-reth-silver-lighthouse \
  | sed -E 's/\x1b\[[0-9;]*m//g' > "$SILVER_LOG_DIR/validator.log"

awk -v gloas_slot=128 '
  /Successfully published block[[:space:]]/ {
    slot = $0
    sub(/^.*slot: /, "", slot)
    sub(/,.*/, "", slot)
    if (slot + 0 < gloas_slot) fulu++; else gloas++
  }
  /Successfully published signed execution payload envelope/ { envelopes++ }
  END {
    printf "Fulu blocks: %d\nGloas blocks: %d\nGloas envelopes: %d\n", fulu, gloas, envelopes
  }
' "$SILVER_LOG_DIR/validator.log"

kurtosis service logs --all --regex-match \
  'Successfully published (block|signed execution payload envelope|payload attestations)' \
  "$SILVER_ENCLAVE" vc-4-reth-silver-lighthouse
```

The VC connects only to Silver, so these publications exercise Silver's local production path.
Gloas requires both a beacon block and a signed execution payload envelope.
A successful block log alone does not establish successful payload publication or acceptance by peers.

### Verify a Gloas proposal on a reference client

After a signed envelope appears in the snapshot, select its block root and query Lighthouse.
The block root ties these checks to a Silver proposal even if the canonical block at that slot changes.

```bash
SILVER_BLOCK_ROOT="$(awk '
  /Successfully published signed execution payload envelope/ { root = $NF }
  END { print root }
' "$SILVER_LOG_DIR/validator.log")"

curl -fsS "$REFERENCE_API/eth/v1/beacon/headers/${SILVER_BLOCK_ROOT:?No published Gloas envelope in the log snapshot}" \
  | jq '.data | {canonical, root, slot: .header.message.slot, proposer_index: .header.message.proposer_index}'

curl -fsS "$REFERENCE_API/eth/v2/beacon/blocks/$SILVER_BLOCK_ROOT" | jq '
  .data.message.body.signed_execution_payload_bid.message as $bid
  | {version, execution_optimistic, slot: .data.message.slot,
     proposer_index: .data.message.proposer_index, builder_index: $bid.builder_index,
     blob_count: ($bid.blob_kzg_commitments | length), block_hash: $bid.block_hash}
'

curl -fsS "$REFERENCE_API/eth/v1/beacon/execution_payload_envelopes/$SILVER_BLOCK_ROOT" | jq '
  .data.message as $envelope
  | {version, execution_optimistic, beacon_block_root: $envelope.beacon_block_root,
     slot: $envelope.payload.slot_number, block_hash: $envelope.payload.block_hash,
     transaction_count: ($envelope.payload.transactions | length)}
'
```

Expect `canonical: true`, `version: "gloas"`, `execution_optimistic: false`, and matching block hashes in the bid and envelope.
Silver's validator indices are 384–511 in this configuration.
The self-build `builder_index` is `18446744073709551615`; blob and transaction counts should be positive for the proposal test.
A missing envelope or an optimistic response does not establish successful execution validation.

### Check following and finality

```bash
for SILVER_CHECK_API in "$SILVER_API" "$REFERENCE_API"; do
  curl -fsS "$SILVER_CHECK_API/eth/v1/node/syncing" \
    | jq --arg endpoint "$SILVER_CHECK_API" '{endpoint: $endpoint} + .data'
  curl -fsS "$SILVER_CHECK_API/eth/v1/beacon/headers/head" \
    | jq --arg endpoint "$SILVER_CHECK_API" \
      '{endpoint: $endpoint, slot: .data.header.message.slot, root: .data.root, execution_optimistic}'
  curl -fsS "$SILVER_CHECK_API/eth/v1/beacon/states/head/finality_checkpoints" \
    | jq --arg endpoint "$SILVER_CHECK_API" '{endpoint: $endpoint} + .data'
done
```

Expect `is_syncing`, `is_optimistic`, and `el_offline` to be false, with no persistent sync distance.
Compare head roots and finalized checkpoints; repeat if a slot boundary falls between requests.
The completed test requires finalized epoch 5 or later.

Silver currently lacks `finalized_checkpoint` and Gloas `execution_payload_available` SSE events.
Their subscription warnings can make the dashboard show Silver offline despite successful direct API checks and block production.

Stop the enclave while preserving its data and logs:

```bash
kurtosis enclave stop "$SILVER_ENCLAVE"
kurtosis enclave ls
```

For logs from a stopped enclave, use the full service UUID from `kurtosis enclave inspect --full-uuids "$SILVER_ENCLAVE"`.
Pass that UUID instead of the service name to `kurtosis service logs --all`.

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
The default and `UNSAFE_NO_EL=0` both keep EL validation enabled.
The host Gloas follower defaults to a finalized anchor; use `--genesis-anchor` when testing its fork transition.

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
