# Silver

[![Release](https://img.shields.io/github/v/release/gattaca-com/silver?include_prereleases)](https://github.com/gattaca-com/silver/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A high-performance Ethereum consensus client.

Silver runs Fulu and Gloas. Prebuilt binaries are linux-x86_64 only.

## Quick start (mainnet)

Silver works with any execution client (EL) that supports the engine API. This
example runs [ethrex](https://github.com/lambdaclass/ethrex) next to it:

```bash
curl -L https://github.com/gattaca-com/silver/releases/latest/download/silver-linux-x86_64 -o silver
curl -L https://github.com/lambdaclass/ethrex/releases/latest/download/ethrex-linux-x86_64 -o ethrex
chmod +x silver ethrex

openssl rand -hex 32 > jwt.hex

nohup ./ethrex --network mainnet --authrpc.jwtsecret jwt.hex > ethrex.log 2>&1 &
nohup ./silver --execution-endpoint http://localhost:8551 --jwt-secret jwt.hex > silver.out 2>&1 &
```

Open UDP ports 31133 (discovery) and 31123 (QUIC peers) to the internet. The
first start takes a few minutes to download a recent state.

An EL on another machine works too: point `--execution-endpoint` at its engine
API URL and give both the same JWT secret file.

## Check it works

[Silver Surfer](crates/surfer/README.md) is a live dashboard for the node,
shipped in each release. Run it on the same machine:

```bash
curl -L https://github.com/gattaca-com/silver/releases/latest/download/silver_surfer-linux-x86_64 -o silver_surfer
chmod +x silver_surfer && ./silver_surfer
```

Or ask the beacon API on port 5051:

```bash
curl -s localhost:5051/eth/v1/node/syncing     # synced: "sync_distance":"0", "is_syncing":false
curl -s localhost:5051/eth/v1/node/peer_count  # "connected" well above zero
```

Logs go to `/tmp/logs/silver.<date>`.

### Verify the download

Each release file has a `.sha256` and a build attestation:

```bash
curl -sL https://github.com/gattaca-com/silver/releases/latest/download/silver-linux-x86_64.sha256 \
  | sed 's/silver-linux-x86_64/silver/' | sha256sum -c
gh attestation verify silver --repo gattaca-com/silver   # proves Silver's CI built it
```

## Networks

### hoodi or sepolia

```bash
./silver --network hoodi --execution-endpoint http://localhost:8551 --jwt-secret jwt.hex
```

The name brings the network's spec, bootnodes and checkpoint providers. Its
data lives in `~/.local/silver/<network>`.

### Devnet

Point `--network` at the devnet's published metadata directory:

```bash
./silver --network /path/to/<devnet>/metadata --execution-endpoint http://localhost:8551 --jwt-secret jwt.hex
```

Silver reads only these files from it:

| File | Use |
|---|---|
| `config.yaml` | The spec. Missing keys default to mainnet values. |
| `genesis.ssz` | The boot state, read on every start. Required. |
| `bootstrap_nodes.yaml` | The bootnodes, as a list of ENRs. Optional. |

Its data lives in a `~/.local/silver/devnet-<id>` subdirectory. Silver logs the
path at startup.

## Flags

`silver --help` lists every flag, and `silver --version` prints the version.
Flags override the config file. The common ones are:

- `--network <name or dir>`
- `--config <path>`
- `--execution-endpoint <url>`
- `--jwt-secret <path>`

## Config file

Pass it with `--config <path>`. Every key is optional. Missing keys default to
mainnet values. Unknown keys are ignored, so check spelling. A malformed config
stops Silver at startup.

```toml
network = "mainnet"
data_storage_dir = "/var/lib/silver"

[engine_config]
execution_endpoint = "http://127.0.0.1:8551"
jwt_secret = "/etc/silver/jwt.hex"
```

A supernode custodies every data column and joins every attestation subnet.
On mainnet it averages about 100 Mbit/s each way, but bursts reach about
500 Mbit/s. Its data directory holds about 400 GB:

```toml
data_column_custody_group_count = 128  # default 8
attestation_subnet_count = 64          # default 2
```

### Overriding a network's defaults

These `[chain_config]` keys replace the network's own values:

| Key | Replaces |
|---|---|
| `bootstrap_enrs` | the bootnodes |
| `checkpoint_sync_urls` | the checkpoint providers, or a devnet's `genesis.ssz` |
| `checkpoint_file` | the boot state, read on every start |

## Docker and Kubernetes

Release images are available as GitHub packages:

```bash
docker pull ghcr.io/gattaca-com/silver:v0.1.0-alpha.6
```

Images contain the same Linux amd64 `silver` and `silver_surfer` binaries attached to the corresponding release.
Each release links to its image tag and digest. Set `LOG_STDOUT=1` and `RUST_LOG` to configure container logs.

Open Surfer inside a running Silver container:

```bash
docker exec -it <container> silver_surfer
```

For Kubernetes, install the [Helm chart](charts/silver/README.md):

```bash
helm upgrade --install silver oci://ghcr.io/gattaca-com/charts/silver \
  --version 0.1.0-alpha.6 --values silver-values.yaml
```

The chart guide explains the required execution endpoint, JWT Secret, storage, and UDP networking.
Maintainers can find package setup and release instructions in [publishing](docs/publishing.md).

## Build from source

Requires Rust (pinned in `rust-toolchain.toml`) and `clang`.

```bash
cargo build --profile release-prod --locked --bin silver
```

Development commands live in the `justfile`.

## License

Silver is licensed under the [MIT licence](LICENSE), with one exception.
[`crates/crypto_simd/proof/lean/`](crates/crypto_simd/proof/lean/) and everything
under it are dedicated to the public domain under
[CC0 1.0](crates/crypto_simd/proof/lean/LICENSE).
