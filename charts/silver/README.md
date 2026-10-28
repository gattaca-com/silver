# Silver Helm chart

This chart deploys Silver as a StatefulSet with persistent storage and an existing Engine API JWT Secret.
The image supports Linux amd64. The default node selector enforces that architecture.

## Install

Create a Secret containing the same JWT file used by your execution client:

```bash
kubectl create secret generic execution-jwt --from-file=jwt=./jwt.hex
```

Save these values as `silver-values.yaml`:

```yaml
jwtSecret:
  existingSecret: execution-jwt
extraArgs:
  network: hoodi
  execution-endpoint: http://execution:8551
```

Install the chart package from GHCR:

```bash
helm upgrade --install silver oci://ghcr.io/gattaca-com/charts/silver \
  --version 0.1.0-alpha.6 --values silver-values.yaml
```

Each Silver release publishes a chart with the same version, without the `v` prefix.
An empty `image.tag` uses that release's image.
Set `image.tag` to select another published Silver release without releasing a new chart.
The chart does not deploy an execution client or generate JWT secrets.

## Configuration and storage

See [values.yaml](values.yaml) for all options.
`config` accepts additional TOML. `extraArgs` accepts Silver CLI flags, which override equivalent TOML settings.

The chart manages `data_storage_dir`, `beacon_api_bind`, `discovery_port`, and `quic_port`.
Change their chart values instead of repeating those keys in `config`.
With external IP discovery enabled, the chart also manages `external_ip_v4`.

```yaml
config: |
  attestation_subnet_count = 4
  [pbs]
  endpoint = "http://commit-boost:18550"
```

The database and node identity persist on `/data`.
Runtime queues and counters use an ephemeral `/runtime` volume.
Use separate storage for each network. Size CPU, memory, and storage for your custody settings.

The default storage mode creates a 500Gi PVC for each pod.
`persistence.type` also supports `existingClaim`, `hostPath`, and `emptyDir`.
`emptyDir` loses the database when the pod is replaced.

Silver runs as UID and GID 1000 with every capability dropped.
`fsGroup` makes PVCs writable, but a `hostPath` directory must already be writable by UID 1000.
Tiles request the highest thread priority and log a warning without `CAP_SYS_NICE`.
Granting it requires running as root, because Kubernetes gives added capabilities only to root processes.

## Networking and monitoring

Silver uses UDP 31133 for discovery, UDP 31123 for QUIC, and TCP 5051 for the Beacon API.
Host ports are enabled by default. Schedule at most one pod per node with the same host ports.
The advertised external IPv4 address must route both UDP ports to the pod.
Hosts behind NAT need matching port forwarding.

The init container discovers the external IPv4 address through `externalIP.serviceURL`.
Set `externalIP.value` to use a known address without an HTTP lookup.
Set `externalIP.enabled=false` to manage advertisement yourself through `config`.

Readiness fails while Silver or its execution client is syncing.
Startup and liveness use the version endpoint, so syncing alone does not restart the node.
Startup allows 30 minutes for checkpoint loading.
Logs go to stdout at `info` level. Override `RUST_LOG` through `env` to change the level.

Silver Surfer is included in the image. Open its terminal dashboard inside the running Silver container:

```bash
kubectl exec -it silver-0 -c silver -- silver_surfer /runtime silver
```

Replace `silver-0` with your pod name. Surfer shares the node's runtime files and uses the same release version.

The optional ServiceMonitor requires the Prometheus Operator CRDs.
Silver `v0.1.0-alpha.6` exposes `/metrics` but returns no samples.

## Release the chart

See [publishing](../../docs/publishing.md) for package setup and chart releases.
