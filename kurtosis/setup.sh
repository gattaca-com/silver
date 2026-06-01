#!/usr/bin/env bash
# Spin up the kurtosis ethereum-package devnet, harvest the network-specific
# values silver needs, and write the silver config TOML.
#
#   kurtosis/setup.sh [--recreate] [enclave-name]   (default: silver-dev)
#
# --recreate tears down the enclave first for a fresh chain (new genesis ->
# new digest/ENRs/genesis-time -> silver must restart). Without it, a healthy
# enclave is reused and the config just re-synced.
#
# Generates silver-devnet.toml from scratch each run (derived fields harvested
# from the CL; static fields — secret_key, ports, next_fork_version — taken
# from the env-overridable vars below). Also writes genesis.ssz (the sync
# anchor) alongside it.
#
# Requires: kurtosis, docker, curl, jq. Linux only — silver runs as a host
# process joining the Docker bridge, and external_ip_v4 detection is
# bridge-specific.
set -euo pipefail

RECREATE=0
ENCLAVE="silver-dev"
for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=1 ;;
    -*) echo "unknown flag: $arg" >&2; exit 1 ;;
    *) ENCLAVE="$arg" ;;
  esac
done

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARGS_FILE="$HERE/net.yaml"
CONFIG="$HERE/silver-devnet.toml"
GENESIS_SSZ="$HERE/genesis.ssz"

# Static (non-harvested) config values — override via env if needed. A fixed
# secret_key gives silver a stable peer-id/ENR across restarts. next_fork_epoch
# is omitted from the config (defaults to FAR_FUTURE, which exceeds TOML's i64).
SECRET_KEY="${SECRET_KEY:-1111111111111111111111111111111111111111111111111111111111111111}"
DISCOVERY_PORT="${DISCOVERY_PORT:-31133}"
QUIC_PORT="${QUIC_PORT:-31123}"
NEXT_FORK_VERSION="${NEXT_FORK_VERSION:-06000000}"

# Pin a known-good release — the bare locator pulls the default branch (HEAD),
# which periodically breaks (e.g. the zkboost `GpuConfig` regression). Bump the
# tag here, or override per-run:
#   PACKAGE='github.com/ethpandaops/ethereum-package@<tag>' kurtosis/setup.sh
# Discover tags:
#   git ls-remote --tags https://github.com/ethpandaops/ethereum-package
PACKAGE="${PACKAGE:-github.com/ethpandaops/ethereum-package@6.1.0}"

for bin in kurtosis docker curl jq; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

# 1. Start the enclave. --recreate forces a fresh chain; otherwise reuse one
#    that already has CL services (a half-built enclave from a failed run is
#    torn down and retried regardless).
if [ "$RECREATE" -eq 1 ]; then
  echo "recreating enclave: $ENCLAVE"
  kurtosis enclave rm -f "$ENCLAVE" >/dev/null 2>&1 || true
fi
if kurtosis enclave inspect "$ENCLAVE" 2>/dev/null | grep -qE 'cl-[0-9]+-'; then
  echo "reusing existing enclave: $ENCLAVE"
else
  kurtosis enclave rm -f "$ENCLAVE" >/dev/null 2>&1 || true
  echo "starting enclave: $ENCLAVE ($PACKAGE)"
  kurtosis run "$PACKAGE" --args-file "$ARGS_FILE" --enclave "$ENCLAVE"
fi

# 2. Enumerate consensus-layer services (cl-<n>-<cl>-<el>).
mapfile -t CL_SVCS < <(kurtosis enclave inspect "$ENCLAVE" \
  | grep -oE 'cl-[0-9]+-[a-z]+-[a-z]+' | sort -u)
[ "${#CL_SVCS[@]}" -gt 0 ] || { echo "no CL services found" >&2; exit 1; }
echo "CL services: ${CL_SVCS[*]}"

# Resolve the beacon REST URL for a service id.
beacon_url() {
  local url
  url="$(kurtosis port print "$ENCLAVE" "$1" http)"
  [[ "$url" == http* ]] || url="http://$url"
  echo "$url"
}

PRIMARY="${CL_SVCS[0]}"
PRIMARY_URL="$(beacon_url "$PRIMARY")"

# 3. Wait until the primary beacon node serves its identity.
echo "waiting for $PRIMARY ($PRIMARY_URL) ..."
for _ in $(seq 1 60); do
  curl -fsS "$PRIMARY_URL/eth/v1/node/identity" >/dev/null 2>&1 && break
  sleep 2
done

# 4. genesis_unix_secs.
GENESIS="$(curl -fsS "$PRIMARY_URL/eth/v1/beacon/genesis" | jq -r .data.genesis_time)"
echo "genesis_unix_secs: $GENESIS"

# 5. fork_digest — ground truth from the client's own gossip topics
#    (/eth2/<digest>/...). Computing it risks the Fulu modified-digest rules;
#    reading the client's topics avoids that. Pick the dominant digest.
echo "resolving fork_digest from $PRIMARY logs ..."
FORK_DIGEST=""
for _ in $(seq 1 30); do
  FORK_DIGEST="$(kurtosis service logs "$ENCLAVE" "$PRIMARY" 2>/dev/null \
    | grep -oE '/eth2/[0-9a-f]{8}/' | grep -oE '[0-9a-f]{8}' \
    | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')"
  [ -n "$FORK_DIGEST" ] && break
  sleep 2
done
[ -n "$FORK_DIGEST" ] || {
  echo "could not resolve fork_digest from logs (is global_log_level debug?)" >&2
  exit 1
}
echo "fork_digest: $FORK_DIGEST"

# 6. bootstrap_enrs — one per CL node.
ENRS=()
for svc in "${CL_SVCS[@]}"; do
  url="$(beacon_url "$svc")"
  enr="$(curl -fsS "$url/eth/v1/node/identity" | jq -r .data.enr)"
  [ -n "$enr" ] && [ "$enr" != null ] && ENRS+=("$enr")
done
[ "${#ENRS[@]}" -gt 0 ] || { echo "no ENRs harvested" >&2; exit 1; }
echo "bootstrap_enrs: ${#ENRS[@]} harvested"

# 7. external_ip_v4 = the host's Docker bridge IP (peers dial silver back via
#    this). Non-fatal: outbound-only peering still works without it.
GATEWAY="$(docker network inspect "kt-$ENCLAVE" 2>/dev/null \
  | jq -r '.[0].IPAM.Config[0].Gateway // empty' || true)"
echo "external_ip_v4: ${GATEWAY:-<unresolved>}"

# 7b. Genesis state — silver's sync anchor. It bootstraps fork choice from
#     this so block 1's parent (the genesis block) resolves; without it sync
#     fails the parent precheck at slot 1.
echo "fetching genesis state -> $GENESIS_SSZ"
curl -fsS -H 'Accept: application/octet-stream' \
  "$PRIMARY_URL/eth/v2/debug/beacon/states/genesis" -o "$GENESIS_SSZ"

# 7c. Spec — devnet fork versions + blob schedule. silver derives the fork
#     digest AND BLS signing domains from these; mainnet defaults mismatch on
#     a devnet (wrong digest -> no peers; wrong domain -> blocks fail sig
#     verification). Beacon-API spec values are strings.
SPEC="$(curl -fsS "$PRIMARY_URL/eth/v1/config/spec" | jq '.data')"
gfv="$(jq -r '.GENESIS_FORK_VERSION' <<<"$SPEC")"
cfv="$(jq -r '.CAPELLA_FORK_VERSION' <<<"$SPEC")"
ffv="$(jq -r '.FULU_FORK_VERSION' <<<"$SPEC")"
efe="$(jq -r '.ELECTRA_FORK_EPOCH | tonumber' <<<"$SPEC")"
mbe="$(jq -r '.MAX_BLOBS_PER_BLOCK_ELECTRA | tonumber' <<<"$SPEC")"
sps="$(jq -r '.SECONDS_PER_SLOT | tonumber' <<<"$SPEC")"
echo "spec: fulu_fork_version=$ffv"

# 8. Write the config TOML. Static fields from the vars above; derived fields
#    harvested. external_ip_v4 omitted if unresolved (outbound-only).
{
  echo "# Generated by kurtosis/setup.sh — re-run to refresh. Loaded via --config."
  echo "secret_key = \"$SECRET_KEY\""
  echo "fork_digest = \"$FORK_DIGEST\""
  echo "next_fork_version = \"$NEXT_FORK_VERSION\""
  [ -n "$GATEWAY" ] && echo "external_ip_v4 = \"$GATEWAY\""
  echo "discovery_port = $DISCOVERY_PORT"
  echo "quic_port = $QUIC_PORT"
  echo
  echo "[chain_config]"
  echo "genesis_unix_secs = $GENESIS"
  echo "checkpoint_file = \"$GENESIS_SSZ\""
  echo "bootstrap_enrs = ["
  printf '  "%s",\n' "${ENRS[@]}"
  echo "]"
  echo
  echo "[chain_config.spec]"
  echo "GENESIS_FORK_VERSION = \"$gfv\""
  echo "CAPELLA_FORK_VERSION = \"$cfv\""
  echo "FULU_FORK_VERSION = \"$ffv\""
  echo "ELECTRA_FORK_EPOCH = $efe"
  echo "MAX_BLOBS_PER_BLOCK_ELECTRA = $mbe"
  echo "SECONDS_PER_SLOT = $sps"
  # BLOB_SCHEDULE entries (array-of-tables) must follow the scalar keys above.
  jq -r '.BLOB_SCHEDULE // [] | .[]
    | "\n[[chain_config.spec.BLOB_SCHEDULE]]\nEPOCH = \(.EPOCH|tonumber)\nMAX_BLOBS_PER_BLOCK = \(.MAX_BLOBS_PER_BLOCK|tonumber)"' \
    <<<"$SPEC"
} > "$CONFIG"

echo "wrote -> $CONFIG"
echo
echo "run silver:"
echo "  RUST_LOG=info,silver_network=info,silver_peer=info \\"
echo "    cargo run --release --bin silver -- --config $CONFIG"
