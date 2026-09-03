#!/usr/bin/env bash
# Spin up the kurtosis ethereum-package devnet, harvest the network-specific
# values silver needs, and write the silver config TOML.
#
#   kurtosis/setup.sh [--recreate] [--finalized-anchor|--genesis-anchor] [enclave-name]
#                                                       (default: silver-dev)
#
# --recreate tears down the enclave first for a fresh chain (new genesis ->
# new digest/ENRs/genesis-time -> silver must restart). Without it, a healthy
# enclave is reused and the config just re-synced.
#
# --finalized-anchor anchors silver at the chain's current finalized state
# instead of genesis, so it joins mid-chain: it forward-syncs the finality gap
# and backfills the history below the anchor. Nothing is finalized at genesis,
# so run it (without --recreate) once the chain has finalized. Implied by
# --gloas. --genesis-anchor pins the genesis anchor, which is what --gloas
# needs on a chain whose Gloas activation is epoch 0: there is nothing
# finalized yet, and genesis is already a Gloas state.
#
# Generates silver-devnet.toml from scratch each run (derived fields harvested
# from the CL; static fields — secret_key, ports — taken from the
# env-overridable vars below). Also writes the anchor state and el/
# (genesis + bootnodes + JWT for silver's dedicated local reth — start it with
# run-reth.sh).
#
# Requires: kurtosis, docker, curl, jq. Linux only — silver runs as a host
# process joining the Docker bridge, and external_ip_v4 detection is
# bridge-specific.
set -euo pipefail

RECREATE=0
GLOAS=0
ANCHOR=genesis
ANCHOR_PINNED=0
ENCLAVE=""
for arg in "$@"; do
  case "$arg" in
    --recreate) RECREATE=1 ;;
    --gloas) GLOAS=1 ;;
    --finalized-anchor) ANCHOR=finalized ;;
    --genesis-anchor) ANCHOR=genesis; ANCHOR_PINNED=1 ;;
    -*) echo "unknown flag: $arg" >&2; exit 1 ;;
    *) ENCLAVE="$arg" ;;
  esac
done
[ -n "$ENCLAVE" ] || { [ "$GLOAS" -eq 1 ] && ENCLAVE="silver-gloas" || ENCLAVE="silver-dev"; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Gloas: separate args/config/anchor so the Fulu devnet files are untouched.
# Default anchor is finalized — silver then anchors already in Gloas and follows
# live, sidestepping the from-genesis DA wedge and the Fulu→Gloas digest
# transition; --genesis-anchor opts into both.
if [ "$GLOAS" -eq 1 ]; then
  ARGS_FILE="$HERE/net-gloas.yaml"
  CONFIG="$HERE/silver-gloas.toml"
  [ "$ANCHOR_PINNED" -eq 1 ] || ANCHOR=finalized
  [ "$ANCHOR" = finalized ] && ANCHOR_SSZ="$HERE/gloas-anchor.ssz" \
    || ANCHOR_SSZ="$HERE/gloas-genesis.ssz"
else
  ARGS_FILE="$HERE/net.yaml"
  CONFIG="$HERE/silver-devnet.toml"
  [ "$ANCHOR" = finalized ] && ANCHOR_SSZ="$HERE/fulu-anchor.ssz" \
    || ANCHOR_SSZ="$HERE/genesis.ssz"
fi

# Static (non-harvested) config values — override via env if needed. A fixed
# secret_key gives silver a stable peer-id/ENR across restarts; rotate it per
# run to shed a peer's accumulated RPC penalties.
SECRET_KEY="${SECRET_KEY:-1111111111111111111111111111111111111111111111111111111111111111}"
DISCOVERY_PORT="${DISCOVERY_PORT:-31133}"
QUIC_PORT="${QUIC_PORT:-31123}"
# Custody groups silver subscribes to / advertises (ENR cgc). 8 = silver's
# floor (SAMPLES_PER_SLOT): custody set covers the full sample set, so values
# below 8 are raised to 8. Bump to custody/serve more columns.
CUSTODY_GROUP_COUNT="${CUSTODY_GROUP_COUNT:-8}"
# silver <-> local reth engine API (see run-reth.sh). Any 32-byte hex JWT
# works — both sides read the same generated file.
ENGINE_PORT="${ENGINE_PORT:-8551}"
JWT_SECRET="${JWT_SECRET:-2222222222222222222222222222222222222222222222222222222222222222}"
UNSAFE_NO_EL="${UNSAFE_NO_EL:-1}"

# Pin a known-good release — the bare locator pulls the default branch (HEAD),
# which periodically breaks (e.g. the zkboost `GpuConfig` regression). Bump the
# tag here, or override per-run:
#   PACKAGE='github.com/ethpandaops/ethereum-package@<tag>' kurtosis/setup.sh
# Discover tags:
#   git ls-remote --tags https://github.com/ethpandaops/ethereum-package
# 6.1.0 already exposes `gloas_fork_epoch`, and its Starlark is compatible with
# the installed Kurtosis CLI (HEAD trips an `undefined: GpuConfig` regression),
# so both Fulu and Gloas pin 6.1.0.
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

# 5. bootstrap_enrs — one per CL node.
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

# 7b. silver's sync anchor. It bootstraps fork choice from this state, so the
#     first synced block's parent resolves; without it sync fails the parent
#     precheck at the anchor slot + 1.
if [ "$ANCHOR" = finalized ]; then
  FIN_EPOCH="$(curl -fsS "$PRIMARY_URL/eth/v1/beacon/states/head/finality_checkpoints" \
    | jq -r '.data.finalized.epoch')"
  # An unfinalized chain serves genesis here, which would silently produce a
  # genesis anchor under a flag asking for a mid-chain one.
  [ "${FIN_EPOCH:-0}" -gt 0 ] || {
    echo "chain has not finalized yet (finalized epoch ${FIN_EPOCH:-?}); re-run later" >&2
    exit 1
  }
  echo "fetching finalized anchor state (epoch $FIN_EPOCH) -> $ANCHOR_SSZ"
  curl -fsS -H 'Accept: application/octet-stream' \
    "$PRIMARY_URL/eth/v2/debug/beacon/states/finalized" -o "$ANCHOR_SSZ"
else
  echo "fetching genesis state -> $ANCHOR_SSZ"
  curl -fsS -H 'Accept: application/octet-stream' \
    "$PRIMARY_URL/eth/v2/debug/beacon/states/genesis" -o "$ANCHOR_SSZ"
fi

# 7c. Spec — devnet fork versions + blob schedule. silver derives the fork
#     digest AND BLS signing domains from these; mainnet defaults mismatch on
#     a devnet (wrong digest -> no peers; wrong domain -> blocks fail sig
#     verification). Beacon-API spec values are strings.
SPEC="$(curl -fsS "$PRIMARY_URL/eth/v1/config/spec" | jq '.data')"
gfv="$(jq -r '.GENESIS_FORK_VERSION' <<<"$SPEC")"
cfv="$(jq -r '.CAPELLA_FORK_VERSION' <<<"$SPEC")"
ffv="$(jq -r '.FULU_FORK_VERSION' <<<"$SPEC")"
gloasfv="$(jq -r '.GLOAS_FORK_VERSION' <<<"$SPEC")"
gloasfe="$(jq -r '.GLOAS_FORK_EPOCH | tonumber' <<<"$SPEC")"
efe="$(jq -r '.ELECTRA_FORK_EPOCH | tonumber' <<<"$SPEC")"
# The Fulu *epoch*, not just its version: `fork_at(epoch)` picks the active
# fork from the epochs, and an unstated FULU_FORK_EPOCH falls back to
# mainnet's 411392 -- so a Fulu-from-genesis devnet reads as Electra, which
# silver does not run, and every fork version derived from the schedule
# (signing domains, the fork digest) is the wrong one.
ffe="$(jq -r '.FULU_FORK_EPOCH | tonumber' <<<"$SPEC")"
mbe="$(jq -r '.MAX_BLOBS_PER_BLOCK_ELECTRA | tonumber' <<<"$SPEC")"
sps="$(jq -r '.SECONDS_PER_SLOT | tonumber' <<<"$SPEC")"
WALL_EPOCH=$(( ( $(date +%s) - GENESIS ) / sps / 32 ))
echo "spec: fulu_fork_version=$ffv gloas_fork_epoch=$gloasfe wall_epoch=$WALL_EPOCH"

# 7d. Local EL — silver drives its own dedicated reth over the engine API
#     (newPayload / forkchoiceUpdated). A dedicated EL, not a shared enclave
#     one: two CLs driving one EL fight over its fork choice. Harvest what a
#     host reth needs — the EL genesis, the devnet EL enodes, and a JWT —
#     into el/; run-reth.sh consumes them.
EL_DIR="$HERE/el"
mkdir -p "$EL_DIR"

echo "fetching EL genesis -> $EL_DIR/genesis"
rm -rf "$EL_DIR/genesis"
kurtosis files download "$ENCLAVE" el_cl_genesis_data "$EL_DIR/genesis" >/dev/null
GENESIS_JSON="$(find "$EL_DIR/genesis" -name genesis.json | head -1)"
[ -n "$GENESIS_JSON" ] && [ -s "$GENESIS_JSON" ] || {
  echo "no genesis.json in el_cl_genesis_data artifact" >&2; exit 1;
}

# A new enclave means a new EL chain: drop the reth datadir when the
# downloaded genesis changes, else reth refuses the mismatched chain.
GENESIS_SUM="$(sha256sum "$GENESIS_JSON" | awk '{print $1}')"
if [ "$(cat "$EL_DIR/genesis.sha256" 2>/dev/null)" != "$GENESIS_SUM" ]; then
  rm -rf "$EL_DIR/datadir"
  echo "$GENESIS_SUM" > "$EL_DIR/genesis.sha256"
fi

# enodes of the devnet ELs -> reth bootnodes/trusted peers. Container IPs in
# the enodes are host-routable on Linux (same model as the CL dialing).
# admin_nodeInfo failures are skipped (client without the admin namespace).
ENODES=()
for svc in $(kurtosis enclave inspect "$ENCLAVE" \
  | grep -oE 'el-[0-9]+-[a-z]+-[a-z]+' | sort -u); do
  url="$(kurtosis port print "$ENCLAVE" "$svc" rpc)" || continue
  [[ "$url" == http* ]] || url="http://$url"
  enode="$(curl -fsS -X POST -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"admin_nodeInfo","params":[],"id":1}' \
    "$url" | jq -r '.result.enode // empty')" || continue
  [ -n "$enode" ] && ENODES+=("$enode")
done
[ "${#ENODES[@]}" -gt 0 ] || { echo "no EL enodes harvested" >&2; exit 1; }
printf '%s\n' "${ENODES[@]}" > "$EL_DIR/bootnodes.txt"
echo "EL bootnodes: ${#ENODES[@]} harvested"

echo "$JWT_SECRET" > "$EL_DIR/jwt.hex"

# 8. Write the config TOML. Static fields from the vars above; derived fields
#    harvested. external_ip_v4 omitted if unresolved (outbound-only).
{
  echo "# Generated by kurtosis/setup.sh — re-run to refresh. Loaded via --config."
  echo "secret_key = \"$SECRET_KEY\""
  # No fork_digest / next_fork_version: silver derives both from
  # [chain_config.spec] and the anchor state's genesis_validators_root, and
  # ignores a literal whenever checkpoint_file names an anchor. The spec keys
  # below are what has to be right.
  [ -n "$GATEWAY" ] && echo "external_ip_v4 = \"$GATEWAY\""
  echo "discovery_port = $DISCOVERY_PORT"
  echo "quic_port = $QUIC_PORT"
  echo "data_column_custody_group_count = $CUSTODY_GROUP_COUNT"
  echo
  echo "[engine_config]"
  echo "execution_endpoint = \"http://127.0.0.1:$ENGINE_PORT\""
  echo "jwt_secret = \"$EL_DIR/jwt.hex\""
  # Unsafe no-EL testing mode: set UNSAFE_NO_EL=1 to run silver without a local
  # reth — the engine tile answers every request VALID (CL-only testing).
  [ -n "${UNSAFE_NO_EL:-}" ] && echo "unsafe_no_el = true"
  echo
  echo "[chain_config]"
  echo "genesis_unix_secs = $GENESIS"
  echo "checkpoint_file = \"$ANCHOR_SSZ\""
  echo "bootstrap_enrs = ["
  printf '  "%s",\n' "${ENRS[@]}"
  echo "]"
  echo
  echo "[chain_config.spec]"
  echo "GENESIS_FORK_VERSION = \"$gfv\""
  echo "CAPELLA_FORK_VERSION = \"$cfv\""
  echo "FULU_FORK_VERSION = \"$ffv\""
  # Only emit Gloas keys for --gloas: the spec's default GLOAS_FORK_EPOCH is
  # FAR_FUTURE (u64 max), which exceeds TOML's i64 range and fails to parse.
  if [ "$GLOAS" -eq 1 ]; then
    echo "GLOAS_FORK_VERSION = \"$gloasfv\""
    echo "GLOAS_FORK_EPOCH = $gloasfe"
  fi
  echo "ELECTRA_FORK_EPOCH = $efe"
  echo "FULU_FORK_EPOCH = $ffe"
  echo "MAX_BLOBS_PER_BLOCK_ELECTRA = $mbe"
  echo "SECONDS_PER_SLOT = $sps"
  # BLOB_SCHEDULE entries (array-of-tables) must follow the scalar keys above.
  jq -r '.BLOB_SCHEDULE // [] | .[]
    | "\n[[chain_config.spec.BLOB_SCHEDULE]]\nEPOCH = \(.EPOCH|tonumber)\nMAX_BLOBS_PER_BLOCK = \(.MAX_BLOBS_PER_BLOCK|tonumber)"' \
    <<<"$SPEC"
} > "$CONFIG"

echo "wrote -> $CONFIG"
echo
echo "start silver's local reth (separate terminal):"
echo "  kurtosis/run-reth.sh"
echo
echo "run silver:"
echo "  RUST_LOG=info,silver_network=info,silver_peer=info \\"
echo "    cargo run --release --bin silver -- --config $CONFIG"
