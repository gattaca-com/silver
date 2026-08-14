#!/usr/bin/env bash
# Run silver's dedicated local reth against the kurtosis devnet.
#
#   kurtosis/run-reth.sh        (setup.sh must have run first)
#
# Consumes the files setup.sh harvested into el/: the devnet EL genesis,
# the enclave EL enodes (bootnodes + trusted peers, so it syncs and shares
# the tx pool), and the silver<->reth JWT. The datadir persists across
# restarts; setup.sh drops it automatically when the enclave genesis changes.
#
# Requires `reth` on PATH. ENGINE_PORT must match the value setup.sh wrote
# into silver-devnet.toml (default 8551).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EL_DIR="$HERE/el"
ENGINE_PORT="${ENGINE_PORT:-8551}"

command -v reth >/dev/null || { echo "missing dependency: reth" >&2; exit 1; }

GENESIS_JSON="$(find "$EL_DIR/genesis" -name genesis.json 2>/dev/null | head -1)"
[ -n "$GENESIS_JSON" ] && [ -s "$EL_DIR/bootnodes.txt" ] && [ -s "$EL_DIR/jwt.hex" ] || {
  echo "el/ incomplete — run kurtosis/setup.sh first" >&2; exit 1;
}

ENODES="$(paste -sd, "$EL_DIR/bootnodes.txt")"

exec reth node \
  --chain "$GENESIS_JSON" \
  --datadir "$EL_DIR/datadir" \
  --http \
  --authrpc.addr 127.0.0.1 \
  --authrpc.port "$ENGINE_PORT" \
  --authrpc.jwtsecret "$EL_DIR/jwt.hex" \
  --bootnodes "$ENODES" \
  --trusted-peers "$ENODES"
