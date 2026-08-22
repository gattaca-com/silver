#!/bin/bash
source "$(dirname "$0")"/common.sh
JWT=/home/ubuntu/config/jwt.hex

if ! command -v ethrex > /dev/null; then
  curl -L https://github.com/lambdaclass/ethrex/releases/latest/download/ethrex-linux-x86_64 -o ethrex
  chmod +x ethrex
  sudo mv ethrex /usr/local/bin/
fi

[ -f "$JWT" ] || openssl rand -hex 32 > "$JWT"

pgrep -f 'ethrex --network mainnet' > /dev/null || systemd-run --scope -p MemoryMax=48G -p AllowedCpus=7-15 --user nohup ethrex \
  --network mainnet --datadir /home/ubuntu/.ethrex \
  --authrpc.jwtsecret "$JWT" > logs/ethrex.log 2>&1 &

start_telemetry
start_silver
