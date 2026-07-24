#!/bin/bash
JWT=/home/ubuntu/config/jwt.hex

if ! command -v ethrex > /dev/null; then
  curl -L https://github.com/lambdaclass/ethrex/releases/latest/download/ethrex-linux-x86_64 -o ethrex
  chmod +x ethrex
  sudo mv ethrex /usr/local/bin/
fi

[ -f "$JWT" ] || openssl rand -hex 32 > "$JWT"

pgrep -f 'ethrex --network mainnet' > /dev/null || nohup ethrex --network mainnet --datadir /home/ubuntu/.ethrex \
  --authrpc.jwtsecret "$JWT" > logs/ethrex.log 2>&1 &

LOG_PATH=/home/ubuntu/logs RUST_LOG=info nohup ./silver --config /home/ubuntu/config/config.toml > logs/stdout.log 2>&1 &
