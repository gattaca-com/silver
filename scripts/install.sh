#!/bin/bash
mkdir repo
mkdir logs
mkdir config
mkdir data

cd repo
git clone https://github.com/gattaca-com/silver.git

# install rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

# install buf
# Substitute BIN for your bin directory.
# Substitute VERSION for the current released version.
BIN="/usr/local/bin" && \
VERSION="1.72.0" && \
sudo curl -sSL \
"https://github.com/bufbuild/buf/releases/download/v${VERSION}/buf-$(uname -s)-$(uname -m)" \
-o "${BIN}/buf" && \
sudo chmod +x "${BIN}/buf"

# socket buffer limits
sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.core.rmem_max=33554432

# builder silver
cd silver
cargo build --release

# move into place
cd
cp repo/silver/target/release/silver .
cp repo/silver/target/release/silver_surfer .
cp repo/silver/target/release/silver_telemetry .

cp repo/silver/scripts/* .

# Network, bootnodes, checkpoint and node key all default to mainnet's; only
# per-box settings go here.
cat > config/config.toml << EOF
data_column_custody_group_count = 128
attestation_subnet_count = 64
incoming_rpc_tcache_size = 536870912

[engine_config]
execution_endpoint = "http://127.0.0.1:8551"
jwt_secret = "/home/ubuntu/config/jwt.hex"
EOF

# start silver
./start_silver_with_ethrex.sh



