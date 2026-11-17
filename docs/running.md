# Running silver as a service

This is the systemd setup used on our own nodes. Below, `D` is the deploy
directory (e.g. `/var/lib/silver`) and `silver` is the user that runs it.

## 1. Host

```bash
# Keep silver's shared memory across ssh logouts.
sudo mkdir -p /etc/systemd/logind.conf.d
printf '[Login]\nRemoveIPC=no\n' | sudo tee /etc/systemd/logind.conf.d/silver-keep-ipc.conf
sudo systemctl restart systemd-logind

echo 'vm.max_map_count=1048576' | sudo tee /etc/sysctl.d/10-map-count.conf
sudo sysctl --system

sudo mkdir -p $D/{data,logs,profiler-traces,releases} && sudo chown -R silver: $D
openssl rand -hex 32 > $D/jwt.hex
```

Without `RemoveIPC=no`, an ssh logout unlinks silver's shared memory. Silver
keeps running, but telemetry, surfer and `silver members` can no longer attach.

Open UDP 31133 (discovery) and 31123 (QUIC), plus the EL's p2p port.

## 2. Binaries

Releases ship `silver` and `silver_surfer`:

```bash
TAG=v0.1.0-alpha.17
BASE=https://github.com/gattaca-com/silver/releases/download/$TAG
mkdir -p $D/releases/$TAG && cd $D/releases/$TAG
for b in silver silver_surfer; do
    curl -sfLO $BASE/$b-linux-x86_64 && curl -sfLO $BASE/$b-linux-x86_64.sha256
    sha256sum -c $b-linux-x86_64.sha256 && mv $b-linux-x86_64 $b
done
chmod 755 silver* && cp silver silver_surfer $D/
```

`silver_telemetry` maps silver's shared memory, so build it at the same tag:

```bash
cargo build --profile release-prod --locked --bin silver_telemetry
```

## 3. Config

`D/config.toml`; see the README for the keys. Silver ignores unknown keys, so
check `crates/config` for renamed keys before an upgrade.

```toml
network = "mainnet"
data_storage_dir = "D/data"
external_ip_v4 = "<public ip>"   # without it the ENR cannot be dialed

[engine_config]
execution_endpoint = "http://127.0.0.1:8551"
jwt_secret = "D/jwt.hex"

[telemetry]                      # read by silver_telemetry only
clickhouse_addr = "<host>:9000"
```

## 4. Units

In `/etc/systemd/system/`, with `D` replaced.

`silver.service`:

```ini
[Unit]
Description=silver consensus client
Wants=network-online.target ethrex.service
After=network-online.target ethrex.service

[Service]
User=silver
WorkingDirectory=D
Environment=LOG_PATH=D/logs RUST_LOG=info RUST_BACKTRACE=1
# Stale shared memory from a previous run fills /dev/shm: SIGBUS, exit 135, no log line.
ExecStartPre=/bin/rm -rf %h/.local/share/silver/shmem
ExecStartPre=/usr/bin/find /dev/shm -maxdepth 1 -name shmem_* -user silver -delete
ExecStart=D/silver --config D/config.toml
StandardOutput=append:D/logs/stdout.log
StandardError=append:D/logs/stdout.log
LimitNOFILE=1048576
Restart=on-failure
RestartSec=30
TimeoutStopSec=120

[Install]
WantedBy=multi-user.target
```

`silver-telemetry.service` (optional):

```ini
[Unit]
Description=silver telemetry
Wants=silver.service
After=silver.service
# silver's ExecStartPre deletes the shared memory this reads.
PartOf=silver.service

[Service]
User=silver
WorkingDirectory=D
Environment=LOG_PATH=D/logs RUST_LOG=info
ExecStart=D/silver_telemetry --dir D/profiler-traces \
    --retain 20GB --period 15m --filter-short-frames 1us --config D/config.toml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

`ethrex.service` (any EL with the engine API works):

```ini
[Unit]
Description=ethrex
Wants=network-online.target
After=network-online.target

[Service]
User=silver
WorkingDirectory=D
ExecStart=D/ethrex --network mainnet --datadir D/ethrex-data \
    --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret D/jwt.hex
StandardOutput=append:D/logs/ethrex.log
StandardError=append:D/logs/ethrex.log
LimitNOFILE=1048576
Restart=on-failure
RestartSec=10
TimeoutStopSec=300

[Install]
WantedBy=multi-user.target
```

## 5. Operate

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ethrex silver silver-telemetry
curl -s localhost:5051/eth/v1/node/syncing
```

- Logs: `D/logs/silver.<date>`, plus `stdout.log` for stderr.
- Restart with `sudo systemctl restart silver`; telemetry follows.
- Upgrade: stage the new tag in `D/releases/<tag>`, keep a copy of the old
  binaries, swap them in, and restart. `sha256sum /proc/$(pgrep -x silver)/exe`
  shows what runs.
- Never run `pkill -f "silver --config ..."` from an ssh shell: it matches the
  shell itself.
- The beacon API answers 403 to an unlisted `Host` header. Add
  `beacon_api_allowed_hosts` when clients use a hostname.
