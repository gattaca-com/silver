# Running silver as a service

This is the systemd setup used on our own nodes. The unit files in
[`deploy/systemd/`](../deploy/systemd) expect the deploy directory
`/var/lib/silver` and a `silver` user. Edit them if yours differ.

## 1. Host

```bash
D=/var/lib/silver

# Keep silver's shared memory across ssh logouts.
sudo mkdir -p /etc/systemd/logind.conf.d
printf '[Login]\nRemoveIPC=no\n' | sudo tee /etc/systemd/logind.conf.d/silver-keep-ipc.conf
sudo systemctl restart systemd-logind

echo 'vm.max_map_count=1048576' | sudo tee /etc/sysctl.d/10-map-count.conf
sudo sysctl --system

sudo useradd --system --create-home silver
sudo mkdir -p $D/{data,logs,profiler-traces,releases} && sudo chown -R silver: $D
openssl rand -hex 32 | sudo -u silver tee $D/jwt.hex > /dev/null
```

Without `RemoveIPC=no`, an ssh logout unlinks silver's shared memory. Silver
keeps running, but telemetry, surfer and `silver members` can no longer attach.

Open UDP 31133 (discovery) and 31123 (QUIC), plus the EL's p2p port.

## 2. Binaries and units

Releases ship `silver`, `silver_surfer` and `silver_telemetry`. Releases before
`v0.1.0-alpha.18` lack `silver_telemetry`; build it at the same tag with
`cargo build --profile release-prod --locked --bin silver_telemetry`.

As `silver` (`sudo -iu silver`):

```bash
D=/var/lib/silver TAG=v0.1.0-alpha.18
BASE=https://github.com/gattaca-com/silver/releases/download/$TAG
mkdir -p $D/releases/$TAG && cd $D/releases/$TAG
for b in silver silver_surfer silver_telemetry; do
    curl -sfLO $BASE/$b-linux-x86_64 && curl -sfLO $BASE/$b-linux-x86_64.sha256
    sha256sum -c $b-linux-x86_64.sha256 && mv $b-linux-x86_64 $b
done
chmod 755 silver* && cp silver silver_surfer silver_telemetry $D/
```

Then install the units, from the same tag:

```bash
TAG=v0.1.0-alpha.18
RAW=https://raw.githubusercontent.com/gattaca-com/silver/$TAG/deploy/systemd
for u in silver silver-telemetry ethrex; do
    sudo curl -sfL $RAW/$u.service -o /etc/systemd/system/$u.service
done
```

`ethrex.service` runs `$D/ethrex` on mainnet. Any EL with the engine API
works; replace that unit to use another.

## 3. Config

`$D/config.toml`; see the README for the keys. Silver ignores unknown keys, so
check `crates/config` for renamed keys before an upgrade.

```toml
network = "mainnet"
data_storage_dir = "/var/lib/silver/data"
external_ip_v4 = "<public ip>"   # without it the ENR cannot be dialed

[engine_config]
execution_endpoint = "http://127.0.0.1:8551"
jwt_secret = "/var/lib/silver/jwt.hex"

[telemetry]                      # read by silver_telemetry only
clickhouse_addr = "<host>:9000"
```

## 4. Operate

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ethrex silver silver-telemetry
curl -s localhost:5051/eth/v1/node/syncing
```

- Logs: `$D/logs/silver.<date>`, plus `stdout.log` for stderr.
- Restart with `sudo systemctl restart silver`; telemetry follows.
- Upgrade: stage the new tag in `$D/releases/<tag>` as above, keep a copy of
  the old binaries, swap them in, and restart.
  `sha256sum /proc/$(pgrep -x silver)/exe` shows what runs.
- Never run `pkill -f "silver --config ..."` from an ssh shell: it matches the
  shell itself.
- The beacon API answers 403 to an unlisted `Host` header. Add
  `beacon_api_allowed_hosts` when clients use a hostname.
