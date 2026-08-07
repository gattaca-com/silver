# Shared paths and launchers, sourced by the start_* scripts.
CONFIG=/home/ubuntu/config/config.toml
LOGS=/home/ubuntu/logs

# Extra args pass through to silver (e.g. --unsafe-no-el).
start_silver() {
    LOG_PATH=$LOGS RUST_LOG=info RUST_BACKTRACE=1 nohup ./silver --config "$CONFIG" "$@" > logs/stdout.log 2>&1 &
}

# The daemon waits for the node's rings, then exits with it; the guard is for a
# second start_* run against a node that is already being traced.
start_telemetry() {
    pgrep -f silver_telemetry > /dev/null && return
    LOG_PATH=$LOGS RUST_LOG=info RUST_BACKTRACE=1 nohup ./silver_telemetry \
        --dir /home/ubuntu/profiler-traces \
        --config "$CONFIG" &
}
