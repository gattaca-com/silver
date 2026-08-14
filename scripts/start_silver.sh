#!/bin/bash
LOG_PATH=/home/ubuntu/logs RUST_LOG=info nohup ./silver --unsafe-no-el --config /home/ubuntu/config/config.toml & 
