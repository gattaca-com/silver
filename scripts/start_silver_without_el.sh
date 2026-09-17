#!/bin/bash
source "$(dirname "$0")"/common.sh

start_telemetry
start_silver --unsafe-no-el
