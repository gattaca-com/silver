#!/bin/bash
pkill -TERM -x silver
# The daemon would notice the exit within a second anyway; stopping it here
# keeps a stop/start cycle from tripping start_telemetry's already-running guard.
pkill -TERM -f silver_telemetry
