#!/bin/bash
curl -s -H 'Accept: application/octet-stream' \
    https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states/finalized \
    -o finalized_state.ssz
