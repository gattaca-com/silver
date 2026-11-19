"""Keeps every SHARD_COUNT-th collected test, starting at SHARD_INDEX.

Shards partition the collection, so their outputs together match one unsharded
run. Collection order is deterministic, so every xdist worker keeps the same
items. Round robin spreads neighbouring tests, which tend to cost alike.
"""

import os

import pytest


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config, items):
    index = int(os.environ["SHARD_INDEX"])
    count = int(os.environ["SHARD_COUNT"])
    assert 0 <= index < count, f"shard {index} of {count}"

    kept = items[index::count]
    dropped = [item for position, item in enumerate(items) if position % count != index]
    config.hook.pytest_deselected(items=dropped)
    items[:] = kept
