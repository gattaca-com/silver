CHECKPOINTS_DIR := ./tests/example_checkpoints
FINALIZED_STATE := $(CHECKPOINTS_DIR)/finalized_state.ssz
# Anchor slot for the snapshot. `finalized` is the moving alias the public
# API resolves to whatever the network has currently finalized; pin to a
# concrete slot number for a reproducible fixture set. Deep-history slots
# only resolve on archive nodes — chainsafe's beaconstate endpoint serves
# them when retained.
ANCHOR_SLOT ?= finalized
FINALIZED_STATE_URL ?= https://beaconstate-mainnet.chainsafe.io/eth/v2/debug/beacon/states/$(ANCHOR_SLOT)
NEXT_BLOCK_URL_BASE ?= https://lodestar-mainnet.chainsafe.io/eth/v2/beacon/blocks
# Number of post-anchor blocks to fetch + apply in the checkpoint_load /
# sync_pm_bs tests. Must match `EXPECTED_BLOCKS` in `tests/sync_pm_bs.rs`.
NEXT_BLOCKS_COUNT ?= 4
# Slots to probe past the anchor (handles empty slots).
NEXT_BLOCKS_LOOKAHEAD ?= 12

.PHONY: all clean finalized-state next-blocks next-blocks-large checkpoint-fixtures checkpoint-fixtures-large

all: checkpoint-fixtures

checkpoint-fixtures: finalized-state next-blocks

# 128-block fixture set for `sync_pm_bs_one_batch`. Public state archives
# don't keep deep history, so `ANCHOR_SLOT` defaults to the moving
# `finalized` alias — pin to a concrete slot with
# `make ANCHOR_SLOT=<slot> checkpoint-fixtures-large` when you have an
# archive that retains it. ~13 min wall-clock for a fresh pull
# (lodestar's 6s per-request anti-rate-limit sleep dominates).
checkpoint-fixtures-large: NEXT_BLOCKS_COUNT := 128
checkpoint-fixtures-large: NEXT_BLOCKS_LOOKAHEAD := 160
checkpoint-fixtures-large: checkpoint-fixtures

# Fetch blocks against whatever `finalized_state.ssz` is already on
# disk — useful when the state was sourced manually (e.g. copied in
# from a slot that no public archive retains). Doesn't touch the
# state file.
next-blocks-large: NEXT_BLOCKS_COUNT := 128
next-blocks-large: NEXT_BLOCKS_LOOKAHEAD := 160
next-blocks-large: next-blocks

finalized-state: $(FINALIZED_STATE)

clean:
	rm -f $(CHECKPOINTS_DIR)/*.ssz

$(FINALIZED_STATE):
	mkdir -p $(dir $(FINALIZED_STATE))
	curl --location --show-error --retry 3 --retry-all-errors --fail \
		-H 'Accept: application/octet-stream' \
		-o $(FINALIZED_STATE) \
		"$(FINALIZED_STATE_URL)"

# Fetch up to NEXT_BLOCKS_COUNT canonical blocks following the anchor slot,
# scanning NEXT_BLOCKS_LOOKAHEAD slots ahead so empty slots don't block us.
# Re-runs are idempotent — if the on-disk state has rotated since the last
# fetch, run `make clean` first.
#
# lodestar serves SSZ binary at non-epoch-boundary slots but rate-limits per
# IP — sleep 6s between requests to stay under the cap.
next-blocks: $(FINALIZED_STATE)
	@slot=$$(od -An -j40 -N8 -tu8 < $(FINALIZED_STATE) | tr -d ' '); \
	echo "anchor slot: $$slot, fetching up to $(NEXT_BLOCKS_COUNT) following blocks"; \
	got=0; probe=1; \
	while [ $$got -lt $(NEXT_BLOCKS_COUNT) ] && [ $$probe -le $(NEXT_BLOCKS_LOOKAHEAD) ]; do \
		next=$$((slot + probe)); \
		out=$(CHECKPOINTS_DIR)/next_block_$$next.ssz; \
		if [ -f $$out ]; then \
			echo "  slot $$next: cached"; \
			got=$$((got + 1)); \
		else \
			attempt=0; \
			while :; do \
				attempt=$$((attempt + 1)); \
				code=$$(curl --silent --location --show-error --max-time 30 \
					-H 'Accept: application/octet-stream' \
					-o $$out.tmp -w '%{http_code}' "$(NEXT_BLOCK_URL_BASE)/$$next" || echo "000"); \
				case "$$code" in \
					200) mv $$out.tmp $$out; echo "  slot $$next: ok"; got=$$((got + 1)); break;; \
					404|500) rm -f $$out.tmp; echo "  slot $$next: empty ($$code), skipping"; break;; \
					429) rm -f $$out.tmp; \
						if [ $$attempt -ge 4 ]; then \
							echo "  slot $$next: still rate-limited after $$attempt tries, aborting"; \
							exit 1; \
						fi; \
						backoff=$$((attempt * 15)); \
						echo "  slot $$next: rate-limited (429), sleeping $$backoff s (attempt $$attempt/4)"; \
						sleep $$backoff;; \
					*) rm -f $$out.tmp; echo "  slot $$next: unexpected $$code, aborting"; exit 1;; \
				esac; \
			done; \
			sleep 6; \
		fi; \
		probe=$$((probe + 1)); \
	done; \
	if [ $$got -lt $(NEXT_BLOCKS_COUNT) ]; then \
		echo "WARN: only got $$got / $(NEXT_BLOCKS_COUNT) blocks within $(NEXT_BLOCKS_LOOKAHEAD)-slot lookahead"; \
	fi
